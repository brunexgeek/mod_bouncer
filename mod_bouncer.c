/* Include the required headers from httpd */
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_strings.h"
#include "util_mutex.h"
#include <unistd.h>

#include "dfa.h"
#include "log.h"
#include "table.h"

#include <stdbool.h>

#define ENABLED_OFF    0
#define ENABLED_ON     1
#define ENABLED_UNDEF  2

#define TABLE_SIZE  1024

static void **get_server_config(request_rec *r );
static void **get_server_config_ex( struct ap_conf_vector_t *mc );

typedef struct
{
    apr_ipsubnet_t *addr;
} proxy_entry_t;

typedef struct
{
    apr_pool_t *pool;
    apr_array_header_t *proxies;
    log_t *log;
    dfa_t *dfa;
    uint8_t enabled;
    uint32_t blocked_methods;
    int jail_time;
} config_t;

static apr_global_mutex_t *offender_mutex;
static const char *offender_mutex_type = "bouncer-shm";
static const char *offender_shm_name;
static apr_shm_t *offender_shm;
static const size_t offender_shm_size = sizeof(table_entry_t) * TABLE_SIZE;

static void *create_server_conf(apr_pool_t *pool, server_rec *s)
{
    (void) s;
    config_t *config = apr_pcalloc(pool, sizeof(config_t));
    if (config)
    {
        config->pool = pool;
        config->enabled = ENABLED_UNDEF;
        config->dfa = dfa_create();
        config->jail_time = 300; // 5 minutes
    }
    return config;
}

static const char *directive_set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
    (void) cfg;

    config_t *config = (config_t*) get_server_config_ex(cmd->server->module_config);
    if (config == NULL) return NULL;
    if (!strcasecmp(arg, "on"))
        config->enabled = ENABLED_ON;
    else
    if (!strcasecmp(arg, "off"))
    {
        config->enabled = ENABLED_OFF;
        if (config->proxies) apr_array_clear(config->proxies);
        if (config->log) log_close(config->log);
        if (config->dfa) dfa_destroy(config->dfa);
        config->proxies = NULL;
        config->log = NULL;
        config->dfa = NULL;
    }
    else
        return "Invalid argument. Possible values are 'on' and 'off'";
    return NULL;
}

static char *add_pattern( config_t *config, apr_pool_t *pool, const char *pattern )
{
    if (pattern == NULL || *pattern == 0)
        return "Pattern cannot be empty or NULL";
    // method only
    if (!strchr(pattern, ' '))
        config->blocked_methods |= dfa_extract_methods(pattern, strlen(pattern));
    else
    // method and expression
    if (!dfa_append(config->dfa, pattern))
        return apr_psprintf(pool, "Unable to add patter '%s'", pattern);
    return NULL;
}

static char *string_trim( char *value )
{
    #define ISWP(c) ((c) == ' ' || (c) == '\t' || (c) == '\r' || (c) == '\n')
    // spaces before
    while (ISWP(*value)) ++value;
    if (*value == 0) return value;
    // spaces after
    char *end = value;
    while (*end != 0) ++end;
    while (end > value && (ISWP(*end) || *end == 0))
        *end-- = 0;
    return value;
    #undef ISWP
}

static const char *directive_set_pattern_file(cmd_parms *cmd, void *cfg, const char *arg)
{
    (void) cfg;
    config_t *config = (config_t*) get_server_config_ex(cmd->server->module_config);
    if (config == NULL || config->enabled != ENABLED_ON)
        return NULL;

    static const size_t BUFFER_LEN = 8 * 1024;
    char *buffer = apr_palloc(cmd->temp_pool, BUFFER_LEN);
    if (buffer == NULL)
        return "Unable to allocate memory";
    apr_file_t *fp = NULL;
    apr_file_open(&fp, arg, APR_FOPEN_READ, 0, cmd->pool);
    if (fp)
    {
        while (apr_file_gets(buffer, BUFFER_LEN-1, fp) == APR_SUCCESS)
        {
            const char *pattern = string_trim(buffer);
            if (*pattern == 0) continue;
            const char *result = add_pattern(config, cmd->pool, pattern);
            if (result)
            {
                apr_file_close(fp);
                return result;
            }

        }
        apr_file_close(fp);
        return NULL;
    }
    else
        return apr_psprintf(cmd->pool, "Unable to open '%s'", arg);
}

static const char *directive_add_pattern(cmd_parms *cmd, void *cfg, const char *arg)
{
    (void) cfg;

    config_t *config = (config_t*) get_server_config_ex(cmd->server->module_config);
    if (config == NULL || config->enabled != ENABLED_ON)
        return NULL;
    //log_print(config->log, LOG_TYPE_INFO, "BouncerPattern %s", arg);
    return add_pattern(config, cmd->pool, arg);
}

static const char *directive_set_jail_time(cmd_parms *cmd, void *cfg, const char *arg)
{
    (void) cfg;

    config_t *config = (config_t*) get_server_config_ex(cmd->server->module_config);
    if (config == NULL || config->enabled != ENABLED_ON)
        return NULL;
    config->jail_time = atoi(arg);
    if (config->jail_time < 10)
        return "The minimum jail time is 10 seconds.";
    else
    if (config->jail_time > 2592000) // 30 days
        return "The maximum jail time is 2592000 seconds (i.e. 30 days).";
    return NULL;
}

static const char *directive_set_log(cmd_parms *cmd, void *cfg, const char *arg)
{
    (void) cfg;

    config_t *config = (config_t*) get_server_config_ex(cmd->server->module_config);
    if (config == NULL || config->enabled != ENABLED_ON)
        return NULL;
    if (config->log != NULL)
        return "Log path aready set";
    if ((config->log = log_open(arg, config->pool)) == NULL)
        return apr_psprintf(cmd->pool, "Unable to open log %s: %s", arg, strerror(errno) );

    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
    {
        log_close(config->log);
        config->log = NULL;
    }

    return NULL;
}

/**
 * Returns a value that indicate whether the argument is definitely not an address (false)
 * or is possibly an address (true).
 */
static int look_like_address( const char *value )
{
    size_t len = strlen(value);
    const char *p = value;

    // IPv6
    if (ap_strchr_c(value, ':'))
    {
        while ((*p >= '0' && *p <= '9') ||
            (*p >= 'a' && *p <= 'f') ||
            (*p >= 'A' && *p <= 'F') ||
            *p == ':' ||
            *p == ' ') ++p;
        return (*p == 0 && len <= 45) ? 6 : 0; // max IPv6 length is 45
    }
    // IPv4
    while ((*p >= '0' && *p <= '9') || *p == '.' || *p == ' ') ++p;
    //syslog_print(config->server, "look_like_address %s %d %d", value, (int)len, (int)*p);
    return (*p == 0 && len >= 7 && len <= 15) ? 4 : 0;  // max IPv4 length is 15
}

static const char *directive_set_proxies(cmd_parms *cmd, void *cfg, const char *arg)
{
    (void) cfg;

    config_t *config = (config_t*) get_server_config_ex(cmd->server->module_config);
    if (config == NULL || config->enabled != ENABLED_ON)
        return NULL;

    //syslog_print(config->server, "Adding trusted proxy %s", arg);

    char *addr = apr_pstrdup(cmd->temp_pool, arg);
    char *mask = ap_strrchr(addr, '/');
    if (mask) *mask++ = 0;

    if (!config->proxies)
        config->proxies = apr_array_make(cmd->pool, 1, sizeof(proxy_entry_t));

    proxy_entry_t *entry = (proxy_entry_t*) apr_array_push(config->proxies);
    entry->addr = NULL;

    if (!look_like_address(addr))
    {
        apr_array_pop(config->proxies);
        return apr_psprintf(cmd->pool, "The value '%s' is not a valid IP address", arg);
    }
    if (apr_ipsubnet_create(&entry->addr, addr, mask, cmd->pool) != APR_SUCCESS)
    {
        apr_array_pop(config->proxies);
        return apr_psprintf(cmd->pool, "Unable to parse address '%s'", arg);
    }
    return NULL;
}

static void bouncer_child_init(apr_pool_t *p, server_rec *s)
{
    (void) p;
    (void) s;

    config_t *config = (config_t*) get_server_config_ex(s->module_config);
    if (config == NULL) return;

    if (apr_global_mutex_child_init(&offender_mutex, apr_global_mutex_lockfile(offender_mutex), p) != APR_SUCCESS)
        offender_mutex = NULL;
}

static bool is_trusted_proxy( const config_t *config, const apr_sockaddr_t *addr )
{
    if (config->proxies == NULL)
        return false;
    const proxy_entry_t *items = (const proxy_entry_t *) config->proxies->elts;
    for (int i = 0; i < config->proxies->nelts; ++i)
        if (apr_ipsubnet_test((apr_ipsubnet_t*)items[i].addr, (apr_sockaddr_t*)addr)) return true;
    return false;
}

static apr_sockaddr_t *get_client_xff_address( request_rec *r )
{
    config_t *config = (config_t*) get_server_config(r);
    if (config == NULL)
        return NULL;

    const char *list = apr_table_get(r->headers_in, "X-Forwarded-For");
    if (list == NULL || !is_trusted_proxy(config, r->connection->client_addr))
        return NULL;

    apr_sockaddr_t *addr = NULL;
    char *dlist = apr_pstrdup(r->pool, list);
    while (dlist)
    {
        char *entry = strrchr(dlist, ',');
        if (entry)
            *entry++ = 0;
        else
        {
            entry = dlist;
            dlist = NULL;
        }
        entry = string_trim(entry);

        int type = look_like_address(entry);
        //syslog_print(config->server, "Processing remote %s [IPv%d]", entry, type);
        if (type == 0 ||
            apr_sockaddr_info_get(&addr, entry, (type == 4) ? APR_INET : APR_INET6, 0, 0, r->pool) != APR_SUCCESS)
        {
            return NULL;
        }

        // use the first non-trusted address
        if (!is_trusted_proxy(config, addr))
            return addr;
    }

    return NULL;
}

static const char *get_client_address( request_rec *r )
{
    // try to retrieve the actual client address from XFF
    char *address = r->connection->client_ip;
    apr_sockaddr_t *xff = get_client_xff_address(r);
    if (xff != NULL)
        apr_sockaddr_ip_get(&address, xff);
    return address;
}

static int block_request( config_t *config, request_rec *r, const char *address )
{
    const char *ua = apr_table_get(r->headers_in, "User-Agent");
    const char *ref = apr_table_get(r->headers_in, "Referer");

    r->status = HTTP_UNAUTHORIZED;
    log_print(config->log, LOG_TYPE_BLOCK, "%s %s %s \"%s\" %d \"%s\" \"%s\"",
        r->connection->client_ip,
        address,
        r->method,
        r->unparsed_uri,
        r->status,
        ref ? ref : "",
        ua ? ua : "");
    return DONE;
}

static bool is_offender( const char *address, bool *found )
{
    if (apr_global_mutex_lock(offender_mutex) != APR_SUCCESS) return false;

    void *table = apr_shm_baseaddr_get(offender_shm);
    table_entry_t *offender = table_find(table, address);
    *found = offender != NULL;
    bool result = (offender != NULL && offender->release_at > current_time());
    //log_print(config->log, LOG_TYPE_INFO, "is %s an offender? %s", address, result ? "yes" : "no");

    apr_global_mutex_unlock(offender_mutex);
    return result;
}

static void update_offender( config_t *config, const char *address, int result )
{
    if (apr_global_mutex_lock(offender_mutex) != APR_SUCCESS) return;

    void *table = apr_shm_baseaddr_get(offender_shm);
    if (result != DECLINED)
    {
        table_entry_t *offender = table_find(table, address);
        int release_at = current_time() + config->jail_time;
        if (offender == NULL)
            table_insert(table, address, release_at);
        else
            offender->release_at = release_at;
        log_print(config->log, LOG_TYPE_INFO, "Address %s jailed for %d seconds", address, config->jail_time);
    }
    else
        table_remove(table, address);

    apr_global_mutex_unlock(offender_mutex);
}

static int bouncer_handler(request_rec *r)
{
    int result = DECLINED;

    config_t *config = (config_t*) get_server_config(r);
    if (config == NULL || config->enabled != ENABLED_ON)
        return DECLINED;

    const char *address = get_client_address(r);
    // is this client serving jail time?
    bool ex_con = false;
    if (is_offender(address, &ex_con))
    {
        r->status = HTTP_UNAUTHORIZED;
        return DONE;
    }

    // try to block by HTTP method
    uint32_t method = dfa_detect_method(r->method, strlen(r->method));
    if (config->blocked_methods != 0)
    {
        if (config->blocked_methods & method)
            result = block_request(config, r, address);
    }
    else
    {
        // try to get the original URI (e.g. not modified by mod_write)
        const char *uri = strchr(r->the_request, ' ');
        if (uri != NULL)
        {
            uri++;
            const char *end = strchr(uri, ' ');
            if (end != NULL)
                uri = apr_pstrndup(r->pool, uri, (size_t) (end - uri));
        }
        // fallback to unparsed URI
        if (uri == NULL)
            uri = r->unparsed_uri;
        // try to block by pattern matching
        if (dfa_match(config->dfa, uri, method))
            result = block_request(config, r, address);
    }

    if (result != DECLINED || ex_con) update_offender(config, address, result);

    return result;
}

static int bouncer_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    (void) pconf;
    (void) plog;
    (void) ptemp;
    ap_mutex_register(pconf, offender_mutex_type, NULL, APR_LOCK_DEFAULT, 0);
    return OK;
}

static apr_status_t shm_cleanup_wrapper(void *unused)
{
    (void) unused;
    if (offender_shm) return apr_shm_destroy(offender_shm);
    return OK;
}

static int bouncer_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    (void) pconf;
    (void) plog;
    (void) ptemp;
    (void) s;

    apr_status_t rs;
    uint8_t *base;
    const char *tempdir;

    // ignore pre-flight configuration
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) return OK;

    // create an shared memory region
    rs = apr_temp_dir_get(&tempdir, pconf);
    if (APR_SUCCESS != rs) return HTTP_INTERNAL_SERVER_ERROR;
    offender_shm_name = apr_psprintf(pconf, "%s/httpd_shm.%ld", tempdir, (long int)getpid());
    rs = apr_shm_create(&offender_shm, offender_shm_size, (const char *) offender_shm_name, pconf);
    if (APR_SUCCESS != rs) return HTTP_INTERNAL_SERVER_ERROR;
    // initialize the hash table
    base = (uint8_t *) apr_shm_baseaddr_get(offender_shm);
    table_init(base, offender_shm_size);
    syslog_print("bla", "Initialized hash table");
    // initialize the mutex to access the hashtable
    rs = ap_global_mutex_create(&offender_mutex, NULL, offender_mutex_type, NULL, s, pconf, 0);
    if (APR_SUCCESS != rs) return HTTP_INTERNAL_SERVER_ERROR;
    // shared memory cleanup function
    apr_pool_cleanup_register(pconf, NULL, shm_cleanup_wrapper, apr_pool_cleanup_null);

    server_rec *server = s;
    while (server != NULL)
    {
        config_t *config = (config_t*) get_server_config_ex(server->module_config);
        if (config && config->log && config->dfa)
        {
            uint32_t size = 0;
            dfa_usage(config->dfa, &size, NULL);
            size += (uint32_t) offender_shm_size;
            log_print(config->log, LOG_TYPE_INFO, "Configuration done. Memory usage is %0.2f KiB.",
                (float) size / 1024.0F);
        }
        server = server->next;
    }

    return OK;
}

static void register_hooks(apr_pool_t *pool)
{
    (void) pool;
    ap_hook_pre_config(bouncer_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(bouncer_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(bouncer_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(bouncer_handler, NULL, NULL, APR_HOOK_FIRST);
}

static const command_rec bouncer_directives[] =
{
    AP_INIT_TAKE1("BouncerEngine", directive_set_enabled, NULL, RSRC_CONF, "Enable or disable the module"),
    AP_INIT_TAKE1("BouncerPatternFile", directive_set_pattern_file, NULL, RSRC_CONF, "Append one or more patterns through external file"),
    AP_INIT_RAW_ARGS("BouncerPattern", directive_add_pattern, NULL, RSRC_CONF, "Append one or more patterns"),
    AP_INIT_ITERATE("BouncerTrustedProxy", directive_set_proxies, NULL, RSRC_CONF, "Append to the list of trusted proxies"),
    AP_INIT_TAKE1("BouncerLog", directive_set_log, NULL, RSRC_CONF, "Set the location of the module log"),
    AP_INIT_TAKE1("BouncerJailTime", directive_set_jail_time, NULL, RSRC_CONF, "The amount of seconds the offending remote address will blocked"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA bouncer_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_server_conf,
    NULL,
    bouncer_directives,
    register_hooks
#if defined(AP_MODULE_FLAG_NONE)
    , AP_MODULE_FLAG_NONE
#endif
};

static void **get_server_config_ex( struct ap_conf_vector_t *mc )
{
    return ap_get_module_config(mc, &bouncer_module);
}

static void **get_server_config(request_rec *r )
{
    return get_server_config_ex((r)->server->module_config);
}