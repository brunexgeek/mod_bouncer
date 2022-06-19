/* Include the required headers from httpd */
#include "httpd.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_strmatch.h"
#include "apr_allocator.h"
#include "apr_strings.h"

#include "tree.h"
#include "log.h"

#include <stdbool.h>

#define ENABLED_OFF    0
#define ENABLED_ON     1
#define ENABLED_UNDEF  2

#define get_server_config(r)  ap_get_module_config((r)->server->module_config, &bouncer_module)

typedef struct
{
    apr_ipsubnet_t *addr;
} proxy_entry_t;

typedef struct
{
    apr_pool_t *pool;
    apr_array_header_t *proxies;
    log_t *log;
    tree_t *tree;
    uint32_t enabled : 2;
    uint32_t flags : 30;
} config_t;

static void *create_server_conf(apr_pool_t *pool, server_rec *s);
static const char *directive_set_enabled(cmd_parms *cmd, void *cfg, const char *arg);
static const char *directive_set_pattern_file(cmd_parms *cmd, void *cfg, const char *arg);
static const char *directive_add_pattern(cmd_parms *cmd, void *cfg, const char *arg);
static const char *directive_set_log(cmd_parms *cmd, void *cfg, const char *arg);
static const char *directive_set_proxies(cmd_parms *cmd, void *cfg, const char *arg);
static void register_hooks(apr_pool_t *pool);
static int bouncer_handler(request_rec *r);

static const command_rec bouncer_directives[] =
{
    AP_INIT_TAKE1("BouncerEngine", directive_set_enabled, NULL, RSRC_CONF, "Enable or disable the module"),
    AP_INIT_TAKE1("BouncerPatternFile", directive_set_pattern_file, NULL, RSRC_CONF, "Append one or more patterns through external file"),
    AP_INIT_RAW_ARGS("BouncerPattern", directive_add_pattern, NULL, RSRC_CONF, "Append one or more patterns"),
    AP_INIT_ITERATE("BouncerTrustedProxy", directive_set_proxies, NULL, RSRC_CONF, "Append to the list of trusted proxies"),
    AP_INIT_TAKE1("BouncerLog", directive_set_log, NULL, RSRC_CONF, "Set the location of the module log"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA bouncer_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                          // Per-directory configuration handler
    NULL,                          // Merge handler for per-directory configurations
    create_server_conf,            // Per-server configuration handler
    NULL,                          // Merge handler for per-server configurations
    bouncer_directives,            // Any directives we may have for httpd
    register_hooks,                // Our hook registering function
    AP_MODULE_FLAG_NONE
};

static void *create_server_conf(apr_pool_t *pool, server_rec *s)
{
    (void) s;
    config_t *config = apr_pcalloc(pool, sizeof(config_t));
    if (config)
    {
        config->pool = pool;
        config->enabled = ENABLED_UNDEF;
        config->tree = tree_create();
    }
    return config;
}

static const char *directive_set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
    (void) cfg;

    config_t *config = (config_t*) get_server_config(cmd);
    if (config == NULL) return NULL;
    if (!strcasecmp(arg, "on"))
        config->enabled = ENABLED_ON;
    else
    if (!strcasecmp(arg, "off"))
    {
        config->enabled = ENABLED_OFF;
        if (config->proxies) apr_array_clear(config->proxies);
        if (config->log) log_close(config->log);
        if (config->tree) tree_destroy(config->tree);
        config->proxies = NULL;
        config->log = NULL;
        config->tree = NULL;
    }
    else
        return "Invalid argument. Possible values are 'on' and 'off'";
    return NULL;
}

static char *add_pattern( config_t *config, apr_pool_t *pool, const char *pattern )
{
    if (pattern == NULL || *pattern == 0)
        return "Pattern cannot be empty or NULL";
    if (!tree_append(config->tree, pattern))
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
    config_t *config = (config_t*) get_server_config(cmd);
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

    config_t *config = (config_t*) get_server_config(cmd);
    if (config == NULL || config->enabled != ENABLED_ON)
        return NULL;
    //log_print(config->log, LOG_TYPE_INFO, "BouncerPattern %s", arg);
    return add_pattern(config, cmd->pool, arg);
}

static const char *directive_set_log(cmd_parms *cmd, void *cfg, const char *arg)
{
    (void) cfg;

    config_t *config = (config_t*) get_server_config(cmd);
    if (config == NULL || config->enabled != ENABLED_ON)
        return NULL;
    if (config->log != NULL)
        return "Log path aready set";
    if ((config->log = log_open(arg, config->pool)) == NULL)
        return apr_psprintf(cmd->pool, "Unable to open log %s: %s", arg, strerror(errno) );
    return NULL;
}

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

    config_t *config = (config_t*) get_server_config(cmd);
    if (config == NULL || config->enabled != ENABLED_ON)
        return NULL;

    //syslog_print(config->server, "Adding trusted proxy %s", arg);

    char *addr = apr_pstrdup(cmd->temp_pool, arg);
    char *mask = ap_strchr(addr, '/');
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

#if 0
static int bouncer_post_config(apr_pool_t *pconf, apr_pool_t *plog,apr_pool_t *ptemp, server_rec *s)
{
    (void) pconf;
    (void) plog;
    (void) ptemp;
    server_rec *server = s;
    while (server != NULL)
    {
        config_t *config = (config_t*) ap_get_module_config(server->module_config, &bouncer_module);
        if (config == NULL) return DECLINED;

        if (config->tree)
        {
            uint32_t size;
            tree_usage(config->tree, &size, NULL);
            log_print(config->log, LOG_TYPE_INFO, "Configuration done. Memory usage is %0.2f KiB.",
                (float) size / 1024.0F);
        }

        server = server->next;
    }
    return OK;
}
#endif

static void register_hooks(apr_pool_t *pool)
{
    (void) pool;

    #if 0
    ap_hook_post_config(bouncer_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    #endif
    ap_hook_handler(bouncer_handler, NULL, NULL, APR_HOOK_FIRST);
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

static int bouncer_handler(request_rec *r)
{
    config_t *config = (config_t*) get_server_config(r);

    if (config == NULL /*|| config->enabled != ENABLED_ON*/)
        return DECLINED;

    if (tree_match(config->tree, r->unparsed_uri))
    {
        // try to retrieve the actual client address from XFF
        char *xff_str = NULL;
        apr_sockaddr_t *xff = get_client_xff_address(r);
        if (xff != NULL)
            apr_sockaddr_ip_get(&xff_str, xff);

        const char *ua = apr_table_get(r->headers_in, "User-Agent");
        const char *ref = apr_table_get(r->headers_in, "Referer");
        const char *rhost = r->connection->client_ip;

        r->status = HTTP_NOT_FOUND;
        log_print(config->log, LOG_TYPE_BLOCK, "%s %s %s \"%s\" %d \"%s\" \"%s\"",
            rhost,
            xff_str ? xff_str : rhost,
            r->method,
            r->unparsed_uri,
            r->status,
            ref ? ref : "",
            ua ? ua : "");
        return DONE;
    }

    return DECLINED;
}