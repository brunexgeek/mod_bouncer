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
    tree_t *tree;
    FILE *log;
    apr_array_header_t *proxies;
    const char *server;
    uint8_t enabled;
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
    AP_INIT_TAKE1("BouncerEngine", directive_set_enabled, NULL, RSRC_CONF, "Enable or disable mod_bouncer"),
    AP_INIT_TAKE1("BouncerPatternFile", directive_set_pattern_file, NULL, RSRC_CONF, "Append one or more patterns"),
    AP_INIT_ITERATE("BouncerPattern", directive_add_pattern, NULL, RSRC_CONF, "Append one or more patterns"),
    AP_INIT_ITERATE("BouncerTrustedProxy", directive_set_proxies, NULL, RSRC_CONF, "List of trusted proxies"),
    AP_INIT_TAKE1("BouncerLog", directive_set_log, NULL, RSRC_CONF, "Set the location of the monitoring log"),
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
        config->tree = tree_init();
        config->server = s->server_hostname;
    }
    return config;
}

static const char *directive_set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
    (void) cfg;

    config_t *config = (config_t*) get_server_config(cmd);
    if (config == NULL) return NULL;
    config->enabled = !strcasecmp(arg, "on") ? ENABLED_ON : ENABLED_OFF;
    return NULL;
}

static char *add_pattern( config_t *config, apr_pool_t *pool, const char *pattern )
{
    if (pattern == NULL || *pattern == 0)
        return "Pattern cannot be empty or NULL";
    size_t len = strlen(pattern);
    if (*pattern == '^') --len;
    if (len < 3 || len > 255)
        return "Pattern length must be 3 to 255 characters long";
    if (!tree_append(config->tree, pattern))
        return apr_psprintf(pool, "Unable to add patter '%s'", pattern);
    return NULL;
}

static const char *directive_set_pattern_file(cmd_parms *cmd, void *cfg, const char *arg)
{
    (void) cfg;
    config_t *config = (config_t*) get_server_config(cmd);
    if (config == NULL || config->enabled != ENABLED_ON) return NULL;

    char pattern[256];
    apr_file_t *fp = NULL;
    apr_file_open(&fp, arg, APR_FOPEN_READ, 0, cmd->pool);
    if (fp)
    {
        while (apr_file_gets(pattern, sizeof(pattern)-1, fp) == APR_SUCCESS)
        {
            apr_collapse_spaces(pattern, pattern);
            if (*pattern == 0) continue;
            const char *result = add_pattern(config, cmd->pool, pattern);
            if (result)
            {
                apr_file_close(fp);
                return result;
            }
            //syslog_print(config->server, "Got pattern '%s'", pattern);
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
    if (config == NULL || config->enabled != ENABLED_ON) return NULL;
    return add_pattern(config, cmd->pool, arg);
}

static const char *directive_set_log(cmd_parms *cmd, void *cfg, const char *arg)
{
    (void) cfg;

    config_t *config = (config_t*) get_server_config(cmd);
    if (config == NULL || config->enabled != ENABLED_ON || config->log != NULL)
        return NULL;
    config->log = log_open(arg);
    if (config->log == NULL)
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

static void register_hooks(apr_pool_t *pool)
{
    (void) pool;

    ap_hook_handler(bouncer_handler, NULL, NULL, APR_HOOK_FIRST);
}

static bool is_trusted_proxy( const config_t *config, const apr_sockaddr_t *addr )
{
    if (config->proxies == NULL) return false;
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
        apr_collapse_spaces(entry, entry);

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
    if (config == NULL) return DECLINED;

    if (config->enabled == ENABLED_ON && tree_match(config->tree, r->unparsed_uri))
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
        log_print(config->log, "[BLOCKED] %s %s %s \"%s\" %d \"%s\" \"%s\"",
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