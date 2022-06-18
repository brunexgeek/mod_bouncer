#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <apr_pools.h>

typedef enum
{
    LOG_TYPE_INFO,
    LOG_TYPE_WARN,
    LOG_TYPE_ERROR,
    LOG_TYPE_BLOCK,
} log_type_t;

struct log;
typedef struct log log_t;

log_t *log_open( const char *path, apr_pool_t *pool );
void log_close( log_t *log );
void log_print( log_t *log, log_type_t type, const char *format, ... );
void syslog_print( const char *server, const char *format, ... );

#endif // LOG_H