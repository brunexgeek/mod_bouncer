#include "log.h"
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>

#include <apr_proc_mutex.h>

struct log
{
    FILE *fp;
    apr_proc_mutex_t *mutex;
};

static const char *TYPE_NAMES[] =
{
	"INFO",
	"WARN",
	"ERROR",
	"BLOCK",
};

log_t *log_open( const char *path, apr_pool_t *pool )
{
	if (pool == NULL || path == NULL)
		return NULL;
	log_t *log = (log_t*) apr_pcalloc(pool, sizeof(log_t));
	if (log == NULL)
		return NULL;
	if (apr_proc_mutex_create(&log->mutex, NULL, APR_LOCK_PROC_PTHREAD, pool) != APR_SUCCESS)
		return NULL;
    if ((log->fp = fopen(path, "a")) == NULL)
	{
		apr_proc_mutex_destroy(log->mutex);
		return NULL;
	}
	return log;
}


void log_close( log_t *log )
{
	if (log == NULL)
		return;
    if (log->fp)
	{
		fclose(log->fp);
		log->fp = NULL;
	}
    if (log->mutex)
	{
		apr_proc_mutex_destroy(log->mutex);
		log->mutex = NULL;
	}
}

void log_print( log_t *log, log_type_t type, const char *format, ... )
{
    va_list args;
	time_t rawtime;
	struct tm timeinfo;
	char timeStr[28];

    if (log == NULL || log->fp == NULL || log->mutex == NULL)
		return;

	if (apr_proc_mutex_lock(log->mutex) != APR_SUCCESS)
		return;

	time(&rawtime);
	localtime_r(&rawtime, &timeinfo);
	strftime(timeStr, sizeof(timeStr) - 1, "%Y-%m-%dT%H:%M:%S%z", &timeinfo);
	fprintf(log->fp, "%s [%s] ", timeStr, TYPE_NAMES[type]);

	va_start(args, format);
	vfprintf(log->fp, format, args);
	va_end(args);
	fprintf(log->fp, "\n");
	fflush(log->fp);

	apr_proc_mutex_unlock(log->mutex);
}

void syslog_print( const char *server, const char *format, ... )
{
    char tmp[512] = {0};
	va_list args;

	if (server == NULL || format == NULL) return;

    openlog("mod_bouncer", LOG_PID, LOG_DAEMON);
    va_start(args, format);
    snprintf(tmp, sizeof(tmp) - 1, "[%s] ", server);
	size_t len = strlen(tmp);
    vsnprintf(tmp + len, sizeof(tmp) - 1 - len, format, args);
	va_end(args);
    syslog( LOG_DAEMON|LOG_ERR, "%s", tmp);
    closelog();
}
