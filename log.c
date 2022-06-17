#include "log.h"
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>

FILE *log_open( const char *filename )
{
    return fopen(filename, "a");
}

void log_close( FILE *output )
{
    fclose(output);
}

void log_print( FILE *output, const char *format, ... )
{
    va_list args;
	time_t rawtime;
	struct tm timeinfo;
	char timeStr[28];

    if (output == NULL) return;

	time(&rawtime);
	localtime_r(&rawtime, &timeinfo);
	strftime(timeStr, sizeof(timeStr) - 1, "%Y-%m-%dT%H:%M:%S%z", &timeinfo);
	fprintf(output, "%s ", timeStr);

	va_start(args, format);
	vfprintf(output, format, args);
	va_end(args);
	fprintf(output, "\n");
	fflush(output);
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
