#include "log.h"
#include <time.h>
#include <stdarg.h>

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