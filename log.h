#ifndef LOG_H
#define LOG_H

#include <stdio.h>

FILE *log_open( const char *filename );
void log_close( FILE *output );
void log_print( FILE *output, const char *format, ... );
void syslog_print( const char *server, const char *format, ... );

#endif // LOG_H