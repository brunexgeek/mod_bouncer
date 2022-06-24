#ifndef TABLE_H
#define TABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint32_t hash;
    char addr[48]; // key
    int release_at;
} table_entry_t;

int current_time();
void table_init( void *table, size_t size );
table_entry_t *table_find( void *table, const char *addr );
bool table_insert( void *table, const char *addr, int release_at );
bool table_remove( void *table, const char *addr );
void table_print( void *table );

#endif // TABLE_H
