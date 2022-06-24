#include "table.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

#define TABLE_MAGIC 0xAA391755

typedef struct
{
    uint32_t magic;
    uint32_t count;
} table_header_t;

int current_time()
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int) (t.tv_sec & 0x7FFFFFFF);
}

void table_init( void *table, size_t size )
{
    memset(table, 0, size);
    table_header_t *header = table;
    header->magic = TABLE_MAGIC;
    header->count = (uint32_t) (size / sizeof(table_entry_t)) - 1;
}

static uint32_t compute_hash( const char *addr )
{
    static const uint64_t INITIAL_VALUE = 0;
    static const uint64_t PRIME_FACTOR = 31;
    uint64_t h = INITIAL_VALUE;
    while (*addr != 0)
        h = (h * PRIME_FACTOR + (uint64_t)*addr++) % UINT32_MAX;
    return h == 0 ? 1 : (uint32_t) h;
}

static int table_find_entry( void *table, const char *addr )
{
    uint32_t count = ((const table_header_t*) table)->count;
    uint32_t hash = compute_hash(addr);
    table_entry_t *p = (table_entry_t*) table + 1;
    int i = (int) (hash % count);
    int s = i;
    int now =  current_time();

    do
    {
        if (p[i].hash == 0)
            return -1;
        if (p[i].release_at < now) // detect expired entries
        {
            p[i].hash = 0;
            return -1;
        }
        if (p[i].hash != hash)
            return -1;
        if (strcmp(p[i].addr, addr) == 0)
            return i;
        i = (i + 1) % (int) count;
    } while (i != s);
    return -1;
}

table_entry_t *table_find( void *table, const char *addr )
{
    int index = table_find_entry(table, addr);
    if (index < 0) return NULL;
    return (table_entry_t*) table + 1 + index;
}

bool table_insert( void *table, const char *addr, int release_at )
{
    uint32_t count = ((const table_header_t*) table)->count;
    uint32_t hash = compute_hash(addr);
    table_entry_t *p = (table_entry_t*) table + 1;
    uint32_t i = hash % count;
    uint32_t s = i;
    int now = current_time();

    do
    {
        if (p[i].hash == 0 || p[i].release_at < now)
        {
            p[i].hash = hash;
            p[i].release_at = release_at;
            strncpy(p[i].addr, addr, 45);
            p[i].addr[45] = 0;
            return true;
        }
        i = (i + 1) % count;
    } while (i != s);
    return false;
}

static int table_find_last( void *table, int index )
{
    uint32_t count = ((const table_header_t*) table)->count;
    table_entry_t *p = (table_entry_t*) table + 1;
    int s = index, i = (index + 1) % (int) count;
    uint32_t hash = p[index].hash;
    int last = -1;

    while (i != s)
    {
        if (p[i].hash != hash) return last;
        last = i;
        i = (i + 1) % (int) count;
    }
    return -1;
}

bool table_remove( void *table, const char *addr )
{
    int index = table_find_entry(table, addr);
    if (index < 0) return false;
    int last = table_find_last(table, index);

    table_entry_t *p = (table_entry_t*) table + 1;
    if (last < 0)
        //memset(p + index, 0, sizeof(table_entry_t));
        p[index].hash = 0;
    else
    {
        memcpy(p + index, p + last, sizeof(table_entry_t));
        //memset(p + last, 0, sizeof(table_entry_t));
        p[last].hash = 0;
    }
    return true;
}

void table_print( void *table )
{
    uint32_t count = ((const table_header_t*) table)->count;
    table_entry_t *p = (table_entry_t*) table + 1;

    for (uint32_t i = 0; i < count; ++i)
        printf("%02d: hash=%08x addr='%-15s' release_at=%d\n", i, p[i].hash, p[i].addr, p[i].release_at);
    putchar('\n');
}