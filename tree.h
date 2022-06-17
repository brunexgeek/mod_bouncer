#ifndef TREE_H
#define TREE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct
{
    uint16_t *slots;
    int count;
    uint16_t min_expr;
} tree_t;

tree_t *tree_init();
bool tree_append( tree_t *root, const char *expr );
bool tree_match( const tree_t *root, const char *value );

#endif // TREE_H