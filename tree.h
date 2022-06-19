#ifndef TREE_H
#define TREE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct
{
    uint32_t *slots;
    uint32_t count;
    uint32_t min_expr;
} tree_t;

tree_t *tree_create();
void tree_destroy( tree_t *tree );
void tree_usage( tree_t *tree, uint32_t *total, uint32_t *waste );
bool tree_append( tree_t *root, const char *expr );
bool tree_match( const tree_t *root, const char *value, const char *method );

#endif // TREE_H