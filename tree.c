#include "tree.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#define TREE_NODE_COUNT 84
#define TREE_NODE_SIZE  (TREE_NODE_COUNT * sizeof(uint16_t))

#define FLAG_TERMINAL 0x8000
#define FLAG_BEGIN    0x4000
#define OFFSET_MASK   0x3FFF

// index to offset
#define I2O(index) (((index) & OFFSET_MASK) * TREE_NODE_COUNT)
// offset to index
#define O2I(offset) (((offset) / TREE_NODE_COUNT) & OFFSET_MASK)

static int ascii_to_index( int c )
{
    // !
    if (c == '!')
        return 0;
    // # $ % ' ( ) * + , - . / 0-9 : ;
    if (c >= '#' && c <= '9')
        return c - '#' + 1;
    // = ? @ A-Z [ ~ ]
    if (c >= '=' && c <= ']')
        return c - '=' + 25;
    // _
    if (c == '_')
        return 57;
    // a-z
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 58;
    return -1;
}

tree_t *tree_init()
{
    tree_t *tree = (tree_t*) calloc(1, sizeof(tree_t));
    if (tree == NULL)
        return NULL;
    tree->slots = (uint16_t*) calloc(1, TREE_NODE_SIZE);
    if (tree == NULL)
    {
        free(tree);
        return NULL;
    }
    tree->count = TREE_NODE_COUNT;
    tree->min_expr = 0xFFFF;
    return tree;
}

static bool tree_append_expr( tree_t *root, const char *expr, size_t len )
{
    if (root == NULL || expr == NULL) return false;

    //for (const char *c = expr; c < expr+len; ++c)
    //    putchar(*c);
    //putchar('\n');

    uint16_t flags = FLAG_TERMINAL;
    if (*expr == '^')
    {
        flags |= FLAG_BEGIN;
        ++expr;
        --len;
    }

    if (len == 0 || len > 255) return false;
    const char *end = expr + len;

    for (const char *p = expr; p < end; ++p)
        if (ascii_to_index(*p) < 0) return false;

    int off = 0;
    int id = -1;
    while (expr < end)
    {
        id = ascii_to_index(*expr++);
        if (expr >= end) break;
        if ((root->slots[off + id] & OFFSET_MASK) == 0)
        {
            root->slots[off + id] = (uint16_t) (root->slots[off + id] | O2I(root->count));
            off = root->count;
            root->count += TREE_NODE_COUNT;
            root->slots = realloc(root->slots, (uint32_t) root->count * sizeof(uint16_t));
            memset(root->slots + off, 0, TREE_NODE_SIZE);
        }
        else
            off = I2O(root->slots[off + id]);
    }
    root->slots[off+id] |= flags;
    if (len < root->min_expr)
        root->min_expr = (uint16_t) len;
    return true;
}

bool tree_append( tree_t *root, const char *expr )
{
    if (root == NULL || expr == NULL || *expr == 0)
        return false;

    const char *p;
    while ((p = strchr(expr, ' ')))
    {
        if (!tree_append_expr(root, expr, (size_t) (p - expr)))
            return false;
        expr = p + 1;
    }
    if (*expr == 0) return true;
    return tree_append_expr(root, expr, strlen(expr));
}

bool tree_match( const tree_t *root, const char *value )
{
    if (root == NULL || value == NULL || *value == 0)
        return false;

    const char *tmp = value;
    int len = (int) strlen(value);
    if (len > 255) return false;

    while (len >= root->min_expr && *tmp)
    {
        const char *p = tmp;
        int off = 0;
        int id = -1;
        while (*p)
        {
            id = ascii_to_index(*p++);
            if (id < 0)
                break;
            if (root->slots[off + id] & FLAG_TERMINAL)
                return (root->slots[off + id] & FLAG_BEGIN) == 0 || tmp == value;
            if ((root->slots[off + id] & OFFSET_MASK) == 0)
                break;
            off = I2O(root->slots[off + id]);
        }
        ++tmp;
        --len;
    }
    return false;
}
