#include "tree.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "log.h"

#define ALPHABET_SIZE 84
#define NODE_SIZE  (ALPHABET_SIZE * sizeof(uint32_t))

#define FLAG_ANY      0x1FF00000U
#define FLAG_GET      0x00100000U
#define FLAG_HEAD     0x00200000U
#define FLAG_POST     0x00400000U
#define FLAG_PUT      0x00800000U
#define FLAG_DELETE   0x01000000U
#define FLAG_CONNECT  0x02000000U
#define FLAG_OPTIONS  0x04000000U
#define FLAG_TRACE    0x08000000U
#define FLAG_PATCH    0x10000000U
#define FLAG_BEGIN    0x20000000U
#define FLAG_END      0x40000000U
#define FLAG_TERMINAL 0x80000000U
#define OFFSET_MASK   0x000FFFFFU

// index to offset
#define I2O(index) (((index) & OFFSET_MASK) * ALPHABET_SIZE)
// offset to index
#define O2I(offset) (((offset) / ALPHABET_SIZE) & OFFSET_MASK)

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

tree_t *tree_create()
{
    tree_t *tree = (tree_t*) calloc(1, sizeof(tree_t));
    if (tree == NULL)
        return NULL;
    tree->slots = (uint32_t*) calloc(1, NODE_SIZE);
    if (tree == NULL)
    {
        free(tree);
        return NULL;
    }
    tree->count = ALPHABET_SIZE;
    tree->min_expr = 0xFFFF;
    return tree;
}

void tree_destroy( tree_t *tree )
{
    free(tree->slots);
    free(tree);
}

void tree_usage( tree_t *tree, uint32_t *total, uint32_t *waste )
{
    if (tree == NULL) return;

    if (total)
        *total = (uint32_t) (sizeof(tree_t) + tree->count * sizeof(uint32_t));
    if (waste)
    {
        *waste = 0;
        uint32_t max = tree->count & 0xFFFFFFFEU;
        for (uint32_t i = 0; i < max; ++i)
            if (tree->slots[i] == 0) *waste += 1;
        *waste *= (uint32_t) sizeof(uint32_t);
    }
}

static bool tree_append_expr( tree_t *tree, const char *expr, size_t len, uint32_t flags )
{
    if (tree == NULL || expr == NULL) return false;

    //for (const char *c = expr; c < expr+len; ++c)
    //    putchar(*c);
    //putchar('\n');

    flags |= FLAG_TERMINAL;
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

    uint32_t off = 0;
    uint32_t id;
    while (expr < end)
    {
        id = (uint32_t) ascii_to_index(*expr++);
        if (expr >= end)
        {
            tree->slots[off+id] |= flags;
            break;
        }
        if ((tree->slots[off + id] & OFFSET_MASK) == 0)
        {
            tree->slots[off + id] = (uint32_t) (tree->slots[off + id] | O2I(tree->count));
            off = tree->count;
            tree->count += ALPHABET_SIZE;
            tree->slots = realloc(tree->slots, (uint32_t) tree->count * sizeof(uint32_t));
            memset(tree->slots + off, 0, NODE_SIZE);
        }
        else
            off = I2O(tree->slots[off + id]);
    }
    if (len < tree->min_expr)
        tree->min_expr = (uint32_t) len;
    return true;
}

inline static uint32_t pattern_get_method( const char *value, size_t len )
{
    if (*value == 'A' && !strncmp(value, "ANY", len))
        return FLAG_ANY;
    else
    if (*value == 'G' && !strncmp(value, "GET", len))
        return FLAG_GET;
    else
    if (*value == 'P' && !strncmp(value, "POST", len))
        return FLAG_POST;
    else
    if (*value == 'P' && !strncmp(value, "PUT", len))
        return FLAG_PUT;
    else
    if (*value == 'D' && !strncmp(value, "DELETE", len))
        return FLAG_DELETE;
    else
    if (*value == 'C' && !strncmp(value, "CONNECT", len))
        return FLAG_CONNECT;
    else
    if (*value == 'O' && !strncmp(value, "OPTIONS", len))
        return FLAG_OPTIONS;
    else
    if (*value == 'T' && !strncmp(value, "TRACE", len))
        return FLAG_TRACE;
    else
    if (*value == 'P' && !strncmp(value, "PATCH", len))
        return FLAG_PATCH;
    else
        return 0;
}
static uint32_t pattern_get_methods( const char *value, size_t len )
{
    if (value == NULL || *value == 0 || len == 0) return 0;
    uint32_t flags = 0;

    char method[12] = "";
    char *m = method;
    while (1)
    {
        if (*value == '|' || len == 0)
        {
            *m = 0;
            uint32_t f = pattern_get_method(method, len);
            if (f == 0)
                return 0;
            flags |= f;
            if (len == 0) return flags;
            m = method;
        }
        else
        if (m >= method + sizeof(method))
            return 0;
        else
            *m++ = *value;
        ++value;
        --len;
    }
    return flags;
}

static const char *pattern_end( const char *str )
{
    if (str == NULL) return NULL;
    while (*str == ' ' || *str == '\t') ++str;
    if (*str == 0) return NULL;
    while (*str != ' ' && *str != '\t' && *str != 0) ++str;
    return str;
}

bool tree_append( tree_t *tree, const char *value )
{
    if (value == NULL) return false;
    while (*value == ' ' || *value == '\t') ++value;
    if (*value == 0) return false;

    uint32_t flags = 0;
    int state = 0;
    const char *p;
    while ((p = pattern_end(value)))
    {
        if (state == 0)
        {
            flags = pattern_get_methods(value, (size_t) (p - value));
            if (flags == 0) return false;
            state = 1;
        }
        else
        {
            size_t len = (size_t) (p - value);
            if (len >= 3 && len <= 255)
                if (!tree_append_expr(tree, value, (size_t) (p - value), flags))
                    return false;
        }
        value = p;
        while (*value == ' ' || *value == '\t') ++value;
    }
    return true;
}

bool tree_match( const tree_t *root, const char *value )
{
    if (root == NULL || value == NULL || *value == 0)
        return false;

    const char *tmp = value;
    uint32_t len = (uint32_t) strlen(value);
    if (len > 255) return false;

    while (len >= root->min_expr && *tmp)
    {
        const char *p = tmp;
        uint32_t off = 0;
        int id = -1;
        while (*p)
        {
            id = ascii_to_index(*p++);
            if (id < 0)
                break;
            uint32_t idx = off + (uint32_t) id;
            if (root->slots[idx] & FLAG_TERMINAL)
                return (root->slots[idx] & FLAG_BEGIN) == 0 || tmp == value;
            if ((root->slots[idx] & OFFSET_MASK) == 0)
                break;
            off = I2O(root->slots[idx]);
        }
        ++tmp;
        --len;
    }
    return false;
}
