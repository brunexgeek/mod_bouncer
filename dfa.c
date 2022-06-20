#include "dfa.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "log.h"

#define ALPHABET_SIZE 84
#define NODE_SIZE  (ALPHABET_SIZE * sizeof(uint32_t))

#define DFA_FLAG_BEGIN    0x20000000U
#define DFA_FLAG_END      0x40000000U
#define DFA_FLAG_TERMINAL 0x80000000U
#define OFFSET_MASK       0x000FFFFFU
#define METHODS_MASK      FLAG_ANY

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

dfa_t *dfa_create()
{
    dfa_t *dfa = (dfa_t*) calloc(1, sizeof(dfa_t));
    if (dfa == NULL)
        return NULL;
    dfa->slots = (uint32_t*) calloc(1, NODE_SIZE);
    if (dfa == NULL)
    {
        free(dfa);
        return NULL;
    }
    dfa->count = ALPHABET_SIZE;
    dfa->min_expr = 0xFFFF;
    return dfa;
}

void dfa_destroy( dfa_t *dfa )
{
    free(dfa->slots);
    free(dfa);
}

void dfa_usage( dfa_t *dfa, uint32_t *total, uint32_t *waste )
{
    if (dfa == NULL) return;

    if (total)
        *total = (uint32_t) (sizeof(dfa_t) + dfa->count * sizeof(uint32_t));
    if (waste)
    {
        *waste = 0;
        uint32_t max = dfa->count & 0xFFFFFFFEU;
        for (uint32_t i = 0; i < max; ++i)
            if (dfa->slots[i] == 0) *waste += 1;
        *waste *= (uint32_t) sizeof(uint32_t);
    }
}

static bool dfa_append_expr( dfa_t *dfa, const char *expr, size_t len, uint32_t flags )
{
    if (dfa == NULL || expr == NULL) return false;

    //for (const char *c = expr; c < expr+len; ++c)
    //    putchar(*c);
    //putchar('\n');

    flags |= DFA_FLAG_TERMINAL;
    if (*expr == '^')
    {
        flags |= DFA_FLAG_BEGIN;
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
            dfa->slots[off+id] |= flags;
            break;
        }
        if ((dfa->slots[off + id] & OFFSET_MASK) == 0)
        {
            dfa->slots[off + id] = (uint32_t) (dfa->slots[off + id] | O2I(dfa->count));
            off = dfa->count;
            dfa->count += ALPHABET_SIZE;
            dfa->slots = realloc(dfa->slots, (uint32_t) dfa->count * sizeof(uint32_t));
            memset(dfa->slots + off, 0, NODE_SIZE);
        }
        else
            off = I2O(dfa->slots[off + id]);
    }
    if (len < dfa->min_expr)
        dfa->min_expr = (uint32_t) len;
    return true;
}

uint32_t dfa_detect_method( const char *value, size_t len )
{
    if (*value == 'A' && !strncmp(value, "ANY", len))
        return DFA_FLAG_ANY;
    else
    if (*value == 'G' && !strncmp(value, "GET", len))
        return DFA_FLAG_GET;
    else
    if (*value == 'P' && !strncmp(value, "POST", len))
        return DFA_FLAG_POST;
    else
    if (*value == 'P' && !strncmp(value, "PUT", len))
        return DFA_FLAG_PUT;
    else
    if (*value == 'D' && !strncmp(value, "DELETE", len))
        return DFA_FLAG_DELETE;
    else
    if (*value == 'C' && !strncmp(value, "CONNECT", len))
        return DFA_FLAG_CONNECT;
    else
    if (*value == 'O' && !strncmp(value, "OPTIONS", len))
        return DFA_FLAG_OPTIONS;
    else
    if (*value == 'T' && !strncmp(value, "TRACE", len))
        return DFA_FLAG_TRACE;
    else
    if (*value == 'P' && !strncmp(value, "PATCH", len))
        return DFA_FLAG_PATCH;
    else
        return 0;
}

uint32_t dfa_extract_methods( const char *value, size_t len )
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
            uint32_t f = dfa_detect_method(method, len);
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

bool dfa_append( dfa_t *dfa, const char *value )
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
            flags = dfa_extract_methods(value, (size_t) (p - value));
            if (flags == 0) return false;
            state = 1;
        }
        else
        {
            size_t len = (size_t) (p - value);
            if (len >= 3 && len <= 255)
                if (!dfa_append_expr(dfa, value, (size_t) (p - value), flags))
                    return false;
        }
        value = p;
        while (*value == ' ' || *value == '\t') ++value;
    }
    return true;
}

bool dfa_match( const dfa_t *root, const char *value, const char *method )
{
    if (root == NULL || value == NULL || *value == 0)
        return false;

    uint32_t fmethod = dfa_detect_method(method, strlen(method));
    if (fmethod == 0)
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
            uint32_t slot = root->slots[off + (uint32_t) id];
            if (slot & DFA_FLAG_TERMINAL && (slot & fmethod))
                return (slot & DFA_FLAG_BEGIN) == 0 || tmp == value;
            if ((slot & OFFSET_MASK) == 0)
                break;
            off = I2O(slot);
        }
        ++tmp;
        --len;
    }
    return false;
}
