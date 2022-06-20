#ifndef TREE_H
#define TREE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define DFA_FLAG_ANY      0x1FF00000U
#define DFA_FLAG_GET      0x00100000U
#define DFA_FLAG_HEAD     0x00200000U
#define DFA_FLAG_POST     0x00400000U
#define DFA_FLAG_PUT      0x00800000U
#define DFA_FLAG_DELETE   0x01000000U
#define DFA_FLAG_CONNECT  0x02000000U
#define DFA_FLAG_OPTIONS  0x04000000U
#define DFA_FLAG_TRACE    0x08000000U
#define DFA_FLAG_PATCH    0x10000000U

typedef struct
{
    /*
     * Each 84 consecutive slots represent a node (a slot for each
     * symbol in the alphabet). The first 84 slots form the node 0,
     * the next 84 the node 1 and so on. Slots have the index to the
     * next node (transition). The slot upper bits can also have
     * flags if the the node is a terminal in that symbol.
     */
    uint32_t *slots;
    // Amount of slots (multiple of the alphabet size).
    uint32_t count;
    // The length of the smaller expression;
    uint32_t min_expr;
} dfa_t;

dfa_t *dfa_create();
void dfa_destroy( dfa_t *dfa );
void dfa_usage( dfa_t *dfa, uint32_t *total, uint32_t *waste );
bool dfa_append( dfa_t *dfa, const char *expr );
bool dfa_match( const dfa_t *dfa, const char *value, const char *method );
uint32_t dfa_detect_method( const char *value, size_t len ); // handle a single HTTP method
uint32_t dfa_extract_methods( const char *value, size_t len ); // handle multiple HTTP methods (using |)

#endif // TREE_H