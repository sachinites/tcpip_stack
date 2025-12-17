#ifndef __MPLS_LSTACK__
#define __MPLS_LSTACK__

#include <stdint.h>
#include <memory.h>
#include <cassert>
#include "../tcpconst.h"

#define MAX_LBL_DEPTH 8
typedef uint32_t mpls_label_val_t;

typedef enum mpls_opr_ {

    MPLS_OP_STACK_OPS_UNKNOWN,
    MPLS_OP_SWAP,
    MPLS_OP_CONTINUE = MPLS_OP_SWAP,
    MPLS_OP_NEXT,
    MPLS_OP_PUSH = MPLS_OP_NEXT,
    MPLS_OP_POP

} mpls_opr_t;

static inline const char *
mpls_op_tostring(mpls_opr_t op)
{
    switch (op)
    {
        case MPLS_OP_SWAP:
            return "swap";
        case MPLS_OP_PUSH:
            return "push";
        case MPLS_OP_POP:
            return "pop";
        default:
            return "unknown";
    }
}

typedef struct mpls_label_ {

    mpls_label_val_t label_val;
    mpls_opr_t op;

} mpls_label_t; 

#define MPLS_NULL_LABEL {0, MPLS_OP_STACK_OPS_UNKNOWN}

typedef struct mpls_lstack_ {

    int8_t curr_index;
    mpls_label_t labels[MAX_LBL_DEPTH];

} mpls_lstack_t;

/* Label format : 
    - Ist 20 bits label value 
    - TTL (3 bits)
    - Bottom of Stack (1 bit)
    - Rest of 3 bits are reserved */

static void 
mpls_lstack_init (mpls_lstack_t *lstack) {

    lstack->curr_index = -1;
    memset (lstack->labels, 0, sizeof (lstack->labels));
}

/* Extract 20-bit label value from mpls_label_t */
static inline uint32_t
mpls_label_get_value(mpls_label_val_t label) {
    return (label >> 12) & 0xFFFFF;
}

static void 
mpls_label_set_value (mpls_label_val_t *label, uint32_t value) {

    *label = 0;
    value &= 0xFFFFF;
    *label |= (value << 12);
}

/* Check if S (Bottom of Stack) bit is set */
static inline bool
mpls_label_is_stack_bottom(mpls_label_val_t label) {
    return (label >> 8) & 0x1;
}

/* Set S (Bottom of Stack) bit */
static inline void
mpls_label_set_stack_bottom(mpls_label_val_t *label) {
    *label |= (1 << 8);
}

/* Clear S (Bottom of Stack) bit */
static inline void 
mpls_label_clear_stack_bottom(mpls_label_val_t *label) {
    *label &= ~(1 << 8);
}

static bool 
mpls_lstack_compare (mpls_lstack_t *label_stk1, mpls_lstack_t *label_stk2) {

    if (!label_stk1 && !label_stk2) return true;
    if (!label_stk1 && label_stk2) return false;
    if (label_stk1 && !label_stk2) return false;
    return ( memcmp (label_stk1, label_stk2, sizeof ( mpls_lstack_t )) == 0 );
}

static bool 
mpls_lstack_is_empty (mpls_lstack_t *label_stk) {

    return label_stk->curr_index == 0;
}

static mpls_label_t
mpls_lstack_pop (mpls_lstack_t *label_stk) {

    assert (!mpls_lstack_is_empty (label_stk));

    mpls_label_t label = label_stk->labels[label_stk->curr_index];

    label_stk->curr_index--;

    if (label_stk->curr_index == 0) {
        mpls_label_set_stack_bottom (
            &(label_stk->labels[label_stk->curr_index].label_val));
    }
    
    return label;
}

static mpls_label_t
mpls_lstack_get_top (mpls_lstack_t *label_stk) {

    assert (!mpls_lstack_is_empty (label_stk));
    return label_stk->labels[label_stk->curr_index];
}

#endif 