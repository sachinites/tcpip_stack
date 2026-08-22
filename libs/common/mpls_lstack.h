#ifndef __MPLS_LSTACK__
#define __MPLS_LSTACK__

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory.h>
#include <assert.h>

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

static inline void 
mpls_label_init (mpls_label_t *label) {

    label->label_val = 0;
    label->op = MPLS_OP_STACK_OPS_UNKNOWN;
}

static void 
mpls_label_set_value (mpls_label_val_t *label, uint32_t value) {

    value = value << 12;
    *label |= value;
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

/* Extract TTL (lower 8 bits) from mpls_label_t */
static inline uint8_t
mpls_label_get_ttl(mpls_label_val_t label) {
    return (uint8_t)(label & 0xFF);
}

static inline void
mpls_label_set_ttl(mpls_label_val_t *label, uint8_t ttl) {
    *label = (*label & ~(mpls_label_val_t)0xFF) | (mpls_label_val_t)ttl;
}

/* Extract EXP/TC (bits 11..9) from mpls_label_t */
static inline uint8_t
mpls_label_get_exp(mpls_label_val_t label) {
    return (uint8_t)((label >> 9) & 0x7);
}

/* A label stack begins 14 bytes into an ethernet frame, so a label entry
   living in packet memory is never 4-byte aligned. Label entries on the wire
   must therefore be accessed only through this 1-byte-aligned type. */
typedef struct mpls_label_wire_ {

    mpls_label_val_t label_val;

} __attribute__((packed)) mpls_label_wire_t;

static inline mpls_label_val_t
mpls_wire_read (const mpls_label_wire_t *wlabel) {
    return wlabel->label_val;
}

static inline void
mpls_wire_write (mpls_label_wire_t *wlabel, mpls_label_val_t label) {
    wlabel->label_val = label;
}

static inline uint32_t
mpls_wire_get_value (const mpls_label_wire_t *wlabel) {
    return mpls_label_get_value (wlabel->label_val);
}

static inline void
mpls_wire_set_value (mpls_label_wire_t *wlabel, uint32_t value) {
    mpls_label_val_t label = wlabel->label_val;
    mpls_label_set_value (&label, value);
    wlabel->label_val = label;
}

static inline bool
mpls_wire_is_stack_bottom (const mpls_label_wire_t *wlabel) {
    return mpls_label_is_stack_bottom (wlabel->label_val);
}

static inline void
mpls_wire_set_stack_bottom (mpls_label_wire_t *wlabel) {
    mpls_label_val_t label = wlabel->label_val;
    mpls_label_set_stack_bottom (&label);
    wlabel->label_val = label;
}

static inline void
mpls_wire_clear_stack_bottom (mpls_label_wire_t *wlabel) {
    mpls_label_val_t label = wlabel->label_val;
    mpls_label_clear_stack_bottom (&label);
    wlabel->label_val = label;
}

static inline uint8_t
mpls_wire_get_ttl (const mpls_label_wire_t *wlabel) {
    return mpls_label_get_ttl (wlabel->label_val);
}

static inline void
mpls_wire_set_ttl (mpls_label_wire_t *wlabel, uint8_t ttl) {
    mpls_label_val_t label = wlabel->label_val;
    mpls_label_set_ttl (&label, ttl);
    wlabel->label_val = label;
}

static inline uint8_t
mpls_wire_get_exp (const mpls_label_wire_t *wlabel) {
    return mpls_label_get_exp (wlabel->label_val);
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

    return label_stk->curr_index == -1;
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

static void 
mpls_lstack_push(mpls_lstack_t *label_stk, mpls_label_t label ) {

    assert (label_stk->curr_index < MAX_LBL_DEPTH);
    label_stk->curr_index++;
    label_stk->labels[label_stk->curr_index] = label;
}

static mpls_label_t *
mpls_lstack_get_top (mpls_lstack_t *label_stk) {

    assert (!mpls_lstack_is_empty (label_stk));
    return &label_stk->labels[label_stk->curr_index];
}

static inline bool 
mpls_label_is_null(mpls_label_t label) {

    return label.label_val == 0 && label.op == MPLS_OP_STACK_OPS_UNKNOWN;
}

/* Format NH label-stack ops for debug (index 0 = BoS / innermost). */
static inline int
mpls_format_lstack (const mpls_lstack_t *lstack, char *buf, size_t buflen)
{
    int off = 0;
    int i;

    if (!buf || buflen == 0)
        return 0;
    buf[0] = '\0';
    if (!lstack || lstack->curr_index < 0)
        return 0;

    for (i = 0; i <= lstack->curr_index && off < (int)buflen - 1; i++) {
        if (lstack->labels[i].op == MPLS_OP_STACK_OPS_UNKNOWN)
            continue;
        off += snprintf(buf + off, buflen - (size_t)off, "%s%s:%u",
                        off ? "," : "",
                        mpls_op_tostring(lstack->labels[i].op),
                        mpls_label_get_value(lstack->labels[i].label_val));
    }
    return off;
}

/* Format labels on the wire (outer→inner) until BoS or nbytes exhausted. */
static inline int
mpls_format_wire_stack (const mpls_label_wire_t *labels, size_t nbytes,
                        char *buf, size_t buflen)
{
    int off = 0;
    int i;

    if (!buf || buflen == 0)
        return 0;
    buf[0] = '\0';
    if (!labels || nbytes < sizeof(mpls_label_wire_t))
        return 0;

    for (i = 0;
         i < MAX_LBL_DEPTH &&
         ((size_t)(i + 1) * sizeof(mpls_label_wire_t)) <= nbytes &&
         off < (int)buflen - 1;
         i++) {
        uint32_t val = mpls_wire_get_value(&labels[i]);
        bool bos = mpls_wire_is_stack_bottom(&labels[i]);
        off += snprintf(buf + off, buflen - (size_t)off,
                        "%s%u%s", i ? "," : "", val, bos ? "(S)" : "");
        if (bos)
            break;
    }
    return off;
}

#endif 
