#ifndef __MPLS_LSTACK__
#define __MPLS_LSTACK__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

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

const char *
mpls_op_tostring(mpls_opr_t op);

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

void
mpls_lstack_init(mpls_lstack_t *lstack);

/* Extract 20-bit label value from mpls_label_t */
uint32_t
mpls_label_get_value(mpls_label_val_t label);

void
mpls_label_init(mpls_label_t *label);

void
mpls_label_set_value(mpls_label_val_t *label, uint32_t value);

/* Check if S (Bottom of Stack) bit is set */
bool
mpls_label_is_stack_bottom(mpls_label_val_t label);

/* Set S (Bottom of Stack) bit */
void
mpls_label_set_stack_bottom(mpls_label_val_t *label);

/* Clear S (Bottom of Stack) bit */
void
mpls_label_clear_stack_bottom(mpls_label_val_t *label);

/* Extract TTL (lower 8 bits) from mpls_label_t */
uint8_t
mpls_label_get_ttl(mpls_label_val_t label);

void
mpls_label_set_ttl(mpls_label_val_t *label, uint8_t ttl);

/* Extract EXP/TC (bits 11..9) from mpls_label_t */
uint8_t
mpls_label_get_exp(mpls_label_val_t label);

/* A label stack begins 14 bytes into an ethernet frame, so a label entry
   living in packet memory is never 4-byte aligned. Label entries on the wire
   must therefore be accessed only through this 1-byte-aligned type. */
typedef struct mpls_label_wire_ {

    mpls_label_val_t label_val;

} __attribute__((packed)) mpls_label_wire_t;

mpls_label_val_t
mpls_wire_read(const mpls_label_wire_t *wlabel);

void
mpls_wire_write(mpls_label_wire_t *wlabel, mpls_label_val_t label);

uint32_t
mpls_wire_get_value(const mpls_label_wire_t *wlabel);

void
mpls_wire_set_value(mpls_label_wire_t *wlabel, uint32_t value);

bool
mpls_wire_is_stack_bottom(const mpls_label_wire_t *wlabel);

void
mpls_wire_set_stack_bottom(mpls_label_wire_t *wlabel);

void
mpls_wire_clear_stack_bottom(mpls_label_wire_t *wlabel);

uint8_t
mpls_wire_get_ttl(const mpls_label_wire_t *wlabel);

void
mpls_wire_set_ttl(mpls_label_wire_t *wlabel, uint8_t ttl);

uint8_t
mpls_wire_get_exp(const mpls_label_wire_t *wlabel);

bool
mpls_lstack_compare(mpls_lstack_t *label_stk1, mpls_lstack_t *label_stk2);

bool
mpls_lstack_is_empty(mpls_lstack_t *label_stk);

mpls_label_t
mpls_lstack_pop(mpls_lstack_t *label_stk);

void
mpls_lstack_push(mpls_lstack_t *label_stk, mpls_label_t label);

mpls_label_t *
mpls_lstack_get_top(mpls_lstack_t *label_stk);

bool
mpls_label_is_null(mpls_label_t label);

/* Format NH label-stack ops for debug (index 0 = BoS / innermost). */
int
mpls_format_lstack(const mpls_lstack_t *lstack, char *buf, size_t buflen);

/* Format labels on the wire (outer→inner) until BoS or nbytes exhausted. */
int
mpls_format_wire_stack(const mpls_label_wire_t *labels, size_t nbytes,
                       char *buf, size_t buflen);

#endif
