#ifndef __MPLS_FWD__
#define __MPLS_FWD__

#include <stdint.h>
#include "mpls_enums.h"
#include "layer3.h"
#include "../c-hashtable/hashtable.h"
#include "../c-hashtable/hashtable_itr.h"

typedef struct nexthop_ nexthop_t;

typedef struct label_ {

    uint32_t label_val;
    mpls_op_t op;

} label_t; 

typedef struct lstack_ {

    uint8_t curr_index;
    label_t labels[MAX_LBL_DEPTH];

} lstack_t;

/* Label format : 
    - ISt 20 bits label value 
    - TTL (3 bits)
    - Bottom of Stack (1 bit)
    - (Rest of 3 bits are reserved)
*/

/* Extract 20-bit label value from label_t */
static inline uint32_t
get_label_value(label_val_t label) {
    return (label >> 12) & 0xFFFFF;
}

static void 
set_label_value (label_val_t *label, uint32_t value) {

    *label = 0;
    value &= 0xFFFFF;
    *label |= (value << 12);
}

/* Check if S (Bottom of Stack) bit is set */
static inline bool
is_stack_bottom(label_val_t label) {
    return (label >> 8) & 0x1;
}

/* Set S (Bottom of Stack) bit */
static inline void
set_stack_bottom(label_val_t *label) {
    *label |= (1 << 8);
}

/* Clear S (Bottom of Stack) bit */
static inline void 
clear_stack_bottom(label_val_t *label) {
    *label &= ~(1 << 8);
}

static bool 
label_stack_compare (lstack_t *label_stk1, lstack_t *label_stk2) {

    if (!label_stk1 && !label_stk2) return true;
    if (!label_stk1 && label_stk2) return false;
    if (label_stk1 && !label_stk2) return false;
    return ( memcmp (label_stk1, label_stk2, sizeof ( lstack_t )) == 0 );
}

/* MPLS RIB / FWD Table */

typedef struct mpls_rt_table_ {
    
    node_t *node;
    hashtable_t *ht;

} mpls_rt_table_t;

typedef struct mpls_route_ {

    label_val_t in_label;
    nexthop_t *nexthops[lbl_proto_nxthop_max][MAX_NXT_HOPS];
    int nxthop_idx;
    time_t install_time;
    uint16_t flags;
    uint16_t nh_count;

} mpls_route_t;

bool
mpls_install_route (node_t *node, label_val_t in_label, nexthop_t *nxthop);

void
mpls_uninstall_route (node_t *node, label_val_t in_label, nexthop_t *nxthop);

void 
mpls_apply_label_stack_on_pkt (pkt_block_t *pkt_block, lstack_t *lstack );

void
mpls_display_routing_table (node_t *node);

#endif 