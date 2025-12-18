#ifndef __MPLS_FWD__
#define __MPLS_FWD__

#include <stdint.h>
#include "mpls_enums.h"
#include "../common/mpls_lstack.h"
#include "layer3.h"
#include "../c-hashtable/hashtable.h"
#include "../c-hashtable/hashtable_itr.h"

typedef struct nexthop_ nexthop_t;

/* MPLS RIB / FWD Table */
typedef struct mpls_rt_table_ {
    
    node_t *node;
    hashtable_t *ht;

} mpls_rt_table_t;

typedef struct mpls_route_ {

    mpls_label_val_t in_label;
    nexthop_t *nexthops[lbl_proto_nxthop_max][MAX_NXT_HOPS];
    int nxthop_idx;
    time_t install_time;
    uint16_t flags;
    uint16_t nh_count;

} mpls_route_t;

bool
mpls_install_route (node_t *node, mpls_label_val_t in_label, nexthop_t *nxthop);

void
mpls_uninstall_route (node_t *node, mpls_label_val_t in_label, nexthop_t *nxthop);

void 
mpls_apply_label_stack_on_pkt (pkt_block_t *pkt_block, mpls_lstack_t *lstack );

void
mpls_display_routing_table (node_t *node);

void
ipv4_mpls_display_routing_table (node_t *node);

#endif 