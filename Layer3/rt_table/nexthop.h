#ifndef __NEXTHOP__
#define __NEXTHOP__

#include "../../utils.h"
#include "../../Interface/InterfaceFwd.h"
#include "../mpls_fwd.h"
#include "../../LinuxMemoryManager/uapi_mm.h"

typedef struct nexthop_{

    InterfaceP oif;
    byte gw_ip[IPV4_ADDR_LEN_STR];
    unsigned char node_name[NODE_NAME_SIZE];
    lstack_t *lbls;
    long long unsigned int hit_count;
    uint32_t ifindex;  
    uint32_t ref_count;
    uint16_t proto;
    
    /* Insert a constructor here */

    nexthop_() {
        ifindex = 0;
        memset(gw_ip, 0, 16);
        proto = 0;
        memset(node_name, 0, NODE_NAME_SIZE);
        lbls = NULL;
        ref_count = 0;
        oif = nullptr;
        hit_count = 0;
    };

} __attribute__((aligned(8))) nexthop_t;

int
nh_flush_nexthops(nexthop_t **nexthop);

nexthop_t *
nh_create_new_nexthop(c_string node_name, uint32_t oif_index, c_string gw_ip, uint16_t proto);

bool 
nh_insert_new_nexthop_nh_array(
                       nexthop_t **nexthop_arry, 
                       nexthop_t *nxthop);

bool
nh_is_nexthop_exist_in_nh_array(
                        nexthop_t **nexthop_array, 
                        nexthop_t *nxthop);

bool 
nh_remove_nexthop_from_nh_array (
                        nexthop_t **nexthop_array, 
                        nexthop_t *nxthop);

 int
nh_union_nexthops_arrays(nexthop_t **src, nexthop_t **dst);

c_string
nh_nexthops_str(nexthop_t **nexthops,  c_string buffer,  uint16_t buffer_size);

static void
nexthop_reference (nexthop_t *nexthop) {nexthop->ref_count++;}

static void
nexthop_dereference (nexthop_t *nexthop) {
    
    if (nexthop->ref_count == 0) {
        if (nexthop->lbls) XFREE (nexthop->lbls);
        if (nexthop->oif) nexthop->oif = nullptr;
        delete nexthop;
        return;
    }

    nexthop->ref_count--;

    if (nexthop->ref_count == 0) {
        if (nexthop->lbls) XFREE (nexthop->lbls);
        if (nexthop->oif) nexthop->oif = nullptr;
        delete nexthop;
    }    
}

/* Implement Label stack operations on nexthop */

/* Add a label to nexthop's label stack */
void static
nh_push_label(nexthop_t *nh, label_t label) {

    if (!nh->lbls) {
        nh->lbls = (lstack_t *)XCALLOC (0, 1, lstack_t);
        nh->lbls->curr_index = 0;
    }

    nh->lbls->labels[nh->lbls->curr_index] = label;

    if (nh->lbls->curr_index == 0 ) 
        set_stack_bottom (&label.label_val);
    else 
        clear_stack_bottom (&label.label_val);

    nh->lbls->curr_index++;
}

/* Remove and return top label from nexthop's label stack */
static label_t
nh_pop_label(nexthop_t *nh) {

    label_t ret = {0 , LBL_STACK_OPS_UNKNOWN};

    if (!nh->lbls) {
        return ret;
    }
    
    label_t label = nh->lbls->labels[nh->lbls->curr_index - 1];
    nh->lbls->curr_index--;

    if (nh->lbls->curr_index == 0) {
        XFREE(nh->lbls);
        nh->lbls = NULL;
    }

    return label;
}

static void
nh_swap_label(nexthop_t *nh, label_t label) {

    if (!nh->lbls) {
        return;
    }
    nh->lbls->labels[nh->lbls->curr_index - 1] = label;

    if (nh->lbls->curr_index == 0 ) 
        set_stack_bottom (&label.label_val);
    else 
        clear_stack_bottom (&label.label_val);    
}

/* Get top label without removing it */
static label_t
nh_peek_label(nexthop_t *nh) {

    label_t ret = {0 , LBL_STACK_OPS_UNKNOWN};

    if (!nh->lbls) {
        return ret;
    }
    
    return nh->lbls->labels[nh->lbls->curr_index - 1];
}

/* Remove all labels from nexthop's label stack */
static void
nh_clear_labels(nexthop_t *nh) {

    if (nh->lbls) {
        XFREE(nh->lbls);
        nh->lbls = NULL;
    }
}

/* Get number of labels in nexthop's label stack */
static uint8_t
nh_label_count(nexthop_t *nh) {

    if (!nh->lbls) {
        return 0;
    }

    return nh->lbls->curr_index;
}

int8_t
nxthop_compare (nexthop_t *nh1, nexthop_t *nh2) ;

#endif 
