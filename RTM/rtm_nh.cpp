#include <memory.h>
#include <stdlib.h>
#include <assert.h>
#include "rtm_nh.h"
#include "rtm_route.h"

/* Helper function to compare two rtm_prefix_t structures */
static int
rtm_prefix_compare(const rtm_prefix_t *p1, const rtm_prefix_t *p2) {
    
    // First compare AFI
    if (p1->afi != p2->afi) {
        return (p1->afi < p2->afi) ? -1 : 1;
    }
    
    // Then compare prefix length
    if (p1->prefix_len != p2->prefix_len) {
        return (p1->prefix_len < p2->prefix_len) ? -1 : 1;
    }
    
    // Finally compare the address based on AFI
    switch (p1->afi) {
        case RTM_AF_IPV4:
            if (p1->u.v4_addr < p2->u.v4_addr) return -1;
            if (p1->u.v4_addr > p2->u.v4_addr) return 1;
            return 0;
            
        case RTM_AF_IPV6:
            return memcmp(p1->u.v6_addr, p2->u.v6_addr, 16);
            
        case RTM_AF_LABEL:
            if (p1->u.mpls_label < p2->u.mpls_label) return -1;
            if (p1->u.mpls_label > p2->u.mpls_label) return 1;
            return 0;
            
        case RTM_AFI_MAC:
            return memcmp(p1->u.mac_addr, p2->u.mac_addr, 6);
            
        default:
            return 0;
    }
}

/* Wrapper for compare function with exact signature from header */
int8_t 
rtm_nh_compare(rtm_nh* nh1, rtm_nh* nh2) {
    
    if (!nh1 || !nh2) {
        return -1;
    }
    
    // Compare protocol
    if (nh1->proto != nh2->proto) {
        return (nh1->proto < nh2->proto) ? -1 : 1;
    }
    
    // Compare sub-protocol
    if (nh1->sub_proto != nh2->sub_proto) {
        return (nh1->sub_proto < nh2->sub_proto) ? -1 : 1;
    }
    
    // Compare action
    if (nh1->action != nh2->action) {
        return (nh1->action < nh2->action) ? -1 : 1;
    }
    
    // Compare outgoing interface
    if (nh1->outgoing_if != nh2->outgoing_if) {
        return (nh1->outgoing_if < nh2->outgoing_if) ? -1 : 1;
    }
    
    // Compare prefix
    int prefix_cmp = rtm_prefix_compare(&nh1->prefix, &nh2->prefix);
    if (prefix_cmp != 0) {
        return prefix_cmp;
    }
    
    // Compare admin distance
    if (nh1->ad != nh2->ad) {
        return (nh1->ad < nh2->ad) ? -1 : 1;
    }
    
    // Compare metric
    if (nh1->metric != nh2->metric) {
        return (nh1->metric < nh2->metric) ? -1 : 1;
    }
    
    return 0;
}

/* Initialize a nexthop structure */
void 
rtm_nh_initialize(rtm_nh* nh) {
    
    if (!nh) return;
    
    nh->flags = 0;
    nh->pth_last_update_time = 0;
    nh->owner_route = NULL;
    
    init_glthread(&nh->route_glue);
    init_glthread(&nh->resolution_list_glue);
    
    nh->rtm_nh_proto = NULL;
    nh->ad = RTM_ADMIN_DIST_UNKNOWN;
    nh->metric = 0;
    nh->action = RTM_NH_ACTION_FORWARD;
    
    memset(&nh->prefix, 0, sizeof(rtm_prefix_t));
    nh->outgoing_if = 0;
    
    nh->is_resolved = false;
    nh->is_indirect = false;
    
    nh->label_stack = NULL;
    nh->ref_count = 0;
}

/* Increment nexthop reference count */
void 
rtm_nh_reference(rtm_nh *nh) {
    
    nh->ref_count++;
}

/* Decrement nexthop reference count and free if necessary */
void 
rtm_nh_dereference(rtm_nh *nh) {
    
    assert(nh->ref_count > 0);
    
    nh->ref_count--;
    
    if (nh->ref_count == 0) {
        // Ensure nexthop has been removed from owner route
        assert(nh->owner_route == NULL);
        assert(!IS_QUEUED_UP_IN_THREAD(&nh->route_glue));
        assert(!IS_QUEUED_UP_IN_THREAD(&nh->resolution_list_glue));
        
        // Free label stack if allocated
        if (nh->label_stack) {
            free(nh->label_stack);
            nh->label_stack = NULL;
        }
        
        // Free the nexthop structure
        free(nh);
    }
}

