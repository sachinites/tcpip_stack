#include <memory.h>
#include <stdlib.h>
#include <assert.h>
#include <atomic>
#include "../Tree/libtree.h"
#include "rtm_nh.h"
#include "rtm_route.h"
#include "rtm_proto.h"
#include "rtm_resolution.h"
#include "rtm_fib_interface.h"
#include "rtm_priv_api.h"
#include "../graph.h"
#include "../tcp_ip_trace.h"
#include "../Tracer/tracer.h"

/* Thread-safe atomic counter for nexthop ID generation */
static std::atomic<uint32_t> rtm_nh_id_counter(1);

/* Generate a unique nexthop ID atomically */
static uint32_t rtm_nh_generate_id(void) {
    return rtm_nh_id_counter.fetch_add(1, std::memory_order_relaxed);
}


static void 
rtm_nh_check_destroy (rtm_nh *nh) {

    assert(nh->owner_route == NULL);
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->route_glue));
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->resolution_list_glue));
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->src_glue));
    assert(!avltree_node_is_inuse(&nh->idx_glue));
    assert (nh->rtm_nh_proto == NULL);
    assert (nh->Oif == nullptr);
    assert (nh->label_stack == NULL);
    assert (nh->ref_count == 0);
    assert (nh->v6segment_lst == NULL);
    free (nh);
}


/* Wrapper for compare function with exact signature from header */
int8_t 
rtm_nh_is_equal(rtm_nh* nh1, rtm_nh* nh2) {
    
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
        // Compare admin distance
    if (nh1->ad != nh2->ad) {
        return (nh1->ad < nh2->ad) ? -1 : 1;
    }

    // Compare metric
    if (nh1->metric != nh2->metric) {
        return (nh1->metric < nh2->metric) ? -1 : 1;
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

    int8_t rc = rtm_nh_proto_is_equal (nh1->rtm_nh_proto, nh2->rtm_nh_proto);
    if (rc != 0) return rc;

    if (!nh1->label_stack && nh2->label_stack) {
        return 1;
    }
    if (nh1->label_stack && !nh2->label_stack) {
        return -1;
    }

    if (!nh1->label_stack && !nh2->label_stack) {
        return 0;
    }

    return memcmp (nh1->label_stack, nh2->label_stack, sizeof(*nh1->label_stack));
}

/* Insert nexthop in route path list as per below rules : 
    1. lowest admin distance wins
    2. if admin distance is same, lowest Action wins
    3. if action is same lowest cost wins
    4. If both paths are BGP, then compare BGP attributes ( ToDO )
    5. if cost is same, then tie
*/
int8_t 
rtm_nh_compare (rtm_nh *nh1, rtm_nh *nh2) {

    // NULL checks
    if (!nh1 && !nh2) return 0;
    if (!nh1) return 1;  // nh2 wins
    if (!nh2) return -1; // nh1 wins
    
    // Rule 1: Lowest admin distance wins
    if (nh1->ad != nh2->ad) {
        return (nh1->ad < nh2->ad) ? -1 : 1;
    }
    
    // Rule 2: If admin distance is same, lowest Action wins
    // (Note: enum order matters - most preferred action first)
    if (nh1->action != nh2->action) {
        return (nh1->action < nh2->action) ? -1 : 1;
    }
    
    // Rule 3: If action is same, lowest cost (metric) wins
    if (nh1->metric != nh2->metric) {
        return (nh1->metric < nh2->metric) ? -1 : 1;
    }
    
    // Rule 4: If both paths are BGP, then compare BGP attributes (TODO)
    // TODO: Implement BGP attribute comparison
    
    // Rule 5: If cost is same, then tie
    return 0;
}

int
rtm_nh_compare_by_idx (const avltree_node_t *node1, const avltree_node_t *node2) {

    rtm_nh *nh1 = avltree_container_of(node1, rtm_nh, idx_glue);
    rtm_nh *nh2 = avltree_container_of(node2, rtm_nh, idx_glue);

    if (nh1->idx < nh2->idx) return -1;
    if (nh1->idx > nh2->idx) return 1;
    return 0;
}

/* Cpmpare only forwarding behavior of the nexthop*/
int8_t 
rtm_nh_forwarding_info_compare (rtm_nh *nh1, rtm_nh *nh2) {

    int8_t rc = rtm_prefix_compare (&nh1->prefix, &nh2->prefix);
    if (!rc) return rc;
    if (nh1->outgoing_if  < nh2->outgoing_if) return -1;
    if (nh1->outgoing_if > nh2->outgoing_if) return 1; 
    if (!nh1->label_stack && !nh2->label_stack) return 0;
    if (nh1->label_stack && !nh2->label_stack) return -1;
    if (!nh1->label_stack && nh2->label_stack) return 1;
    rc = memcmp (nh1->label_stack, nh2->label_stack, sizeof(nh1->label_stack));
    if (!rc) return rc;
     // Add more attributes here ...
    return rc;
   
}

/* Initialize a nexthop structure */
void 
rtm_nh_initialize(rtm_nh* nh) {
    
    nh->idx = rtm_nh_generate_id();
    nh->flags = 0;
    nh->pth_last_update_time = time(NULL);
    nh->owner_route = NULL;
    
    init_glthread(&nh->route_glue);
    init_glthread(&nh->src_glue);
    init_glthread(&nh->resolution_list_glue);
    avltree_node_init(&nh->idx_glue);
    
    nh->rtm_nh_proto = NULL;
    nh->ad = RTM_ADMIN_DIST_UNKNOWN;
    nh->metric = 0;
    nh->action = RTM_NH_ACTION_FORWARD;
    
    memset(&nh->prefix, 0, sizeof(rtm_prefix_t));
    nh->outgoing_if = 0;
    
    nh->is_resolved = false;
    nh->is_indirect = false;
    nh->is_active = false;
    
    nh->label_stack = NULL;
    nh->ref_count = 0;
}


void 
rtm_nh_set_active(rtm_t *rtm, rtm_nh *nh) {

    char prefix_str[48];
    char gw_str[48];

    assert (!nh->is_active);

    if (rtm && rtm->node && nh->owner_route) {
        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : Setting NH active for route %s, NH=%s Proto=%s Indirect=%s Resolved=%s",
            rtm->name,
            rtm_format_prefix(&nh->owner_route->prefix, prefix_str, sizeof(prefix_str)),
            rtm_format_nexthop(&nh->prefix, gw_str, sizeof(gw_str)),
            rtm_proto_to_string(nh->proto),
            nh->is_indirect ? "Yes" : "No",
            nh->is_resolved ? "Yes" : "No");
    }

    if (nh->is_indirect) rtm_track_for_resolution (rtm, nh);

    if (nh->is_resolved) {
        nh->is_active = true;
        rtm_fib_install(nh->owner_route, nh);
        
        if (rtm && rtm->node && nh->owner_route) {
            tracer(rtm->node->cptr, DRTM,
                "RTM[%s] : NH activated and installed in FIB for route %s, NH=%s",
                rtm->name,
                rtm_format_prefix(&nh->owner_route->prefix, prefix_str, sizeof(prefix_str)),
                rtm_format_nexthop(&nh->prefix, gw_str, sizeof(gw_str)));
        }
    } else {
        if (rtm && rtm->node && nh->owner_route) {
            tracer(rtm->node->cptr, DRTM | DERR,
                "RTM[%s] : WARNING: NH for route %s not resolved, cannot activate",
                rtm->name,
                rtm_format_prefix(&nh->owner_route->prefix, prefix_str, sizeof(prefix_str)));
        }
    }
}

void 
rtm_nh_set_inactive(rtm_t *rtm, rtm_nh *nh) {

    char prefix_str[48];
    char gw_str[48];

    assert(nh->is_active);
    
    if (rtm && rtm->node && nh->owner_route) {
        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : Setting NH inactive for route %s, NH=%s Proto=%s",
            rtm->name,
            rtm_format_prefix(&nh->owner_route->prefix, prefix_str, sizeof(prefix_str)),
            rtm_format_nexthop(&nh->prefix, gw_str, sizeof(gw_str)),
            rtm_proto_to_string(nh->proto));
    }
    
    rtm_untrack_for_resolution(rtm, nh);
    rtm_fib_uninstall(nh->owner_route, nh);
    nh->is_active = false;
    
    if (rtm && rtm->node && nh->owner_route) {
        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : NH deactivated and removed from FIB for route %s",
            rtm->name,
            rtm_format_prefix(&nh->owner_route->prefix, prefix_str, sizeof(prefix_str)));
    }
}

void 
rtm_nh_reference(rtm_nh *nh) {
    
    nh->ref_count++;
}

/* Decrement nexthop reference count and free if necessary */
void 
rtm_nh_dereference(rtm_t *rtm, rtm_nh *nh) {
    
    char gw_str[48];
    
    if (nh->ref_count <= 1) {

        if (rtm && rtm->node) {
            tracer(rtm->node->cptr, DRTM_DET,
                "RTM[%s] : NH %s ref_count reaching 0, destroying NH (idx=%u)",
                rtm->name,
                rtm_format_nexthop(&nh->prefix, gw_str, sizeof(gw_str)),
                nh->idx);
        }

        if (nh->label_stack) {
            free(nh->label_stack);
            nh->label_stack = NULL;
        }

        if (nh->rtm_nh_proto) {
            rtm_nh_proto_dereference (rtm, nh->rtm_nh_proto);
            nh->rtm_nh_proto = NULL;
        }
        
        nh->Oif = nullptr;

        /* Handle hosting Data structure */
        if (avltree_node_is_inuse (&nh->idx_glue)) {
            avltree_remove (&nh->idx_glue, &rtm->nhs_by_idx);
            avltree_node_init (&nh->idx_glue);
            assert (nh->ref_count == 1);
            nh->ref_count--;
        }

        rtm_nh_check_destroy (nh);
        return;
    }

    nh->ref_count--;
}