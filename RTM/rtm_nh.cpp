/*
 * =====================================================================================
 *
 *       Filename:  rtm_nh.cpp
 *
 *    Description:  RTM Nexthop Management - Nexthop Lifecycle and Operations
 *
 *        This file manages nexthops in the RTM system, including creation, deletion,
 *        comparison, and state management (active/inactive).
 *
 *        Nexthop Types:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ Direct Nexthop (DNH)                                       │
 *        │   - Gateway is directly reachable                          │
 *        │   - Has outgoing interface                                 │
 *        │   - Can be used immediately for forwarding                  │
 *        │                                                              │
 *        │ Indirect Nexthop (INH)                                      │
 *        │   - Gateway requires recursive resolution                   │
 *        │   - Resolves over another route                            │
 *        │   - Has list of direct nexthops (from resolved route)      │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Nexthop Structure:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ rtm_nh                                                       │
 *        │  - prefix: Gateway/nexthop address                        │
 *        │  - oif: Outgoing interface index                          │
 *        │  - proto: Protocol (BGP, OSPF, etc.)                        │
 *        │  - ad: Admin distance                                       │
 *        │  - metric: Route metric                                     │
 *        │  - is_active: Whether this is the best path                 │
 *        │  - is_indirect: Whether this is an indirect nexthop         │
 *        │  - direct_nh_list: List of direct NHs (for INH)            │
 *        │  - idx: Unique nexthop ID                                   │
 *        │  - ref_count: Reference count                               │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Nexthop Comparison (for Path Selection):
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ Comparison Order:                                          │
 *        │ 1. Admin Distance (lower is better)                         │
 *        │ 2. Metric (lower is better)                                 │
 *        │ 3. Protocol-specific attributes                              │
 *        │ 4. Gateway address                                          │
 *        │ 5. Outgoing interface                                       │
 *        │ 6. MPLS label stack                                         │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Nexthop Storage:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ RTM                                                          │
 *        │  ┌──────────────────────────────────────────────────────┐   │
 *        │  │ nhs_by_idx (AVL Tree)                                │   │
 *        │  │  └─> Nexthops indexed by unique ID                    │   │
 *        │  └──────────────────────────────────────────────────────┘   │
 *        │  ┌──────────────────────────────────────────────────────┐   │
 *        │  │ nhs_by_src[proto] (Linked Lists)                    │   │
 *        │  │  └─> Nexthops grouped by protocol                    │   │
 *        │  └──────────────────────────────────────────────────────┘   │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Version:  1.0
 *        Created:  [Original Date]
 *       Revision:  1.0
 *       Compiler:  gcc/g++
 *
 * =====================================================================================
 */

#include <memory.h>
#include <stdlib.h>
#include <assert.h>
#include <atomic>
#include "../lmm_enums.h"
#include "../libs/Tree/libtree.h"
#include "rtm_nh.h"
#include "rtm_route.h"
#include "rtm_proto.h"
#include "rtm_resolution.h"
#include "rtm_fib_interface.h"
#include "rtm_priv_api.h"
#include "rtm_nb_integ.h"
#include "../router_init.h"
#include "../tcp_ip_trace.h"
#include "../libs/Tracer/tracer.h"
#include "rtm_presentation.h"
#include "rtm_gc.h"
#include "../libs/common/mpls_lstack.h"
#include "../libs/BitOp/bitsop.h"
#include "../libs/LinuxMemoryManager/uapi_mm.h"

/* ========================================================================
 * Nexthop ID Generation
 * ======================================================================== */

static void rtm_nh_goes_active (rtm_t *rtm, rtm_nh *nh);
static void rtm_nh_goes_inactive (rtm_t *rtm, rtm_nh *nh);

extern void rtm_presentation_layer_route_add (rtm_t *rtm, rtm_nh *nh);

/* ========================================================================
 * Nexthop Resource Management
 * ======================================================================== */

/**
 * @brief Release all resources held by a nexthop
 * 
 * Cleans up all resources associated with a nexthop before deletion:
 * - MPLS label stack
 * - Protocol information
 * - Outgoing interface
 * - Owner route reference
 * 
 * @param rtm Pointer to routing table
 * @param nh Nexthop to clean up
 */
static void
rtm_nh_release_all_resources(rtm_t *rtm, rtm_nh *nh)
{
    if (nh->label_stack)
    {
        XFREE(nh->label_stack);
        nh->label_stack = NULL;
    }

    if (nh->rtm_nh_proto)
    {
        rtm_nh_proto_dereference(rtm, nh->rtm_nh_proto);
        nh->rtm_nh_proto = NULL;
    }

    nh->oif = 0;

    rtm_route_dereference (rtm, nh->owner_route);
    nh->owner_route = NULL;
}

void 
rtm_nh_check_and_delete (rtm_t *rtm, rtm_nh *nh) {

    char gw_str[48];
    rtm_nh_release_all_resources(rtm, nh);
    assert(nh->owner_route == NULL);
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->route_glue));
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->route_resolved_list_glue));
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->unresolvable_list_glue));
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->src_glue));
    assert(!avltree_node_is_inuse(&rtm->nhs_by_idx, &nh->idx_glue));
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->advt_glue));
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->tnh_member_glue));
    assert (nh->tnh == NULL);
    assert (nh->rtm_nh_proto == NULL);
    assert (nh->oif == 0);
    assert (nh->label_stack == NULL);
    assert (nh->ref_count == 0);
    assert (nh->v6segment_lst == NULL);
    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : NH %s(idx=%u) destroyed NH\n",
        rtm->name,
        rtm_format_nexthop(&nh->prefix, gw_str, sizeof(gw_str)),
        nh->idx);    
    XFREE (nh);
}

void 
rtm_nh_reference(rtm_nh *nh) {
    
    nh->ref_count++;
}

void 
rtm_nh_dereference(rtm_t *rtm, rtm_nh *nh) {
        
    nh->ref_count--;

    if (nh->ref_count == 0) {
        rtm_gc_nh (rtm, nh);
    }
}

/* ========================================================================
 * Nexthop Comparison Functions
 * ======================================================================== */

/**
 * @brief Check if two nexthops are exactly equal
 * 
 * Compares all attributes of two nexthops to determine if they are
 * identical. Used for duplicate detection.
 * 
 * Comparison includes:
 * - Protocol and sub-protocol
 * - Admin distance
 * - Metric
 * - Action
 * - Outgoing interface
 * - Gateway prefix
 * - Protocol-specific information
 * - MPLS label stack
 * 
 * @param nh1 First nexthop
 * @param nh2 Second nexthop
 * 
 * @return 0 if equal, non-zero if different
 */
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
    if (nh1->oif != nh2->oif) {
        return (nh1->oif < nh2->oif) ? -1 : 1;
    }
    
    // Compare prefix
    int prefix_cmp = cmn_prefix_compare(&nh1->prefix, &nh2->prefix);
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

int8_t 
rtm_nh_is_equal_in_data_plane(rtm_nh *nh1, rtm_nh *nh2) {

    if (nh1->action != nh2->action) {
        return (nh1->action < nh2->action) ? -1 : 1;
    }

    // Compare outgoing interface
    if (nh1->oif != nh2->oif) {
        return (nh1->oif < nh2->oif) ? -1 : 1;
    }
    
    // Compare prefix
    int prefix_cmp = cmn_prefix_compare(&nh1->prefix, &nh2->prefix);
    if (prefix_cmp != 0) {
        return prefix_cmp;
    }

    if (!nh1->label_stack && nh2->label_stack) {
        return 1;
    }
    if (nh1->label_stack && !nh2->label_stack) {
        return -1;
    }

    if (!nh1->label_stack && !nh2->label_stack) {
        return 0;
    }

    if (!mpls_lstack_compare (nh1->label_stack, nh2->label_stack)) return -1;

    return 0;
    // Copare SRv6 .. Later ...
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

    int8_t rc = cmn_prefix_compare (&nh1->prefix, &nh2->prefix);
    if (!rc) return rc;
    if (nh1->oif  < nh2->oif) return -1;
    if (nh1->oif > nh2->oif) return 1; 

    if (!mpls_lstack_compare (nh1->label_stack, nh2->label_stack)) return -1;

     // Add more attributes here ...
    return rc;
}

/* Initialize a nexthop structure */
void 
rtm_nh_initialize(rtm_nh* nh, uint32_t idx) {
    
    nh->idx = idx;
    nh->rtm_flags = 0;
    nh->fwd_flags = 0;
    nh->pth_last_update_time = time(NULL);
    nh->owner_route = NULL;
    
    init_glthread(&nh->route_glue);
    init_glthread(&nh->src_glue);
    init_glthread(&nh->route_resolved_list_glue);
    init_glthread(&nh->unresolvable_list_glue);
    init_glthread(&nh->tnh_member_glue);
    avltree_node_init(&nh->idx_glue);
    init_glthread(&nh->advt_glue);
    
    nh->rtm_nh_proto = NULL;
    nh->ad = RTM_ADMIN_DIST_UNKNOWN;
    nh->metric = 0;
    nh->action = RTM_NH_ACTION_FORWARD;
    
    memset(&nh->prefix, 0, sizeof(cmn_prefix_t));
    nh->oif = 0;
    
    nh->is_indirect = false;
    nh->is_active = false;
    nh->tnh = NULL;
    
    nh->label_stack = NULL;
    nh->install_time = time(NULL);
    nh->ref_count = 0;
}


void 
rtm_nh_set_active(rtm_t *rtm, rtm_nh *nh) {

    char gw_str[128];
    char prefix_str[48];

    assert (!nh->is_active);

    tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : Route : %s : Setting NH Active, NH=%s Is_indirect=%s Resolved=%s\n",
            rtm->name,
            rtm_format_prefix(&nh->owner_route->prefix, prefix_str, sizeof(prefix_str)),
            rtm_nh_one_liner_trace(nh, gw_str, sizeof(gw_str)),
            nh->is_indirect ? "Yes" : "No",
            rtm_nh_is_resolved(nh) ? "Yes" : "No");

    nh->is_active = true;

    /* If this is indirect NH, then submit it for resolution again, There can be more INHs 
        being set to active at this point, so defer the work of updating Routes upstream in 
        resolution graph */
    if (nh->is_indirect) {
        
        assert (!rtm_nh_is_resolved (nh));
        assert (nh->resolved_via_route == NULL);
        assert (!IS_QUEUED_UP_IN_THREAD(&nh->route_resolved_list_glue));
        assert (!nh->resolved_via_route);
        assert (!IS_QUEUED_UP_IN_THREAD(&nh->unresolvable_list_glue));
        assert (Fglthread_list_is_empty (&nh->direct_nh_list));

        /* Check if this nexthop can be resolved */
        rtm_route *route = rtm_get_resolver_route(rtm, nh);
        
        if (!route) {

            /* INH is not resolvable */
            tracer(rtm->node->cptr, DRTM,
                "RTM[%s] : Route : %s : INH %s is still unresolvable, queuing for resolution\n",
                rtm->name,
                rtm_format_prefix(&nh->owner_route->prefix, prefix_str, sizeof(prefix_str)),
                rtm_nh_one_liner_trace(nh, gw_str, sizeof(gw_str)));

            rtm_nh_Fglthread_add_last (nh, 
                                &rtm->unresolvable_paths, 
                                &nh->unresolvable_list_glue); 

            rtm_schedule_nh_resolution_worker(rtm);
            return;
        }

        /* The INH is resolvale , borrow its DNHs from the route's active set */
        rtm_copy_route_active_nhs_to_inh_direct_nh_set(rtm, route, nh);

        /* Establish the linkage with downstream router in resolution graph*/
        nh->resolved_via_route = route;
        rtm_route_reference (route);
        rtm_nh_Fglthread_add_last (nh, &route->resolved_lnhs, 
            &nh->route_resolved_list_glue);
        rtm_inh_moved_to_resolved_state(rtm, nh);

        /* The caller must call rtm_resolve_routes_recursively ( ) to propogate resolution
            effect upstream in resolution graph*/
    }
    else {
        /* Handled by caller by calling rtm_resolve_routes_recursively ( )*/
    }

    rtm_schedule_route_advertisement (nh->rtm, nh->owner_route);
}

void 
rtm_nh_set_inactive(rtm_t *rtm, rtm_nh *nh) {

    char prefix_str[48];
    char gw_str[48];

    assert(nh->is_active);
    
    tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : Setting NH inactive for route %s, NH=%s Proto=%s\n",
            rtm->name,
            rtm_format_prefix(&nh->owner_route->prefix, prefix_str, sizeof(prefix_str)),
            rtm_format_nexthop(&nh->prefix, gw_str, sizeof(gw_str)),
            rtm_proto_to_string(nh->proto));
    
    nh->is_active = false;

    /* The INH is switched from Active to Inactive state , Possible Cases : 
        1. It is already awaiting resolution , Action : Dont bother to resolve it anymore
        2. It is resolved, Action : Make it unresolved and update upstream Routes in resolution graph
    */
    if (nh->is_indirect) {

        rtm_resolution_nh_withdraw(rtm, nh);
    }
    else {
        /* Handled by caller by calling rtm_resolve_routes_recursively ( )*/
    }

    rtm_schedule_route_advertisement (nh->rtm, nh->owner_route);
    
    tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : NH deactivated and removed from FIB for route %s\n",
            rtm->name,
            rtm_format_prefix(&nh->owner_route->prefix, prefix_str, sizeof(prefix_str)));
}

void
rtm_flush_inh_direct_nh_set(
    rtm_t *rtm, rtm_nh *indirect_nh) {
    
    glthread_t *curr_glue;
    glthread_t *next_glue;
    glthread_data_node_t *data_node;
    rtm_nh *nh;
    char gw_str[128];
    char nh_str[128];

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Flushing direct NH set of INH %s\n",
        rtm->name,
        rtm_nh_one_liner_trace(indirect_nh, gw_str, sizeof(gw_str)));

    ITERATE_GLTHREAD_BEGIN(&indirect_nh->direct_nh_list.head, curr_glue) {

        data_node = glue_to_glthread_data_node(curr_glue);
        nh = (rtm_nh *)data_node->data;
        rtm_nh_remove_Fglthread (rtm, nh, 
            &indirect_nh->direct_nh_list, curr_glue);

        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : INH %s removing direct NH %s from its direct NH set\n",
            rtm->name,
            rtm_nh_one_liner_trace(indirect_nh, gw_str, sizeof(gw_str)),
            rtm_nh_one_liner_trace(nh, nh_str, sizeof(nh_str)));

        XFREE (data_node);

    } ITERATE_GLTHREAD_END(&indirect_nh->direct_nh_list.head, curr_glue);

}

bool rtm_nh_is_resolved (rtm_nh *nh) {

    if (!nh->is_indirect) return true;
    return !(Fglthread_list_is_empty(&nh->direct_nh_list));
}

void 
rtm_inh_moved_to_resolved_state (rtm_t *rtm, rtm_nh *inh) {

    char route_str[48];
    char inh_str[128];
    char route_resolver_str[48];

    tracer (rtm->node->cptr, DRTM,
        "RTM[%s] : Route : %s : INH %s moved to resolved state, Resolved by %s\n",
        rtm->name,
        rtm_format_prefix(&inh->owner_route->prefix, route_str, sizeof(route_str)),
        rtm_nh_one_liner_trace(inh, inh_str, sizeof(inh_str)),
        rtm_format_prefix(&inh->resolved_via_route->prefix, 
            route_resolver_str, sizeof(route_resolver_str)));

    inh->owner_route->resolved_inh_count++;

    if (inh->owner_route->resolved_inh_count == 1) {
        rtm_route_moved_to_resolved_state (rtm, inh->owner_route);
    }

    if (IS_QUEUED_UP_IN_THREAD(&inh->stats_resolved_glue)) {
        remove_glthread(&inh->stats_resolved_glue);
        rtm_nh_dereference(rtm, inh);
    }

    glthread_add_next(&rtm->stats.new_resolved_nhs, &inh->stats_resolved_glue);
    rtm_nh_reference(inh);
}

void 
rtm_inh_moved_to_unresolved_state (rtm_t *rtm, rtm_nh *inh) {

    char route_str[48];
    char inh_str[128];

    tracer (rtm->node->cptr, DRTM,
        "RTM[%s] : Route : %s : INH %s moved to UnResolved state\n",
        rtm->name,
        rtm_format_prefix(&inh->owner_route->prefix, route_str, sizeof(route_str)),
        rtm_nh_one_liner_trace(inh, inh_str, sizeof(inh_str)));

        assert (inh->owner_route->resolved_inh_count > 0);
        inh->owner_route->resolved_inh_count--;

        if (inh->owner_route->resolved_inh_count == 0) {
            rtm_route_moved_to_unresolved_state (rtm, inh->owner_route);
        }

    if (IS_QUEUED_UP_IN_THREAD(&inh->stats_resolved_glue)) {
        remove_glthread(&inh->stats_resolved_glue);
        rtm_nh_dereference(rtm, inh);
    }

    glthread_add_next(&rtm->stats.new_unresolved_nhs, &inh->stats_resolved_glue);
    rtm_nh_reference(inh);
}

void rtm_nh_glthread_add_next (
    rtm_nh *nh, glthread_t *curr_glthread, glthread_t *new_glthread){
    
    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    glthread_add_next (curr_glthread, new_glthread);
    rtm_nh_reference (nh);
    
    /* Note: Cannot trace here as we don't have RTM context */
}

void rtm_nh_glthread_add_before (
    rtm_nh *nh, glthread_t *curr_glthread, glthread_t *new_glthread){
    
    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    glthread_add_before (curr_glthread, new_glthread);
    rtm_nh_reference (nh);
}

void rtm_nh_remove_glthread (rtm_t *rtm, rtm_nh *nh, glthread_t *curr_glthread){

    assert (IS_QUEUED_UP_IN_THREAD(curr_glthread));
    
    char nh_str[128];
    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : NH %s removing from glthread\n",
        rtm->name,
        rtm_nh_one_liner_trace(nh, nh_str, sizeof(nh_str)));
    
    remove_glthread (curr_glthread);
    rtm_nh_dereference (rtm, nh);
}

void rtm_nh_fglthread_add_next (rtm_nh *nh, 
        Fglthread_t *head, 
        glthread_t *base_glthread, glthread_t *new_glthread) {

    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    Fglthread_add_next (head, base_glthread, new_glthread);
    rtm_nh_reference (nh);
}

void rtm_nh_fglthread_add_before (rtm_nh *nh, 
        Fglthread_t *head, 
        glthread_t *base_glthread, glthread_t *new_glthread) {

    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    Fglthread_add_before (head, base_glthread, new_glthread);
    rtm_nh_reference (nh);
}

void
rtm_nh_remove_Fglthread(rtm_t *rtm, rtm_nh *nh, 
                Fglthread_t *head, glthread_t *glthread){

    assert (IS_QUEUED_UP_IN_THREAD(glthread));
    remove_Fglthread (head, glthread);
    rtm_nh_dereference (rtm, nh);
}

void
rtm_nh_Fglthread_add_last(rtm_nh *nh, 
        Fglthread_t *head, glthread_t *new_glthread) {


    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    Fglthread_add_last (head, new_glthread);
    rtm_nh_reference (nh);
}

void 
rtm_nh_avl_insert (rtm_nh *nh, avltree_t *tree, avltree_node_t *avlnode){

    assert (!avltree_node_is_inuse(tree, avlnode));
    assert (!avltree_insert(avlnode, tree));
    rtm_nh_reference (nh);
    
    /* Note: Cannot trace here as we don't have RTM context */
}

void 
rtm_nh_avl_remove (rtm_t *rtm, rtm_nh *nh, 
    avltree_t *tree, avltree_node_t *avlnode){

    assert (avltree_node_is_inuse(tree, avlnode));
    avltree_strict_remove(avlnode, tree); 
    rtm_nh_dereference (rtm, nh);
}

char *
rtm_nh_one_liner_trace (rtm_nh *nh, char *buffer_str, int buff_size) {

    char nh_addr_str[48];
    rtm_format_nexthop(&nh->prefix, nh_addr_str, sizeof(nh_addr_str));

    snprintf(buffer_str, buff_size, 
             "NH[idx=%u, %s, %s]",
             nh->idx,
             nh_addr_str,
             rtm_proto_to_string(nh->proto));

    return buffer_str;
}

rtm_nh *
rtm_nh_lookup_by_idx(rtm_t *rtm, uint32_t idx) {

    rtm_nh nh_template;

    rtm_nh_initialize (&nh_template, node_get_sequence_no(rtm->node));
    nh_template.idx = idx;

    avltree_node_t *node = avltree_lookup(&nh_template.idx_glue, &rtm->nhs_by_idx);
    if (!node) return NULL;

    return avltree_container_of(node, rtm_nh, idx_glue);
}

rtm_error_t 
rtm_nh_add_to_idx_tree(rtm_t *rtm, rtm_nh *nh) {

    rtm_nh_avl_insert(nh, &rtm->nhs_by_idx, &nh->idx_glue);
    return RTM_SUCCESS;
}

rtm_error_t 
rtm_nh_remove_from_idx_tree(rtm_t *rtm, rtm_nh *nh) {

    rtm_nh_avl_remove(rtm, nh, &rtm->nhs_by_idx, &nh->idx_glue);
    return RTM_SUCCESS;
}

rtm_nh *
rtm_nh_duplicate (rtm_nh *nh) {

    if (!nh) return NULL;
    
    /* Allocate new nexthop */
    rtm_nh *nh_dup = (rtm_nh *)XCALLOC2(0, 1, rtm_nh);
    rtm_nh_initialize(nh_dup, nh->idx);

    /* Copy simple scalar fields */
    nh_dup->rtm_flags = 0;
    nh_dup->fwd_flags = nh->fwd_flags;
    nh_dup->pth_last_update_time = nh->pth_last_update_time;
    nh_dup->proto = nh->proto;
    nh_dup->sub_proto = nh->sub_proto;
    nh_dup->ad = nh->ad;
    nh_dup->metric = nh->metric;
    nh_dup->action = nh->action;
    nh_dup->prefix = nh->prefix;
    nh_dup->oif = nh->oif;
    nh_dup->is_indirect = nh->is_indirect;
    nh_dup->is_active = nh->is_active;
    nh_dup->l3_vpn_label = nh->l3_vpn_label;
    nh_dup->install_time = time(NULL);

    /* Deep copy rtm_nh_proto if present */
    if (nh->rtm_nh_proto) {
        nh_dup->rtm_nh_proto = (rtm_nh_proto_t *)XCALLOC2(0, 1, rtm_nh_proto_t);
        rtm_nh_proto_copy(nh->rtm_nh_proto, nh_dup->rtm_nh_proto);
    }

    /* Deep copy label stack if present */
    if (nh->label_stack && nh->label_stack->curr_index > -1) {
        nh_dup->label_stack = (mpls_lstack_t *)XCALLOC2(0, 1, mpls_lstack_t);
        memcpy (nh_dup->label_stack, nh->label_stack, sizeof (mpls_lstack_t));
    }

    /* Deep copy SRv6 segment list if present */
    nh_dup->endfn = nh->endfn;
    nh_dup->n_segment_list = nh->n_segment_list;
    if (nh->v6segment_lst && nh->n_segment_list > 0) {
        nh_dup->v6segment_lst = (cmn_prefix_t *)XCALLOC2(0, nh->n_segment_list, cmn_prefix_t);
        if (nh_dup->v6segment_lst) {
            memcpy(nh_dup->v6segment_lst, nh->v6segment_lst, 
                   nh->n_segment_list * sizeof(cmn_prefix_t));
        }
    }

    /* Initialize direct_nh_list as empty (DO NOT COPY direct nexthops for indirect nexthops) */
    init_Fglthread(&nh_dup->direct_nh_list);
    nh_dup->ref_count = 0;
    return nh_dup;
}


/* rtm_tnh methods */

static int
rtm_tnh_v6segment_lst_compare (
        uint8_t n_seg1, cmn_prefix_t *seg_lst1,
        uint8_t n_seg2, cmn_prefix_t *seg_lst2) {

    uint8_t i;
    int rc;

    if (n_seg1 < n_seg2) return -1;
    if (n_seg1 > n_seg2) return 1;
    if (n_seg1 == 0) return 0;
    if (!seg_lst1 && !seg_lst2) return 0;
    if (!seg_lst1) return -1;
    if (!seg_lst2) return 1;

    for (i = 0; i < n_seg1; i++) {
        rc = cmn_prefix_compare (&seg_lst1[i], &seg_lst2[i]);
        if (rc != 0) return rc;
    }
    return 0;
}

void
rtm_tnh_initialize(rtm_tnh_t *tnh) {

    memset (tnh, 0, sizeof (*tnh));

    init_glthread (&tnh->src_glue);
    init_glthread (&tnh->route_resolved_list_glue);
    init_glthread (&tnh->unresolvable_list_glue);
    init_Fglthread (&tnh->direct_nh_list);
    init_Fglthread (&tnh->route_nh_list);
    avltree_node_init (&tnh->rtm_tnh_glue);

    tnh->ad = RTM_ADMIN_DIST_UNKNOWN;
    tnh->action = RTM_NH_ACTION_FORWARD;
    tnh->install_time = time (NULL);
}

void
rtm_tnh_free (rtm_tnh_t *tnh) {

    if (!tnh) return;

    if (tnh->label_stack) {
        XFREE (tnh->label_stack);
        tnh->label_stack = NULL;
    }

    if (tnh->v6segment_lst) {
        XFREE (tnh->v6segment_lst);
        tnh->v6segment_lst = NULL;
    }

    /* Proto on a free'd TNH is a private copy, not in nh_proto_info_tree */
    if (tnh->rtm_nh_proto) {
        rtm_nh_proto_dereference(tnh->rtm, tnh->rtm_nh_proto);
        tnh->rtm_nh_proto = NULL;
    }

    XFREE (tnh);
}

int
rtm_tnh_compare(rtm_tnh_t *tnh1, rtm_tnh_t *tnh2) {

    int rc;

    if (!tnh1 && !tnh2) return 0;
    if (!tnh1) return -1;
    if (!tnh2) return 1;

    if (tnh1->fwd_flags < tnh2->fwd_flags) return -1;
    if (tnh1->fwd_flags > tnh2->fwd_flags) return 1;

    if (tnh1->proto < tnh2->proto) return -1;
    if (tnh1->proto > tnh2->proto) return 1;

    if (tnh1->sub_proto < tnh2->sub_proto) return -1;
    if (tnh1->sub_proto > tnh2->sub_proto) return 1;

    if (tnh1->ad < tnh2->ad) return -1;
    if (tnh1->ad > tnh2->ad) return 1;

    if (tnh1->metric < tnh2->metric) return -1;
    if (tnh1->metric > tnh2->metric) return 1;

    if (tnh1->action < tnh2->action) return -1;
    if (tnh1->action > tnh2->action) return 1;

    if (tnh1->oif < tnh2->oif) return -1;
    if (tnh1->oif > tnh2->oif) return 1;

    if (tnh1->is_indirect != tnh2->is_indirect) {
        return tnh1->is_indirect ? 1 : -1;
    }

    rc = cmn_prefix_compare (&tnh1->prefix, &tnh2->prefix);
    if (rc != 0) return rc;

    if (tnh1->l3_vpn_label < tnh2->l3_vpn_label) return -1;
    if (tnh1->l3_vpn_label > tnh2->l3_vpn_label) return 1;

    if (tnh1->import_rt.asn < tnh2->import_rt.asn) return -1;
    if (tnh1->import_rt.asn > tnh2->import_rt.asn) return 1;
    if (tnh1->import_rt.number < tnh2->import_rt.number) return -1;
    if (tnh1->import_rt.number > tnh2->import_rt.number) return 1;

    if (!tnh1->rtm_nh_proto && tnh2->rtm_nh_proto) return -1;
    if (tnh1->rtm_nh_proto && !tnh2->rtm_nh_proto) return 1;
    if (tnh1->rtm_nh_proto && tnh2->rtm_nh_proto) {
        rc = rtm_nh_proto_is_equal (tnh1->rtm_nh_proto, tnh2->rtm_nh_proto);
        if (rc != 0) return rc;
    }

    if (!tnh1->label_stack && tnh2->label_stack) return -1;
    if (tnh1->label_stack && !tnh2->label_stack) return 1;
    if (tnh1->label_stack && tnh2->label_stack) {
        rc = memcmp (tnh1->label_stack, tnh2->label_stack, sizeof (*tnh1->label_stack));
        if (rc != 0) return (rc < 0) ? -1 : 1;
    }

    if (tnh1->endfn < tnh2->endfn) return -1;
    if (tnh1->endfn > tnh2->endfn) return 1;

    rc = rtm_tnh_v6segment_lst_compare (
            tnh1->n_segment_list, tnh1->v6segment_lst,
            tnh2->n_segment_list, tnh2->v6segment_lst);
    if (rc != 0) return rc;

    rc = cmn_prefix_compare (&tnh1->gre_tunnel_src, &tnh2->gre_tunnel_src);
    if (rc != 0) return rc;

    rc = cmn_prefix_compare (&tnh1->gre_tunnel_dst, &tnh2->gre_tunnel_dst);
    if (rc != 0) return rc;

    return 0;
}

int
rtm_tnh_avl_tree_comp_fn (const avltree_node_t *node1, const avltree_node_t *node2) {

    rtm_tnh_t *tnh1 = avltree_container_of (node1, rtm_tnh_t, rtm_tnh_glue);
    rtm_tnh_t *tnh2 = avltree_container_of (node2, rtm_tnh_t, rtm_tnh_glue);

    return rtm_tnh_compare (tnh1, tnh2);
}

rtm_tnh_t *
rtm_tnh_get_or_insert (rtm_t *rtm, rtm_tnh_t *candidate) {

    avltree_node_t *node;

    assert (rtm && candidate);

    node = avltree_lookup (&candidate->rtm_tnh_glue, &rtm->tnh_tree);
    if (node) {
        rtm_tnh_free (candidate);
        return avltree_container_of (node, rtm_tnh_t, rtm_tnh_glue);
    }

    assert (!avltree_insert (&candidate->rtm_tnh_glue, &rtm->tnh_tree));
    candidate->rtm = rtm;
    return candidate;
}

rtm_tnh_t *
rtm_tnh_lookup (rtm_t *rtm, rtm_tnh_t *candidate_template) {

    avltree_node_t *node;
    assert (rtm && candidate_template);
    node = avltree_lookup (&candidate_template->rtm_tnh_glue, &rtm->tnh_tree);
    if (!node) return NULL;
    return avltree_container_of (node, rtm_tnh_t, rtm_tnh_glue);
}

void
rtm_tnh_link_nh (rtm_t *rtm, rtm_tnh_t *tnh, rtm_nh *nh) {

    assert (rtm && tnh && nh);
    assert (nh->tnh == NULL);
    assert (!IS_QUEUED_UP_IN_THREAD (&nh->tnh_member_glue));

    nh->tnh = tnh;
    rtm_nh_Fglthread_add_last (nh, &tnh->route_nh_list, &nh->tnh_member_glue);
}

void
rtm_tnh_unlink_nh (rtm_t *rtm, rtm_nh *nh) {

    rtm_tnh_t *tnh;

    assert (rtm && nh);

    tnh = nh->tnh;
    if (!tnh) {
        assert (!IS_QUEUED_UP_IN_THREAD (&nh->tnh_member_glue));
        return;
    }

    assert (IS_QUEUED_UP_IN_THREAD (&nh->tnh_member_glue));
    /* Clear backpointer before remove_Fglthread — that may drop the last
     * NH ref and free nh via GC. */
    nh->tnh = NULL;
    rtm_nh_remove_Fglthread (rtm, nh, &tnh->route_nh_list, &nh->tnh_member_glue);

    if (Fglthread_list_is_empty (&tnh->route_nh_list)) {

        /* Remove from Src List */
        assert (IS_QUEUED_UP_IN_THREAD(&tnh->src_glue));
        remove_glthread (&tnh->src_glue);
        
        assert (avltree_node_is_inuse (&rtm->tnh_tree, &tnh->rtm_tnh_glue));
        avltree_strict_remove (&tnh->rtm_tnh_glue, &rtm->tnh_tree);
        rtm_tnh_free (tnh);
    }
}

rtm_tnh_t *
rtm_tnh_create_from_nh_template(cp_nexthop_template_t *cp_nh_template) {

    if (!cp_nh_template) return NULL;

    rtm_tnh_t *tnh = (rtm_tnh_t *)XCALLOC2 (0, 1, rtm_tnh_t);
    rtm_tnh_initialize (tnh);

    tnh->fwd_flags = cp_nh_template->fwd_flags;
    tnh->proto = cp_nh_template->proto;
    tnh->sub_proto = cp_nh_template->sub_proto;
    tnh->ad = rtm_get_admin_distance (tnh->proto, tnh->sub_proto);
    tnh->metric = cp_nh_template->metric;
    tnh->action = cp_nh_template->action;
    tnh->prefix = cp_nh_template->gateway;
    tnh->oif = cp_nh_template->oif;
    tnh->is_indirect = cp_nh_template->is_indirect;
    tnh->l3_vpn_label = cp_nh_template->l3_vpn_label;
    tnh->import_rt = cp_nh_template->import_rt;

    /* is set in caller
    tnh->rtm_nh_proto 
    */ 

    if (IS_BIT_SET (cp_nh_template->fwd_flags, FIB_NH_FWD_F_MPLS_LBL_STCK) &&
        cp_nh_template->u.l_stack.label_stack) {

        tnh->label_stack = (mpls_lstack_t *)XCALLOC2 (0, 1, mpls_lstack_t);
        tnh->label_stack->curr_index =
            cp_nh_template->u.l_stack.label_stack->curr_index;

        for (int i = 0; i <= tnh->label_stack->curr_index; i++) {
            tnh->label_stack->labels[i].label_val =
                cp_nh_template->u.l_stack.label_stack->labels[i].label_val;
            tnh->label_stack->labels[i].op =
                cp_nh_template->u.l_stack.label_stack->labels[i].op;
        }
    }

    if (IS_BIT_SET (cp_nh_template->fwd_flags, FIB_NH_FWD_F_IPV6_STCK)) {

        tnh->endfn = cp_nh_template->u.srv6_stack.endfn;

        if (cp_nh_template->u.srv6_stack.n_segment_list) {

            tnh->n_segment_list = cp_nh_template->u.srv6_stack.n_segment_list;
            tnh->v6segment_lst = (cmn_prefix_t *)XCALLOC2 (
                0, cp_nh_template->u.srv6_stack.n_segment_list, cmn_prefix_t);

            for (int i = 0; i < tnh->n_segment_list; i++) {
                memcpy (&tnh->v6segment_lst[i],
                        &cp_nh_template->u.srv6_stack.v6segment_lst[i],
                        sizeof (tnh->v6segment_lst[i]));
            }
        }
    }

    if (IS_BIT_SET (cp_nh_template->fwd_flags, FIB_NH_FWD_F_TUNNEL)) {
        tnh->gre_tunnel_src = cp_nh_template->u.gre_tunnel.gre_tunnel_src;
        tnh->gre_tunnel_dst = cp_nh_template->u.gre_tunnel.gre_tunnel_dst;
    }

    return tnh;
}