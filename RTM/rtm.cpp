/*
 * =====================================================================================
 *
 *       Filename:  rtm.cpp
 *
 *    Description:  RTM Core - Routing Table Manager Initialization and Lifecycle
 *
 *        This file implements the core RTM initialization, lifecycle management,
 *        and data structure setup. It provides the foundation for all RTM
 *        operations.
 *
 *        RTM Structure:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ rtm_t (Routing Table Manager)                                │
 *        │  ├─> route_tree: AVL tree of all routes                     │
 *        │  ├─> lpm_rt_tree: MTrie for LPM lookups                     │
 *        │  ├─> nhs_by_idx: AVL tree of nexthops by ID                 │
 *        │  ├─> nhs_by_src[proto]: Lists of nexthops by protocol      │
 *        │  ├─> proto_info_tree[proto]: Protocol information trees    │
 *        │  ├─> ppt_db_route_tree: Presentation DB route tree          │
 *        │  ├─> unresolvable_paths: Queue of unresolvable INHs         │
 *        │  ├─> route_advt_queue: Queue of routes to advertise        │
 *        │  └─> gc_queue: Garbage collection queue                    │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        RTM Initialization Flow:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ 1. Allocate RTM structure                                    │
 *        │ 2. Initialize keys (VRF, AFI, RTM ID)                        │
 *        │ 3. Generate RTM name (vrf.inet[6].table_id)                 │
 *        │ 4. Initialize LPM tree (MTrie)                                │
 *        │ 5. Initialize route tree (AVL)                                │
 *        │ 6. Initialize nexthop index tree (AVL)                         │
 *        │ 7. Initialize protocol-specific structures                     │
 *        │ 8. Initialize presentation layer (PPT DB)                     │
 *        │ 9. Initialize queues and job handlers                        │
 *        │ 10. Initialize statistics                                    │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        RTM Naming Convention:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ Format: <vrf_name>.<afi>.<rtm_id>                           │
 *        │                                                              │
 *        │ Examples:                                                   │
 *        │   - Default VRF IPv4: "0.inet.0"                            │
 *        │   - Default VRF IPv6: "0.inet6.0"                          │
 *        │   - Default VRF MPLS: "0.mpls.0"                           │
 *        │   - VRF 1 IPv4: "vrf1.inet.0"                               │
 *        │   - VRF 1 IPv6: "vrf1.inet6.0"                             │
 *        │   - L3VPN IPv4: "0.inet3.0"                                 │
 *        │   - L3VPN IPv6: "0.inet63.0"                                │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Version:  1.0
 *        Created:  [Original Date]
 *       Revision:  1.0
 *       Compiler:  gcc/g++
 *
 * =====================================================================================
 */

#include <stdint.h>
#include <cstring>
#include <assert.h>
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include "../libs/gluethread/glthread.h"
#include "../libs/LinuxMemoryManager/uapi_mm.h"
#include "rtm.h"
#include "rtm_route.h"
#include "rtm_proto.h"
#include "rtm_nh.h"
#include "rtm_presentation.h"
#include "../lmm_enums.h"
#include "../libs/mtrie/mtrie.h"
#include "../libs/Tracer/tracer.h"
#include "../router_init.h"

/* ========================================================================
 * Forward Declarations
 * ======================================================================== */

extern void rtm_lpm_tree_init(rtm_t *rtm);
extern void rtm_lpm_tree_destroy(rtm_t *rtm);
extern rtm_t *rtm_get(node_t *node, uint8_t vrf_id, AFI_T afi, uint8_t rtm_id);

/* AVL Tree comparison function */
extern int8_t
rtm_nh_proto_is_equal (rtm_nh_proto_t *nh_proto1, rtm_nh_proto_t *nh_proto2);
extern int8_t
rtm_proto_compare (rtm_proto_info_t* proto1, rtm_proto_info_t* proto2);
extern int
rtm_route_compare(const avltree_node_t *node1, const avltree_node_t *node2);
extern int
rtm_nh_compare_by_idx (const avltree_node_t *node1, const avltree_node_t *node2);
extern int
rtm_tnh_avl_tree_comp_fn (const avltree_node_t *node1, const avltree_node_t *node2);

/* Wrapper for NH proto compare */
static int
rtm_nh_proto_avl_tree_comp_fn (const avltree_node_t *node1, const avltree_node_t *node2) {

    rtm_nh_proto_t *nh_proto1 = avltree_container_of(node1, rtm_nh_proto_t, proto_glue);
    rtm_nh_proto_t *nh_proto2 = avltree_container_of(node2, rtm_nh_proto_t, proto_glue);

    return rtm_nh_proto_is_equal(nh_proto1, nh_proto2);
}

/* Wrapper for proto info compare */
static int
rtm_proto_info_avl_tree_comp_fn (const avltree_node_t *node1, const avltree_node_t *node2) {

    rtm_proto_info_t *proto_info1 = avltree_container_of(node1, rtm_proto_info_t, proto_glue);
    rtm_proto_info_t *proto_info2 = avltree_container_of(node2, rtm_proto_info_t, proto_glue);

    return rtm_proto_compare(proto_info1, proto_info2);
}

/* ========================================================================
 * RTM Initialization and Lifecycle
 * ======================================================================== */

/**
 * @brief Initialize a new RTM instance
 * 
 * Creates and initializes a new Routing Table Manager instance.
 * Sets up all data structures, trees, queues, and job handlers.
 * 
 * Initialization includes:
 * - Route storage (AVL tree and MTrie)
 * - Nexthop indexing (AVL tree)
 * - Protocol-specific structures
 * - Presentation layer (PPT DB)
 * - Resolution queues
 * - Advertisement queues
 * - Garbage collection queues
 * - Statistics tracking
 * 
 * @param node Pointer to network node
 * @param vrf_id VRF identifier
 * @param afi Address family (AF_IPV4, AF_IPV6, AF_LABEL, etc.)
 * @param rtm_id Routing table ID
 * 
 * @return Pointer to initialized RTM structure
 */
rtm_t *
rtm_initialize(node_t *node, 
               uint8_t vrf_id, 
               char *vrf_name, 
               AFI_T afi, 
               uint32_t rtm_id) {
    
    rtm_t *rtm = (rtm_t *)XCALLOC2 (0, 1, rtm_t);

    rtm->vrf = vrf_id;
    rtm->afi = afi;
    rtm->rtm_id = rtm_id;
    rtm->flags = 0;

    snprintf (rtm->name, sizeof(rtm->name), "%s.%s.%d", 
        vrf_name,
        afi == AF_IPV4 ? "inet" : afi == AF_IPV6 ? \
        "inet6" :  afi == AF_LABEL ? "mpls" : "mac", rtm_id);

    rtm_lpm_tree_init(rtm);
    avltree_init(&rtm->route_tree, rtm_route_compare);
    avltree_init (&rtm->nh_proto_info_tree, rtm_nh_proto_avl_tree_comp_fn);
    avltree_init (&rtm->nhs_by_idx, rtm_nh_compare_by_idx);
    avltree_init (&rtm->tnh_tree, rtm_tnh_avl_tree_comp_fn);

    for (int i = 0; i < RTM_PROTO_MAX; i++) {
        init_glthread(&rtm->nhs_by_src[i]);
        avltree_init(&rtm->proto_info_tree[i], rtm_proto_info_avl_tree_comp_fn);
        init_Fglthread (&rtm->advt_nhs[i]);
    }
    
    rtm->node = node;

    init_Fglthread(&rtm->unresolvable_paths);

    rtm->nh_resolution_job = NULL;
    rtm->rt_resolution_job = NULL;

    rtm_ppt_db_initialize(rtm);

    init_Fglthread(&rtm->route_advt_queue);

    rtm->route_advt_prep_job = NULL;
    rtm->advt_job = NULL;
    rtm->gc_job = NULL;

    init_Fglthread(&rtm->gc_queue);

    init_glthread (&rtm->stats.new_resolved_routes);
    init_glthread (&rtm->stats.new_resolved_nhs);
    init_glthread (&rtm->stats.new_unresolved_routes);
    init_glthread (&rtm->stats.new_unresolved_nhs);
    
    return rtm;
}

extern rtm_error_t 
cp_rtm_uninstall_route_by_idx ( 
                rtm_t *rtm, 
                uint32_t idx);


/**
 * @brief Check RTM state and delete if requested
 * 
 * Validates that all RTM resources have been properly cleaned up before
 * deletion. Performs assertions to ensure:
 * - All routes have been removed
 * - All nexthops have been removed
 * - All protocol information has been cleaned up
 * - All queues are empty
 * - All jobs have been cancelled
 * - LPM tree is empty
 * - Presentation DB is empty
 * 
 * This function is used during RTM shutdown to ensure proper cleanup.
 * 
 * @param rtm Pointer to RTM to check/delete
 * @param free_rtm If true, free the RTM structure after validation
 */
void
rtm_check_and_delete (rtm_t *rtm, bool free_rtm) {
    
    /* Before we delete RTM, check all resources have been freed already*/
    assert (avltree_is_empty (&rtm->route_tree) );
    assert (avltree_is_empty (&rtm->nh_proto_info_tree) );
    assert (avltree_is_empty (&rtm->nhs_by_idx));
    assert (avltree_is_empty (&rtm->tnh_tree));

    for (int i = 0; i < RTM_PROTO_MAX; i++) {
        assert (avltree_is_empty (&rtm->proto_info_tree[i]) );
        assert (IS_GLTHREAD_LIST_EMPTY (&rtm->nhs_by_src[i]) );
        assert (Fglthread_list_is_empty (&rtm->advt_nhs[i]) );
    }
    
    assert (Fglthread_list_is_empty(&rtm->unresolvable_paths) );
    assert (Fglthread_list_is_empty(&rtm->route_advt_queue) );
    
    assert (rtm->nh_resolution_job == NULL);
    assert (rtm->rt_resolution_job == NULL);
    assert (rtm->route_advt_prep_job == NULL);
    assert (rtm->advt_job == NULL);
    assert (rtm->gc_job == NULL);

    /* Destroy LPM tree */
    assert (mtrie_is_leaf_node(rtm->lpm_rt_tree->root));
    assert (avltree_is_empty (&rtm->ppt_db_route_tree));

    assert (Fglthread_list_is_empty(&rtm->gc_queue) );

    assert (!IS_GLTHREAD_LIST_EMPTY (&rtm->stats.new_resolved_routes));
    assert (!IS_GLTHREAD_LIST_EMPTY (&rtm->stats.new_unresolved_routes));
    assert (!IS_GLTHREAD_LIST_EMPTY (&rtm->stats.new_resolved_nhs));
    assert (!IS_GLTHREAD_LIST_EMPTY (&rtm->stats.new_unresolved_nhs));

    if (free_rtm) XFREE(rtm);
}

/* Destroy an RTM instance */
void 
rtm_stop (rtm_t *rtm) {

    int i; 
    rtm_nh *nh;
    glthread_t *curr;
    node_t *node = rtm->node;

    for (i = RTM_PROTO_STATIC; i < RTM_PROTO_MAX; i++) {

        ITERATE_GLTHREAD_BEGIN(&rtm->nhs_by_src[i], curr) {

            nh = src_glue_to_rtm_nh(curr);
            cp_rtm_uninstall_route_by_idx(rtm, nh->idx);

        } ITERATE_GLTHREAD_END(&rtm->nhs_by_src[i], curr);
    }

    /* Kill all the jobs */
    if (rtm->nh_resolution_job) {
        task_cancel_job(EV(node), rtm->nh_resolution_job);
        rtm->nh_resolution_job = NULL;
    }

    if (rtm->rt_resolution_job) {
        task_cancel_job(EV(node), rtm->rt_resolution_job);
        rtm->rt_resolution_job = NULL;
    }    

    if (rtm->route_advt_prep_job) {
        task_cancel_job(EV(node), rtm->route_advt_prep_job);
        rtm->route_advt_prep_job = NULL;
    }    

    if (rtm->advt_job) {
        task_cancel_job(EV(node), rtm->advt_job);
        rtm->advt_job = NULL;
    }    

    if (rtm->gc_job) {
        task_cancel_job(EV(node), rtm->gc_job);
        rtm->gc_job = NULL;
    }        

    rtm_ppt_db_destroy(rtm);
    rtm_clear_stats (rtm);
    rtm_check_and_delete(rtm, false);
}

void 
rtm_log_stats (rtm_t *rtm) {

    glthread_t *curr;
    rtm_nh *inh;
    rtm_route *route;
    char prefix_str[48];
    uint32_t count = 1;

    return;

    if (!IS_GLTHREAD_LIST_EMPTY(&rtm->stats.new_resolved_routes))
    {

    tracer(rtm->node->cptr, DRTM_DET, "RTM[%s] : Stats : Resolved Routes:\n", rtm->name);
    count = 1;
    ITERATE_GLTHREAD_BEGIN(&rtm->stats.new_resolved_routes, curr) {

        route = stats_resolved_glue_to_route(curr);

        tracer(rtm->node->cptr, DRTM_DET, "    RTM[%s] : Stats : %u. Resolved Route : %s\n",
                rtm->name, count++, 
                rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));

    } ITERATE_GLTHREAD_END(&rtm->stats.new_resolved_routes, curr);

    }

    if (!IS_GLTHREAD_LIST_EMPTY(&rtm->stats.new_resolved_nhs))
    {

    tracer(rtm->node->cptr, DRTM_DET, "RTM[%s] : Stats : Resolved INHs:\n", rtm->name);
    count = 1;
    ITERATE_GLTHREAD_BEGIN(&rtm->stats.new_resolved_nhs, curr) {

        inh = stats_resolved_glue_to_rtm_nh(curr);

        tracer(rtm->node->cptr, DRTM_DET, "    RTM[%s] : Stats : %u. Resolved INH : %s, idx=%u\n",
               rtm->name, count++,
               rtm_format_prefix(&inh->prefix, prefix_str, sizeof(prefix_str)), inh->idx);

    } ITERATE_GLTHREAD_END(&rtm->stats.new_resolved_nhs, curr);

    }


    if (!IS_GLTHREAD_LIST_EMPTY(&rtm->stats.new_unresolved_routes))
    {

    tracer(rtm->node->cptr, DRTM_DET, "RTM[%s] : Stats : UnResolved Routes:\n", rtm->name);
    count = 1;
    ITERATE_GLTHREAD_BEGIN(&rtm->stats.new_unresolved_routes, curr) {

        route = stats_resolved_glue_to_route(curr);

        tracer(rtm->node->cptr, DRTM_DET, "    RTM[%s] : Stats : %u. UnResolved Route : %s\n",
                rtm->name, count++, 
                rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));

    } ITERATE_GLTHREAD_END(&rtm->stats.new_unresolved_routes, curr);

    }


    if (!IS_GLTHREAD_LIST_EMPTY(&rtm->stats.new_unresolved_nhs))
    {

    tracer(rtm->node->cptr, DRTM_DET, "RTM[%s] : Stats : UnResolved INHs:\n", rtm->name);
    count = 1;
    ITERATE_GLTHREAD_BEGIN(&rtm->stats.new_unresolved_nhs, curr) {

        inh = stats_resolved_glue_to_rtm_nh(curr);

        tracer(rtm->node->cptr, DRTM_DET, "    RTM[%s] : Stats : %u. UnResolved INH : %s, idx=%u\n",
               rtm->name, count++,
               rtm_format_prefix(&inh->prefix, prefix_str, sizeof(prefix_str)), inh->idx);

    } ITERATE_GLTHREAD_END(&rtm->stats.new_unresolved_nhs, curr);

    }

}

void 
rtm_clear_stats(rtm_t *rtm) {

        glthread_t *curr;

        while ((curr = dequeue_glthread_first(&rtm->stats.new_resolved_routes))) {
            rtm_route_dereference(rtm, stats_resolved_glue_to_route(curr));
        }

        while ((curr = dequeue_glthread_first(&rtm->stats.new_unresolved_routes))) {
            rtm_route_dereference(rtm, stats_resolved_glue_to_route(curr));
        }        

        while ((curr = dequeue_glthread_first(&rtm->stats.new_resolved_nhs))) {
            rtm_nh_dereference(rtm, stats_resolved_glue_to_rtm_nh(curr));
        }        

        while ((curr = dequeue_glthread_first(&rtm->stats.new_unresolved_nhs))) {
            rtm_nh_dereference(rtm, stats_resolved_glue_to_rtm_nh(curr));
        }        
}