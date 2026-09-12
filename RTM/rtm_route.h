/*
 * =====================================================================================
 *
 *       Filename:  rtm_route.h
 *
 *    Description:  RTM Route Header - Route Structure and Operations
 *
 *        This header defines the route structure and all route-related operations
 *        in the RTM system. Routes represent destination networks with associated
 *        nexthops.
 *
 *        Route Structure:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ rtm_route                                                     │
 *        │  - prefix: Destination network                              │
 *        │  - path_list: Sorted list of nexthops                        │
 *        │  - resolved_lnhs: List of INHs resolved over this route       │
 *        │  - nh_count: Number of nexthops                              │
 *        │  - ref_count: Reference count                                │
 *        │  - route_glue: AVL tree node                                │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Route Operations:
 *        - Lookup: Find route by prefix
 *        - Add: Add route to RTM
 *        - Delete: Remove route from RTM
 *        - Nexthop Management: Add/remove nexthops
 *        - Resolution: Track which INHs resolve over this route
 *
 *        Version:  1.0
 *        Created:  [Original Date]
 *       Revision:  1.0
 *       Compiler:  gcc/g++
 *
 * =====================================================================================
 */

#ifndef __RTM_ROUTE__
#define __RTM_ROUTE__

#include <stdint.h>
#include <stdbool.h>
#include "../libs/gluethread/glthread.h"
#include "../libs/Tree/libtree.h"
#include "rtm.h"
#include "rtm_enums.h"
#include "rtm_error.h"
#include "rtm_nh.h"

/* ========================================================================
 * Forward Declarations
 * ======================================================================== */

typedef struct bitmap_ bitmap_t;

#pragma pack(push, 8)

/**
 * @brief Route structure
 * 
 * Represents a destination network with associated nexthops.
 * Routes are stored in AVL trees for efficient lookup and in
 * MTrie structures for longest prefix match operations.
 */
typedef struct rtm_route_ {

    /* Route's unique Id, used to distinsguish from route's 
        previous incarnation */
    uint32_t ridx;

    /* List of Nexthops of this route*/
    glthread_t path_list;
    
    /* List of LNHs resolved by this route */
    Fglthread_t resolved_lnhs;

    /* Glues */
    /* Glue in RTM main tree */
    avltree_node_t route_glue;

    glthread_t resolved_route_glue;

    /* Prefix for this route */
    cmn_prefix_t prefix;

    uint16_t flags;

    /* How manu INHs are in resolved state.*/
    uint16_t resolved_inh_count;

    /* Number of nexthops */
    uint16_t nh_count;

    uint32_t ref_count;

    glthread_t advt_glue;
    glthread_t stats_resolved_glue;

} rtm_route;

#pragma pack(pop)

/* ========================================================================
 * Glue Macros
 * ======================================================================== */

GLTHREAD_TO_STRUCT(resolved_route_glue_to_route, rtm_route, resolved_route_glue);
GLTHREAD_TO_STRUCT(advt_glue_to_route, rtm_route, advt_glue);
GLTHREAD_TO_STRUCT(stats_resolved_glue_to_route, rtm_route, stats_resolved_glue);

/* ========================================================================
 * Route Management API
 * ======================================================================== */

/* Methods */
void rtm_route_initialize(rtm_route *route, uint32_t ridx);
bool rtm_validate_with_route(rtm_t *rtm, cmn_prefix_t *prefix);

/* Route Mgmt Functions */
rtm_route *rtm_route_lookup(rtm_t *rtm, cmn_prefix_t *prefix_key);
rtm_error_t rtm_route_add(rtm_t *rtm, rtm_route *route);

/* Nexthop Mgmt*/
rtm_nh *rtm_route_lookup_nh(rtm_route *route, rtm_nh *nh_template);
rtm_error_t rtm_route_add_nh(rtm_t *rtm, rtm_route *route, rtm_nh *nh);
rtm_error_t rtm_route_delete_nh (rtm_t *rtm, rtm_route* route, rtm_nh* nh);
rtm_error_t rtm_route_delete (rtm_t *rtm, rtm_route* route) ;


void rtm_route_refresh_nexthops(rtm_t *rtm, rtm_route* route) ;
bool rtm_route_is_resolved (rtm_route* route);
bool rtm_route_is_local (rtm_route* route);

bool
rtm_route_is_path_present (
        rtm_route *rtm_route, 
        RTM_PROTO_T proto, 
        RTM_SUB_PROTO_T sub_proto, uint32_t *cost);

void 
rtm_route_check_and_delete(rtm_t *rtm, rtm_route* route);

/* LPM Tree Operations */
void rtm_lpm_tree_init(rtm_t *rtm);
void rtm_lpm_tree_destroy(rtm_t *rtm);
rtm_error_t rtm_lpm_tree_insert(rtm_t *rtm, rtm_route *route);
rtm_error_t rtm_lpm_tree_delete(rtm_t *rtm, cmn_prefix_t *prefix);
rtm_route *rtm_lpm_tree_lookup(rtm_t *rtm, cmn_prefix_t *prefix);

void rtm_route_reference(rtm_route* route);
uint32_t rtm_route_dereference(rtm_t *rtm, rtm_route* route);

void rtm_route_moved_to_resolved_state (rtm_t *rtm, rtm_route *route) ;
void rtm_route_moved_to_unresolved_state (rtm_t *rtm, rtm_route *route) ;




/* Wrapper to glthread_add_next ()*/
void rtm_route_glthread_add_next (rtm_route *route, 
        glthread_t *curr_glthread, glthread_t *new_glthread);

/* Wrapper over remove_glthread( ) */
void rtm_route_remove_glthread (rtm_t *rtm, rtm_route *route, glthread_t *curr_glthread);

/* Wrapper over Fglthread_add_next()*/
void rtm_route_fglthread_add_next (rtm_route *route, 
        Fglthread_t *head, 
        glthread_t *base_glthread, glthread_t *new_glthread);

/* Wrapper over Fglthread_add_before()*/
void rtm_route_fglthread_add_before (rtm_route *route, 
        Fglthread_t *head, 
        glthread_t *base_glthread, glthread_t *new_glthread);

void
rtm_route_remove_Fglthread(rtm_t *rtm, rtm_route *route, 
                Fglthread_t *head, glthread_t *glthread);

void
rtm_route_Fglthread_add_last(rtm_route *route, 
        Fglthread_t *head, glthread_t *new_glthread);

void 
rtm_route_avl_insert (rtm_route *route, avltree_t *tree, avltree_node_t *avlnode);

void 
rtm_route_avl_remove (rtm_t *rtm, rtm_route *route, 
        avltree_t *tree, avltree_node_t *avlnode);

#endif
