/*
 * =====================================================================================
 *
 *       Filename:  rtm_presentation.h
 *
 *    Description:  RTM Presentation Layer Header - FIB Updates and Route Advertisement
 *
 *        This header defines the presentation layer structures and APIs that handle
 *        route advertisement to protocols and FIB updates.
 *
 *        Presentation Layer Purpose:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ RTM → Presentation Layer → FIB/Protocols                    │
 *        │                                                              │
 *        │ 1. Route changes detected in RTM                           │
 *        │ 2. Diff computed (old vs new state)                        │
 *        │ 3. ADD/DELETE operations created                            │
 *        │ 4. Operations queued for advertisement                      │
 *        │ 5. FIB updated with new forwarding information              │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Key Structures:
 *        - rtm_presentation_data_t: Data for route advertisement
 *        - rtm_ppt_route_t: Route blueprint in presentation DB
 *        - rtm_ppt_nhidx_t: Nexthop index information
 *        - rtm_rt_subscription_t: Protocol subscription information
 *
 *        Version:  1.0
 *        Created:  [Original Date]
 *       Revision:  1.0
 *       Compiler:  gcc/g++
 *
 * =====================================================================================
 */

#ifndef __RTM_PRESENTATION__
#define __RTM_PRESENTATION__

#include "rtm_enums.h"
#include "../libs/common/cmn_prefix.h"
#include "../libs/Tree/libtree.h"
#include "../libs/gluethread/glthread.h"

/* ========================================================================
 * Forward Declarations
 * ======================================================================== */

typedef struct rtm_ rtm_t;
typedef struct rtm_nh_ rtm_nh;
typedef struct rtm_route_ rtm_route;
typedef struct prefix_lst_ prefix_list_t;
typedef struct rtm_nh_proto_ rtm_nh_proto_t;

/* ========================================================================
 * Presentation Layer Enumerations
 * ======================================================================== */

/**
 * @brief Operation type for route advertisements
 * 
 * Defines the type of operation being performed on a route/nexthop
 * during advertisement to protocols or FIB updates.
 */
typedef enum rtm_ppt_operation_ {
    RTM_PPT_OP_ADD = 1,      /* Route/NH is being added */
    RTM_PPT_OP_DELETE = 2,   /* Route/NH is being deleted */
    RTM_PPT_OP_UPDATE = 3    /* Route/NH is being updated */
} rtm_ppt_operation_t;


#pragma pack(push, 8)

typedef struct rtm_rt_subscription_ {

    /* Below three fields are keys */
    /* Subscribe routes from this protocol */
    RTM_PROTO_T target_proto; 
    /* Subscribe these route types*/
    RTM_SUB_PROTO_T target_sub_proto;
    /* Subscrive route from this instance of protocol */
    uint32_t target_instance_no;

    /* Subscribe these routes */
    prefix_list_t *prefix_list;

    /* Second layer comparison function, for the matching route, compare the 
        nexthop protocol properties. For example, Subscriber protocol need BGP 
        routes with MED value > 100 only */
    // To be Supported Later
    rtm_nh_proto_t *nh_proto;

    /* Callback fn used for notif - receives operation type and nh_idx */
    void (*cbk)(rtm_t *, uint32_t nh_idx, rtm_nh *, rtm_nh_proto_t *, rtm_ppt_operation_t);

    /* Hook up in rtm_proto_info_t sub_db Tree*/
    avltree_node_t avl_glue;

} rtm_rt_subscription_t;

/* The data structire to present the route info to clients */
typedef struct rtm_presentation_data_ {

    /* Route prefix being advertised */
    cmn_prefix_t route;
    /* Pointer to Direct nexthop being added, if deleted it would be NULL*/
    rtm_nh *nh; 
    /* nh_idx of DNH being added or deleted. Clients must use this if nh ptr is NULL*/
    uint32_t nh_idx;     
    /*Indirect Nexthop being resolved by nh, if deleted it would be NULL*/            
    rtm_nh *inh;
    /* inh_idx of INH being added or deleted. Clients must use this if inh ptr is NULL*/
    uint32_t inh_idx;    
    /* Nexthop Entire Src Proto info */
    rtm_nh_proto_t *rtm_nh_proto;
    /* Nh Addr*/
    cmn_prefix_t nh_addr;
    /* Prefix List to match*/
    prefix_list_t *prefix_list;
    /* Add or Delete operation , Update not supported*/
    rtm_ppt_operation_t operation;  /* ADD, DELETE, or UPDATE */
    
    /* Used to delete route from FIB in delete case*/
    struct {
        uint8_t vrf;
        AFI_T afi;
    } target_fib;
    
    /* Glue to link in rtm->advt_nhs[] lists */
    glthread_t glue;

} rtm_presentation_data_t;

/* This structure represents the blue print of the routes and its NHs.
    This structure is maintained per route. This structure is intentionally
    kept linkage free from RTM module
    
    IMPORTANT INVARIANT: Both the outer nhidx_list and inner dnh_list arrays
    are maintained in sorted order (by nh_pidx and DNH index respectively).
    This allows efficient O(n+m) diffing algorithms instead of O(n*m) nested loops.
*/
typedef struct rtm_ppt_nhidx_ {
    
    uint32_t nh_pidx;
    /* backpointer to owning RTM*/
    rtm_t *nh_pidx_rtm;

    /* If Nexthop is indirect, then sorted list (in increasing order) of 
        nhidx values of direct nexthops */
    uint16_t dnh_list_count;

    /* Pointer to separately allocated array of DNHs 
        Idx values*/
    struct dnh{

        uint32_t dnh_idx;
        rtm_t *dnh_idx_rtm;
    };

    struct dnh *dnh_list;  

}rtm_ppt_nhidx_t;

typedef struct rtm_ppt_route_ {

    uint32_t ridx;
    cmn_prefix_t prefix; // key

    /* AVL tree glue for route_tree in rtm_ppt_db_entry_t */
    avltree_node_t route_glue;

    /* NHs idx values, sorted in increasing order by nh_pidx */
    /* Each entry's dnh_list is also sorted in increasing order */
    uint16_t nhidx_list_count;
    rtm_ppt_nhidx_t nhidx_list[0];

} rtm_ppt_route_t;

#pragma pack(pop)

GLTHREAD_TO_STRUCT(rtm_presentation_data_to_glue, rtm_presentation_data_t, glue);

void rtm_on_demand_route_request (
        rtm_t *rtm, 
        uint8_t vrf_id, 
        uint8_t instance_no, 
        RTM_PROTO_T proto);

/* APIs over RTM PPT DB */
void rtm_ppt_db_initialize (rtm_t *rtm);
void rtm_ppt_db_destroy (rtm_t *rtm);
void rtm_ppt_register_route (rtm_t *rtm, cmn_prefix_t *prefix, uint32_t ridx);
void rtm_ppt_unregister_route (rtm_t *rtm, cmn_prefix_t *prefix, uint32_t ridx);
void rtm_schedule_route_advertisement (rtm_t *rtm, rtm_route *route);

#endif 
