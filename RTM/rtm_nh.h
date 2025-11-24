#ifndef __RTM_NH__
#define __RTM_NH__
#pragma pack(push, 8)

#include <stdint.h>
#include <time.h>
#include "../gluethread/glthread.h"
#include "../Tree/libtree.h"
#include "rtm_enums.h"
#include "rtm_common.h"
#include "../Interface/InterfaceFwd.h"
#include "../Layer3/SegmentRouting/SRv6/common/srv6_const.h"

typedef struct rtm_ rtm_t;
typedef struct rtm_route_ rtm_route;
typedef struct rtm_nh_proto_ rtm_nh_proto_t;
typedef struct rtm_proto_info_ rtm_proto_info_t;

typedef struct rtm_nh_ {

        /* Unique nexthop index - constant throughout lifetime */
        uint32_t idx;
        uint32_t flags;
        time_t pth_last_update_time;

        /* Owning protocol*/
        RTM_PROTO_T proto;
        /* Owning Sub-protocol */
        RTM_SUB_PROTO_T sub_proto;

        /* Backpointer to the owning route (shared Pointer)*/
        rtm_route* owner_route;

        /* Glues*/
        glthread_t route_glue;
        glthread_t src_glue;
        glthread_t resolution_list_glue;
        avltree_node_t idx_glue;
        glthread_t advt_glue; // keyed by idx
        
        /* Shared pointer to the protocol info */
        rtm_nh_proto_t *rtm_nh_proto;

        /* Admin distance */
        RTM_AD_T ad;

        /* Metric */
        uint32_t metric;

        /* Action */
        RTM_NH_ACTION_TYPE_T action;

        /* Nexthop prefix */
        rtm_prefix_t prefix;

        /* Outgoing Interface*/
        InterfaceP Oif;
       uint32_t outgoing_if;

        bool is_resolved;
        bool is_indirect;
        bool is_active;

        /*MPLS  Label Stack*/
        rtm_lstack_t *label_stack;

        /*SRv6 Stack*/
        Srv6_endpcode_t endfn;
        uint8_t n_segment_list;
        rtm_prefix_t *v6segment_lst;

        uint32_t ref_count;
} rtm_nh; 

#pragma pack(pop)

GLTHREAD_TO_STRUCT(resolution_list_glue_to_rtm_nh, rtm_nh, resolution_list_glue);
GLTHREAD_TO_STRUCT(route_glue_to_rtm_nh, rtm_nh, route_glue);

/* Methods */
int8_t rtm_nh_is_equal(rtm_nh *nh1, rtm_nh *nh2);
int8_t rtm_nh_compare (rtm_nh *nh1, rtm_nh *nh2);
int8_t rtm_nh_compare_by_idx (rtm_nh *nh1, rtm_nh *nh2);
int8_t rtm_nh_forwarding_info_compare (rtm_nh *nh1, rtm_nh *nh2);
void rtm_nh_initialize(rtm_nh *nh);
void rtm_nh_reference(rtm_nh *nh);
void rtm_nh_dereference(rtm_t *rtm, rtm_nh *nh);
void rtm_nh_set_active(rtm_t *rtm, rtm_nh *nh);
void rtm_nh_set_inactive(rtm_t *rtm, rtm_nh *nh);

#define RTM_NH_LOCK(nh_ptr)  rtm_nh_reference(nh_ptr)
#define RTM_NH_UNLOCK(rtm, nh_ptr) rtm_nh_dereference(rtm, nh_ptr)

#endif 
