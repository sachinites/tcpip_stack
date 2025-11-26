#ifndef __RTM_PRESENTATION__
#define __RTM_PRESENTATION__

#include "rtm_enums.h"
#include "rtm_common.h"
#include "../Tree/libtree.h"

typedef struct rtm_ rtm_t;
typedef struct rtm_nh_ rtm_nh;
typedef struct prefix_lst_ prefix_list_t;
//typedef struct rtm_nh_proto_ rtm_nh_proto_t;


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
    //rtm_nh_proto_t *nh_proto;

    /* Callback fn used for notif */
    void (*cbk)(rtm_t *, rtm_nh *);

    /* Hook up in rtm_proto_info_t sub_db Tree*/
    avltree_node_t avl_glue;

} rtm_rt_subscription_t;

void 
rtm_presentation_layer_route_add (rtm_t *rtm, rtm_nh *nh);

void rtm_on_demand_route_request (rtm_t *rtm, uint8_t vrf_id, uint8_t instance_no, RTM_PROTO_T proto);

#endif 