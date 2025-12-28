#ifndef __RTM_INTEG__
#define __RTM_INTEG__

#include <stdint.h>
#include "rtm_enums.h"
#include "rtm_error.h"
#include "../common/mpls_lstack.h"
#include "../common/cmn_prefix.h"
#include "../Layer3/SegmentRouting/SRv6/common/srv6_const.h"
#include "../vrf/vrf.h"

typedef struct node_ node_t;
typedef struct rtm_ rtm_t;
class Interface;
typedef struct rtm_nh_proto_ rtm_nh_proto_t;
typedef struct rtm_rt_subscription_ rtm_rt_subscription_t;
typedef struct mpls_lstack_ mpls_lstack_t;

#pragma pack(push, 8)

typedef struct cp_nexthop_template_ {

    uint32_t idx;
    
    RTM_PROTO_T proto;
    RTM_SUB_PROTO_T sub_proto;

    rtm_nh_proto_t *rtm_nh_proto;
    
    uint16_t fwd_flags;

    uint32_t metric;

    RTM_NH_ACTION_TYPE_T action;

    cmn_prefix_t gateway;
    uint32_t oif;
    bool is_indirect;
    bool is_resolved;

    /* If this is L3 VPN BGP INH, then it should have vpn service label also */
    mpls_label_val_t l3_vpn_label;
    rt_t import_rt;

    union {

        struct {

            mpls_lstack_t *label_stack;

        } l_stack;

        struct {
            
            Srv6_endpcode_t endfn;
            uint8_t n_segment_list;
            cmn_prefix_t *v6segment_lst;

        } srv6_stack;

    }u;

} cp_nexthop_template_t;

#pragma pack(pop)

void node_init_default_rtm(node_t *node);
rtm_t *rtm_get(node_t *node, uint8_t vrf, AFI_T afi, uint8_t rtm_id);

/* APIs to install/uninstall local/connected routes */
uint32_t cp_rtm_install_local_or_connected_v4_routes ( 
        rtm_t *rtm, uint32_t ip_addr, uint8_t mask, InterfaceP Oif);

/* APIs to install/uninstall static routes */
uint32_t
cp_rtm_install_static_route (
        rtm_t *rtm,
        cmn_prefix_t *prefix, 
        cmn_prefix_t *gateway,
        InterfaceP oif, uint32_t cost);

rtm_error_t
cp_rtm_uninstall_static_route (
                rtm_t *rtm,
                cmn_prefix_t *prefix, 
                cmn_prefix_t *gateway,
                InterfaceP oif, uint32_t cost);

/* Generic API to install/uninstall routes */
rtm_error_t 
cp_rtm_install_route ( rtm_t *rtm, cmn_prefix_t *route, cp_nexthop_template_t *nh_template);

rtm_error_t 
cp_rtm_uninstall_route_by_idx ( rtm_t *rtm,  uint32_t idx) ;

rtm_error_t 
cp_rtm_uninstall_route ( rtm_t *rtm, cmn_prefix_t *route, cp_nexthop_template_t *nh_template);

uint32_t
cp_rtm_uninstall_route_by_proto ( rtm_t *rtm, cmn_prefix_t *route,  RTM_PROTO_T proto, RTM_SUB_PROTO_T sub_proto);

uint32_t
cp_rtm_uninstall_routes_by_proto ( rtm_t *rtm, RTM_PROTO_T proto, RTM_SUB_PROTO_T sub_proto);

/* Advanced API for complete route configuration */
#if 0
# Basic route
config node H1 rtm-route prefix 10.0.0.0/24 0 0 0 2 10 gateway 192.168.0.12 interface eth1
config node H1 rtm-route prefix 2001::/120 0 0 0 2 10 gateway 2002::1 interface eth1

# Route with MPLS labels
config node H1 rtm-route prefix 100100 0 0 0 2 10 gateway 192.168.0.12 interface eth1 label-stack 100 200 300

RTM_PROTO_ISIS
RTM_PROTO_L1_ISIS_INT
instance 0
action : forward 
cost : 10 
config node H1 rtm-route prefix 11.0.0.0/24 4 2 0 2 10 gateway 192.168.0.12 interface eth1 label-stack 100 200 300
OSPF:
config node H1 rtm-route prefix 11.0.0.0/24 5 10 0 2 10 gateway 192.168.0.12 interface eth1

BGP :
config node H1 rtm-route prefix 10.0.0.0/24 0 0 0 2 10 gateway 192.168.0.12 interface eth1
config node H1 rtm-route prefix 20.0.0.0/16 0 0 0 2 10 gateway 192.168.0.13 interface eth1
config node H1 rtm-route prefix 122.1.1.0/24 3 6 0 2 10 gateway 10.0.0.1
config node H1 rtm-route prefix 123.1.1.0/24 3 6 0 2 10 gateway 122.1.1.2


#endif

rtm_error_t
cp_rtm_install_route_advanced (
    rtm_t *rtm,
    cmn_prefix_t *prefix,
    RTM_PROTO_T proto,
    RTM_SUB_PROTO_T sub_proto,
    uint32_t instance_no,
    RTM_NH_ACTION_TYPE_T action,
    uint32_t metric,
    cmn_prefix_t *gateway,
    InterfaceP oif,
    uint32_t *label_stack,
    uint8_t label_stack_count,
    mpls_label_val_t l3_vpn_label);

rtm_error_t
cp_rtm_uninstall_route_advanced (
    rtm_t *rtm,
    cmn_prefix_t *prefix,
    RTM_PROTO_T proto,
    RTM_SUB_PROTO_T sub_proto,
    uint32_t instance_no,
    RTM_NH_ACTION_TYPE_T action,
    uint32_t metric,
    cmn_prefix_t *gateway,
    InterfaceP oif,
    uint32_t *label_stack,
    uint8_t label_stack_count,
    mpls_label_val_t l3_vpn_label);


/* Protocol Subscribing to RTM */
bool
cp_rtm_protocol_register (rtm_t *rtm, RTM_PROTO_T proto, uint32_t instance_no, uint8_t vrf_id);

bool
cp_rtm_protocol_unregister (rtm_t *rtm, RTM_PROTO_T proto, uint32_t instance_no, uint8_t vrf_id);

rtm_error_t
cp_rtm_subscribe(rtm_t *rtm, 
                            uint8_t src_vrf, uint8_t src_instance_no, RTM_PROTO_T src_proto, 
                            rtm_rt_subscription_t *sub_template) ;

rtm_error_t 
cp_rtm_unsubscribe (rtm_t *rtm, rtm_rt_subscription_t *sub_template);

rtm_t *
cp_rtm_get_route_target_rtm( node_t *node, 
                          vrf_t *vrf, AFI_T afi,  // NULL if default VRF
                          RTM_PROTO_T proto, 
                          RTM_SUB_PROTO_T sub_proto);


#endif 
