#ifndef __CP2DP__
#define __CP2DP__

#include <stdint.h>

typedef struct node_ node_t;
typedef struct pkt_block_ pkt_block_t; 
typedef struct mac_table_entry_ mac_table_entry_t; 
typedef struct rtm_nh_fwd_info_ rtm_nh_fwd_info_t;

#include "cmn_prefix.h"
#include "../Interface/InterfaceFwd.h"
#include "../Layer3/ipv6/ipv6_hdrs.h"
#include "../Layer3/SegmentRouting/SRv6/dp/srv6-endpoint.h"
#include "../Layer3/mpls_enums.h"
#include "../Layer3/mpls_fwd.h"
#include "../RTM/rtm_fib_common.h"
#include "../RTM/rtm_nh.h"
#include "../FIB/fib_nh.h"
#include "../datapath/Vrfs/dp_vrf.h"

#define CP2DP_MSG_SIZE_MAX  2048

/* Route update msg to RTM*/
typedef struct rt_update_msg_ {

    uint32_t prefix;
    uint32_t gateway;
    uint32_t ifindex;
    uint32_t metric;
    uint16_t proto_id;
    uint8_t  mask;
    char padding[3];

} rt_update_msg_t;

#pragma pack(push, 1)
typedef struct fib_update_msg_ {

    /* Target FIB VRF ID*/
    uint8_t target_fib_vrf_id;
    /* Target fib AFI*/
    uint8_t target_fib_afi;
    /* Route : ipv4/ipv6/mpls */
    cmn_prefix_t prefix;
    /* Forwarding flags for the nexthop*/
    uint16_t fwd_flags;
    /* Nexthop ID*/
    uint32_t nhidx;
    /* INH ID*/
    uint32_t inhidx;
    /* Forwarding info */
    rtm_nh_fwd_info_t fwd_info;

} fib_update_msg_t;
#pragma pack(pop)

typedef struct rt6_update_msg_ {

    uint8_t prefix[16];
    uint8_t gateway[16];
    uint32_t ifindex;
    uint32_t metric;
    uint16_t proto_id;
    uint16_t srv6_end_fn;
    uint8_t  prefix_len;
    uint8_t rt_flags;
    uint8_t seg_lst_count;
    uint8_t seglst[0][16];

} rt6_update_msg_t;

/* MAC table update msg to MAC_TABLE*/
typedef struct mac_update_msg_ {

    uint8_t mac_addr[6];
    uint16_t vlan_id;
    uint32_t ifindex;
    uint16_t flags;
    uint32_t remote_dst_ip;
    char padding[2];

} mac_update_msg_t;

/* MPLS route update msg to MPLS_TABLE*/
typedef struct mpls_route_update_msg_ {

    mpls_label_val_t in_label;     /* Encoded label value */
    uint32_t ifindex;
    uint32_t gw_ip;
    uint8_t label_stack_count;
    char padding[3];
    mpls_label_t label_stack[MAX_LBL_DEPTH];  /* MAX_LBL_DEPTH = 8, labels are encoded */

} mpls_route_update_msg_t;

/* IPv4 MPLS route update msg to IPV4_MPLS_TABLE*/
typedef struct ipv4_mpls_route_update_msg_ {

    uint32_t prefix;          /* IPv4 prefix */
    uint32_t gw_ip;           /* Gateway IP */
    uint32_t ifindex;         /* Interface index */
    uint8_t mask;             /* Prefix mask */
    uint8_t label_stack_count;
    char padding[2];
    mpls_label_t label_stack[MAX_LBL_DEPTH];  /* MAX_LBL_DEPTH = 8, labels are encoded */

} ipv4_mpls_route_update_msg_t;

typedef enum DP_COMPONENT_TYPE_ {

    MAC_TABLE,
    PKT_BLOCK,
    FIB_TABLE,
    INTF_TABLE,
    VRF_TABLE

} DP_COMPONENT_TYPE_T;

typedef enum DP_OPR_TYPE_ {

    DP_CREATE,
    DP_DEL,
    DP_UPDATE,
    DP_READ,
    DP_L3_NORTHBOUND_IN
    
} DP_OPR_TYPE_T;

typedef struct dp_msg_ {

    uint8_t data[CP2DP_MSG_SIZE_MAX];
    DP_COMPONENT_TYPE_T component_type;
    DP_OPR_TYPE_T opr_type;
    uint32_t data_size;
    uint16_t flags;
    char padding[2];

    dp_msg_ () {
        memset (data, 0, CP2DP_MSG_SIZE_MAX);
        component_type = (DP_COMPONENT_TYPE_T)0;
        opr_type = (DP_OPR_TYPE_T )0;
        data_size = 0;
        flags = 0;
    }
    
} dp_msg_t;

void 
cp2dp_submit (node_t *node, dp_msg_t *dp_msg, bool async);

dp_msg_t *
cp2dp_msg_alloc ();

void
cp2dp_msg_free (dp_msg_t *dp_msg);

void
cp2dp_xmit_pkt (node_t *node, pkt_block_t *pkt_block, Interface *xmit_interface) ;

void 
cp2dp_send_ip_data ( node_t *node, 
                                    pkt_block_t *pkt_block,
                                    uint32_t dest_ip_addr,
                                    uint16_t std_ip_protocol) ;

void 
cp2dp_send_ip6_data ( node_t *node, 
                                    pkt_block_t *pkt_block,
                                    ipv6_addr_t dest_ip_addr,
                                    uint16_t std_ip_protocol) ;

/* Wrapper fn to add MAC entry to MAC table Asynchronously*/
void
cp2dp_mac_table_entry_add (node_t *node,
                      uint8_t *mac_addr,
                      uint16_t vlan_id,
                      uint32_t ifindex,
                      uint16_t flags,
                      bool async,
                      uint32_t remote_dst_ip = 0);

void
cp2dp_mac_table_entry_del (node_t *node,
                      uint8_t *mac_addr,
                      uint16_t vlan_id,
                      uint32_t ifindex,
                      bool async, uint32_t remote_dst_ip);

void
cp2dp_fib_update (
                node_t *node,
                uint8_t target_fib_vrf_id,
                AFI_T target_fib_afi,
                cmn_prefix_t *prefix,
                uint32_t nh_idx,
                uint32_t inh_idx,
                rtm_nh_fwd_info_t *fwd_info,
                FIB_OPN_T operation) ;

void 
cp2dp_vrf_create (node_t *node, char *vrf_name, uint8_t vrf_id);

void 
cp2dp_vrf_delete (node_t *node, uint8_t vrf_id);

void 
cp2dp_vrf_delete_interface (node_t *node, uint8_t vrf_id, uint32_t ifindex);

void 
cp2dp_vrf_add_interface (node_t *node, uint8_t vrf_id, uint32_t ifindex);

#endif 
