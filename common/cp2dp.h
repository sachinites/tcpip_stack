#ifndef __CP2DP__
#define __CP2DP__

#include <stdint.h>

typedef struct node_ node_t;
typedef struct pkt_block_ pkt_block_t; 
typedef struct mac_table_entry_ mac_table_entry_t; 

#include "../Interface/InterfaceFwd.h"
#include "../Layer3/ipv6/ipv6_hdrs.h"
#include "../Layer3/SegmentRouting/SRv6/dp/srv6-endpoint.h"
#include "../Layer3/mpls_enums.h"
#include "../Layer3/mpls_fwd.h"

#define CP2DP_MSG_SIZE_MAX  512

/* Route update msg to RTM*/
typedef struct rt_update_msg_ {

    uint32_t prefix;
    uint32_t gateway;
    uint32_t ifindex;
    uint32_t metric;
    uint16_t proto_id;
    uint8_t   mask;
    char padding[3];

} rt_update_msg_t;

typedef struct rt6_update_msg_ {

    uint8_t prefix[16];
    uint8_t gateway[16];
    uint32_t ifindex;
    uint32_t metric;
    uint16_t proto_id;
    uint16_t srv6_end_fn;
    uint8_t   prefix_len;
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
    label_val_t in_label;     /* Encoded label value */
    uint32_t ifindex;
    uint32_t gw_ip;
    uint8_t label_stack_count;
    char padding[3];
    label_t label_stack[MAX_LBL_DEPTH];  /* MAX_LBL_DEPTH = 8, labels are encoded */
} mpls_route_update_msg_t;

/* IPv4 MPLS route update msg to IPV4_MPLS_TABLE*/
typedef struct ipv4_mpls_route_update_msg_ {
    uint32_t prefix;          /* IPv4 prefix */
    uint32_t gw_ip;           /* Gateway IP */
    uint32_t ifindex;         /* Interface index */
    uint8_t mask;             /* Prefix mask */
    uint8_t label_stack_count;
    char padding[2];
    label_t label_stack[MAX_LBL_DEPTH];  /* MAX_LBL_DEPTH = 8, labels are encoded */
} ipv4_mpls_route_update_msg_t;

typedef enum DP_COMPONENT_TYPE_ {

    RT_TABLE_IPV4,
    RT_TABLE_IPV6,
    MAC_TABLE,
    PKT_BLOCK,
    MPLS_TABLE,
    IPV4_MPLS_TABLE

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

/* Wrapper fn to add route to Routing table Asynchronously*/
void
rt_ipv4_route_add (node_t *node,
                                uint32_t prefix,
                                uint8_t mask,
                                uint32_t gw_ip,
                                Interface *oif,
                                uint32_t metric,
                                uint16_t proto_id,
                                bool async) ;

void
rt_ipv4_route_del (node_t *node,
                                uint32_t prefix,
                                uint8_t mask,
                                uint16_t proto_id,
                                bool async) ;

void
ipv6_route_install (node_t *node,
                                ipv6_addr_t *prefix,
                                uint8_t prefix_len,
                                uint8_t rt_flags,
                                ipv6_addr_t *gw,
                                Interface* oif,
                                ipv6_addr_t (*segment_lst)[16],
                                uint32_t spf_metric,
                                Srv6_endpcode_t endfn,
                                uint16_t proto_id);

void
ipv6_route_uninstall (node_t *node,
                                    ipv6_addr_t *prefix,
                                    uint8_t prefix_len,
                                    ipv6_addr_t *gw,
                                    Interface* oif,
                                    uint16_t proto_id);

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

/* MPLS Route APIs */
void
cp2dp_mpls_route_install (node_t *node,
                         label_val_t in_label,
                         c_string gw_ip,
                         uint32_t ifindex,
                         label_val_t (*label_stack)[MAX_LBL_DEPTH],
                         uint8_t label_stack_count);

void
cp2dp_mpls_route_delete (node_t *node, label_val_t in_label);

void
cp2dp_mpls_nexthop_delete (node_t *node,
                           label_val_t in_label,
                           c_string gw_ip,
                           uint32_t ifindex,
                           label_val_t (*label_stack)[MAX_LBL_DEPTH],
                           uint8_t label_stack_count);

/* IPv4 MPLS Route APIs */
void
cp2dp_ipv4_mpls_route_install (node_t *node,
                               c_string prefix,
                               uint8_t mask,
                               c_string gw_ip,
                               uint32_t ifindex,
                               label_val_t (*label_stack)[MAX_LBL_DEPTH],
                               uint8_t label_stack_count);

void
cp2dp_ipv4_mpls_route_delete (node_t *node,
                              c_string prefix,
                              uint8_t mask);

void
cp2dp_ipv4_mpls_nexthop_delete (node_t *node,
                                c_string prefix,
                                uint8_t mask,
                                c_string gw_ip,
                                uint32_t ifindex,
                                label_val_t (*label_stack)[MAX_LBL_DEPTH],
                                uint8_t label_stack_count);

#endif 
