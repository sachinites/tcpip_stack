#ifndef __CP2DP__
#define __CP2DP__

#include <stdint.h>

typedef struct node_ node_t;
typedef struct pkt_block_ pkt_block_t; 

#include "../Interface/InterfaceFwd.h"
#include "../Layer3/ipv6/ipv6_hdrs.h"
#include "../Layer3/SegmentRouting/SRv6/dp/srv6-endpoint.h"

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

typedef enum DP_COMPONENT_TYPE_ {

    RT_TABLE_IPV4,
    RT_TABLE_IPV6,
    PKT_BLOCK

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

#endif 
