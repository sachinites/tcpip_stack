#ifndef __CP2DP__
#define __CP2DP__

#include <stdint.h>

typedef struct node_ node_t;
class Interface;
typedef struct pkt_block_ pkt_block_t; 

/* Route update msg to RTM*/
typedef struct rt_update_msg_ {

    uint32_t prefix;
    uint8_t   mask;
    uint32_t gateway;
    Interface *oif;
    uint32_t metric;
    uint16_t proto_id;

} rt_update_msg_t;

typedef enum DP_COMPONENT_TYPE_ {

    RT_TABLE_IPV4,
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

    DP_COMPONENT_TYPE_T component_type;
    DP_OPR_TYPE_T opr_type;
    uint16_t flags;
    uint32_t data_size;
    uint8_t data[0];

} dp_msg_t;

void 
cp2dp_submit (node_t *node, dp_msg_t *dp_msg, bool async);

dp_msg_t *
cp2dp_msg_alloc (node_t *node, uint32_t data_size);

void
cp2dp_msg_free (node_t *node, dp_msg_t *dp_msg);

void
cp2dp_xmit_pkt (node_t *node, pkt_block_t *pkt_block, Interface *xmit_interface) ;

void 
cp2dp_send_ip_data ( node_t *node, 
                                    pkt_block_t *pkt_block,
                                    uint32_t dest_ip_addr,
                                    uint16_t std_ip_protocol) ;

#endif 