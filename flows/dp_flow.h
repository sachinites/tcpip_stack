#ifndef __DP_FLOW__
#define __DP_FLOW__

#include <stdint.h>
#include <atomic>
#include "../FIB/fib_nh.h"

struct rte_mbuf;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_intf_ dp_intf_t;

#pragma pack(push, 1)
typedef struct flow_key_ {

    uint32_t ifindex;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t src_ip;
    uint32_t dst_ip;    
    uint16_t vrf_id;
    uint8_t ip_protocol;
    uint8_t flags;

} flow_key_t;
#pragma pack(pop)

typedef struct flow_data_ {

    alignas(8) uint8_t nexthop_mac[6];
    alignas(8) fib_nh_t nh;

} flow_data_t;

typedef enum dp_flow_state_ {

    /* This flow is no more valid for some reason, do not honor it for forwarding */
    DP_FLOW_STATE_INVALID,
    /* DP has sent the flow creation request to DP Flow Mgr, response pending */
    DP_FLOW_STATE_PENDING,
    /* This flow is active and ready to be forwarded */
    DP_FLOW_STATE_ACTIVE,

    DP_FLOW_STATE_MAX
} dp_flow_state_t;

typedef struct dp_flow_ {

     alignas(8) flow_key_t flow_key;
     alignas(8) flow_data_t fdata;
     alignas(8) std::atomic<dp_flow_state_t> state;

} dp_flow_t;

void
dp_intf_send_flow_creation_request(dp_ctx_t *dp_ctx, 
                                   dp_intf_t *intf, 
                                   struct rte_mbuf *mbuf);

#endif 