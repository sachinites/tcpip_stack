/*
 * =============================================================================
 * File: dp_utils.h
 * Description: Datapath utility APIs (e.g. subnet / interface lookup).
 * =============================================================================
 *
 * Design:
 *   - Provides helpers used across DP and CP for interface selection and
 *     address handling.
 *   - dp_intf_get_matching_subnet_interface: returns the local interface
 *     whose configured subnet contains the given IPv4 address (used e.g. for
 *     ARP and next-hop resolution).
 * =============================================================================
 */

#ifndef __DP_UTILS__
#define __DP_UTILS__

typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_intf_ dp_intf_t;

#include <stdint.h>
#include <cstddef>

#include "../tcpconst.h"
#include "../libs/LinuxMemoryManager/uapi_mm.h"

#include "Interface/dp_intf.h"

/**
 * Payload for recv/send path: packet pointer, interface index, and size.
 * Used when passing packets into the datapath event dispatcher.
 */
typedef struct ev_dis_pkt_data_ {

    unsigned char *pkt;
    uint32_t ifindex;
    uint32_t pkt_size;

} ev_dis_pkt_data_t;

/**
 * dp_intf_get_matching_subnet_interface - Find interface whose subnet contains ip_addr
 * @dp_ctx:   Datapath context
 * @vrf:     VRF to search
 * @ip_addr: IPv4 address (host byte order)
 *
 * Uses FIB to resolve a connected/local route for ip_addr; if found, returns
 * the outgoing interface for that route. Returns NULL if no matching subnet.
 */
dp_intf_t *
dp_intf_get_matching_subnet_interface(dp_ctx_t *dp_ctx,
                                      dp_vrf_t *vrf,
                                      uint32_t ip_addr);

static inline uint16_t 
dp_intf_get_dpdk_port_id (dp_intf_t *dp_intf) {

    return dp_intf->port_id - 1;
}

/* Wrapper Function for Data path to allocate memory buffers for packets */
struct rte_mbuf *
dp_pkt_mbuf_copy_and_wrap_raw_pkt_copy (dp_ctx_t *dp_ctx, uint8_t *pkt, uint16_t pkt_size);

struct rte_mbuf *
dp_pkt_mbuf_get_new (dp_ctx_t *dp_ctx, uint16_t pkt_size);

#endif /* __DP_UTILS__ */
