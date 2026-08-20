/*
 * =============================================================================
 * File: dp_utils.c
 * Description: Implementation of datapath utility functions.
 * =============================================================================
 *
 * Design:
 *   - dp_intf_get_matching_subnet_interface() uses the VRF FIB to find a
 *     connected or local route for the given IPv4 address and returns the
 *     corresponding egress interface. Used by ARP and other code that needs
 *     "which local interface is in the same subnet as this IP?"
 * =============================================================================
 */

#include "dp_utils.h"
#include "Vrfs/dp_vrf.h"
#include "FIB/fib_nh.h"
#include "dp_ctx.h"
#include "dp_uapi.h"
#include "../libs/pkt-block/pkt_mbuf.h"

struct rte_mempool;

/**
 * Returns the local interface whose configured subnet contains @ip_addr.
 * Uses FIB lookup; only connected/local routes are considered.
 */
dp_intf_t *
dp_intf_get_matching_subnet_interface(dp_ctx_t *dp_ctx,
                                      dp_vrf_t *vrf,
                                      uint32_t ip_addr)
{
    uint8_t mask;
    dp_intf_t *intf;
    cmn_prefix_t prefix;

    cmn_prefix_initialize_v4(&prefix, ip_addr, 32);

    fib_nh_t *nh = fib_get_forwarding_nh(vrf->fib_inet0, &prefix);

    if (!nh) {
        return NULL;
    }

    /* Only accept directly connected or local routes */
    if (nh->fwd_info->fwd_flags &
        (FIB_NH_FWD_F_CONNECTED | FIB_NH_FWD_F_LOCAL)) {
        return nh->fwd_info->oif;
    }

    return NULL;
}

struct rte_mbuf *
dp_pkt_mbuf_copy_and_wrap_raw_pkt_copy (
        dp_ctx_t *dp_ctx, 
        uint8_t *pkt, 
        uint16_t pkt_size) {

    /* Get the mempool on this socket*/
    struct rte_mempool *mpool = dp_uapi_get_current_socket_mpool(dp_ctx);
    return PKT_MBUF_WRAP(mpool, pkt, (pkt_size_t)pkt_size);
}

struct rte_mbuf *
dp_pkt_mbuf_get_new (dp_ctx_t *dp_ctx, uint16_t pkt_size) {

    /* Get the mempool on this socket*/
    struct rte_mempool *mpool = dp_uapi_get_current_socket_mpool(dp_ctx);
    return  PKT_MBUF_GET_NEW(mpool, (pkt_size_t)pkt_size);
}

bool 
dp_is_eligble_l2_port (DP_InterfaceType_t iftype) {

    if (iftype == DP_INTF_TYPE_PHY || 
        iftype == DP_INTF_TYPE_AC) {

        return true;
    }

    return false;
}

dp_intf_t *
pkt_mbuf_get_ingress_intf(dp_ctx_t *dp_ctx, struct rte_mbuf *mbuf)
{
    uint32_t ifindex = pkt_mbuf_get_ingress_ifindex(mbuf);

    if (!dp_ctx || !ifindex || ifindex >= DP_MAX_INTF)
        return NULL;
    return dp_ctx->intf_table[ifindex];
}

void
pkt_mbuf_set_ingress_intf(struct rte_mbuf *mbuf, dp_intf_t *intf)
{
    pkt_mbuf_set_ingress_ifindex(mbuf, intf ? intf->port_id : 0);
}