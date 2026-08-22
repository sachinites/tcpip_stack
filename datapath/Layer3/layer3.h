/*
 * =============================================================================
 * File: layer3.h
 * Description: Datapath Layer 3 entry points - promote to L3, route IPv4/IPv6, send.
 * =============================================================================
 *
 * Design:
 *   - dp_promote_pkt_to_layer3: hand off L3 payload to L3 by protocol number.
 *   - layer3_ip_route_pkt / layer3_ipv6_route_pkt: route IPv4/IPv6 packet in VRF.
 *   - dp_send_ip_data / dp_send_ip6_data: send IP/IPv6 packet (FIB lookup, next-hop).
 * =============================================================================
 */

#ifndef __LAYER3__
#define __LAYER3__

#include <stdint.h>
#include <stdbool.h>

typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct rte_mbuf pkt_mbuf_t;
typedef struct fib_nh_ fib_nh_t;
typedef struct mpls_lstack_ mpls_lstack_t;

void
dp_promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,               /*Current node on which the pkt is received*/
                      dp_intf_t *interface,        /*ingress interface*/
                      struct rte_mbuf *mbuf);      /*L3 payload*/


void layer3_ip_route_pkt(dp_ctx_t *dp_ctx,
                         dp_vrf_t *vrf,
                         dp_intf_t *interface,
                         struct rte_mbuf *mbuf);


void layer3_ipv6_route_pkt(dp_ctx_t *dp_ctx, 
                           dp_vrf_t *vrf,
                           dp_intf_t *interface,
                           struct rte_mbuf *mbuf,
                           fib_nh_t *nh);

void
dp_send_ip_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, struct rte_mbuf *mbuf);

void
dp_send_ip6_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, struct rte_mbuf *mbuf);

void
dp_mpls_fwd_pkt(dp_ctx_t *dp_ctx,
                dp_vrf_t *vrf,
                dp_intf_t *iif,
                struct rte_mbuf *mbuf);

/* Impose/swap/pop the labels in lstack onto mbuf, in stack order
   ( index 0 = innermost/BoS .. curr_index = outermost ). Works whether the
   packet already carries an MPLS header ( transit swap/pop/push ) or is bare
   IP ( first PUSH imposes the label with S-bit set and TTL 255 ).
   Returns true if the packet's top header is still MPLS after applying the
   stack, false if the last label was popped off. */
bool
mpls_apply_nh_label_stack(dp_ctx_t *dp_ctx,
                          struct rte_mbuf *mbuf,
                          mpls_lstack_t *lstack);

#endif /* __LAYER3__ */
