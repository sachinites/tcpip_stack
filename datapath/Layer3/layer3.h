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

typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct fib_nh_ fib_nh_t;

void
dp_promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,               /*Current node on which the pkt is received*/
                      dp_intf_t *interface,        /*ingress interface*/
                      pkt_block_t *pkt_block,      /*L3 payload*/
                      int L3_protocol_number) ;


void layer3_ip_route_pkt(dp_ctx_t *dp_ctx,
                         dp_vrf_t *vrf,
                         dp_intf_t *interface,
                         pkt_block_t *pkt_block);


void layer3_ipv6_route_pkt(dp_ctx_t *dp_ctx, 
                           dp_vrf_t *vrf,
                           dp_intf_t *interface,
                           pkt_block_t *pkt_block,
                           fib_nh_t *nh);

void
dp_send_ip_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, pkt_block_t *pkt_block);

void
dp_send_ip6_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, pkt_block_t *pkt_block);

#endif /* __LAYER3__ */
