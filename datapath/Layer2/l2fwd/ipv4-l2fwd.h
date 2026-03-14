/*
 * =============================================================================
 * File: ipv4-l2fwd.h
 * Description: IPv4 L2 forwarding helpers - VLAN tag/untag, SVI ARP, promote to L2.
 * =============================================================================
 *
 * Design:
 *   - tag_pkt_with_vlan_id / untag_pkt_with_vlan_id: 802.1Q tag handling.
 *   - svi_interface_intercept_arp_pkt: true if packet is subject to inter-VLAN routing.
 *   - is_arp_pkt_for_svi_interface: true if ARP is for an SVI (VLAN interface).
 *   - promote_pkt_to_layer2: push packet into L2 path (VRF, iif).
 *   - l2_frame_recv_qualify_on_interface: qualify L2 frame on interface, optional output vlan.
 * =============================================================================
 */

#ifndef __IPV4_L2FWD__
#define __IPV4_L2FWD__

#include <stdint.h>
#include <stdbool.h>

typedef struct pkt_block_ pkt_block_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_intf_ dp_intf_t;

void untag_pkt_with_vlan_id(pkt_block_t *pkt_block);
void tag_pkt_with_vlan_id (pkt_block_t *pkt_block, int vlan_id );

/* Return TRUE if the pkt is subjected to inter-vlan routing*/
bool
svi_interface_intercept_arp_pkt (dp_ctx_t *dp_ctx,
                        dp_vrf_t *vrf,
                        pkt_block_t *pkt_block);

bool 
is_arp_pkt_for_svi_interface (dp_ctx_t *dp_ctx, dp_vrf_t *vrf,
                              pkt_block_t *pkt_block);

void
promote_pkt_to_layer2(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      dp_intf_t *iif, 
                      pkt_block_t *pkt_block);

bool 
l2_frame_recv_qualify_on_interface(dp_ctx_t *dp_ctx,
                                   dp_vrf_t *vrf,
                                   dp_intf_t *interface, 
                                   pkt_block_t *pkt_block,
                                   uint16_t *output_vlan_id);

#endif /* __IPV4_L2FWD__ */
