/*
 * =============================================================================
 * File: dp_intf.h
 * Description: Datapath interface (dp_intf_t) - per-interface forwarding state.
 * =============================================================================
 *
 * Design:
 *   - One dp_intf_t per logical interface in the datapath (physical, VLAN,
 *     GRE, loopback, virtual, etc.). Mirrors control-plane interface config.
 *   - Holds identifiers (port_id, if_type, if_name), L3 (vrf, IPv4/IPv6, mask),
 *     L2 (MAC, switchport, vlan_intf, vlan_id, vni_id, l2_mode, mports,
 *     vlan_bitmap), tunnel (gre_tunnel_dst_ip, virtual_port, olay_tunnel_intf),
 *     stats, logging, and dp_ctx/nbr_intf for topology.
 * =============================================================================
 */

#ifndef __DP_INTF__
#define __DP_INTF__

#include <stdint.h>
#include "../../tcp_ip_trace.h"
#include "intf_cons.h"
#include "../../common/cmn_struct.h"

typedef struct pkt_block_ pkt_block_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct node_ node_t;
typedef struct bitmap_ bitmap_t;
typedef struct dp_ctx_ dp_ctx_t;

#pragma pack(push, 8)

typedef struct dp_intf_ {

    /* Identifiers */
    uint32_t port_id;
    DP_InterfaceType_t if_type;
    char if_name[DP_INTF_NAME];

    /* Stats */
    uint32_t pkt_recv;
    uint32_t pkt_sent;
    uint32_t xmit_pkt_dropped;
    uint32_t recvd_pkt_dropped;

    /* L3 properties */
    dp_vrf_t *vrf;
    uint8_t v6addr_link_local[16];
    uint8_t v6addr[16];
    uint8_t v6mask;
    uint32_t ip_addr;
    uint8_t mask;

    /* L2 Properties */
    mac_addr_t mac_add;
    bool switchport;

    /* Pointer to parent vlan if this interface is switchport
        in access mode */
    struct dp_intf_ *vlan_intf;

    /* If this interface is vlan interface, then vlan id */
    uint16_t vlan_id;
    uint32_t vni_id;
    DP_IntfL2Mode l2_mode;

    /* If it is a vlan interface, then array of member ports*/
    struct dp_intf_ *mports[MAX_VLAN_MEMBER_PORTS];

    /* If it is a switchport operating in a trunk node, then
        bitmap of vlans of sizeof 4096 (512B) which it is a member of.
    */
    bitmap_t *vlan_bitmap;

    /* Physical Properties */
    bool is_up;

    /* If this is GRE tunnel intf, then its dest ip and virtual port*/
    uint32_t gre_tunnel_dst_ip;
    struct dp_intf_ *virtual_port;

    bool is_tunnel_up;

    /* If this is Virtual port, then overlay tunnel interface */
    struct dp_intf_ *olay_tunnel_intf;

    /* Id this is SRv6 interface, then this is SRv6 data.*/
    union {

        dp_vrf_t *steered_dt4_vrf; 

    } srv6_data;

    /* Logging */
    log_t log_info;

    /* Wire connection Simulation */
    dp_ctx_t *dp_ctx;
    struct dp_intf_ *nbr_intf;

} dp_intf_t;

#pragma pack(pop)

void
dp_send_pkt_out(dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block);

#endif /* __DP_INTF__ */