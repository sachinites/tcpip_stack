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
#include <atomic>
#include "../../tcp_ip_trace.h"
#include "intf_cons.h"
#include "../../libs/common/cmn_struct.h"

typedef struct rte_mbuf pkt_mbuf_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct node_ node_t;
typedef struct bitmap_ bitmap_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct mtrie_ mtrie_t;
typedef struct trap_rule_ trap_rule_t;
typedef struct mac_table_ mac_table_t;

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
    std::atomic<mtrie_t *> l3_acl_ingress;
    std::atomic<mtrie_t *> l3_acl_egress;

    /* L2 Properties */
    mac_addr_t mac_add;
    bool switchport;
    std::atomic<mtrie_t *> l2_acl_ingress;
    std::atomic<mtrie_t *> l2_acl_egress;

    /* Pointer to parent vlan if this interface is switchport
        in access mode , 
        if this is VFIF interface, this field is temporarily used to 
        cache vlan interface     
    */
    struct dp_intf_ *vlan_intf;

    /* If this is a physical interface under AC, then this is the
        pointer to owning AC */
    struct dp_intf_ *ac_intf;

    /* Attachment Circuit */
    struct dp_intf_ *bd_intf;       /* Pointer to parent BD  */
    uint16_t encap_8021q_tag;
    mpls_lstack_t *lbl_stack;       /* If this AC is MPLS tunnel bridging domains */
    struct dp_intf_ *underlying_intf;


    /* If this interface is vlan interface, then vlan id */
    uint16_t vlan_id;
    uint32_t vni_id;
    DP_IntfL2Mode l2_mode;

    /* If it is a vlan interface, then array of member ports*/
    /* If it is a BD interface, then array of AC member ports */
    struct dp_intf_ *mports[MAX_VLAN_MEMBER_PORTS];

    /* if this is BD interface, then below interface is used to
    steer traffic from Default VRF LFIB into this BD */
    struct dp_intf_ *l2vpn_evpn_steering_intf;

    /* If it is a switchport operating in a trunk node, then
        bitmap of vlans of sizeof 4096 (512B) which it is a member of.
    */
    bitmap_t *vlan_bitmap;

    /* Physical Properties */
    bool is_up;

    /* If this is GRE tunnel intf, then its dest ip and virtual port*/
    uint32_t gre_tunnel_src_ip;
    uint32_t gre_tunnel_dst_ip;
    bool is_tunnel_up;
    struct dp_intf_ *virtual_port;

    /* If this is Virtual port, then overlay tunnel interface */
    struct dp_intf_ *olay_tunnel_intf;

    /* Id this is SRv6 interface, then this is SRv6 data.*/
    union {

        dp_vrf_t *steered_dt4_vrf; 

    } srv6_data;

    /* If this is vpnv4 steering interface */
    dp_vrf_t *steered_vpnv4_vrf; 

    /* If this is L3VPN EVPN Xconnect intf, then steer the 
    traffic into Cust-VRF*/
    dp_vrf_t *steered_l3vpn_evpn_vrf;
    
    /* If this is L2VPN EVPN Xconnect intf, then steer the 
    traffic into BD */
    uint32_t bd_intf_ifindex;

    /* If it is a BD interface, then it owns a mac table */
    mac_table_t *mac_table;

    /* Logging */
    log_t log_info;

    int LinuxRtr_sockfd;
    uint16_t dpdk_max_rx_queues;
    uint16_t dpdk_max_tx_queues;
    uint32_t dpdk_tx_queue_lb;
    
    trap_rule_t* trap_rule_table[PROTO_IDX_MAX];

    /* Wire connection Simulation */
    dp_ctx_t *dp_ctx;
    struct dp_intf_ *nbr_intf;

} dp_intf_t;

#pragma pack(pop)

void
dp_send_pkt_out(dp_ctx_t *dp_ctx, 
                dp_intf_t *intf, 
                struct rte_mbuf *mbuf, 
                dp_intf_t *pintf); // Today represent as vlan intf/BD intf if 'intf' 
                                   // is vfif, in all other cases NULL

#endif /* __DP_INTF__ */