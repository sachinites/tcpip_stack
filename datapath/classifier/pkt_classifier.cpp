#include <arpa/inet.h>
#include <string.h>

#include "pkt_classifier.h"
#include "../../libs/common/protoIds.h"
#include "../../libs/common/l2_hdrs.h"
#include "../../libs/common/l3_hdrs.h"
#include "../../libs/common/l4_hdrs.h"
#include "../../libs/common/ipv6_hdrs.h"
#include "../../libs/common/cmn_prefix.h"
#include "../../libs/pkt-block/pkt_mbuf.h"
#include "../dp_ctx.h"
#include "cp_trap_fns.h"

#define TRAP_RULE_ID_DEFAULT 0

/*
 * dp_pkt_classify — extract every classifiable field from an mbuf.
 *
 * Parsing order:
 *   L2  →  Ethernet (optional 802.1Q) → EtherType
 *   L3  →  IPv4 / IPv6 / ARP / MPLS
 *   L4  →  TCP / UDP / ICMP / ICMPv6
 *
 * All multi-byte values in headers are in network byte order; we convert
 * them to host byte order when storing in pkt_class_t.
 */
pkt_class_t
dp_pkt_classify(struct rte_mbuf *mbuf)
{
    pkt_class_t cls;
    memset(&cls, 0, sizeof(cls));

    /* ------------------------------------------------------------------ */
    /* L2 — Ethernet                                                        */
    /* ------------------------------------------------------------------ */
    pkt_size_t pkt_size = 0;
    ethernet_hdr_t *eth = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
    if (!eth) return cls;

    /* 802.1Q VLAN tag */
    vlan_8021q_hdr_t *vlan = is_pkt_vlan_tagged(eth);
    uint16_t eth_type;

    if (vlan) {
        cls.vlan_id  = (uint16_t)GET_802_1Q_VLAN_ID(vlan);
        eth_type     = ntohs(((vlan_ethernet_hdr_t *)eth)->type);
    } else {
        cls.vlan_id  = 0;
        eth_type     = ntohs(eth->type);
    }
    cls.eth_proto = eth_type;

    /* L3 payload starts right after the Ethernet (+ optional VLAN) header */
    unsigned char *l3 = GET_ETHERNET_HDR_PAYLOAD(eth);

    /* ------------------------------------------------------------------ */
    /* L3 — dispatch on EtherType                                           */
    /* ------------------------------------------------------------------ */
    switch (eth_type) {

    /* ---- IPv4 ---- */
    case ETH_TYPE_IPv4: {
        ip_hdr_t *ip = (ip_hdr_t *)l3;

        cmn_prefix_initialize_v4(&cls.src_ip, ntohl(ip->src_ip), 32);
        cmn_prefix_initialize_v4(&cls.dst_ip, ntohl(ip->dst_ip), 32);

        uint8_t proto = (uint8_t)ip->protocol;
        cls.ip_proto  = proto;

        unsigned char *l4 = l3 + IP_HDR_LEN_IN_BYTES(ip);

        switch (proto) {
        case IP_PROTO_TCP:
        case IP_PROTO_UDP: {
            /* Both TCP and UDP place src_port / dst_port at the same offsets */
            udp_hdr_t *udp = (udp_hdr_t *)l4;
            cls.src_port   = ntohs(udp->src_port_no);
            cls.dst_port   = ntohs(udp->dst_port_no);

            /* Further sub-classification for known UDP tunnels */
            if (proto == IP_PROTO_UDP) {
                uint16_t dp = cls.dst_port;
                if (dp == PORT_VXLAN || dp == PORT_GENEVE)
                    cls.sub_proto = dp;
            }
            break;
        }
        case IP_PROTO_ICMP:
            /* ICMP: type byte at offset 0 of ICMP header */
            cls.sub_proto = (uint16_t)((uint8_t *)l4)[0];
            break;
        case IP_PROTO_GRE:
        case IP_PROTO_ESP:
        case IP_PROTO_AH:
        case IP_PROTO_OSPF:
        case IP_PROTO_PIM:
        case IP_PROTO_EIGRP:
        case IP_PROTO_IGMP:
        case IP_PROTO_RSVP:
            cls.sub_proto = proto;
            break;
        /* IS-IS over IPv4 (RFC 1195) */
        case IP_PROTO_ISIS:
        case IP_PROTO_ISIS_SRv6:
            cls.sub_proto = (uint16_t)((uint8_t *)l4)[0]; /* IS-IS PDU type */
            break;
        default:
            break;
        }
        break;
    }

    /* ---- IPv6 ---- */
    case ETH_TYPE_IPv6: {
        ipv6_hdr_t *ip6 = (ipv6_hdr_t *)l3;

        /* Store as /128 host addresses */
        cmn_prefix_initialize_v6(&cls.src_ip,
                                  (uint8_t (*)[16])ip6->src_addr, 128);
        cmn_prefix_initialize_v6(&cls.dst_ip,
                                  (uint8_t (*)[16])ip6->dst_addr, 128);

        uint8_t nexthdr = ip6->next_header;
        cls.ipv6_proto  = nexthdr;

        unsigned char *l4 = l3 + sizeof(ipv6_hdr_t);

        switch (nexthdr) {
        case IP_PROTO_TCP:
        case IP_PROTO_UDP: {
            udp_hdr_t *udp = (udp_hdr_t *)l4;
            cls.src_port   = ntohs(udp->src_port_no);
            cls.dst_port   = ntohs(udp->dst_port_no);

            if (nexthdr == IP_PROTO_UDP) {
                uint16_t dp = cls.dst_port;
                if (dp == PORT_VXLAN || dp == PORT_GENEVE)
                    cls.sub_proto = dp;
            }
            break;
        }
        case IP_PROTO_ICMPv6:
            cls.sub_proto = (uint16_t)((uint8_t *)l4)[0];
            break;
        case IP_PROTO_SRH:
            cls.sub_proto = IP_PROTO_SRH;
            break;
        /* IS-IS over IPv6 (RFC 1195 extension) */
        case IP_PROTO_ISIS:
        case IP_PROTO_ISIS_SRv6:
            cls.sub_proto = (uint16_t)((uint8_t *)l4)[0]; /* IS-IS PDU type */
            break;
        default:
            break;
        }
        break;
    }

    /* ---- ARP ---- */
    case ETH_TYPE_ARP: {
        arp_hdr_t *arp  = (arp_hdr_t *)l3;
        uint16_t opcode = ntohs(arp->op_code);

        cmn_prefix_initialize_v4(&cls.src_ip, ntohl(arp->src_ip), 32);
        cmn_prefix_initialize_v4(&cls.dst_ip, ntohl(arp->dst_ip), 32);

        if (opcode == 1)          /* ARP request */
            cls.sub_proto = ARP_BROAD_REQ;
        else if (opcode == 2)     /* ARP reply   */
            cls.sub_proto = ARP_REPLY;
        break;
    }

    /* ---- MPLS unicast / multicast ---- */
    case ETH_TYPE_MPLS_UC:
    case ETH_TYPE_MPLS_MC: {
        /* Read the top MPLS label (first 20 bits of the 4-byte label entry) */
        uint32_t lse = ntohl(*(uint32_t *)l3);
        cls.sub_proto = (uint16_t)((lse >> 12) & 0xFFFFF);   /* label value */
        break;
    }

    /* ---- IS-IS directly over Ethernet (LLC/SNAP, EtherType 0x00FE) ---- */
    case ETH_TYPE_ISIS: {
        /* First byte of the IS-IS payload is the PDU type (NLPID / PDU code).
         * Store it in sub_proto for finer-grained matching by callers. */
        if (pkt_size > GET_ETH_HDR_SIZE_EXCL_PAYLOAD(eth))
            cls.sub_proto = (uint16_t)l3[0];
        break;
    }

    /* ---- Passthrough EtherTypes (no L3 data to extract) ---- */
    case ETH_TYPE_RARP:
    case ETH_TYPE_LLDP:
    case ETH_TYPE_EAP_8021X:
    case ETH_TYPE_PPPoE_DISC:
    case ETH_TYPE_PPPoE_SES:
    default:
        break;
    }

    return cls;
}

static void
dp_pkt_trap_distribute(dp_ctx_t *dp_ctx,
                       trap_rule_t *trap_rule,
                       struct rte_mbuf *mbuf)
{
    while (trap_rule)
    {
        if (trap_rule->trap_fn) {

            if (!trap_rule->trap_fn(mbuf)) {
                trap_rule = trap_rule->next;
                continue;
            }
        }

        if (trap_rule->trap_app_cbk) {
            trap_rule->trap_app_cbk(dp_ctx->ctx_pvt_data, mbuf);
            trap_rule->trap_count++;
            trap_rule = trap_rule->next;
            continue;
        }
        
        if (trap_rule->ev_dis && trap_rule->pkt_q)
        {
            pkt_mbuf_ref_inc(mbuf);
            pkt_q_enqueue(trap_rule->ev_dis, trap_rule->pkt_q, (char *)mbuf, sizeof(*mbuf));
            trap_rule->trap_count++;
        }

        trap_rule = trap_rule->next;
    }
}

void
dp_pkt_trap_l2(dp_ctx_t *dp_ctx, 
              trap_rule_t* (*trap_rule_table)[PROTO_IDX_MAX], 
              struct rte_mbuf *mbuf) {

    pkt_class_t cls = dp_pkt_classify(mbuf);
    proto_idx_t idx = proto_idx((gen_proto_id_t)cls.eth_proto);
    if (idx == PROTO_IDX_MAX) return;
    dp_pkt_trap_distribute(dp_ctx, (*trap_rule_table)[idx], mbuf);
}

void
dp_pkt_trap_l3(dp_ctx_t *dp_ctx, 
              trap_rule_t* (*trap_rule_table)[PROTO_IDX_MAX], 
              struct rte_mbuf *mbuf) {

    pkt_class_t cls = dp_pkt_classify(mbuf);

    proto_idx_t idx = proto_idx((gen_proto_id_t)cls.ip_proto);
    if (idx != PROTO_IDX_MAX)
        dp_pkt_trap_distribute(dp_ctx, (*trap_rule_table)[idx], mbuf);

    idx = proto_idx((gen_proto_id_t)cls.ipv6_proto);
    if (idx != PROTO_IDX_MAX)
        dp_pkt_trap_distribute(dp_ctx, (*trap_rule_table)[idx], mbuf);
}

void
dp_trap_rule_install (trap_rule_t* (*trap_rule_table)[PROTO_IDX_MAX], 
                      trap_rule_t *trap_rule) {

    proto_idx_t idx = proto_idx((gen_proto_id_t)trap_rule->proto);
    assert (idx != PROTO_IDX_MAX) ;

    /* Prepend to the per-proto linked list */
    trap_rule->next = (*trap_rule_table)[idx];
    (*trap_rule_table)[idx] = trap_rule;
}

void
dp_trap_rule_uninstall (trap_rule_t* (*trap_rule_table)[PROTO_IDX_MAX], 
                        trap_rule_t *trap_rule) {

    proto_idx_t idx = proto_idx((gen_proto_id_t)trap_rule->proto);
    assert (idx != PROTO_IDX_MAX);

    trap_rule_t **curr = &(*trap_rule_table)[idx];

    while (*curr) {
        trap_rule_t *candidate = *curr;
        if (candidate->proto        == trap_rule->proto        &&
            candidate->trap_fn      == trap_rule->trap_fn      &&
            candidate->trap_app_cbk == trap_rule->trap_app_cbk &&
            candidate->ev_dis       == trap_rule->ev_dis       &&
            candidate->pkt_q        == trap_rule->pkt_q        &&
            candidate->consume      == trap_rule->consume) {
            *curr = candidate->next;
            return;
        }
        curr = &(*curr)->next;
    }
}