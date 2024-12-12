#include <assert.h>
#include <arpa/inet.h>
#include "../graph.h"
#include "ipv6_route.h"
#include "../pkt_block.h"
#include "../Interface/InterfaceUApi.h"
#include "ipv6_hdrs.h"
#include "../tcpconst.h"
#include "ipv6_utils.h"
#include "../Tracer/tracer.h"
#include "../Layer2/layer2.h"

extern void
promote_pkt_to_layer4(node_t *node,
                      Interface *recv_intf,
                      pkt_block_t *pkt_block,
                      int L4_protocol_number);

extern void
demote_pkt_to_layer2 (node_t *node, 
                                       uint32_t next_hop_ip,   
                                      c_string outgoing_intf,
                                      pkt_block_t *pkt_block, 
                                      hdr_type_t hdr_type) ;

v6nexthop_t *
l3_v6route_get_active_nexthop (ipv6_route_t *l3_route) {

    int nh_index_old;
    v6nexthop_t *nexthop;
    nxthop_proto_id_t nh_proto;

    nh_index_old = l3_route->nxthop_idx;

    FOR_ALL_NXTHOP_PROTO(nh_proto) {

        do {

            nexthop = l3_route->nexthops[nh_proto][l3_route->nxthop_idx];

            if (!nexthop) { 

                l3_route->nxthop_idx++;

                if (l3_route->nxthop_idx == MAX_NXT_HOPS) {
                    l3_route->nxthop_idx = 0;
                }

                if (l3_route->nxthop_idx == nh_index_old) {
                    break;
                }

                continue;
            }

            l3_route->nxthop_idx++;

            if (l3_route->nxthop_idx == MAX_NXT_HOPS) {
                l3_route->nxthop_idx = 0;
            }

            return nexthop;

        } while (1);

    }

    return NULL;
}

void 
layer3_ipv6_plain_forward_nexthop(node_t *node, v6nexthop_t *nexthop, pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    byte *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;

    Interface *oif = nexthop->oif.get();

    if (!oif) return;

    ipv6_addr_t v6_addr = {0};
    oif->InterfaceGetIpv6LinkLocalAddress(&v6_addr.addr);

    /* If the ipv6 hdr do not have any src address yet, because it is locally generated pkt, use OIF ipv6 link local address */
    if (is_ipv6_addr_unspecified (&ipv6_hdr->src_addr) && 
        !is_ipv6_addr_unspecified (&v6_addr.addr)) {

        memcpy (ipv6_hdr->src_addr, v6_addr.addr, 16);
    }

    ipv6_hdr->hop_limit--;

    if (ipv6_hdr->hop_limit == 0) {

        tracer (node->dptr, DL3FWD, "Dest : %s :  Pkt Dropped : TTL Expired\n", 
            pkt_block_str(pkt_block));
        return;
    }

    tracer (node->dptr, DL3FWD, "Dest : %s :  Nexthop found OIF %s, Gw : %s\n", 
        pkt_block_str(pkt_block), oif->if_name.c_str() );

    tcp_dump_l3_fwding_logger(node,  (c_string)oif->if_name.c_str(), 0);

    demote_pkt_to_layer2(node, 
            0,
            (c_string)oif->if_name.c_str(),
            pkt_block,
            IP6_HDR);

    nexthop->hit_count++;
}

 void
layer3_ipv6_route_pkt (node_t *node,
							          Interface *interface,
					                  pkt_block_t *pkt_block)  {

    pkt_size_t pkt_size;
    char dst_addr_str[48];

    byte *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    /* Should be ipv6 pkt*/
    assert (pkt_block_get_starting_hdr(pkt_block) == IP6_HDR);

    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;

    /* Get v6 address in string form for logging*/
    inet_ntop (AF_INET6, &ipv6_hdr->dst_addr, dst_addr_str, INET6_ADDRSTRLEN);

    /* Look up the route from RIB */
    ipv6_route_t *route = l3rib_v6lookup_lpm(NODE_V6RT_TABLE(node), &ipv6_hdr->dst_addr);

    if (!route) {
        tracer (node->dptr, DL3FWD | DERR, "Dest : %s :  Pkt Dropped : No L3 route\n", 
            dst_addr_str);
        return;
    }

    /* If the route is local */
    if (!route->nh_count) {

        tracer (node->dptr, DL3FWD, "Pkt : %s : L3 Route found is local route\n", 
            pkt_block_str(pkt_block));

        switch (ipv6_hdr->next_header) {

            case ICMP6_PROTO:
                /* ICMP packet */
                 cprintf("IP6 Address : %s, ping success\n", dst_addr_str);
                return;

            case TCP_PROTO:
                /* TCP packet */
                pkt_block_set_new_pkt(pkt_block, 
                                        (uint8_t *) (ipv6_hdr + 1),
                                        pkt_size - sizeof (ipv6_hdr_t));
                pkt_block_set_starting_hdr_type(pkt_block, TCP_HDR);
                promote_pkt_to_layer4(
                                node, interface,
                                pkt_block,
                                TCP_HDR);
                return;

            case UDP_PROTO:
                /* UDP packet */
                pkt_block_set_new_pkt(pkt_block,
                                      (uint8_t *)(ipv6_hdr + 1),
                                      pkt_size - sizeof(ipv6_hdr_t));
                pkt_block_set_starting_hdr_type(pkt_block, UDP_HDR);
                promote_pkt_to_layer4(
                                node, interface,
                                pkt_block,
                                UDP_HDR);
                return;

            case GRE_PROTO:
                /* GRE packet */
                break;

            case ETH_IP6:
                /* IPV6 packet */
                break;

            case PROTO_SRH:
                /* SRH packet */
                Process_Srv6_Packet (node,
                                interface, 
                                pkt_block, 
                                ipv6_hdr, 
                                (srh_hdr_t *)(ipv6_hdr + 1) , 0);
                return;

            default:
                tracer (node->dptr, DL3FWD, "Pkt : %s :  Pkt is being subjected to Layer 5\n", 
                    pkt_block_str(pkt_block));
                return;
        }
    }


    /* If route has a nexthop */
    v6nexthop_t *nexthop = l3_v6route_get_active_nexthop(route);

    if (!nexthop) {
        tracer (node->dptr, DL3FWD | DERR, "Pkt : %s :  Pkt Dropped : No active nexthop\n", 
            pkt_block_str(pkt_block));
        return;
    }

    if (((nexthop->proto == PROTO_STATIC || 
                nexthop->proto == PROTO_ISIS))) {

        /* Do normal ipv6 forwarding */
        if (!nexthop->oif) return;

        layer3_ipv6_plain_forward_nexthop (node, nexthop, pkt_block);
        return;
    }

    if (nexthop->proto == PROTO_SRv6 ) {

        /* Do SRv6 forwarding */
        Process_Srv6_Packet (node, interface, pkt_block, 
                                            ipv6_hdr, 
                                            ipv6_hdr->next_header == PROTO_SRH ? \
                                                 (srh_hdr_t *)(ipv6_hdr + 1) : NULL, 
                                            nexthop);
        return;
    }
}


/* Attach Eth hdr and forward the pkt out of interface. Skip ARP/ND for ipv6 */
void 
l2_forward_ipv6_packet(node_t *node,  
                                        c_string outgoing_intf,
                                        pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;

    tcp_ip_expand_buffer_ethernet_hdr(pkt_block);

    ethernet_hdr_t *empty_ethernet_hdr =
        (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);
    
    empty_ethernet_hdr->type = ETH_IP6;

    Interface *oif = node_get_intf_by_name(node, (char *)outgoing_intf);

    if (!oif) return;

    /* Src MAC = MAC of OIF*/
    memcpy(empty_ethernet_hdr->src_mac.mac, IF_MAC(oif), MAC_ADDR_SIZE);

    /* Dest MAC as MAC broadcast address */
    memset(empty_ethernet_hdr->dst_mac.mac, 0xFF, MAC_ADDR_SIZE);

    SET_COMMON_ETH_FCS(empty_ethernet_hdr, pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD, 0);

    oif->SendPacketOut(pkt_block);
} 

void
np_tcp_ip_send_ip6_data (node_t *node, pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    char ip6_addr_str[48];

    assert (pkt_block_verify_pkt (pkt_block, IP6_HDR));

    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt_block_get_pkt (pkt_block,  &pkt_size);

    /* This API expects that IP-HDR must have following fields set */
    assert (ipv6_hdr->next_header);

    // Src IP may or may not be set already. If not set, we will determine it
    //assert (ip_hdr->src_ip);

    assert (!is_ipv6_addr_unspecified (&ipv6_hdr->dst_addr));

    tracer (node->dptr, DL3FWD, "Dest : %s : NP Recvd Routing Request\n", 
        pkt_block_str(pkt_block));

    layer3_ipv6_route_pkt (node, NULL, pkt_block); 
}