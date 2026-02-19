#include <assert.h>
#include <arpa/inet.h>
#include "../../router_init.h"
#include "ipv6_route.h"
#include "../../pkt_block.h"
#include "../../Interface/InterfaceUApi.h"
#include "ipv6_hdrs.h"
#include "../../tcpconst.h"
#include "ipv6_utils.h"
#include "../../Tracer/tracer.h"
#include "../../Layer2/layer2.h"
#include "../../FIB/fib_nh.h"
#include "../../FIB/fib.h"

extern void
demote_pkt_to_layer2(node_t *node,
                     uint32_t next_hop_ip,
                     c_string outgoing_intf,
                     pkt_block_t *pkt_block,
                     hdr_type_t hdr_type);

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
ipv6_layer3_forward_nexthop (node_t *node, fib_nh_t *nexthop, pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    byte *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;

    Interface *oif = nexthop->fwd_info->oif.get();

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
        pkt_block_str(pkt_block), oif->if_name.c_str() , "::");

    tcp_dump_l3_fwding_logger(node,  (c_string)oif->if_name.c_str(), 0);

    demote_pkt_to_layer2(node, 
            0,
            (c_string)oif->if_name.c_str(),
            pkt_block,
            IP6_HDR);

    nexthop->hit_count++;
}

void layer3_ipv6_route_pkt(node_t *node,
                           Interface *interface,
                           pkt_block_t *pkt_block)
{
    pkt_size_t pkt_size;
    char dst_addr_str[48];
    char route_addr_str[48];

    byte *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    /* Should be ipv6 pkt*/
    assert (pkt_block_get_starting_hdr(pkt_block) == IP6_HDR);

    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;

    /* Get v6 address in string form for logging*/
    inet_ntop (AF_INET6, &ipv6_hdr->dst_addr, dst_addr_str, INET6_ADDRSTRLEN);

    cmn_prefix_t prefix;
    cmn_prefix_initialize_v6(&prefix, &ipv6_hdr->dst_addr, 128);
    fib_nh_t *nh = fib_get_forwarding_nh(
        fib_get (node, AF_IPV6, 0), &prefix);

    if(!nh){
        tracer (node->dptr, DL3FWD | DERR, 
            "Pkt : %s :  Pkt Dropped :  No L3 Route\n", pkt_block_str(pkt_block));
        return;
    }

    tracer (node->dptr, DL3FWD, "Dest : %s : L3 route found\n", dst_addr_str);

    /* Reject if the nexthop action is Reject */
    if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_REJECT) {

        tracer (node->dptr, DL3FWD, 
            "Dest : %s : Pkt rejected by REJECT route\n", dst_addr_str);
        return;
    }

    /* For local routes , Trap the packet for local processing*/
    if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_LOCAL) {

        tracer (node->dptr, DL3FWD, "Pkt : %s : L3 Route found is local route\n", 
            pkt_block_str(pkt_block));

        pkt_block_set_new_pkt(pkt_block,
                              (uint8_t *)(ipv6_hdr + 1),
                              pkt_size - sizeof(ipv6_hdr_t));

        pkt_block_update_new_hdr_type (pkt_block, ipv6_hdr->next_header);
        ipv6_process_v6_payload (node, pkt_block) ;
        return;
    }

    /* For Connnected route, forward it to in local v6 connected subnet*/
    if (nh->fwd_info->fwd_flags & (FIB_NH_FWD_F_CONNECTED | FIB_NH_FWD_F_FORWARD)) {    

        ipv6_layer3_forward_nexthop (node, nh, pkt_block);
        return;
    }

    if (nh->fwd_info->fwd_flags & (FIB_NH_FWD_F_SRv6_FORWARD)) {

        /* Do SRv6 forwarding */
        Process_Srv6_Packet(node,
                            interface,
                            pkt_block,
                            ipv6_hdr,
                            ipv6_hdr->next_header == PROTO_SRH ? (srh_hdr_t *)(ipv6_hdr + 1) : NULL,
                            nh);
        return;
    }
}

void
np_tcp_ip_send_ip6_data (node_t *node, pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;

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
