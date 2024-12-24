#include <stdint.h>
#include <assert.h>
#include "../../../../common/l3_hdrs.h"
#include "SRv6-EndPoint.h"
#include "../../../ipv6/ipv6_hdrs.h"
#include "../../../ipv6/ipv6_route.h"
#include "../../../../graph.h"
#include "../../../../pkt_block.h"
#include "../../../../Tracer/tracer.h"
#include "../../../../Interface/InterfaceUApi.h"

extern void 
ipv6_layer3_forward_nexthop(
                node_t *node, 
                v6nexthop_t *nexthop, 
                pkt_block_t *pkt_block);

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
                                      hdr_type_t hdr_type);

extern v6nexthop_t *
l3_v6route_get_active_nexthop (ipv6_route_t *l3_route) ;

#define drop_packet return;
#define NOOP    

ipv6_addr_t 
srv6_srh_get_destination_segment (srh_hdr_t *srh) {

    ipv6_addr_t dst_addr;
    memcpy (&dst_addr.addr, srh->segments[0], 16);
    return dst_addr;
}

pkt_block_t *
Srv6_apply_flavor (node_t *node, 
                                pkt_block_t *orig_pkt, 
                                uint8_t flavor, uint8_t segments_left) {

    assert (pkt_block_verify_pkt (orig_pkt, IP6_HDR));

    /* flavors are not applied on the intermediate node*/
    if (segments_left > 1) return orig_pkt;

    if (segments_left == 1) {

        /* This is penultimate node, apply flavors : PSP or PSD*/

        if (flavor & PSD) {

            pkt_size_t pkt_size = 0;
            byte *pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
            ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;
            srh_hdr_t *srh = (srh_hdr_t *)(pkt + sizeof(ipv6_hdr_t));
            byte *payload = pkt + sizeof(ipv6_hdr_t) + srh->hdrlen;
            pkt_block_set_new_pkt (orig_pkt, payload, pkt_size - sizeof(ipv6_hdr_t) - srh->hdrlen);
            pkt_block_update_new_hdr_type (orig_pkt, srh->nexthdr);
            return orig_pkt;
        }

        if (flavor & PSP) {
            pkt_size_t pkt_size = 0;
            byte *pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
            ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;
            ipv6_hdr_t ipv6_hdr_copy;
            memcpy (&ipv6_hdr_copy, ipv6_hdr, sizeof(ipv6_hdr_t));
            srh_hdr_t *srh = (srh_hdr_t *)(pkt + sizeof(ipv6_hdr_t));
            ipv6_addr_t dst_addr = srv6_srh_get_destination_segment (srh);
            memcpy (&ipv6_hdr_copy.dst_addr, &dst_addr.addr, 16);
            ipv6_hdr_copy.next_header = srh->nexthdr;
             ipv6_hdr_copy.payload_length -= srh->hdrlen;
            byte *payload = pkt + sizeof(ipv6_hdr_t) + srh->hdrlen;
            pkt_block_set_new_pkt (orig_pkt, payload, pkt_size - sizeof(ipv6_hdr_t) - srh->hdrlen);
            pkt_block_expand_buffer_left (orig_pkt, sizeof(ipv6_hdr_t));
            pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
            memcpy (pkt, &ipv6_hdr_copy, sizeof(ipv6_hdr_t));
            pkt_block_update_new_hdr_type (orig_pkt, ETH_IP6);
            return orig_pkt;
        }
    }

    if (segments_left == 0) {
            
            /* This is destination node, apply flavors : USD*/
    
            if (flavor & USD) {
                pkt_size_t pkt_size = 0;
                byte *pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
                ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;
                srh_hdr_t *srh = (srh_hdr_t *)(pkt + sizeof(ipv6_hdr_t));
                byte *payload = pkt + sizeof(ipv6_hdr_t) + srh->hdrlen;
                pkt_block_set_new_pkt (orig_pkt, payload, pkt_size - sizeof(ipv6_hdr_t) - srh->hdrlen);
                pkt_block_update_new_hdr_type (orig_pkt, srh->nexthdr);
                return orig_pkt;
            }
    }

    return orig_pkt;
}

void 
Srv6_decapsulate (node_t *node, pkt_block_t *pkt_block) {

    pkt_size_t pkt_size = 0;
    if (pkt_block_get_starting_hdr(pkt_block) != IP6_HDR) return;
    byte *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);
    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;
    if (ipv6_hdr->next_header != PROTO_SRH) {
        pkt_block_set_new_pkt (pkt_block, (uint8_t *)(ipv6_hdr + 1), pkt_size - sizeof(ipv6_hdr_t));
        pkt_block_update_new_hdr_type (pkt_block, ipv6_hdr->next_header);
        return;
    }
    srh_hdr_t *srh = (srh_hdr_t *)(ipv6_hdr  + 1);
    byte *payload = pkt + sizeof(ipv6_hdr_t) + srh->hdrlen;
    pkt_block_set_new_pkt (pkt_block, payload, pkt_size - sizeof(ipv6_hdr_t) - srh->hdrlen);
    pkt_block_update_new_hdr_type (pkt_block, srh->nexthdr);
}

void 
Srv6_copy_current_sid_to_DA (srh_hdr_t *srh, ipv6_hdr_t *ipv6_hdr) {

    memcpy (ipv6_hdr->dst_addr, srh->segments[srh->segments_left], 16);
}

void 
SRv6_process_payload (node_t *node, pkt_block_t *pkt_block) {

    hdr_type_t hdr_type = pkt_block_get_starting_hdr(pkt_block);

    /* Inject the pakcet into data path pipelines again as appropriate */
    switch (hdr_type) {

        case IP_HDR:
             layer3_ip_route_pkt(node, NULL, pkt_block);
             return;
        case IP6_HDR:
            layer3_ipv6_route_pkt(node, NULL, pkt_block);
            return;
        case ICMP6_HDR:
            cprintf("ipv6 ping success\n");
        break;
        case TCP_HDR:
            promote_pkt_to_layer4(node, NULL, pkt_block, TCP_HDR);
            return;
        case UDP_HDR:
            promote_pkt_to_layer4(node, NULL, pkt_block, UDP_HDR);
            return;
        case GRE_HDR:
            break;
        case SRH_HDR:
            break;
        default:
            cprintf ("%s : SRv6 payload handler missing \n", node->node_name);
            break;
    }
}

const char *
end_fn_str(Srv6_endpcode_t end_fn) {

    switch (end_fn) {

        case END:
            return "END";
        case END_X:
            return "END_X";
        case END_T:
            return "END_T";
        case END_DX6:
            return "END_DX6";
        case END_DX4:
            return "END_DX4";
        case END_DT6:
            return "END_DT6";
        case END_DT4:
            return "END_DT4";
        case END_B6_ENCAP:
            return "END_B6_ENCAP";
        case END_B6_ENCAP_X:
            return "END_B6_ENCAP_X";
        default:
            return "UNKNOWN";
    }
}

const char *
flavor_str(uint8_t flavors) {

    switch (flavors) {

        case PSP:
            return "PSP";
        case USD:
            return "USD";
        case PSD:
            return "PSD";
        case PSP | USD:
            return "PSP | USD";
        case PSP | PSD:
            return "PSP | PSD";
        case USD | PSD:
            return "USD | PSD";
        case PSP | USD | PSD:
            return "PSP | USD | PSD";
        default:
            return "UNKNOWN";
    }
}

/* Prepare new SRH header from segment list */
static srh_hdr_t *
srh_hdr_prepare (ipv6_addr_t *segment_lst, uint8_t n) {

    srh_hdr_t *srh = (srh_hdr_t *)calloc(1, sizeof(srh_hdr_t) + n * 16);
    srh->nexthdr = 0;
    srh->hdrlen = sizeof(srh_hdr_t) + n * 16;
    srh->type = 4;
    srh->segments_left = n;
    srh->first_segment = 0;
    srh->flags = 0;
    srh->tag = 0;
    for (int i = 0, j = n; i < n; i++) {
        memcpy (srh->segments[j - i - 1], segment_lst[i].addr, 16);
    }
    return srh;
}

static void 
Srv6_encapsulate (pkt_block_t *pkt_block, srh_hdr_t *srh) {

    pkt_size_t pkt_size = 0;

    /* Add SRH header first*/
    hdr_type_t hdr_type = pkt_block_get_starting_hdr(pkt_block);
    pkt_block_expand_buffer_left (pkt_block, srh->hdrlen);
    byte *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);
    memcpy (pkt, srh, srh->hdrlen);
    srh_hdr_t *new_srh = (srh_hdr_t *)pkt;
    new_srh->nexthdr = tcp_ip_convert_internal_proto_to_std_proto (hdr_type);
    pkt_block_update_new_hdr_type (pkt_block, PROTO_SRH);

    /* Add ipv6 header now*/
    pkt_block_expand_buffer_left (pkt_block, sizeof(ipv6_hdr_t));
    pkt = pkt_block_get_pkt(pkt_block, &pkt_size);
    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;
    initialize_ipv6_hdr (ipv6_hdr);
    ipv6_hdr->next_header = PROTO_SRH;
    ipv6_hdr->payload_length = pkt_size - sizeof(ipv6_hdr_t);
    
    /* src address, not known, fill will 0s*/

    /* dst address, will with the bottom-most segment in SRH*/
    new_srh->segments_left--;
    memcpy (ipv6_hdr->dst_addr, new_srh->segments[new_srh->segments_left], 16);

    pkt_block_update_new_hdr_type (pkt_block, ETH_IP6);
}


/* Fn  for ipv6 pkt processing 
    Used to process the ipv6 pkt whose destination do not belong to any local sid of the
    router. In this case, simply forward the packet using the route. Route could be binding sid,
    in that case , mount the segmebt list on the packet.
*/
static void 
Process_Srv6_remote_packet (
                        node_t *node, 
                        Interface* recv_intf,
                        pkt_block_t *pkt_block, 
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh,
                        v6nexthop_t *nexthop) {

    if (nexthop->u.srv6.flags & BINDING_SID) {


    }

    ipv6_layer3_forward_nexthop(node, nexthop, pkt_block);
}

static void 
Srv6_apply_penultimate_processing (node_t *node, 
                                                pkt_block_t *pkt_block, 
                                                ipv6_hdr_t *ipv6_hdr, 
                                                srh_hdr_t *srh) {

    ipv6_addr_t dst_addr = srv6_srh_get_destination_segment (srh);
    ipv6_route_t *dst_route = l3rib_v6lookup_lpm(
                                            NODE_V6RT_TABLE(node), &dst_addr.addr);
    v6nexthop_t *dst_nexthop = l3_v6route_get_active_nexthop(dst_route);

    pkt_block_t *flavored_pkt = Srv6_apply_flavor(
                node, pkt_block, dst_nexthop->u.srv6.srv6_flavors, srh->segments_left);    

    switch (dst_nexthop->u.srv6.srv6_flavors) {

        case PSP:
            ipv6_layer3_forward_nexthop(node, dst_nexthop, flavored_pkt);
            break;

        case PSD: 
            /* Payload has been exposed, forward the pkt by handling it to L2 layer. L2 layer will
                attach ethernet hdr and forward onto the nexthop link*/
            if (!dst_route) {
                    pkt_block_dereference(flavored_pkt);
                    drop_packet;
                }

            if (!dst_nexthop->oif) {

                tracer (node->dptr, DL3FWD | DERR, "Pkt : %s :  Pkt Dropped : No active nexthop\n", 
                    pkt_block_str(flavored_pkt));
                drop_packet;
            }

            demote_pkt_to_layer2 (node, 0,
                                                    (c_string)dst_nexthop->oif->if_name.c_str(), flavored_pkt,
                                                    pkt_block_get_starting_hdr(flavored_pkt));
        break;
        
        case USD:
            /* Penultimate router do not apply USD*/
            NOOP; // Fall through

        default: 
            srh->segments_left--;
            Srv6_copy_current_sid_to_DA (srh, ipv6_hdr);
            ipv6_layer3_forward_nexthop(node, dst_nexthop, flavored_pkt);
    }
}

/*
In SRv6, flavors are applied before the END function processing. This ordering ensures that any specific handling or adjustments dictated by the flavor are completed before the standard or custom END behavior is executed
*/
void
Process_Srv6_Packet (
                        node_t *node, 
                        Interface* recv_intf,
                        pkt_block_t *pkt_block, 
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh,
                        v6nexthop_t *nexthop) {

    if (!nexthop) return;

    bool flavor_applied = false;

    /* Dont feed any non ipv6 pkt into SRv6 Data path pipeline. If the router recvs non-ipv6 pkt,
        It should be processed by non-v6 module*/
    assert (ipv6_hdr);
    
   if (nexthop->u.srv6.flags & SRV6_REMOTE_RT) {
        Process_Srv6_remote_packet (node, recv_intf, pkt_block, ipv6_hdr, srh, nexthop);
        return;
    }
    
    /* IF the pkt dont have SRH header ( because PSP has been done) , it is as good as
        recving packet with SL = 0*/
    if (!srh) {

        Srv6_apply_endpoint_fn (
                    node, 
                    recv_intf, 
                    pkt_block, 
                    ipv6_hdr, 
                    NULL,
                    nexthop); 
        return;
    }

    /* processing when SL > 1, same processing needs to be done irrespective of end-point fn*/
    if (srh->segments_left > 1) {

        srh->segments_left -= 1;
        Srv6_copy_current_sid_to_DA (srh, ipv6_hdr);
        ipv6_route_t *nxt_route = l3rib_v6lookup_lpm(
                                                NODE_V6RT_TABLE(node), &ipv6_hdr->dst_addr);

        if (!nxt_route) {

            tracer (node->dptr, DL3FWD | DERR,  "Pkt : %s :  Pkt Dropped : No forwarding route\n", 
            pkt_block_str(pkt_block));            
            drop_packet;
        }

        v6nexthop_t *nxt_nexthop = l3_v6route_get_active_nexthop(nxt_route);

        if (!nxt_nexthop) {
            
            tracer (node->dptr, DL3FWD | DERR,  "Pkt : %s :  Pkt Dropped : No forwarding nexthop\n", 
            pkt_block_str(pkt_block));            
            drop_packet;
        }

        if (nxt_nexthop->u.srv6.flags & BINDING_SID) {

            /* Mount seg lst here onto the pkt*/
        }

        ipv6_layer3_forward_nexthop(node, nxt_nexthop, pkt_block);
        return;
}

    /* SL = 1, Apply flavors advertised by the destination node and forward the pkt*/
    if (srh->segments_left == 1) {

        Srv6_apply_penultimate_processing (node, pkt_block, ipv6_hdr, srh);
        return;
    }

    /* if SL = 0, apply end point function processing */
    Srv6_apply_endpoint_fn (
                node, 
                recv_intf, 
                pkt_block, 
                ipv6_hdr, 
                srh, 
                nexthop); 
}

void 
Srv6_apply_endpoint_fn (
        node_t *node, 
        Interface *recv_intf, 
        pkt_block_t *pkt_block, 
        ipv6_hdr_t *ipv6_hdr, 
        srh_hdr_t *srh, 
        v6nexthop_t *nexthop) {

    Srv6_endpcode_t endfn = nexthop->u.srv6.endfn;

    switch (endfn) {

        /* Node is processing its prefix/node sid*/
        case END:
            Process_END(node, pkt_block, ipv6_hdr, srh, nexthop);
            break;

        /* Node is processing its own Adjacency Sid*/
        case END_X:
            Process_END_X(node, recv_intf, pkt_block, ipv6_hdr, srh, nexthop);
            break;

        case END_B6_ENCAP:
            Process_END_B6_ENCAP(node, pkt_block, ipv6_hdr, srh, nexthop);
            break;

        case END_B6_ENCAP_X:
            Process_END_B6_ENCAP_X(node, recv_intf, pkt_block, ipv6_hdr, srh, nexthop);
            break;

        default:
            assert(0);
    }
}

/* End Point Functions Definitions */

void
Process_END (node_t *node, 
                        pkt_block_t *pkt_block,
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh, // can be NULL
                        v6nexthop_t *nexthop) {

    assert (!srh || (srh->segments_left == 0));
    Srv6_decapsulate(node, pkt_block);
    SRv6_process_payload(node, pkt_block);
}

void
Process_END_X (node_t *node, 
                        Interface* recv_intf,
                        pkt_block_t *orig_pkt,
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh,
                        v6nexthop_t *nexthop) {

    assert (!srh || (srh->segments_left == 0));

    ipv6_route_t *x_route = l3rib_v6lookup_lpm(
                                                    NODE_V6RT_TABLE(node), &ipv6_hdr->dst_addr);
    
    v6nexthop_t *x_v6nexthop = l3_v6route_get_active_nexthop(x_route);
    Srv6_decapsulate(node, orig_pkt);
    ipv6_layer3_forward_nexthop(node, x_v6nexthop, orig_pkt);
}

void
Process_END_B6_ENCAP (node_t *node, 
                                              pkt_block_t *orig_pkt,
                                              ipv6_hdr_t *ipv6_hdr, 
                                              srh_hdr_t *srh,
                                              v6nexthop_t *nexthop) {

    pkt_size_t pkt_size;

    assert (!srh || (srh->segments_left == 0));

    Srv6_decapsulate(node, orig_pkt);

    srh_hdr_t *new_srh = srh_hdr_prepare (
                nexthop->u.srv6.segment_lst,
                nexthop->u.srv6.n_segment_list);

    Srv6_encapsulate (orig_pkt, new_srh);
    
    free (new_srh);

    ipv6_hdr_t *outer_ipv6_hdr = 
        (ipv6_hdr_t *)pkt_block_get_pkt (orig_pkt, &pkt_size);

    ipv6_route_t *nxt_route = l3rib_v6lookup_lpm(
                                                    NODE_V6RT_TABLE(node), &outer_ipv6_hdr->dst_addr);

    if (!nxt_route) {

        tracer (node->dptr, DL3FWD | DERR,  "Pkt : %s :  Pkt Dropped : No forwarding route\n", 
            pkt_block_str(orig_pkt));            
        drop_packet;
    }

    v6nexthop_t *nxt_nxthop = l3_v6route_get_active_nexthop (nxt_route);

    if (!nxt_nxthop) {

        tracer (node->dptr, DL3FWD | DERR,  "Pkt : %s :  Pkt Dropped : No forwarding nexthop\n", 
        pkt_block_str(orig_pkt));            
        drop_packet;
    }

    if (nxt_nxthop->u.srv6.flags & BINDING_SID) {

    }

     ipv6_layer3_forward_nexthop(node, nxt_nxthop, orig_pkt);
}

void
Process_END_B6_ENCAP_X (node_t *node, 
                                                  Interface* recv_intf,
                                                  pkt_block_t *pkt_block,
                                                  ipv6_hdr_t *ipv6_hdr, 
                                                  srh_hdr_t *srh,
                                                  v6nexthop_t *nexthop) {
    pkt_size_t pkt_size;

    assert (!srh || (srh->segments_left == 0));

    Srv6_decapsulate(node, pkt_block);

    srh_hdr_t *new_srh = srh_hdr_prepare (
                nexthop->u.srv6.segment_lst,
                nexthop->u.srv6.n_segment_list);

    Srv6_encapsulate (pkt_block, new_srh);    
    free (new_srh);
    ipv6_layer3_forward_nexthop(node, nexthop, pkt_block);
}
