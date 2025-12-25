#include <stdint.h>
#include <assert.h>
#include "../../../../common/l3_hdrs.h"
#include "srv6-endpoint.h"
#include "../../../ipv6/ipv6_hdrs.h"
#include "../../../ipv6/ipv6_route.h"
#include "../../../../router_init.h"
#include "../../../../pkt_block.h"
#include "../../../../Tracer/tracer.h"
#include "../../../../Interface/InterfaceUApi.h"
#include "srv6-end-behavior.h"

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
Srv6_apply_flavor(node_t *node,
                  pkt_block_t *orig_pkt,
                  uint8_t flavor)
{

    assert(pkt_block_verify_pkt(orig_pkt, IP6_HDR));

    if (flavor & PSP)
    {
        pkt_size_t pkt_size = 0;
        byte *pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
        ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;
        ipv6_hdr_t ipv6_hdr_copy;
        memcpy(&ipv6_hdr_copy, ipv6_hdr, sizeof(ipv6_hdr_t));
        srh_hdr_t *srh = (srh_hdr_t *)(pkt + sizeof(ipv6_hdr_t));
        ipv6_addr_t dst_addr = srv6_srh_get_destination_segment(srh);
        memcpy(&ipv6_hdr_copy.dst_addr, &dst_addr.addr, 16);
        ipv6_hdr_copy.next_header = srh->nexthdr;
        ipv6_hdr_copy.payload_length -= srh->hdrlen;
        byte *payload = pkt + sizeof(ipv6_hdr_t) + srh->hdrlen;
        pkt_block_set_new_pkt(orig_pkt, payload, pkt_size - sizeof(ipv6_hdr_t) - srh->hdrlen);
        pkt_block_expand_buffer_left(orig_pkt, sizeof(ipv6_hdr_t));
        pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
        memcpy(pkt, &ipv6_hdr_copy, sizeof(ipv6_hdr_t));
        pkt_block_update_new_hdr_type(orig_pkt, ETH_IP6);
        return orig_pkt;
    }

    if (flavor & USP)
    {
        pkt_size_t pkt_size = 0;
        byte *pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
        ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;
        if (ipv6_hdr->next_header != PROTO_SRH) return orig_pkt;
        ipv6_hdr_t ipv6_hdr_copy;
        memcpy (&ipv6_hdr_copy, ipv6_hdr, sizeof(ipv6_hdr_t));
        srh_hdr_t *srh = (srh_hdr_t *)(pkt + sizeof(ipv6_hdr_t));
        uint16_t srh_next_hdr = srh->nexthdr;
        byte *payload = pkt + sizeof(ipv6_hdr_t) + srh->hdrlen;
        pkt_block_set_new_pkt(orig_pkt, payload, pkt_size - sizeof(ipv6_hdr_t) - srh->hdrlen);
        pkt_block_expand_buffer_left(orig_pkt, sizeof(ipv6_hdr_t));
        pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
        ipv6_hdr_copy.next_header = srh_next_hdr;
        ipv6_hdr_copy.payload_length -= srh->hdrlen;
        memcpy(pkt, &ipv6_hdr_copy, sizeof(ipv6_hdr_t));
        pkt_block_set_starting_hdr_type(orig_pkt, IP6_HDR);
        return orig_pkt;
    }

    if (flavor & USD)
    {
        pkt_size_t pkt_size = 0;
        byte *pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
        ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;
        srh_hdr_t *srh = (srh_hdr_t *)(pkt + sizeof(ipv6_hdr_t));
        byte *payload = pkt + sizeof(ipv6_hdr_t) + srh->hdrlen;
        pkt_block_set_new_pkt(orig_pkt, payload, pkt_size - sizeof(ipv6_hdr_t) - srh->hdrlen);
        pkt_block_update_new_hdr_type(orig_pkt, srh->nexthdr);
        return orig_pkt;
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
            cprintf ("%s : SRv6 incapable node Recvs SRH Header pkt, pkt dropped\n",
	       node->node_name);
            break;
        default:
            cprintf ("%s : SRv6 payload handler missing \n", node->node_name);
            break;
    }
}

/* Prepare new SRH header from segment list */
srh_hdr_t *
srh_hdr_prepare (ipv6_addr_t *segment_lst, uint8_t n) {

    srh_hdr_t *srh = (srh_hdr_t *)XCALLOC_BUFF(0, sizeof(srh_hdr_t) + n * 16);
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

void 
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


/* End Point processing Functions */

static void 
Process_END_flavors_penultimate (node_t *node, 
                                                pkt_block_t *pkt_block, 
                                                ipv6_hdr_t *ipv6_hdr, 
                                                srh_hdr_t *srh,  
                                                v6nexthop_t *nexthop, 
                                                uint8_t flavor) {

    assert (srh && srh->segments_left == 1);
    assert (ipv6_hdr);
    assert (nexthop);

    switch (flavor) {
            
            case 0:
                srv6_END(node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP:
                srv6_END_w_PSP (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USP:
                srv6_END_w_PSP_USP (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USD:
                srv6_END_w_PSP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USP | USD:
                srv6_END_w_PSP_USP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            default:
                assert(0);
    }
}

static void 
Process_END_X_flavors_penultimate (node_t *node, 
                                                pkt_block_t *pkt_block, 
                                                ipv6_hdr_t *ipv6_hdr, 
                                                srh_hdr_t *srh,  
                                                v6nexthop_t *nexthop, 
                                                uint8_t flavor) {

    assert (srh && srh->segments_left == 1);
    assert (ipv6_hdr);
    assert (nexthop);

    switch (flavor) {
            
            case 0:
                srv6_END_X(node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP:
                srv6_END_X_w_PSP (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USP:
                srv6_END_X_w_PSP_USP (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USD:
                srv6_END_X_w_PSP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USP | USD:
                srv6_END_X_w_PSP_USP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            default:
                assert(0);
    }
}

static void 
Process_END_T_flavors_penultimate (node_t *node, 
                                                pkt_block_t *pkt_block, 
                                                ipv6_hdr_t *ipv6_hdr, 
                                                srh_hdr_t *srh,  
                                                v6nexthop_t *nexthop, 
                                                uint8_t flavor) {

    assert (srh && srh->segments_left == 1);
    assert (ipv6_hdr);
    assert (nexthop);

    switch (flavor) {
            
            case 0:
                srv6_END_T(node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP:
                srv6_END_T_w_PSP (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USP:
                srv6_END_T_w_PSP_USP (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USD:
                srv6_END_T_w_PSP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USP | USD:
                srv6_END_T_w_PSP_USP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            default:
                assert(0);
    }

}

/* This fn abides : 
    https://www.rfc-editor.org/rfc/rfc8986.pdf : page 23
*/
void 
Srv6_apply_penultimate_processing (node_t *node, 
                                                pkt_block_t *pkt_block, 
                                                ipv6_hdr_t *ipv6_hdr, 
                                                srh_hdr_t *srh) {

    uint8_t flavor = 0;

    assert (srh && srh->segments_left == 1);

    /* Find nexthop of the current node SRV6 route and flavor of the destination node*/

    ipv6_route_t *current_node_route = l3rib_v6lookup_lpm(
                                            NODE_V6RT_TABLE(node), &ipv6_hdr->dst_addr);

    if (!current_node_route) {

        tracer (node->dptr, DL3FWD, 
            "Pkt : %s :  No SRV6 route found, Pkt is being dropped\n",  
            pkt_block_str(pkt_block));
            return;
    }

    v6nexthop_t *nexthop = l3_v6route_get_active_nexthop(current_node_route);

    Srv6_endpcode_t CompositeEndfn = nexthop->u.srv6.endfn;

    Srv6_endpcode_t endfn = srv6_split_endpcode(CompositeEndfn, &flavor);

    switch (endfn) {

        case END:
            Process_END_flavors_penultimate (node, pkt_block, ipv6_hdr, srh, nexthop, flavor);
            break;
        case END_X:
            Process_END_X_flavors_penultimate (node, pkt_block, ipv6_hdr, srh, nexthop, flavor);
            break;
        case END_T:
            Process_END_T_flavors_penultimate (node, pkt_block, ipv6_hdr, srh, nexthop, flavor);
            break;
        default: ;
    }
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

    if (nexthop->flags & BINDING_SID) {

    }

    ipv6_layer3_forward_nexthop(node, nexthop, pkt_block);
}

void
Process_Srv6_Packet (
                        node_t *node, 
                        Interface* recv_intf,
                        pkt_block_t *pkt_block, 
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh,
                        v6nexthop_t *nexthop) {

    if (!nexthop) return;

    /* Dont feed any non ipv6 pkt into SRv6 Data path pipeline. If the router recvs non-ipv6 pkt,
        It should be processed by non-v6 module*/
    assert (ipv6_hdr);
    
   if (nexthop->flags & IPV6_REMOTE_RT) {
        Process_Srv6_remote_packet (node, recv_intf, pkt_block, ipv6_hdr, srh, nexthop);
        return;
    }

    /* Hitting the local route. Three cases :  
        1. Hitting the SRV6 locator route --> Consume pkt irrespective of SL value
        2. Hitting the SRV6 prefix sid --> process as per SL value
        3. Hitting the SRV6 adjacency sid --> process as per SL value
    */

   /* If hitting the locator route. Locator route are local route with no end point fn
      fn. Locator routes are no different from traditional ipv6 routes. Their over all
      purpose is to steer the traffic upto destination, and handover the pkt to L4 for
      further processing. So, strip the outer L3 hdr and handover the payload to ipv6 module.*/
    if ((nexthop->flags & IPV6_LOCAL_RT) && 
            !nexthop->u.srv6.endfn) {

        tracer (node->dptr, DL3FWD, "Pkt : %s : L3 Route found is local locator route\n", 
            pkt_block_str(pkt_block));

        uint8_t *pkt;
        pkt_size_t pkt_size;

        pkt = pkt_block_get_pkt(pkt_block, &pkt_size) ;
        ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;

        pkt_block_set_new_pkt(pkt_block, 
                             (uint8_t *)(ipv6_hdr + 1), 
                            pkt_size - sizeof (ipv6_hdr_t));
        
        pkt_block_update_new_hdr_type (pkt_block, ipv6_hdr->next_header);
        SRv6_process_payload (node, pkt_block) ;
        return;
    }

    /* now we hit the SRV6 route with end point function attached to it. Now, how to
        process the route depends on SL value in the SRH hdr. */

    /* If the SRV6 enabled node recv the ipv6 pkt with  SL == 1
        Apply PSP flavors advertised by the destination node and forward the pkt*/
    if (srh && srh->segments_left == 1) {

        Srv6_apply_penultimate_processing (node, pkt_block, ipv6_hdr, srh);
        return;
    }

    /* For SL = 0, apply end fn processing */

    if (!srh || srh->segments_left == 0) {

        Srv6_apply_endpoint_fn (
                    node, 
                    recv_intf, 
                    pkt_block,
                    ipv6_hdr, 
                    srh,
                    nexthop); 
        return;
    }

    /* processing when SL > 1, same processing needs to be done irrespective of end-point fn.
        Just apply shift and forward */
    if (srh->segments_left > 1) {
        srv6_shift_and_forward (node, pkt_block);
    }
    
}

static void 
Process_END_flavors_ultimate (node_t *node, 
                                                pkt_block_t *pkt_block, 
                                                ipv6_hdr_t *ipv6_hdr, 
                                                srh_hdr_t *srh,  
                                                v6nexthop_t *nexthop, 
                                                uint8_t flavor) {
    
    assert (!srh || srh->segments_left == 0);
    assert (ipv6_hdr);
    assert (nexthop);

    switch (flavor) {
            
            case 0:
                srv6_END(node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case USP:
                srv6_END_w_USP (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USP:
                srv6_END_w_PSP_USP (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case USD:
                srv6_END_w_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USD:
                srv6_END_w_PSP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USP | USD:
                srv6_END_w_PSP_USP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            default:
                /* Apply default end point behavior when flavor is not applicable for 
                    ultimate end point node, for ex flavor applied is PSP */
                srv6_END(node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
    }
}

static void 
Process_END_X_flavors_ultimate (node_t *node, 
                                                pkt_block_t *pkt_block, 
                                                ipv6_hdr_t *ipv6_hdr, 
                                                srh_hdr_t *srh,  
                                                v6nexthop_t *nexthop, 
                                                uint8_t flavor) {

    assert (srh && srh->segments_left == 1);
    assert (ipv6_hdr);
    assert (nexthop);

    switch (flavor) {
            
            case 0:
                srv6_END_X(node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case USP:
                srv6_END_X_w_USP (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case USD:
                srv6_END_X_w_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USP:
                srv6_END_X_w_PSP_USP (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case USP | USD:
                srv6_END_X_w_USP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USD:
                srv6_END_X_w_PSP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USP | USD:
                srv6_END_X_w_PSP_USP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            default:
                assert(0);
    }
}

static void 
Process_END_T_flavors_ultimate (node_t *node, 
                                                pkt_block_t *pkt_block, 
                                                ipv6_hdr_t *ipv6_hdr, 
                                                srh_hdr_t *srh,  
                                                v6nexthop_t *nexthop, 
                                                uint8_t flavor) {

    assert (srh && srh->segments_left == 1);
    assert (ipv6_hdr);
    assert (nexthop);

    switch (flavor) {
            
            case 0:
                srv6_END_T(node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case USP:
                srv6_END_T_w_USP (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USP:
                srv6_END_T_w_PSP_USP (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case USD:
                srv6_END_T_w_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USD:
                srv6_END_T_w_PSP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case USP | USD:
                srv6_END_T_w_USP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            case PSP | USP | USD:
                srv6_END_T_w_PSP_USP_USD (node, pkt_block, ipv6_hdr, srh, nexthop);
                break;
            default:
                assert(0);
    }

}


void 
Srv6_apply_endpoint_fn (
            node_t *node, 
            Interface *recv_intf, 
            pkt_block_t *pkt_block, 
            ipv6_hdr_t *ipv6_hdr, 
            srh_hdr_t *srh, 
            v6nexthop_t *nexthop) { 

    Srv6_endpcode_t CompositeEndfn = nexthop->u.srv6.endfn;
    uint8_t flavor = 0;
    Srv6_endpcode_t endfn = srv6_split_endpcode(CompositeEndfn, &flavor);

    tracer (node->dptr, DL3FWD, "Pkt : %s :  Applying SRv6 end point function : %s\n", 
        pkt_block_str(pkt_block), srv6_end_fn_str (CompositeEndfn));

    assert (!srh || (srh->segments_left == 0));
    assert (ipv6_hdr);

    switch (endfn) {

        /* Node is processing its prefix/node sid*/
        case END:
            Process_END_flavors_ultimate (node, pkt_block, ipv6_hdr, srh, nexthop, flavor);
            break;

        /* Node is processing its own Adjacency Sid*/
        case END_X:
            Process_END_X_flavors_ultimate (node, pkt_block, ipv6_hdr, srh, nexthop, flavor);
            break;

        case END_T:
            Process_END_T_flavors_ultimate(node, pkt_block, ipv6_hdr, srh, nexthop, flavor);
            break;

        case END_B6_ENCAP:
            srv6_END_B6_ENCAP(node, pkt_block, ipv6_hdr, srh, nexthop);
            break;

        default:
            assert(0);
            break;
    }
}

