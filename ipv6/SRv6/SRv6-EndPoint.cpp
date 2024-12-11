#include <stdint.h>
#include <assert.h>
#include "../ipv6_hdrs.h"
#include "Srv6.h"
#include "SRv6-EndPoint.h"
#include "../ipv6_route.h"
#include "../../graph.h"
#include "../../pkt_block.h"

extern void 
layer3_ipv6_plain_forward_nexthop(
                node_t *node, 
                v6nexthop_t *nexthop, 
                pkt_block_t *pkt_block);

extern v6nexthop_t *
l3_v6route_get_active_nexthop (ipv6_route_t *l3_route) ;

#define drop_packet return;
#define NOOP    

/* Fn  for ipv6 pkt processing 
    Used to process the ipv6 pkt whose destination do not belong to any local sid of the
    router. In this case, only apply Dest-SID flavors (PSP Or PSD) if applicable if the current router is the penultimate of the destination. SL value dont matter.
*/
static void 
Process_Srv6_remote_packet (
                        node_t *node, 
                        Interface* recv_intf,
                        pkt_block_t *pkt_block, 
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh,
                        v6nexthop_t *nexthop) {

    bool flavor_applied = false;

    ipv6_addr_t dst_addr;

    memcpy (&dst_addr.addr, ipv6_hdr->dst_addr, 16);

    /* Apply the flavors on the pkt */
    uint8_t flavor = nexthop->u.srv6.srv6_flavors;

    /* flavor will be PSP or PSD if i am penultimate router of the 'route' sid.
        In data path, I have no business to check whether i am Penultinate router
        or not by abalyzing the IGP topology */
    if (((flavor & PSP) || (flavor & PSD)) ) {

        pkt_block_t *flavored_pkt = Srv6_apply_flavor(node, pkt_block, flavor, srh->segments_left);
        pkt_block = flavored_pkt;
        pkt_block_reference(pkt_block);
        flavor_applied = true;
    }

    layer3_ipv6_plain_forward_nexthop(node, nexthop, pkt_block);

    if (flavor_applied )  pkt_block_dereference(pkt_block);
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

        default:
            assert(0);
    }
}

void
Process_END(node_t *node, 
                        pkt_block_t *pkt_block,
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh,
                        v6nexthop_t *nexthop) {

    ipv6_route_t *nxt_route;
    v6nexthop_t *nexthop2;

    /* case 1 : 
        When Router Recvs Already Decapsulated pkt. This would be destination router.
        It would happen when Penultimate router has already performed PSD. BAsed on
        payload type, pkt must go to that particular module for processing, not SRV6*/
        assert (ipv6_hdr);


    /* case 2 : 
        When the router recvs the pkt with outer ipv6 header but without SRH header. In 
        this case, remove outer ipv6 header and process the pkt locally. When Router recvs the 
        pkt without SRH, it would mean it is ultimate destination */
    if (!srh) {
        Srv6_decapsulate (node, pkt_block);
        SRv6_process_payload (node, pkt_block);
        return;
    }

    /* case 3: 
        If the current node is intermediate node ( not event penultimate node )
     */
    if (srh->segments_left > 1) {

        srh->segments_left -= 1;
        Srv6_copy_current_sid_to_DA (srh, ipv6_hdr);
        nxt_route = l3rib_v6lookup_lpm(
                                            NODE_V6RT_TABLE(node), &ipv6_hdr->dst_addr);
        
        nexthop2 = l3_v6route_get_active_nexthop(nxt_route);
        layer3_ipv6_plain_forward_nexthop(node, nexthop2, pkt_block);
        return;
    }
    
    /* case 4 : If the current node is  penultimate node */
    else if (srh->segments_left == 1) {

        /* Implement flavors */
        ipv6_addr_t dst_addr = srv6_srh_get_destination_segment (srh);

        pkt_block_t *flavored_pkt = Srv6_apply_flavor(
                node, pkt_block, nexthop->u.srv6.srv6_flavors, srh->segments_left);

        pkt_block_reference(flavored_pkt);

        uint8_t flavor = nexthop->u.srv6.srv6_flavors;

        switch (flavor) {

            case PSP:
                nxt_route = l3rib_v6lookup_lpm(
                                            NODE_V6RT_TABLE(node), &ipv6_hdr->dst_addr);
                nexthop2 = l3_v6route_get_active_nexthop(nxt_route);
                layer3_ipv6_plain_forward_nexthop(node, nexthop2, flavored_pkt);
                break;

            case PSD:
                /*Router has removed outer ipv6_hdr and SRH header. Payload must be pushed to
                next router in SRH */
                nxt_route = l3rib_v6lookup_lpm(
                                            NODE_V6RT_TABLE(node), &dst_addr.addr);

                if (!nxt_route) {
                    pkt_block_dereference(flavored_pkt);
                    drop_packet;
                }

                nexthop2 = l3_v6route_get_active_nexthop(nxt_route);
                layer3_ipv6_plain_forward_nexthop(node, nexthop2, flavored_pkt);
                break;

             /* Only destinations implement USD */
            case USD:
                    NOOP; // Fall through

            default:
                srh->segments_left--;
                Srv6_copy_current_sid_to_DA (srh, ipv6_hdr);
                nxt_route = l3rib_v6lookup_lpm(
                                            NODE_V6RT_TABLE(node), &ipv6_hdr->dst_addr);
                nexthop2 = l3_v6route_get_active_nexthop(nxt_route);
                layer3_ipv6_plain_forward_nexthop(node, nexthop2, flavored_pkt);
        }

        pkt_block_dereference(flavored_pkt);
        return;
    }

    /*  case 5 : If the current node is destination node */
    assert (srh->segments_left == 0);   
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

    ipv6_route_t *x_route = l3rib_v6lookup_lpm(
                                                    NODE_V6RT_TABLE(node), &ipv6_hdr->dst_addr);
    
    v6nexthop_t *x_v6nexthop = l3_v6route_get_active_nexthop(x_route);

    /* case 1 : 
        When Router Recvs Already Decapsulated pkt. This would be destination router.
        It would happen when Penultimate router has already performed PSD. BAsed on
        payload type, pkt must go to that particular module for processing, not SRV6*/
        assert (ipv6_hdr);

    /* case 2 : 
        When the router recvs the pkt with outer ipv6 header but without SRH header. In 
        this case, remove outer ipv6 header and push the packet out of Interface. */
    if (!srh) {
        Srv6_decapsulate (node, orig_pkt);
        layer3_ipv6_plain_forward_nexthop(node, x_v6nexthop, orig_pkt);
        return;
    }

    /* case 3: 
        If the current node is intermediate node ( not event penultimate node ). Forward it to
        the nexthop. In this case, nexthop would be the directly connected node through this
        adjaceny sid.
     */
    if (srh->segments_left > 1) {

        srh->segments_left -= 1;
        Srv6_copy_current_sid_to_DA (srh, ipv6_hdr);
        layer3_ipv6_plain_forward_nexthop(node, x_v6nexthop, orig_pkt);
        return;
}

    /* case 4 : If the current node is  penultimate node */
    else if (srh->segments_left == 1) {

        pkt_block_t *flavored_pkt = Srv6_apply_flavor(
                node, orig_pkt, nexthop->u.srv6.srv6_flavors, srh->segments_left);

        pkt_block_reference(flavored_pkt);

        switch (nexthop->u.srv6.srv6_flavors) {

            case PSP:
                /* Push the packet along the directly attached link*/
                layer3_ipv6_plain_forward_nexthop(node, x_v6nexthop, flavored_pkt);
                break;

            case PSD:
                /*Router has removed outer ipv6_hdr and SRH header. Payload must be pushed to
                next router along the adjacency segment */
                layer3_ipv6_plain_forward_nexthop(node, x_v6nexthop, flavored_pkt);
                break;

             /* Only destinations implement USD */
            case USD:
                    NOOP; // Fall through

            default:
                srh->segments_left--;
                Srv6_copy_current_sid_to_DA (srh, ipv6_hdr);
                layer3_ipv6_plain_forward_nexthop(node, x_v6nexthop, flavored_pkt);
        }

        pkt_block_dereference(flavored_pkt);
        return;
    }

    /*  case 5 : If the current node is destination node. In this case, decap and
        emit the payload out of connected interface  */
    assert (srh->segments_left == 0);
    Srv6_decapsulate(node, orig_pkt);
    layer3_ipv6_plain_forward_nexthop(node, x_v6nexthop, orig_pkt);
}

ipv6_addr_t 
srv6_srh_get_destination_segment (srh_hdr_t *srh) {

    ipv6_addr_t dst_addr;
    memcpy (&dst_addr.addr, &srh->segments[0], 16);
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
            memcpy (&ipv6_hdr->dst_addr, &dst_addr.addr, 16);
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

        case ETH_IP:
             layer3_ip_route_pkt(node, NULL, pkt_block);
             return;
        case ETH_IP6:
            layer3_ipv6_route_pkt(node, NULL, pkt_block);
            return;
        default:
            cprintf ("%s() : SRv6 payload handler missing \n");
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
