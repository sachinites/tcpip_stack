#include <stdint.h>
#include "../ipv6_hdrs.h"
#include "Srv6.h"
#include "SRv6-EndPoint.h"
#include "../ipv6_route.h"
#include "../../graph.h"
#include "../../pkt_block.h"

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
                        ipv6_route_t *route) {

    bool flavor_applied = false;
    ipv6_addr_t dst_addr;

    assert (!route->is_direct);

    memcpy (&dst_addr.addr, ipv6_hdr->dst_addr, 16);

    /* Apply the flavors on the pkt */
    Srv6_flavor_t flavor = route->flavor;

    /* flavor will be PSP or PSD if i am penultimate router of the 'route' sid.
        In data path, I have no business to check whether i am Penultinate router
        or not by abalyzing the IGP topology */
    if ((flavor == PSP || flavor == PSD) ) {

        pkt_block_t *flavored_pkt = Srv6_apply_flavor(node, pkt_block, flavor, srh->segments_left);
        pkt_block = flavored_pkt;
        pkt_block_reference(pkt_block);
        flavor_applied = true;
    }

    layer3_ipv6_forward_nexthop(node, route, pkt_block);

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
                        srh_hdr_t *srh) {

    bool flavor_applied = false;

    /* Dont feed any non ipv6 pkt into SRv6 Data path pipeline. If the router recvs non-ipv6 pkt,
        It should be processed by non-v6 module*/
    assert (ipv6_hdr);

    /* Case 1 : If the pkt is not for me, then forward the packet using normal ipv6 routing
        Only flavor to be applied ( if required ) : PSP Or PSD associated with the dest sid If the current router is the penultimate of the Destination. (SL = 1 or not dont matter)
    */
    ipv6_route_t *route = l3rib_v6lookup_lpm(
                                            NODE_V6RT_TABLE(node), &ipv6_hdr->dst_addr);

    if (!route) drop_packet;
    
    if (! route->is_direct ) {
        Process_Srv6_remote_packet (node, recv_intf, pkt_block, ipv6_hdr, srh, route);
        return;
    }

    Srv6_apply_endpoint_fn (
                node, 
                recv_intf, 
                pkt_block, 
                ipv6_hdr, 
                srh, 
                route->endfn,
                route);
}

void 
Srv6_apply_endpoint_fn (
        node_t *node, 
        Interface *recv_intf, 
        pkt_block_t *pkt_block, 
        ipv6_hdr_t *ipv6_hdr, 
        srh_hdr_t *srh, 
        Srv6_endpcode_t endfn,
        ipv6_route_t *route) {

    switch (endfn) {

        /* Node is processing its prefix/node sid*/
        case END:
            Process_END(node, pkt_block, ipv6_hdr, srh, route);
            break;

        /* Node is processing its own Adjacency Sid*/
        case END_X:
            Process_END_X(node, recv_intf, pkt_block, ipv6_hdr, srh, route);
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
                        ipv6_route_t *route) {

    ipv6_route_t *nxt_route;

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
        layer3_ipv6_forward_nexthop(node, nxt_route, pkt_block);
        return;
    }
    
    /* case 4 : If the current node is  penultimate node */
    else if (srh->segments_left == 1) {

        /* Implement flavors */
        ipv6_addr_t dst_addr = srv6_srh_get_destination_segment (srh);

        pkt_block_t *flavored_pkt = Srv6_apply_flavor(
                node, pkt_block, route->flavor, srh->segments_left);

        pkt_block_reference(flavored_pkt);

        switch (route->flavor) {

            case PSP:
                nxt_route = l3rib_v6lookup_lpm(
                                            NODE_V6RT_TABLE(node), &ipv6_hdr->dst_addr);
                layer3_ipv6_forward_nexthop(node, nxt_route, flavored_pkt);
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

                layer3_ipv6_forward_nexthop(node, nxt_route, flavored_pkt);
                break;

             /* Only destinations implement USD */
            case USD:
                    NOOP; // Fall through

            default:
                srh->segments_left--;
                Srv6_copy_current_sid_to_DA (srh, ipv6_hdr);
                nxt_route = l3rib_v6lookup_lpm(
                                            NODE_V6RT_TABLE(node), &ipv6_hdr->dst_addr);
                layer3_ipv6_forward_nexthop(node, nxt_route, flavored_pkt);
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
                        ipv6_route_t *route) {

    ipv6_route_t *x_route = l3rib_v6lookup_lpm(
                                                    NODE_V6RT_TABLE(node), &ipv6_hdr->dst_addr);
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
        layer3_ipv6_forward_nexthop(node, x_route, orig_pkt);
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
        layer3_ipv6_forward_nexthop(node, x_route, orig_pkt);
        return;
}

    /* case 4 : If the current node is  penultimate node */
    else if (srh->segments_left == 1) {

        pkt_block_t *flavored_pkt = Srv6_apply_flavor(
                node, orig_pkt, route->flavor, srh->segments_left);

        pkt_block_reference(flavored_pkt);

        switch (route->flavor) {

            case PSP:
                /* Push the packet along the directly attached link*/
                layer3_ipv6_forward_nexthop(node, x_route, flavored_pkt);
                break;

            case PSD:
                /*Router has removed outer ipv6_hdr and SRH header. Payload must be pushed to
                next router along the adjacency segment */
                layer3_ipv6_forward_nexthop(node, x_route, flavored_pkt);
                break;

             /* Only destinations implement USD */
            case USD:
                    NOOP; // Fall through

            default:
                srh->segments_left--;
                Srv6_copy_current_sid_to_DA (srh, ipv6_hdr);
                layer3_ipv6_forward_nexthop(node, x_route, flavored_pkt);
        }

        pkt_block_dereference(flavored_pkt);
        return;
    }

    /*  case 5 : If the current node is destination node. In this case, decap and
        emit the payload out of connected interface  */
    assert (srh->segments_left == 0);
    Srv6_decapsulate(node, orig_pkt);
    layer3_ipv6_forward_nexthop(node, x_route, orig_pkt);
}

