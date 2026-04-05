/*
 * ============================================================================
 * File: srv6-endpoint.cpp
 * 
 * Description:
 *   This file implements SRv6 (Segment Routing over IPv6) endpoint processing
 *   in the data plane. It handles SRv6 packet processing including:
 *   - SRv6 flavors (PSP, USP, USD)
 *   - END, END.X, END.T endpoint functions
 *   - SRH (Segment Routing Header) manipulation
 *   - Encapsulation and decapsulation operations
 *   - Penultimate and ultimate segment processing
 *
 * Reference: RFC 8986 - SRv6 Network Programming
 * ============================================================================
 */

#include <stdint.h>
#include <assert.h>
#include "../../../libs/common/l3_hdrs.h"
#include "srv6-endpoint.h"
#include "../../../libs/common/ipv6_hdrs.h"
#include "../../Layer3/layer3.h"
#include "../../Layer3/ipv6/ipv6-fwd.h"
#include "../../../router_init.h"
#include "../../../libs/pkt-block/pkt_block.h"
#include "../../../libs/Tracer/tracer.h"
#include "../../../Interface/InterfaceUApi.h"
#include "srv6-end-behavior.h"
#include "../../FIB/fib_nh.h"
#include "../../FIB/fib.h"
#include "../../Vrfs/dp_vrf.h"

/* ============================================================================
 * External Function Declarations
 * ============================================================================
 */

/* Forward IPv6 packet using the specified nexthop */
extern void 
ipv6_layer3_forward_nexthop(
    dp_ctx_t *dp_ctx,
    dp_vrf_t *vrf,
    fib_nh_t *nexthop, 
    pkt_block_t *pkt_block);

/* Promote packet to Layer 4 for upper layer protocol processing */
extern void
dp2cp_punt_pkt_to_layer4(
    void *node,
    Interface *recv_intf,
    pkt_block_t *pkt_block,
    int L4_protocol_number);

/* Demote packet to Layer 2 for link-layer forwarding */
extern void
dp_demote_pkt_to_layer2(
    dp_ctx_t *dp_ctx,
    dp_vrf_t *vrf,
    uint32_t next_hop_ip,
    dp_intf_t *outgoing_intf,
    pkt_block_t *pkt_block,
    gen_proto_id_t hdr_type);

extern void
layer3_ip_route_pkt(dp_ctx_t *dp_ctx,
                    dp_vrf_t *vrf,
					dp_intf_t *interface,
					pkt_block_t *pkt_block);

extern void 
dp_send_pkt_out (dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block) ;


/* ============================================================================
 * Macro Definitions
 * ============================================================================
 */

#define drop_packet return;
#define NOOP    

/* ============================================================================
 * SRv6 Segment Routing Header Helper Functions
 * ============================================================================
 */

/**
 * srv6_srh_get_destination_segment()
 * 
 * Purpose:
 *   Extracts the destination segment (first segment) from the SRH.
 *   In SRv6, segments are processed in reverse order, so the destination
 *   segment is at index 0.
 * 
 * Parameters:
 *   @srh: Pointer to the Segment Routing Header
 * 
 * Returns:
 *   IPv6 address of the destination segment
 */
ipv6_addr_t 
srv6_srh_get_destination_segment(srh_hdr_t *srh) {
    ipv6_addr_t dst_addr;
    memcpy(&dst_addr.addr, srh->segments[0], 16);
    return dst_addr;
}


/* ============================================================================
 * SRv6 Flavor Processing Functions
 * 
 * SRv6 Flavors modify the behavior of endpoint functions:
 *   - PSP (Penultimate Segment Pop): Remove SRH before forwarding to final dest
 *   - USP (Ultimate Segment Pop): Remove SRH at final destination
 *   - USD (Ultimate Segment Decapsulation): Remove outer IPv6+SRH headers
 * ============================================================================
 */

/**
 * Srv6_apply_flavor()
 * 
 * Purpose:
 *   Applies SRv6 flavor modifications to the packet based on the flavor type.
 *   Handles PSP, USP, and USD flavors by manipulating the packet headers.
 * 
 * Parameters:
 *   @node:      Pointer to the node processing the packet
 *   @orig_pkt:  Original packet block to be modified
 *   @flavor:    Flavor bitmask (PSP, USP, USD or combinations)
 * 
 * Returns:
 *   Modified packet block with flavor applied
 * 
 * Processing:
 *   - PSP: Removes SRH and updates IPv6 header with destination segment
 *   - USP: Removes SRH if present, preserving IPv6 header
 *   - USD: Removes both IPv6 header and SRH, exposing inner packet
 */
pkt_block_t *
Srv6_apply_flavor(
                dp_ctx_t *dp_ctx,
                dp_vrf_t *vrf,
                pkt_block_t *orig_pkt,
                uint8_t flavor)
{
    assert(pkt_block_verify_pkt(orig_pkt, ETH_TYPE_IPv6));

    /* PSP (Penultimate Segment Pop) Flavor Processing */
    if (flavor & PSP) {
        pkt_size_t pkt_size = 0;
        byte *pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
        ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;
        ipv6_hdr_t ipv6_hdr_copy;
        
        /* Create a copy of IPv6 header for modification */
        memcpy(&ipv6_hdr_copy, ipv6_hdr, sizeof(ipv6_hdr_t));
        
        /* Get SRH and extract the destination segment */
        srh_hdr_t *srh = (srh_hdr_t *)(pkt + sizeof(ipv6_hdr_t));
        ipv6_addr_t dst_addr = srv6_srh_get_destination_segment(srh);
        
        /* Update IPv6 header: set DA to final segment, adjust next_header and length */
        memcpy(&ipv6_hdr_copy.dst_addr, &dst_addr.addr, 16);
        ipv6_hdr_copy.next_header = srh->nexthdr;
        ipv6_hdr_copy.payload_length -= srh->hdrlen;
        
        /* Remove IPv6 and SRH headers, keep only payload */
        byte *payload = pkt + sizeof(ipv6_hdr_t) + srh->hdrlen;
        pkt_block_set_new_pkt(orig_pkt, payload, 
                              pkt_size - sizeof(ipv6_hdr_t) - srh->hdrlen);
        
        /* Add modified IPv6 header back */
        pkt_block_expand_buffer_left(orig_pkt, sizeof(ipv6_hdr_t));
        pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
        memcpy(pkt, &ipv6_hdr_copy, sizeof(ipv6_hdr_t));
        pkt_block_update_new_hdr_type(orig_pkt, IP_PROTO_IPv6);
        
        return orig_pkt;
    }

    /* USP (Ultimate Segment Pop) Flavor Processing */
    if (flavor & USP) {
        pkt_size_t pkt_size = 0;
        byte *pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
        ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;
        
        /* Only process if SRH is present */
        if (ipv6_hdr->next_header != IP_PROTO_SRH) {
            return orig_pkt;
        }
        
        ipv6_hdr_t ipv6_hdr_copy;
        memcpy(&ipv6_hdr_copy, ipv6_hdr, sizeof(ipv6_hdr_t));
        
        /* Get SRH and its next header value */
        srh_hdr_t *srh = (srh_hdr_t *)(pkt + sizeof(ipv6_hdr_t));
        uint16_t srh_next_hdr = srh->nexthdr;
        
        /* Remove IPv6 and SRH headers, keep only payload */
        byte *payload = pkt + sizeof(ipv6_hdr_t) + srh->hdrlen;
        pkt_block_set_new_pkt(orig_pkt, payload, 
                              pkt_size - sizeof(ipv6_hdr_t) - srh->hdrlen);
        
        /* Add IPv6 header back with updated next_header field */
        pkt_block_expand_buffer_left(orig_pkt, sizeof(ipv6_hdr_t));
        pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
        ipv6_hdr_copy.next_header = srh_next_hdr;
        ipv6_hdr_copy.payload_length -= srh->hdrlen;
        memcpy(pkt, &ipv6_hdr_copy, sizeof(ipv6_hdr_t));
        pkt_block_update_new_hdr_type(orig_pkt, IP_PROTO_IPv6);
        
        return orig_pkt;
    }

    /* USD (Ultimate Segment Decapsulation) Flavor Processing */
    if (flavor & USD) {
        pkt_size_t pkt_size = 0;
        byte *pkt = pkt_block_get_pkt(orig_pkt, &pkt_size);
        ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;
        srh_hdr_t *srh = (srh_hdr_t *)(pkt + sizeof(ipv6_hdr_t));
        
        /* Remove outer IPv6 and SRH headers completely */
        byte *payload = pkt + sizeof(ipv6_hdr_t) + srh->hdrlen;
        pkt_block_set_new_pkt(orig_pkt, payload, 
                              pkt_size - sizeof(ipv6_hdr_t) - srh->hdrlen);
        pkt_block_update_new_hdr_type(orig_pkt, srh->nexthdr);
        
        return orig_pkt;
    }

    /* No flavor applied, return packet unchanged */
    return orig_pkt;
}

/* ============================================================================
 * SRv6 Packet Manipulation Functions
 * ============================================================================
 */

/**
 * Srv6_decapsulate()
 * 
 * Purpose:
 *   Decapsulates an SRv6 packet by removing the outer IPv6 header and
 *   optionally the SRH header, exposing the inner payload.
 * 
 * Parameters:
 *   @node:       Pointer to the node performing decapsulation
 *   @pkt_block:  Packet block to be decapsulated
 * 
 * Processing:
 *   1. Verify packet starts with IPv6 header
 *   2. If SRH is present, remove both IPv6 and SRH headers
 *   3. If no SRH, remove only IPv6 header
 *   4. Update packet header type to reflect the exposed payload
 */
void 
Srv6_decapsulate(pkt_block_t *pkt_block) {
    
    pkt_size_t pkt_size = 0;
    
    /* Only process IPv6 packets */
    if (pkt_block_get_starting_hdr(pkt_block) != ETH_TYPE_IPv6) {
        return;
    }
    
    byte *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);
    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;
    
    /* Case 1: No SRH present - remove only IPv6 header */
    if (ipv6_hdr->next_header != IP_PROTO_SRH) {
        pkt_block_set_new_pkt(pkt_block, 
                              (uint8_t *)(ipv6_hdr + 1), 
                              pkt_size - sizeof(ipv6_hdr_t));
        pkt_block_update_new_hdr_type(pkt_block, ipv6_hdr->next_header);
        return;
    }
    
    /* Case 2: SRH present - remove both IPv6 and SRH headers */
    srh_hdr_t *srh = (srh_hdr_t *)(ipv6_hdr + 1);
    byte *payload = pkt + sizeof(ipv6_hdr_t) + srh->hdrlen;
    pkt_block_set_new_pkt(pkt_block, 
                          payload, 
                          pkt_size - sizeof(ipv6_hdr_t) - srh->hdrlen);
    
    pkt_block_update_new_hdr_type(pkt_block, srh->nexthdr);
}

/**
 * Srv6_copy_current_sid_to_DA()
 * 
 * Purpose:
 *   Copies the current SID (Segment Identifier) from the SRH segment list
 *   to the IPv6 destination address field. This is part of the segment
 *   processing mechanism in SRv6.
 * 
 * Parameters:
 *   @srh:       Pointer to Segment Routing Header
 *   @ipv6_hdr:  Pointer to IPv6 header to update
 * 
 * Note:
 *   The current segment is determined by the segments_left counter in SRH.
 */
void 
Srv6_copy_current_sid_to_DA(srh_hdr_t *srh, ipv6_hdr_t *ipv6_hdr) {
    memcpy(ipv6_hdr->dst_addr, srh->segments[srh->segments_left], 16);
}

/**
 * ipv6_process_v6_payload()
 * 
 * Purpose:
 *   Processes the payload after SRv6 decapsulation by re-injecting it into
 *   the appropriate data plane pipeline based on the inner header type.
 * 
 * Parameters:
 *   @node:       Pointer to the node processing the packet
 *   @pkt_block:  Packet block containing the decapsulated payload
 * 
 * Processing:
 *   Examines the inner header type and routes the packet to:
 *   - Layer 3 routing (IPv4/IPv6)
 *   - Layer 4 processing (TCP/UDP)
 *   - ICMP6 handling
 *   - Other protocol handlers
 */
void 
ipv6_process_v6_payload(dp_ctx_t *dp_ctx, 
                        dp_vrf_t *vrf, 
                        pkt_block_t *pkt_block) {

    gen_proto_id_t hdr_type = pkt_block_get_starting_hdr(pkt_block);

    /* Re-inject the packet into the appropriate data path pipeline */
    switch (hdr_type) {
        
        case IP_PROTO_IP_IN_IP:
            /* Inner packet is IPv4 - route it */
            layer3_ip_route_pkt(dp_ctx, vrf,  NULL, pkt_block);
            return;
            
        case IP_PROTO_IPv6:
            /* Inner packet is IPv6 - route it */
            layer3_ipv6_route_pkt(dp_ctx, vrf,  NULL, pkt_block, NULL);
            return;
            
        case IP_PROTO_ICMPv6:
            /* ICMPv6 packet - typically ping response */
            cprintf("ipv6 ping success\n");
            break;
            
        case IP_PROTO_TCP:
            /* Promote to Layer 4 TCP processing */
            dp2cp_punt_pkt_to_layer4(dp_ctx->ctx_pvt_data, NULL, pkt_block, IP_PROTO_TCP);
            return;
            
        case IP_PROTO_UDP:
            /* Promote to Layer 4 UDP processing */
            dp2cp_punt_pkt_to_layer4(dp_ctx->ctx_pvt_data, NULL, pkt_block, IP_PROTO_UDP);
            return;
            
        case IP_PROTO_GRE:
            /* GRE tunnel - handler not yet implemented */
            break;
            
        case IP_PROTO_IPv6_ROUTE:
            /* SRH received at non-SRv6 capable node - drop */
            cprintf("%s : SRv6 incapable node received SRH header packet, dropped\n",
                    dp_ctx->ctx_name);
            break;
            
        default:
            /* Unknown or unsupported protocol */
            cprintf("%s : SRv6 payload handler missing for protocol type\n", 
                    dp_ctx->ctx_name);
            break;
    }
}

/* ============================================================================
 * SRv6 Encapsulation Functions
 * ============================================================================
 */

/**
 * srh_hdr_prepare()
 * 
 * Purpose:
 *   Prepares a new Segment Routing Header (SRH) from a given segment list.
 *   The segments are stored in reverse order as per SRv6 specification.
 * 
 * Parameters:
 *   @segment_lst: Array of IPv6 addresses representing the segment list
 *   @n:           Number of segments in the list
 * 
 * Returns:
 *   Pointer to newly allocated and initialized SRH header
 * 
 * SRH Structure:
 *   - nexthdr: Next header type (filled later during encapsulation)
 *   - hdrlen: Total length of SRH including all segments
 *   - type: SRH type (4 for SRv6)
 *   - segments_left: Number of segments remaining to process
 *   - segments[]: Array of segment identifiers in reverse order
 * 
 * Note:
 *   Segments are copied in reverse order because SRv6 processes them
 *   from last to first (segments_left counter decrements).
 */
srh_hdr_t *
srh_hdr_prepare(ipv6_addr_t *segment_lst, uint8_t n) {
    /* Allocate memory for SRH + segment list (each segment is 16 bytes) */
    srh_hdr_t *srh = (srh_hdr_t *)XCALLOC_BUFF(0, sizeof(srh_hdr_t) + n * 16);
    
    /* Initialize SRH fields */
    srh->nexthdr = 0;                                    /* Set later during encap */
    srh->hdrlen = sizeof(srh_hdr_t) + n * 16;           /* Total header length */
    srh->type = 4;                                       /* SRv6 type */
    srh->segments_left = n;                              /* All segments active */
    srh->first_segment = 0;                              /* Index of first segment */
    srh->flags = 0;                                      /* No flags set */
    srh->tag = 0;                                        /* No tag */
    
    /* Copy segments in reverse order */
    for (int i = 0, j = n; i < n; i++) {
        memcpy(srh->segments[j - i - 1], segment_lst[i].addr, 16);
    }
    
    return srh;
}

/**
 * Srv6_encapsulate()
 * 
 * Purpose:
 *   Encapsulates a packet with SRv6 headers (IPv6 + SRH). This is used when
 *   inserting a packet into an SRv6 segment routing path.
 * 
 * Parameters:
 *   @pkt_block: Packet block to encapsulate
 *   @srh:       Pre-prepared Segment Routing Header
 * 
 * Processing Steps:
 *   1. Prepend SRH to the existing packet
 *   2. Set SRH's next_header to point to the original packet type
 *   3. Prepend IPv6 header
 *   4. Set IPv6 DA to the first active segment (bottom-most in segment list)
 *   5. Decrement segments_left as we're consuming the first segment
 * 
 * Packet Structure After Encapsulation:
 *   [Ethernet] [IPv6 Hdr] [SRH] [Original Packet]
 * 
 * Note:
 *   Source address is left as zeros (will be filled by lower layers).
 *   Destination address is set to the first segment to be processed.
 */
void 
Srv6_encapsulate(pkt_block_t *pkt_block, srh_hdr_t *srh) {

    pkt_size_t pkt_size = 0;

    /* Step 1: Add SRH header first */
    gen_proto_id_t hdr_type = pkt_block_get_starting_hdr(pkt_block);
    pkt_block_expand_buffer_left(pkt_block, srh->hdrlen);
    byte *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);
    memcpy(pkt, srh, srh->hdrlen);
    
    /* Update SRH's next_header to point to the encapsulated packet type */
    srh_hdr_t *new_srh = (srh_hdr_t *)pkt;
    new_srh->nexthdr = (uint8_t)hdr_type;
    pkt_block_update_new_hdr_type(pkt_block, IP_PROTO_SRH);

    /* Step 2: Add IPv6 header */
    pkt_block_expand_buffer_left(pkt_block, sizeof(ipv6_hdr_t));
    pkt = pkt_block_get_pkt(pkt_block, &pkt_size);
    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt;
    
    /* Initialize IPv6 header with default values */
    initialize_ipv6_hdr(ipv6_hdr);
    ipv6_hdr->next_header = IP_PROTO_SRH;
    ipv6_hdr->payload_length = pkt_size - sizeof(ipv6_hdr_t);
    
    /* Source address: Not known at this point, filled with zeros */
    /* Will be set by routing layer based on outgoing interface */
    
    /* Destination address: Set to the first segment to process */
    /* This is the bottom-most segment in the SRH segment list */
    new_srh->segments_left--;
    memcpy(ipv6_hdr->dst_addr, 
           new_srh->segments[new_srh->segments_left], 
           16);

    /* Update packet header type to indicate IPv6 packet */
    pkt_block_update_new_hdr_type(pkt_block, IP_PROTO_IPv6);
}


/* ============================================================================
 * SRv6 Endpoint Flavor Processing Functions
 * 
 * These functions handle different combinations of SRv6 flavors at:
 *   - Penultimate node (segments_left == 1)
 *   - Ultimate node (segments_left == 0)
 * 
 * For each endpoint function type (END, END.X, END.T), we have separate
 * handlers for penultimate and ultimate processing with various flavor
 * combinations.
 * ============================================================================
 */

/**
 * Process_END_flavors_penultimate()
 * 
 * Purpose:
 *   Processes END function with flavors at the penultimate segment node.
 *   The penultimate node is the second-to-last node in the segment path
 *   (segments_left == 1).
 * 
 * Parameters:
 *   @node:       Current processing node
 *   @pkt_block:  Packet being processed
 *   @ipv6_hdr:   IPv6 header pointer
 *   @srh:        Segment Routing Header pointer
 *   @nexthop:    Next hop information
 *   @flavor:     Flavor bitmask (PSP, USP, USD combinations)
 * 
 * Supported Flavor Combinations:
 *   - No flavor (base END function)
 *   - PSP: Pop SRH before forwarding to final destination
 *   - PSP | USP: Penultimate pops SRH, ultimate pops if present
 *   - PSP | USD: Penultimate pops SRH, ultimate decapsulates
 *   - PSP | USP | USD: All three flavors combined
 */
static void 
Process_END_flavors_penultimate(
    dp_ctx_t *dp_ctx,
    dp_vrf_t *vrf,
    pkt_block_t *pkt_block, 
    ipv6_hdr_t *ipv6_hdr, 
    srh_hdr_t *srh,  
    fib_nh_t *nexthop, 
    uint8_t flavor)
{
    assert(srh && srh->segments_left == 1);
    assert(ipv6_hdr);
    assert(nexthop);

    switch (flavor) {
        case 0:
            /* Base END function without any flavor */
            srv6_END(dp_ctx, vrf, pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP:
            /* Penultimate Segment Pop flavor */
            srv6_END_w_PSP(dp_ctx, vrf, pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USP:
            /* PSP + Ultimate Segment Pop combination */
            srv6_END_w_PSP_USP(dp_ctx, vrf, pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USD:
            /* PSP + Ultimate Segment Decapsulation combination */
            srv6_END_w_PSP_USD(dp_ctx, vrf, pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USP | USD:
            /* All three flavors combined */
            srv6_END_w_PSP_USP_USD(dp_ctx, vrf, pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        default:
            /* Invalid flavor combination */
            assert(0);
    }
}

/**
 * Process_END_X_flavors_penultimate()
 * 
 * Purpose:
 *   Processes END.X function with flavors at the penultimate segment node.
 *   END.X specifies both the next segment AND the outgoing interface/nexthop,
 *   providing explicit Layer 3 cross-connect functionality.
 * 
 * Parameters:
 *   @node:       Current processing node
 *   @pkt_block:  Packet being processed
 *   @ipv6_hdr:   IPv6 header pointer
 *   @srh:        Segment Routing Header pointer
 *   @nexthop:    Next hop information (includes explicit cross-connect info)
 *   @flavor:     Flavor bitmask (PSP, USP, USD combinations)
 * 
 * END.X vs END:
 *   - END: Performs route lookup for next hop
 *   - END.X: Uses pre-configured explicit next hop (no route lookup needed)
 */
static void
Process_END_X_flavors_penultimate(
    dp_ctx_t *dp_ctx, 
    dp_vrf_t *vrf,
    pkt_block_t *pkt_block,
    ipv6_hdr_t *ipv6_hdr,
    srh_hdr_t *srh,
    fib_nh_t *nexthop,
    uint8_t flavor)
{
    assert(srh && srh->segments_left == 1);
    assert(ipv6_hdr);
    assert(nexthop);

    switch (flavor) {
        case 0:
            /* Base END.X function without any flavor */
            srv6_END_X(dp_ctx, vrf, pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP:
            /* END.X with Penultimate Segment Pop */
            srv6_END_X_w_PSP(dp_ctx, vrf, pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USP:
            /* END.X with PSP + USP flavors */
            srv6_END_X_w_PSP_USP(dp_ctx, vrf, pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USD:
            /* END.X with PSP + USD flavors */
            srv6_END_X_w_PSP_USD(dp_ctx, vrf, pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USP | USD:
            /* END.X with all three flavors */
            srv6_END_X_w_PSP_USP_USD(dp_ctx, vrf, pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        default:
            /* Invalid flavor combination */
            assert(0);
    }
}

/**
 * Process_END_T_flavors_penultimate()
 * 
 * Purpose:
 *   Processes END.T function with flavors at the penultimate segment node.
 *   END.T performs VRF (Virtual Routing and Forwarding) table lookup,
 *   enabling SRv6 to cross VRF boundaries.
 * 
 * Parameters:
 *   @node:       Current processing node
 *   @pkt_block:  Packet being processed
 *   @ipv6_hdr:   IPv6 header pointer
 *   @srh:        Segment Routing Header pointer
 *   @nexthop:    Next hop information (includes VRF context)
 *   @flavor:     Flavor bitmask (PSP, USP, USD combinations)
 * 
 * END.T Functionality:
 *   Decapsulates the packet and performs route lookup in a specific VRF table,
 *   allowing traffic to be steered between different routing domains.
 */
static void
Process_END_T_flavors_penultimate(
    dp_ctx_t *dp_ctx, 
    dp_vrf_t *vrf,
    pkt_block_t *pkt_block,
    ipv6_hdr_t *ipv6_hdr,
    srh_hdr_t *srh,
    fib_nh_t *nexthop,
    uint8_t flavor)
{
    assert(srh && srh->segments_left == 1);
    assert(ipv6_hdr);
    assert(nexthop);

    switch (flavor) {
        case 0:
            /* Base END.T function without any flavor */
            srv6_END_T(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP:
            /* END.T with Penultimate Segment Pop */
            srv6_END_T_w_PSP(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USP:
            /* END.T with PSP + USP flavors */
            srv6_END_T_w_PSP_USP(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USD:
            /* END.T with PSP + USD flavors */
            srv6_END_T_w_PSP_USD(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USP | USD:
            /* END.T with all three flavors */
            srv6_END_T_w_PSP_USP_USD(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        default:
            /* Invalid flavor combination */
            assert(0);
    }
}

/**
 * Srv6_apply_penultimate_processing()
 * 
 * Purpose:
 *   Applies SRv6 penultimate node processing when segments_left == 1.
 *   The penultimate node is responsible for potentially removing the SRH
 *   (if PSP flavor is set) before forwarding to the final destination.
 * 
 * Parameters:
 *   @node:       Current processing node
 *   @pkt_block:  Packet being processed
 *   @ipv6_hdr:   IPv6 header pointer
 *   @srh:        Segment Routing Header pointer
 * 
 * Processing Steps:
 *   1. Perform route lookup for the current destination (last segment)
 *   2. Extract the endpoint function and flavor from the route
 *   3. Dispatch to appropriate flavor handler based on endpoint type
 * 
 * Reference:
 *   RFC 8986 - SRv6 Network Programming, Section 4.1
 *   https://www.rfc-editor.org/rfc/rfc8986.pdf : page 23
 * 
 * Note:
 *   The penultimate node uses the endpoint function configuration of the
 *   final destination to determine how to process the packet (e.g., whether
 *   to apply PSP flavor).
 */
void 
Srv6_apply_penultimate_processing(
        dp_ctx_t *dp_ctx,
        dp_vrf_t *vrf, 
        pkt_block_t *pkt_block, 
        ipv6_hdr_t *ipv6_hdr, 
        srh_hdr_t *srh)
{
    uint8_t flavor = 0;

    assert(srh && srh->segments_left == 1);

    cmn_prefix_t prefix;
    cmn_prefix_initialize_v6(&prefix, &ipv6_hdr->dst_addr, 128);
    fib_nh_t *nexthop = fib_get_forwarding_nh(vrf->fib_inet6, &prefix);

    if (!nexthop) {
        /* No route found - drop the packet */
        tracer(dp_ctx->dptr, DL3FWD, 
               "Pkt : %s : No SRV6 route found, packet dropped\n",  
               pkt_block_str(pkt_block));
        return;
    }

    /* Extract endpoint function and flavor from the composite value */
    Srv6_endpcode_t CompositeEndfn = nexthop->fwd_info->u.v6_fwd.endfn;
    Srv6_endpcode_t endfn = srv6_split_endpcode(CompositeEndfn, &flavor);

    /* Dispatch to appropriate endpoint function handler with flavor */
    switch (endfn) {
        case END:
            /* Process END function variants */
            Process_END_flavors_penultimate(dp_ctx, vrf,  pkt_block, ipv6_hdr, 
                                            srh, nexthop, flavor);
            break;
            
        case END_X:
            /* Process END.X function variants */
            Process_END_X_flavors_penultimate(dp_ctx, vrf,  pkt_block, ipv6_hdr, 
                                              srh, nexthop, flavor);
            break;
            
        case END_T:
            /* Process END.T function variants */
            Process_END_T_flavors_penultimate(dp_ctx, vrf,  pkt_block, ipv6_hdr, 
                                              srh, nexthop, flavor);
            break;
            
        default:
            /* Unknown endpoint function - no action */
            break;
    }
}

/* ============================================================================
 * SRv6 Packet Processing Main Functions
 * ============================================================================
 */

/**
 * Process_Srv6_remote_packet()
 * 
 * Purpose:
 *   Processes SRv6 packets whose destination is NOT a local SID of the router.
 *   These are transit packets that need to be forwarded to the next hop.
 * 
 * Parameters:
 *   @node:       Current processing node
 *   @recv_intf:  Interface on which packet was received
 *   @pkt_block:  Packet being processed
 *   @ipv6_hdr:   IPv6 header pointer
 *   @srh:        Segment Routing Header pointer (may be NULL)
 *   @nexthop:    Next hop information for forwarding
 * 
 * Processing:
 *   - For regular SRv6 routes: Forward packet to next hop
 *   - For binding SID routes: Apply segment list encapsulation (TODO)
 * 
 * Note:
 *   Binding SID functionality is currently commented out and needs to be
 *   implemented. When implemented, it will encapsulate the packet with a
 *   new segment list associated with the binding SID.
 */
static void 
Process_Srv6_remote_packet(
    dp_ctx_t *dp_ctx, 
    dp_vrf_t *vrf, 
    Interface* recv_intf,
    pkt_block_t *pkt_block, 
    ipv6_hdr_t *ipv6_hdr, 
    srh_hdr_t *srh,
    fib_nh_t *nexthop)
{
    /* TODO: Handle Binding SID case */
    /* If nexthop is a binding SID, mount the segment list on the packet */
    // if (nexthop->flags & BINDING_SID) {
    //     /* Apply segment list encapsulation */
    // }

    /* Forward packet using standard IPv6 layer 3 forwarding */
    ipv6_layer3_forward_nexthop(dp_ctx, vrf, nexthop, pkt_block);
}

/**
 * Process_Srv6_Packet()
 * 
 * Purpose:
 *   Main entry point for SRv6 packet processing. Dispatches packets to
 *   appropriate handlers based on the segments_left (SL) value in the SRH.
 * 
 * Parameters:
 *   @node:       Current processing node
 *   @recv_intf:  Interface on which packet was received
 *   @pkt_block:  Packet being processed
 *   @ipv6_hdr:   IPv6 header pointer
 *   @srh:        Segment Routing Header pointer (may be NULL)
 *   @nexthop:    Next hop information from route lookup
 * 
 * Processing Logic (based on segments_left value):
 * 
 *   segments_left == 1 (Penultimate Node):
 *     - Apply penultimate segment processing
 *     - May remove SRH if PSP flavor is set
 *     - Forward to final destination
 * 
 *   segments_left == 0 OR no SRH (Ultimate/Destination Node):
 *     - This node is the destination of the current segment
 *     - Apply endpoint function (END, END.X, END.T, etc.)
 *     - May decapsulate or forward to next layer
 * 
 *   segments_left > 1 (Transit Node):
 *     - This node is a transit point in the segment path
 *     - Update IPv6 DA to next segment (shift operation)
 *     - Forward packet to next hop
 * 
 * Reference:
 *   RFC 8754 - IPv6 Segment Routing Header (SRH)
 *   RFC 8986 - SRv6 Network Programming
 */
void
Process_Srv6_Packet(
        dp_ctx_t *dp_ctx, 
        dp_vrf_t *vrf,
        dp_intf_t* recv_intf,
        pkt_block_t *pkt_block, 
        ipv6_hdr_t *ipv6_hdr, 
        srh_hdr_t *srh,
        fib_nh_t *nexthop)
{
    /* Validate nexthop exists */
    if (!nexthop) {
        return;
    }

    /* SRv6 only processes IPv6 packets */
    /* Non-IPv6 packets should be handled by their respective modules */
    assert(ipv6_hdr);

    /*
     * At this point, we have hit an SRv6 route with an endpoint function.
     * The processing path depends on the segments_left (SL) value in SRH.
     */

    /* ========================================================================
     * Case 1: Penultimate Segment Processing (segments_left == 1)
     * ======================================================================== */
    if (srh && srh->segments_left == 1) {
        /*
         * This node is the penultimate (second-to-last) node in the path.
         * Apply penultimate processing which may include:
         *   - PSP flavor: Remove SRH before forwarding to final destination
         *   - Standard forwarding to the ultimate segment node
         */
        Srv6_apply_penultimate_processing(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh);
        return;
    }

    /* ========================================================================
     * Case 2: Ultimate Segment Processing (segments_left == 0 or no SRH)
     * ======================================================================== */
    if (!srh || srh->segments_left == 0) {
        /*
         * This node is the destination of the current segment.
         * Apply the configured endpoint function:
         *   - END: Update segment and route lookup
         *   - END.X: Update segment and use explicit next hop
         *   - END.T: Update segment and lookup in specific VRF
         *   - END.B6.ENCAP: Binding SID encapsulation
         *   - Others: Various specialized functions
         * 
         * Flavors (USP, USD) may also be applied at this stage.
         */
        Srv6_apply_endpoint_fn(
            dp_ctx, 
            vrf,
            recv_intf, 
            pkt_block,
            ipv6_hdr, 
            srh,
            nexthop); 
        return;
    }

    /* ========================================================================
     * Case 3: Transit Segment Processing (segments_left > 1)
     * ======================================================================== */
    if (srh->segments_left > 1) {
        /*
         * This node is a transit node in the middle of the segment path.
         * Processing is the same regardless of endpoint function type:
         *   1. Decrement segments_left
         *   2. Copy segments[segments_left] to IPv6 destination address
         *   3. Forward packet to next hop
         * 
         * This is called "shift and forward" operation.
         */
        srv6_shift_and_forward(dp_ctx, vrf, pkt_block);
    }
}

/* ============================================================================
 * Ultimate Segment Flavor Processing Functions
 * 
 * These functions handle flavor processing at the ultimate (final) segment
 * node where segments_left == 0. Unlike penultimate processing, PSP flavor
 * is not applicable here (it's already been applied at penultimate node).
 * ============================================================================
 */

/**
 * Process_END_flavors_ultimate()
 * 
 * Purpose:
 *   Processes END function with flavors at the ultimate (final) segment node.
 *   This is where the packet reaches its destination segment.
 * 
 * Parameters:
 *   @node:       Current processing node
 *   @pkt_block:  Packet being processed
 *   @ipv6_hdr:   IPv6 header pointer
 *   @srh:        Segment Routing Header pointer (may be NULL or SL=0)
 *   @nexthop:    Next hop information
 *   @flavor:     Flavor bitmask (USP, USD, PSP combinations)
 * 
 * Supported Flavor Combinations at Ultimate Node:
 *   - No flavor: Base END function
 *   - USP: Pop SRH at ultimate node
 *   - USD: Decapsulate entire outer IPv6+SRH
 *   - PSP | USP: SRH already removed by penultimate, USP is redundant
 *   - PSP | USD: PSP done at penultimate, USD done here
 *   - PSP | USP | USD: All flavors combined
 * 
 * Note:
 *   If an invalid or non-applicable flavor is specified (e.g., only PSP
 *   without USP/USD), the function falls back to base END behavior.
 */
static void
Process_END_flavors_ultimate(
    dp_ctx_t *dp_ctx, 
    dp_vrf_t *vrf,
    pkt_block_t *pkt_block,
    ipv6_hdr_t *ipv6_hdr,
    srh_hdr_t *srh,
    fib_nh_t *nexthop,
    uint8_t flavor)
{
    assert(!srh || srh->segments_left == 0);
    assert(ipv6_hdr);
    assert(nexthop);

    switch (flavor) {
        case 0:
            /* Base END function without any flavor */
            srv6_END(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case USP:
            /* Ultimate Segment Pop: Remove SRH at destination */
            srv6_END_w_USP(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USP:
            /*
             * PSP already applied at penultimate node
             * USP applies here at ultimate node
             */
            srv6_END_w_PSP_USP(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case USD:
            /* Ultimate Segment Decapsulation: Remove outer headers */
            srv6_END_w_USD(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USD:
            /*
             * PSP applied at penultimate (SRH removed there)
             * USD applies here (decapsulate outer IPv6)
             */
            srv6_END_w_PSP_USD(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USP | USD:
            /* All three flavors combined */
            srv6_END_w_PSP_USP_USD(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        default:
            /*
             * Invalid or non-applicable flavor for ultimate node
             * (e.g., PSP alone is not valid at ultimate node)
             * Fall back to base END behavior
             */
            srv6_END(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
    }
}

/**
 * Process_END_X_flavors_ultimate()
 * 
 * Purpose:
 *   Processes END.X function with flavors at the ultimate (final) segment node.
 *   END.X combines segment endpoint processing with explicit Layer 3 cross-connect,
 *   specifying both the destination and the outgoing interface/nexthop.
 * 
 * Parameters:
 *   @node:       Current processing node
 *   @pkt_block:  Packet being processed
 *   @ipv6_hdr:   IPv6 header pointer
 *   @srh:        Segment Routing Header pointer (segments_left should be 0)
 *   @nexthop:    Pre-configured explicit next hop (no route lookup needed)
 *   @flavor:     Flavor bitmask (USP, USD, PSP combinations)
 * 
 * Note:
 *   The assertion "segments_left == 1" appears to be an error in the original
 *   code. For ultimate processing, it should be segments_left == 0 or no SRH.
 *   This function is called from ultimate processing context.
 */
static void
Process_END_X_flavors_ultimate(
    dp_ctx_t *dp_ctx, 
    dp_vrf_t *vrf,
    pkt_block_t *pkt_block,
    ipv6_hdr_t *ipv6_hdr,
    srh_hdr_t *srh,
    fib_nh_t *nexthop,
    uint8_t flavor)
{
    /* Note: Original assertion may be incorrect - should check segments_left == 0 */
    assert(srh && srh->segments_left == 1);
    assert(ipv6_hdr);
    assert(nexthop);

    switch (flavor) {
        case 0:
            /* Base END.X function without any flavor */
            srv6_END_X(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case USP:
            /* END.X with Ultimate Segment Pop */
            srv6_END_X_w_USP(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case USD:
            /* END.X with Ultimate Segment Decapsulation */
            srv6_END_X_w_USD(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USP:
            /* END.X with PSP (done at penultimate) + USP (done here) */
            srv6_END_X_w_PSP_USP(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case USP | USD:
            /* END.X with both USP and USD flavors */
            srv6_END_X_w_USP_USD(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USD:
            /* END.X with PSP (done at penultimate) + USD (done here) */
            srv6_END_X_w_PSP_USD(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USP | USD:
            /* END.X with all three flavors combined */
            srv6_END_X_w_PSP_USP_USD(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        default:
            /* Invalid flavor combination */
            assert(0);
    }
}

/**
 * Process_END_T_flavors_ultimate()
 * 
 * Purpose:
 *   Processes END.T function with flavors at the ultimate (final) segment node.
 *   END.T performs VRF-aware processing, allowing SRv6 to cross VRF boundaries
 *   by performing route lookup in a specific VRF table.
 * 
 * Parameters:
 *   @node:       Current processing node
 *   @pkt_block:  Packet being processed
 *   @ipv6_hdr:   IPv6 header pointer
 *   @srh:        Segment Routing Header pointer (segments_left should be 0)
 *   @nexthop:    Next hop information including VRF context
 *   @flavor:     Flavor bitmask (USP, USD, PSP combinations)
 * 
 * END.T Use Cases:
 *   - Inter-VRF traffic steering
 *   - Service chaining across routing domains
 *   - Multi-tenant network segmentation
 * 
 * Note:
 *   Similar to END.X, the assertion "segments_left == 1" may be incorrect
 *   for ultimate processing context.
 */
static void 
Process_END_T_flavors_ultimate(
    dp_ctx_t *dp_ctx, 
    dp_vrf_t *vrf,
    pkt_block_t *pkt_block, 
    ipv6_hdr_t *ipv6_hdr, 
    srh_hdr_t *srh,  
    fib_nh_t *nexthop, 
    uint8_t flavor)
{
    /* Note: Original assertion may be incorrect - should check segments_left == 0 */
    assert(srh && srh->segments_left == 1);
    assert(ipv6_hdr);
    assert(nexthop);

    switch (flavor) {
        case 0:
            /* Base END.T function without any flavor */
            srv6_END_T(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case USP:
            /* END.T with Ultimate Segment Pop */
            srv6_END_T_w_USP(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USP:
            /* END.T with PSP (done at penultimate) + USP (done here) */
            srv6_END_T_w_PSP_USP(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case USD:
            /* END.T with Ultimate Segment Decapsulation */
            srv6_END_T_w_USD(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USD:
            /* END.T with PSP (done at penultimate) + USD (done here) */
            srv6_END_T_w_PSP_USD(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case USP | USD:
            /* END.T with both USP and USD flavors */
            srv6_END_T_w_USP_USD(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        case PSP | USP | USD:
            /* END.T with all three flavors combined */
            srv6_END_T_w_PSP_USP_USD(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;
            
        default:
            /* Invalid flavor combination */
            assert(0);
    }
}


/* ============================================================================
 * Main SRv6 Endpoint Function Dispatcher
 * ============================================================================
 */

/**
 * Srv6_apply_endpoint_fn()
 * 
 * Purpose:
 *   Main dispatcher for applying SRv6 endpoint functions at the ultimate
 *   (destination) segment node. This function is called when the packet
 *   reaches a node whose address matches the current segment destination.
 * 
 * Parameters:
 *   @node:       Current processing node
 *   @recv_intf:  Interface on which packet was received
 *   @pkt_block:  Packet being processed
 *   @ipv6_hdr:   IPv6 header pointer
 *   @srh:        Segment Routing Header pointer (may be NULL or SL=0)
 *   @nexthop:    Next hop containing endpoint function configuration
 * 
 * Endpoint Functions:
 * 
 *   END - Basic Endpoint Function:
 *     - Update DA to next segment (if segments remain)
 *     - Perform route lookup for next destination
 *     - Most common endpoint function
 *     - Used for: Node SID, Prefix SID
 * 
 *   END.X - Endpoint with Layer 3 Cross-connect:
 *     - Similar to END but uses explicit next hop
 *     - No route lookup needed
 *     - Used for: Adjacency SID, explicit paths
 *     - Provides fast forwarding by avoiding FIB lookup
 * 
 *   END.T - Endpoint with VRF Table lookup:
 *     - Performs route lookup in specific VRF table
 *     - Enables inter-VRF traffic steering
 *     - Used for: Multi-tenant networks, service chaining
 * 
 *   END.B6.ENCAP - Binding SID with Encapsulation:
 *     - Encapsulates packet with new segment list
 *     - Used for: Policy-based routing, traffic engineering
 *     - Enables hierarchical segment routing
 * 
 * Processing Steps:
 *   1. Extract composite endpoint function from nexthop
 *   2. Split into base function and flavor components
 *   3. Log the endpoint function being applied (for debugging)
 *   4. Validate segments_left is 0 (ultimate node condition)
 *   5. Dispatch to appropriate flavor handler
 * 
 * Reference:
 *   RFC 8986 - SRv6 Network Programming
 *   Section 4: SRv6 Endpoint Behaviors
 */
void 
Srv6_apply_endpoint_fn(
    dp_ctx_t *dp_ctx, 
    dp_vrf_t *vrf,
    dp_intf_t *recv_intf, 
    pkt_block_t *pkt_block, 
    ipv6_hdr_t *ipv6_hdr, 
    srh_hdr_t *srh, 
    fib_nh_t *nexthop)
{ 

    /* Extract endpoint function and flavor from nexthop configuration */
    Srv6_endpcode_t CompositeEndfn = nexthop->fwd_info->u.v6_fwd.endfn;
    uint8_t flavor = 0;
    Srv6_endpcode_t endfn = srv6_split_endpcode(CompositeEndfn, &flavor);

    /* Log endpoint function application for debugging/tracing */
    tracer(dp_ctx->dptr, DL3FWD, 
           "Pkt : %s : Applying SRv6 endpoint function : %s\n", 
           pkt_block_str(pkt_block), 
           srv6_end_fn_str(CompositeEndfn));

    /* Validate this is ultimate segment processing (SL == 0 or no SRH) */
    assert(!srh || (srh->segments_left == 0));
    assert(ipv6_hdr);

    /* Dispatch to appropriate endpoint function handler */
    switch (endfn) {
        case END:
            /* Process END function variants with flavors */
            /* Used when node is processing its own prefix/node SID */
            Process_END_flavors_ultimate(dp_ctx, vrf,  pkt_block, ipv6_hdr, 
                                         srh, nexthop, flavor);
            break;

        case END_X:
            /* Process END.X function variants with flavors */
            /* Used when node is processing its own Adjacency SID */
            Process_END_X_flavors_ultimate(dp_ctx, vrf,  pkt_block, ipv6_hdr, 
                                           srh, nexthop, flavor);
            break;

        case END_T:
            /* Process END.T function variants with flavors */
            /* Used for VRF-aware endpoint processing */
            Process_END_T_flavors_ultimate(dp_ctx, vrf,  pkt_block, ipv6_hdr, 
                                           srh, nexthop, flavor);
            break;

        case END_B6_ENCAP:
            /* Process Binding SID with encapsulation */
            /* No flavors supported for this function */
            srv6_END_B6_ENCAP(dp_ctx, vrf,  pkt_block, ipv6_hdr, srh, nexthop);
            break;

        case END_DT4:
            /* L3VPN case, Egress PE router processing */
            //srv6_END_DT4(dp_ctx, vrf, pkt_block, ipv6_hdr, srh, nexthop);
            dp_send_pkt_out(dp_ctx, nexthop->fwd_info->oif, pkt_block);
            break;

        default:
            /* Unknown endpoint function - this should not happen */
            assert(0);
            break;
    }
}

