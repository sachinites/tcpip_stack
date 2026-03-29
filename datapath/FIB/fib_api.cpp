/*
 * =====================================================================================
 *
 *       Filename:  fib_api.cpp
 *
 *    Description:  Helper functions for FIB implementation
 *                  - Prefix format conversions (FIB prefix <-> bitmap)
 *                  - Packet destination extraction
 *                  - Nexthop forwarding operations
 *                  - MPLS label stack operations
 *
 * =====================================================================================
 */

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "fib_api.h"
#include "fib.h"
#include "fib_route.h"
#include "fib_nh.h"
#include "../../libs/common/mpls_lstack.h"
#include "../../libs/pkt-block/pkt_block.h"
#include "../../libs/common/l3_hdrs.h"
#include "../../tcpconst.h"
#include "../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../Interface/dp_intf.h"

extern void
dp_demote_pkt_to_layer2 (dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      uint32_t next_hop_ip,
                      dp_intf_t *outgoing_intf,
                      pkt_block_t *pkt_block,
                      gen_proto_id_t hdr_type);

/* Extract destination address from packet based on header type */
bool fib_extract_dest_from_pkt(pkt_block_t *pkt, cmn_prefix_t *dest) {
    
    gen_proto_id_t hdr_type = pkt_block_get_starting_hdr(pkt);
    pkt_size_t pkt_size;
    
    switch (hdr_type) {
        case ETH_TYPE_IPv4:
        case IP_PROTO_IP_IN_IP: {
            ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt);
            if (!ip_hdr) return false;
            
            dest->afi = AF_IPV4;
            dest->prefix_len = 32;
            dest->u.v4_addr = ntohl(ip_hdr->dst_ip);
            return true;
        }
        
        case ETH_TYPE_IPv6: {
            /* IPv6 support would go here */
            return false;
        }
        
        case ETH_TYPE_MPLS_UC: {
            /* Extract MPLS label from packet */
            uint32_t *label_ptr = (uint32_t *)pkt_block_get_pkt(pkt, &pkt_size);
            if (!label_ptr || pkt_size < 4) return false;
            
            dest->afi = AF_LABEL;
            dest->prefix_len = 20;
            /* Extract 20-bit label from 32-bit label entry */
            dest->u.mpls_label = (ntohl(*label_ptr) >> 12) & 0xFFFFF;
            return true;
        }
        
        case ETHERNET_HEADER: {
            /* MAC destination would be extracted here */
            return false;
        }
        
        default:
            return false;
    }
}

fib_nh_t *
fib_get_active_nexthop(fib_route_t *route) {
    
    fib_nh_t *active_nh = NULL;
    
    /* Count valid nexthops */
    int i = route->nh_index + 1;

    if (i == FIB_MAX_ECMP_NH) i = 0;

    for (; i < FIB_MAX_ECMP_NH; i++) {
        if (route->nhs[i]) return route->nhs[i];
    }

    for (i = 0; i < FIB_MAX_ECMP_NH; i++) {
        if (route->nhs[i]) return route->nhs[i];
    }    
    
    return NULL;
}

static void 
mpls_apply_label_stack_on_pkt (pkt_block_t *pkt_block, mpls_lstack_t *lstack) {

    int i = 0;
    bool s_bit = false;
    pkt_size_t pkt_size;
    mpls_label_val_t *pkt_label;

    for (i = 0; i < MAX_LBL_DEPTH; i++) {

        if (lstack->labels[i].op == MPLS_OP_STACK_OPS_UNKNOWN) continue;

        switch (lstack->labels[i].op ) {

            case MPLS_OP_POP:
                if (pkt_block_get_starting_hdr (pkt_block) == ETH_TYPE_MPLS_UC) {
                    pkt_label = (mpls_label_val_t *)pkt_block_get_pkt (pkt_block, &pkt_size);
                    if (mpls_label_is_stack_bottom (*pkt_label)) s_bit = true;
                    pkt_block_set_new_pkt (pkt_block, (uint8_t *)(pkt_label + 1), pkt_size - sizeof (mpls_label_val_t));
                    if (s_bit) pkt_block_set_starting_hdr_type (pkt_block,  PROTO_MISC_APP);
                }
            break;


            case MPLS_OP_PUSH:
                pkt_block_expand_buffer_left (pkt_block, sizeof (mpls_label_val_t));
                pkt_label = (mpls_label_val_t *)pkt_block_get_pkt (pkt_block, &pkt_size);
                mpls_label_set_value (pkt_label, mpls_label_get_value (lstack->labels[i].label_val ));
                if (pkt_block_get_starting_hdr (pkt_block) != ETH_TYPE_MPLS_UC) {
                    pkt_block_set_starting_hdr_type (pkt_block, ETH_TYPE_MPLS_UC);
                    mpls_label_set_stack_bottom (pkt_label);
                }
            break;


            case MPLS_OP_SWAP:
                s_bit = false;
                if (pkt_block_get_starting_hdr (pkt_block) == ETH_TYPE_MPLS_UC) {
                    pkt_label = (mpls_label_val_t *)pkt_block_get_pkt (pkt_block, &pkt_size);
                    if (mpls_label_is_stack_bottom (*pkt_label)) s_bit = true;
                    mpls_label_set_value (pkt_label, mpls_label_get_value (lstack->labels[i].label_val ));
                    if (s_bit) mpls_label_set_stack_bottom (pkt_label);
                }
            break;

        }
    }
};

/* Perform actual forwarding based on next hop */
fib_error_t 
fib_forward_pkt_to_nh(dp_ctx_t *dp_ctx, 
                      dp_vrf_t *vrf, 
                      pkt_block_t *pkt_block, fib_nh_t *nh) {
    
    /* Apply MPLS label stack operations if present */
    if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) {
        mpls_apply_label_stack_on_pkt  (pkt_block, 
            &nh->fwd_info->u.mpls_fwd.label_stack);
    }
    
    /* Decrement TTL if IP packet */
    gen_proto_id_t hdr_type = pkt_block_get_starting_hdr(pkt_block);

    if (hdr_type == ETH_TYPE_IPv4 || hdr_type == IP_PROTO_IP_IN_IP) {

        ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt_block);

        if (ip_hdr) {

            if (ip_hdr->ttl > 0) {

                ip_hdr->ttl--;

                if (ip_hdr->ttl == 0) {
                    /* TTL expired - drop packet */
                    return FIB_ERROR_TTL_EXPIRED;
                }
            }
        }
    }

    nh->hit_count++;

    dp_demote_pkt_to_layer2(
        dp_ctx,
        vrf,
        hdr_type == ETH_TYPE_IPv6 ? 0 : nh->fwd_info->nh_addr.u.v4_addr,
        nh->fwd_info->oif,
        pkt_block, hdr_type);

    /* Packet successfully processed - would be sent out OIF in real hardware */
    return FIB_ERROR_SUCCESS;
}
