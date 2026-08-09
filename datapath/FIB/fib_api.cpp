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
#include "../../libs/pkt-block/pkt_mbuf.h"
#include "../../libs/common/l3_hdrs.h"
#include "../../tcpconst.h"
#include "../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../Interface/dp_intf.h"

extern void
dp_demote_pkt_to_layer2 (dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      uint32_t next_hop_ip,
                      dp_intf_t *outgoing_intf,
                      struct rte_mbuf *mbuf,
                      gen_proto_id_t hdr_type);

/* Extract destination address from packet based on header type */
bool fib_extract_dest_from_pkt(struct rte_mbuf *pkt, cmn_prefix_t *dest) {
    
    gen_proto_id_t hdr_type = pkt_mbuf_get_starting_hdr(pkt);
    pkt_size_t pkt_size;
    
    switch (hdr_type) {

        case IP_PROTO_IP_IN_IP: 
        {
            ip_hdr_t *ip_hdr = pkt_mbuf_get_ip_hdr(pkt);
            if (!ip_hdr) return false;
            
            dest->afi = AF_IPV4;
            dest->prefix_len = 32;
            dest->u.v4_addr = ntohl(ip_hdr->dst_ip);
            return true;
        }

        case IP_PROTO_IPv6: {
            /* IPv6 support would go here */
            return false;
        }
        
        case ETH_TYPE_MPLS_UC:
        case IP_PROTO_MPLS_IN_IP: {
            /* Extract MPLS label from packet */
            mpls_label_wire_t *label_ptr =
                (mpls_label_wire_t *)pkt_mbuf_get_pkt(pkt, &pkt_size);
            if (!label_ptr || pkt_size < sizeof(mpls_label_wire_t)) return false;
            
            dest->afi = AF_LABEL;
            dest->prefix_len = 20;
            mpls_label_set_value(&dest->u.mpls_label,
                mpls_wire_get_value(label_ptr));
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

static bool
mpls_pkt_has_mpls_hdr(struct rte_mbuf *mbuf)
{
    gen_proto_id_t hdr = pkt_mbuf_get_starting_hdr(mbuf);
    return hdr == ETH_TYPE_MPLS_UC || hdr == IP_PROTO_MPLS_IN_IP;
}

static void 
mpls_apply_label_stack_on_pkt (struct rte_mbuf *mbuf, mpls_lstack_t *lstack) {

    int i = 0;
    bool s_bit = false;
    uint8_t ttl;
    pkt_size_t pkt_size;
    mpls_label_wire_t *pkt_label;

    for (i = 0; i < MAX_LBL_DEPTH; i++) {

        if (lstack->labels[i].op == MPLS_OP_STACK_OPS_UNKNOWN) continue;

        switch (lstack->labels[i].op ) {

            case MPLS_OP_POP:
                if (mpls_pkt_has_mpls_hdr(mbuf)) {
                    pkt_label = (mpls_label_wire_t *)pkt_mbuf_get_pkt (mbuf, &pkt_size);
                    if (mpls_wire_is_stack_bottom (pkt_label)) s_bit = true;
                    /* Pop the top MPLS label: shrink head by one label. */
                    pkt_mbuf_slide (mbuf, -1, 1,
                                     (uint16_t)sizeof (mpls_label_wire_t));
                    if (s_bit) pkt_mbuf_update_new_hdr_type (mbuf, IP_PROTO_IP_IN_IP);
                }
            break;


            case MPLS_OP_PUSH:
                pkt_mbuf_expand_buffer_left (mbuf, sizeof (mpls_label_wire_t));
                pkt_label = (mpls_label_wire_t *)pkt_mbuf_get_pkt (mbuf, &pkt_size);
                mpls_wire_set_value (pkt_label, mpls_label_get_value (lstack->labels[i].label_val ));
                if (!mpls_pkt_has_mpls_hdr(mbuf)) {
                    pkt_mbuf_update_new_hdr_type (mbuf, IP_PROTO_MPLS_IN_IP);
                    mpls_wire_set_stack_bottom (pkt_label);
                }
            break;


            case MPLS_OP_SWAP:
                s_bit = false;
                if (mpls_pkt_has_mpls_hdr(mbuf)) {
                    pkt_label = (mpls_label_wire_t *)pkt_mbuf_get_pkt (mbuf, &pkt_size);
                    if (mpls_wire_is_stack_bottom (pkt_label)) s_bit = true;
                    ttl = mpls_wire_get_ttl (pkt_label);
                    mpls_wire_write (pkt_label, 0);
                    mpls_wire_set_value (pkt_label,
                        mpls_label_get_value (lstack->labels[i].label_val ));
                    mpls_wire_set_ttl (pkt_label, ttl);
                    if (s_bit) mpls_wire_set_stack_bottom (pkt_label);
                }
            break;

        }
    }
};

/* Perform actual forwarding based on next hop */
fib_error_t 
fib_forward_pkt_to_nh(dp_ctx_t *dp_ctx, 
                      dp_vrf_t *vrf, 
                      struct rte_mbuf *mbuf, fib_nh_t *nh) {
    
    /* Apply MPLS label stack operations if present */
    if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) {
        mpls_apply_label_stack_on_pkt  (mbuf, 
            &nh->fwd_info->u.mpls_fwd.label_stack);
    }
    
    /* Decrement TTL if IP packet */
    gen_proto_id_t hdr_type = pkt_mbuf_get_starting_hdr(mbuf);

    if (hdr_type == ETHERNET_HEADER || hdr_type == IP_PROTO_IP_IN_IP) {

        ip_hdr_t *ip_hdr = pkt_mbuf_get_ip_hdr(mbuf);

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
        mbuf, hdr_type);

    /* Packet successfully processed - would be sent out OIF in real hardware */
    return FIB_ERROR_SUCCESS;
}
