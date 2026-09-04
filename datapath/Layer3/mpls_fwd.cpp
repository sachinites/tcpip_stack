#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

#include "../../tcpconst.h"
#include "../../tcp_ip_trace.h"
#include "../../utils.h"
#include "../../libs/pkt-block/pkt_mbuf.h"
#include "../../libs/common/l3_hdrs.h"
#include "../../libs/common/mpls_lstack.h"
#include "../../libs/common/cmn_prefix.h"
#include "../../libs/Tracer/tracer.h"

#include "../dp_ctx.h"
#include "../Vrfs/dp_vrf.h"
#include "../Interface/dp_intf.h"
#include "../FIB/fib_nh.h"
#include "layer3.h"

extern void
dp_demote_pkt_to_layer2(dp_ctx_t *dp_ctx,
                        dp_vrf_t *vrf,
                        uint32_t next_hop_ip,
                        dp_intf_t *oif,
                        struct rte_mbuf *mbuf,
                        gen_proto_id_t hdr_type);

#define MPLS_DEFAULT_TTL 255

static bool
mpls_decrement_top_ttl(struct rte_mbuf *mbuf)
{
    pkt_size_t pkt_size;
    mpls_label_wire_t *pkt_label =
        (mpls_label_wire_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    if (!pkt_label || pkt_size < sizeof(mpls_label_wire_t)) {
        return false;
    }

    uint8_t ttl = mpls_wire_get_ttl(pkt_label);

    if (ttl <= 1) {
        return false;
    }

    mpls_wire_set_ttl(pkt_label, (uint8_t)(ttl - 1));
    return true;
}

/* Retrun true if the top header in the packet still mpls header
    else return false.  When dp_ctx is non-NULL, each label op is logged
    at DMPLS_DET. */
bool
mpls_apply_nh_label_stack(dp_ctx_t *dp_ctx,
                          struct rte_mbuf *mbuf,
                          mpls_lstack_t *lstack)
{
    int i;
    bool s_bit;
    uint8_t ttl;
    char ops_buf[128];
    char wire_buf[128];
    pkt_size_t pkt_size;
    mpls_label_wire_t *pkt_label;

    gen_proto_id_t starting_hdr = pkt_mbuf_get_starting_hdr(mbuf);
    bool top_hdr_is_mpls = (starting_hdr == IP_PROTO_MPLS_IN_IP);
        
    mpls_format_lstack(lstack, ops_buf, sizeof(ops_buf));
    pkt_label = (mpls_label_wire_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
    mpls_format_wire_stack(pkt_label, top_hdr_is_mpls ? (size_t)pkt_size : 0,
                               wire_buf, sizeof(wire_buf));
    pkt_tracer(mbuf, dp_ctx->dptr, DMPLS_DET,
            "mpls_apply: start_hdr=%s wire=[%s] nh_ops=[%s]\n",
            top_hdr_is_mpls ? "MPLS" : "non-MPLS",
            wire_buf[0] ? wire_buf : "-",
            ops_buf[0] ? ops_buf : "-");
    

    for (i = 0; i < MAX_LBL_DEPTH; i++) {

        if (lstack->labels[i].op == MPLS_OP_STACK_OPS_UNKNOWN) continue;
        
        switch (lstack->labels[i].op) {

        case MPLS_OP_POP:
            pkt_label = (mpls_label_wire_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
            if (!pkt_label || pkt_size < sizeof(mpls_label_wire_t)) {
                assert(0);
                return false;
            }
            s_bit = mpls_wire_is_stack_bottom(pkt_label);

            pkt_tracer(mbuf, dp_ctx->dptr, DMPLS_DET,
                    "mpls_apply: POP label %u%s\n",
                    mpls_wire_get_value(pkt_label),
                    s_bit ? " (BoS → payload)" : "");
            
            pkt_mbuf_slide(mbuf, -1, 1, (uint16_t)sizeof(mpls_label_wire_t));
            if (s_bit) {
                /* Last label in the packet is gone */
                top_hdr_is_mpls = false;
            }
            break;

        case MPLS_OP_PUSH:
            /* Inherit the TTL of the label being covered so that the whole
               stack carries one consistent hop count */
            pkt_label = (mpls_label_wire_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
            ttl = (top_hdr_is_mpls && pkt_label &&
                   pkt_size >= sizeof(mpls_label_wire_t)) ?
                        mpls_wire_get_ttl(pkt_label) : MPLS_DEFAULT_TTL;

            pkt_mbuf_expand_buffer_left(mbuf, sizeof(mpls_label_wire_t));
            pkt_label = (mpls_label_wire_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
            mpls_wire_write(pkt_label, 0);
            mpls_wire_set_value(pkt_label,
                mpls_label_get_value(lstack->labels[i].label_val));
            mpls_wire_set_ttl(pkt_label, ttl);

            /* A label imposed over bare payload is itself bottom of stack */
            if (!top_hdr_is_mpls) {
                mpls_wire_set_stack_bottom(pkt_label);
                top_hdr_is_mpls = true;

                pkt_tracer(mbuf, dp_ctx->dptr, DMPLS_DET,
                           "mpls_apply: PUSH label %u TTL %u (first/BoS)\n",
                           mpls_wire_get_value(pkt_label), ttl);
            } 
            else 
            {
                pkt_tracer(mbuf, dp_ctx->dptr, DMPLS_DET,
                    "mpls_apply: PUSH label %u TTL %u (outer)\n",
                    mpls_wire_get_value(pkt_label), ttl);
            }
            break;

        case MPLS_OP_SWAP:
            pkt_label = (mpls_label_wire_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
            if (!pkt_label || pkt_size < sizeof(mpls_label_wire_t)) {
                assert(0);
                return false;
            }
            s_bit = mpls_wire_is_stack_bottom(pkt_label);
            ttl = mpls_wire_get_ttl(pkt_label);

            pkt_tracer(mbuf, dp_ctx->dptr, DMPLS_DET,
                    "mpls_apply: SWAP %u → %u%s TTL %u\n",
                    mpls_wire_get_value(pkt_label),
                    mpls_label_get_value(lstack->labels[i].label_val),
                    s_bit ? " (BoS)" : "",
                    ttl);
            
            /* Replace the label value only : S and TTL survive the swap */
            mpls_wire_write(pkt_label, 0);
            mpls_wire_set_value(pkt_label,
                mpls_label_get_value(lstack->labels[i].label_val));
            mpls_wire_set_ttl(pkt_label, ttl);
            if (s_bit) mpls_wire_set_stack_bottom(pkt_label);
            break;

        default:
            break;
        }
    }


    pkt_label = (mpls_label_wire_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
    mpls_format_wire_stack(
            top_hdr_is_mpls ? pkt_label : NULL,
            top_hdr_is_mpls ? (size_t)pkt_size : 0,
            wire_buf, sizeof(wire_buf));
    pkt_tracer(mbuf, dp_ctx->dptr, DMPLS_DET,
            "mpls_apply: done top_hdr=%s wire=[%s] pkt_size=%u\n",
            top_hdr_is_mpls ? "MPLS" : "non-MPLS",
            wire_buf[0] ? wire_buf : "-",
            (unsigned)pkt_size);
    

    return top_hdr_is_mpls;
}

void
dp_mpls_fwd_pkt(dp_ctx_t *dp_ctx,
                dp_vrf_t *vrf,
                dp_intf_t *iif,
                struct rte_mbuf *mbuf)
{
    fib_nh_t *nh;
    uint32_t in_label;
    pkt_size_t pkt_size;
    cmn_prefix_t prefix;
    bool top_hdr_is_mpls;
    mpls_label_wire_t *pkt_label;
    char gw_str[IPV4_ADDR_LEN_STR];
    char wire_buf[128];
    char ops_buf[128];
    uint8_t in_ttl;
    
    assert(pkt_mbuf_get_starting_hdr(mbuf) == IP_PROTO_MPLS_IN_IP);

    pkt_mbuf_clear_ingress_intf(mbuf);

    pkt_label = (mpls_label_wire_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
    if (!pkt_label || pkt_size < sizeof(mpls_label_wire_t)) {
        pkt_tracer(mbuf, dp_ctx->dptr, DMPLS | DERR,
            "VRF %s: MPLS pkt too short (size=%u), dropping\n",
            vrf->vrf_name, (unsigned)pkt_size);
        return;
    }

    in_label = mpls_wire_get_value(pkt_label);
    in_ttl = mpls_wire_get_ttl(pkt_label);
    mpls_format_wire_stack(pkt_label, (size_t)pkt_size, wire_buf, sizeof(wire_buf));

    pkt_tracer(mbuf, dp_ctx->dptr, DMPLS,
        "VRF %s: MPLS LFIB lookup in-label %u TTL %u iif %s wire=[%s] size=%u\n",
        vrf->vrf_name, in_label, in_ttl,
        iif ? iif->if_name : "-",
        wire_buf, (unsigned)pkt_size);

    memset(&prefix, 0, sizeof(prefix));
    prefix.afi = AF_LABEL;
    prefix.prefix_len = 20;
    mpls_label_set_value(&prefix.u.mpls_label, in_label);

    nh = fib_get_forwarding_nh(vrf->fib_mpls0, &prefix);
    if (!nh) {
        pkt_tracer(mbuf, dp_ctx->dptr, DMPLS | DERR,
            "VRF %s: MPLS in-label %u: no LFIB route, dropping\n",
            vrf->vrf_name, in_label);
        return;
    }

    if (!mpls_decrement_top_ttl(mbuf)) {
        pkt_tracer(mbuf, dp_ctx->dptr, DMPLS | DERR,
            "VRF %s: MPLS in-label %u: TTL expired (was %u), dropping\n",
            vrf->vrf_name, in_label, in_ttl);
        return;
    }

    ip_ntop(nh->fwd_info->nh_addr.u.v4_addr, (c_string)gw_str);
    mpls_format_lstack(&nh->fwd_info->u.mpls_fwd.label_stack,
                       ops_buf, sizeof(ops_buf));

    pkt_tracer(mbuf, dp_ctx->dptr, DMPLS,
        "VRF %s: MPLS in-label %u: OIF %s Gw %s nh_ops=[%s]\n",
        vrf->vrf_name, in_label,
        nh->fwd_info->oif ? nh->fwd_info->oif->if_name : "-",
        gw_str,
        ops_buf[0] ? ops_buf : "-");

    top_hdr_is_mpls = mpls_apply_nh_label_stack(dp_ctx, mbuf,
            &nh->fwd_info->u.mpls_fwd.label_stack);

    pkt_label = (mpls_label_wire_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
    mpls_format_wire_stack(
        top_hdr_is_mpls ? pkt_label : NULL,
        top_hdr_is_mpls ? (size_t)pkt_size : 0,
        wire_buf, sizeof(wire_buf));

    pkt_tracer(mbuf, dp_ctx->dptr, DMPLS,
        "VRF %s: MPLS in-label %u: after NH ops top=%s wire=[%s] size=%u\n",
        vrf->vrf_name, in_label,
        top_hdr_is_mpls ? "MPLS" : "non-MPLS",
        wire_buf[0] ? wire_buf : "-",
        (unsigned)pkt_size);

    switch (nh->fwd_info->oif->if_type)
    {
        /* Handle Special Interfaces */
        case DP_INTF_TYPE_MPLS_TO_VRF_STEER:
            pkt_tracer(mbuf, dp_ctx->dptr, DMPLS,
                "VRF %s: MPLS in-label %u: steer into VRF via %s xconnect-id=%u\n",
                vrf->vrf_name, in_label,
                nh->fwd_info->oif->if_name,
                nh->fwd_info->xconnect_id);
            dp_send_pkt_out(dp_ctx, nh->fwd_info->oif, mbuf, nh->fwd_info->xconnect_id);
            return;
        case DP_INTF_TYPE_MPLS_TO_BD_STEER:
            pkt_tracer(mbuf, dp_ctx->dptr, DMPLS,
                "VRF %s: MPLS in-label %u: steer into BD via %s xconnect-id=%u\n",
                vrf->vrf_name, in_label,
                nh->fwd_info->oif->if_name,
                nh->fwd_info->xconnect_id);
            dp_send_pkt_out(dp_ctx, nh->fwd_info->oif, mbuf, nh->fwd_info->xconnect_id);
            return;
        default:
            break;
    }

    pkt_tracer(mbuf, dp_ctx->dptr, DMPLS,
        "VRF %s: MPLS in-label %u: demote to L2 OIF %s Gw %s ethertype=%s\n",
        vrf->vrf_name, in_label,
        nh->fwd_info->oif ? nh->fwd_info->oif->if_name : "-",
        gw_str,
        top_hdr_is_mpls ? "MPLS_UC" : "IPv4");

    /* Transit swap/push: forward labeled packet to L2 */
    dp_demote_pkt_to_layer2(dp_ctx, 
        vrf,
        nh->fwd_info->nh_addr.u.v4_addr,
        nh->fwd_info->oif,
        mbuf,
        top_hdr_is_mpls ? IP_PROTO_MPLS_IN_IP : IP_PROTO_IP_IN_IP /* Default */);
}
