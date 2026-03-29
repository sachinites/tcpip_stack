#include <stdint.h>
#include <assert.h>
#include "../../../libs/common/l3_hdrs.h"
#include "../../../libs/common/l3_hdrs.h"
#include "../../Layer3/ipv6/ipv6-fwd.h"
#include "../../../router_init.h"
#include "../../../libs/pkt-block/pkt_block.h"
#include "../../../libs/Tracer/tracer.h"
#include "../../../Interface/InterfaceUApi.h"
#include "srv6-end-behavior.h"
#include "srv6-endpoint.h"
#include "../../FIB/fib_nh.h"
#include "../../FIB/fib.h"
#include "../../Vrfs/dp_vrf.h"
#include "../../Interface/dp_intf.h"

#define drop_packet return;

static void 
srv6_shift (pkt_block_t *pkt_block) {

    assert (pkt_block_get_starting_hdr(pkt_block) == ETH_TYPE_IPv6); 
    ipv6_hdr_t *ipv6_hdr = pkt_block_get_ip6_hdr(pkt_block);
    assert (ipv6_hdr->next_header == IP_PROTO_SRH);
    srh_hdr_t *srh = (srh_hdr_t *)(ipv6_hdr + 1);
    srh->segments_left--;
    Srv6_copy_current_sid_to_DA(srh, ipv6_hdr);
}

static uint8_t
srv6_get_flavor (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, 
                 uint8_t (*dst_addr)[16], 
                 fib_nh_t **nexthop) {

    if (nexthop) *nexthop = NULL;

    cmn_prefix_t prefix;
    cmn_prefix_initialize_v6(&prefix, dst_addr, 128);
    *nexthop = fib_get_forwarding_nh(
                dp_vrf_fib_get(vrf, AF_IPV6), &prefix);

    if (!nexthop) {
        return 0;
    }

    Srv6_endpcode_t CompositEndp = (*nexthop)->fwd_info->u.v6_fwd.endfn;
    if (CompositEndp == 0) return 0;

    uint8_t flavor = 0;
    Srv6_endpcode_t endp = srv6_split_endpcode(CompositEndp, &flavor);
    return flavor;
}


static bool 
srv6_ipv6_forward (dp_ctx_t *dp_ctx, 
                   dp_vrf_t *vrf, 
                   pkt_block_t *pkt_block, 
                   fib_nh_t *nexthop) {

    if (nexthop) {

        //if (nexthop->flags & BINDING_SID) {
            /* Mount seg lst here onto the pkt*/
        //}

        ipv6_layer3_forward_nexthop(dp_ctx, vrf, nexthop, pkt_block);
        return true;
    }

    ipv6_hdr_t *ipv6_hdr = pkt_block_get_ip6_hdr(pkt_block);

    cmn_prefix_t prefix;
    cmn_prefix_initialize_v6(&prefix, &ipv6_hdr->dst_addr, 128);

    fib_nh_t *nh = fib_get_forwarding_nh(vrf->fib_inet6, &prefix);

    if(!nh){
        tracer(dp_ctx->dptr, DL3FWD | DERR, 
            "VRF:%s: Pkt : %s :  Pkt Dropped : No forwarding nexthop\n",
	   vrf->vrf_name, pkt_block_str(pkt_block));
        return false;
    }

    //if (nxt_nexthop->flags & BINDING_SID) {
        /* Mount seg lst here onto the pkt*/
    //}

    ipv6_layer3_forward_nexthop(dp_ctx, vrf, nh, pkt_block);
    return true;
}

void
srv6_shift_and_forward(dp_ctx_t *dp_ctx, 
                       dp_vrf_t *vrf,
                       pkt_block_t *pkt_block) {

    srv6_shift(pkt_block);
    srv6_ipv6_forward(dp_ctx, vrf, pkt_block, 0);
}


/* Each of the below functions needs to be implemented in three categories : 
    SL = 0, SL = 1, SL > 1. You can Omit SL > 1 case in all of them as it is
    common for all fns, hence handled separately
*/

fn_template(srv6_END) {

    if (!srh || srh->segments_left == 0) {
        Srv6_decapsulate (pkt_block);
        ipv6_process_v6_payload(dp_ctx, vrf, pkt_block);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf,
                            &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf, pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }
 
}

fn_template(srv6_END_w_PSP) {

    if (!srh || srh->segments_left == 0) {
        Srv6_decapsulate (pkt_block);
        ipv6_process_v6_payload(dp_ctx, vrf, pkt_block);
        return;
    }

    if (srh->segments_left == 1) {

        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf, pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }
}

fn_template(srv6_END_w_USP) {

    if (!srh || srh->segments_left == 0) {
        Srv6_decapsulate (pkt_block);
        ipv6_process_v6_payload(dp_ctx, vrf, pkt_block);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf,  pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }
}

fn_template(srv6_END_w_PSP_USP) {

    if (!srh || srh->segments_left == 0) {
        Srv6_decapsulate (pkt_block);
        ipv6_process_v6_payload(dp_ctx, vrf, pkt_block);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf,  pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

}

fn_template(srv6_END_X) {

    if (!srh || srh->segments_left == 0) {
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf,  pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

}

fn_template(srv6_END_X_w_PSP) {

    if (!srh || srh->segments_left == 0) {
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf,  pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

}

fn_template(srv6_END_X_w_USP) {

    if (!srh || srh->segments_left == 0) {
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf,  pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

}

fn_template(srv6_END_X_w_PSP_USP) {

    if (!srh || srh->segments_left == 0) {
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf,  pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

}

fn_template(srv6_END_T) {

}

fn_template(srv6_END_T_w_PSP) {

}

fn_template(srv6_END_T_w_USP) {

}

fn_template(srv6_END_T_w_PSP_USP) {

}

fn_template(srv6_END_B6_ENCAP) {

    pkt_size_t pkt_size;

    assert (!srh || (srh->segments_left == 0));

    Srv6_decapsulate(pkt_block);

    srh_hdr_t *new_srh = srh_hdr_prepare (
                (ipv6_addr_t *)nexthop->fwd_info->u.v6_fwd.v6segment_lst,
                nexthop->fwd_info->u.v6_fwd.n_segment_list);

    Srv6_encapsulate (pkt_block, new_srh);
    
    XFREE (new_srh);

    srv6_ipv6_forward(dp_ctx, vrf, pkt_block, 0);
}


fn_template(srv6_END_BM) {

}

fn_template(srv6_END_DX6) {

}

fn_template(srv6_END_DX4) {

}

fn_template(srv6_END_DT6) {

}

/* Encapsulate the pkt within ipv6 heaader, ipv6 dst address obtained from
    nexthop segment list. If there are more SRv6 SIDs in nexthop segment list, then
    remaining SIDs will in SRH hdr. Then semote the packet to L2 for forwarding*/

/* 
    <IPv6 Hdr> <SRH hdr> <ipv4 hdr> <reamining ... >
*/
extern void
layer3_ip_route_pkt(dp_ctx_t *dp_ctx,
                    dp_vrf_t *vrf,
					dp_intf_t *interface,
					pkt_block_t *pkt_block);

fn_template(srv6_END_DT4) {

    assert(0);

    assert (!srh || (srh->segments_left == 0));

    Srv6_decapsulate(pkt_block);
    
    assert (pkt_block_get_starting_hdr (pkt_block) == ETH_TYPE_IPv4);

    layer3_ip_route_pkt(dp_ctx, 
        nexthop->fwd_info->oif->srv6_data.steered_dt4_vrf,
        NULL, pkt_block);
}

fn_template(srv6_END_DT46) {

}

fn_template(srv6_END_DX2) {

}

fn_template(srv6_END_DX2V) {

}

fn_template(srv6_END_DT2U) {

}

fn_template(srv6_END_DT2M) {

}

fn_template(srv6_END_B6_ENCAPS_Red) {

}

fn_template(srv6_END_w_USD) {

    if (!srh || srh->segments_left == 0) {
        Srv6_decapsulate (pkt_block);
        ipv6_process_v6_payload(dp_ctx, vrf, pkt_block);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf,  pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

}

fn_template(srv6_END_w_PSP_USD) {

    if (!srh || srh->segments_left == 0) {
        Srv6_decapsulate (pkt_block);
        ipv6_process_v6_payload(dp_ctx, vrf, pkt_block);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf,  pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

}

fn_template(srv6_END_X_w_USP_USD) {

    if (!srh || srh->segments_left == 0) {
        /* USD take precendece over USP*/
        Srv6_decapsulate (pkt_block);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf,  pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }
    
}

fn_template(srv6_END_w_PSP_USP_USD) {

    if (!srh || srh->segments_left == 0) {
        Srv6_decapsulate (pkt_block);
        ipv6_process_v6_payload(dp_ctx, vrf, pkt_block);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf,  pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

}

fn_template(srv6_END_X_w_USD) {

    if (!srh || srh->segments_left == 0) {
        Srv6_decapsulate (pkt_block);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf,  pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }
}

fn_template(srv6_END_X_w_PSP_USD) {

    if (!srh || srh->segments_left == 0) {
        Srv6_decapsulate (pkt_block);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf,  pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

}


fn_template(srv6_END_X_w_PSP_USP_USD) {

    if (!srh || srh->segments_left == 0) {
        Srv6_decapsulate (pkt_block);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

    if (srh->segments_left == 1) {
        srv6_shift (pkt_block);
        fib_nh_t *nexthop = NULL;
        uint8_t flavor = srv6_get_flavor(dp_ctx, vrf, &ipv6_hdr->dst_addr, &nexthop);
        Srv6_apply_flavor(dp_ctx, vrf,  pkt_block, flavor & PSP ? PSP : 0);
        srv6_ipv6_forward(dp_ctx, vrf, pkt_block, nexthop);
        return;
    }

}

fn_template(srv6_END_T_w_USD) {

}

fn_template(srv6_END_T_w_PSP_USD) {

}

fn_template(srv6_END_T_w_USP_USD) {

}

fn_template(srv6_END_T_w_PSP_USP_USD) {

}


