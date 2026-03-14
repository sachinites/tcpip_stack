#include <assert.h>
#include <stdlib.h>

#include "../../../pkt_block.h"
#include "../../../Layer3/ipv6/ipv6_hdrs.h"
#include "../../../common/l3_hdrs.h"
#include "../../../LinuxMemoryManager/uapi_mm.h"

#include "../../../tcpconst.h"
#include "l3vpn.h"

#include "../../dp_ctx.h"
#include "../../FIB/fib_nh.h"
#include "../SRv6/srv6-endpoint.h"
#include "../ipv6/ipv6-fwd.h"


/* This fn is called when pkt in Customer VRF hits the 
    ipv4 route which has SRv6 Nexthop 

    After this fn, the pk_block structure would be 
    <ipv6 hdr> <srh hdr> <original pkt payload>    
*/
void 
vpnv4_ingress_pe_encap_srv6 (dp_ctx_t *dp_ctx, 
                             dp_vrf_t *vrf, 
                             pkt_block_t *pkt_block, 
                             fib_nh_t *srv6_nh) {

    srh_hdr_t *srh_hdr = NULL;

    /* Should be Customer VRF */
    assert (vrf != dp_ctx->default_vrf ) ;

    /* NH should be ipv6 addr family*/
    assert (srv6_nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV6);

    /* NH should be SRv6 NH*/
    assert (srv6_nh->fwd_info->fwd_flags & FIB_NH_FWD_F_SRv6_FORWARD);

    assert(srv6_nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV6_STCK);

    /* Perform Srv6 Encapsulation of ipv4 pkt*/
    assert (pkt_block_get_starting_hdr(pkt_block) == IP_HDR);

    srh_hdr = srh_hdr_prepare(
        (ipv6_addr_t *)srv6_nh->fwd_info->u.v6_fwd.v6segment_lst,
        srv6_nh->fwd_info->u.v6_fwd.n_segment_list);

    Srv6_encapsulate(pkt_block, srh_hdr);
    XFREE(srh_hdr);

    /* Have to do forwarding in Default VRF */
    ipv6_layer3_forward_nexthop(dp_ctx, dp_ctx->default_vrf, srv6_nh, pkt_block);
}