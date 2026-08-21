#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "../../../libs/pkt-block/pkt_mbuf.h"
#include "../../../libs/common/ipv6_hdrs.h"
#include "../../../libs/common/l3_hdrs.h"
#include "../../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../../../libs/Tracer/tracer.h"

#include "../../../tcpconst.h"
#include "l3vpn.h"

#include "../../dp_ctx.h"
#include "../../Vrfs/dp_vrf.h"
#include "../../FIB/fib_nh.h"
#include "../SRv6/srv6-endpoint.h"
#include "../ipv6/ipv6-fwd.h"
#include "../layer3.h"

/*

Implemented L3 VPNv4 over SRv6 Data Plane in a User-Space TCP/IP Stack Simulator
I have been building a full-featured, user-space TCP/IP network simulator in C/C++ from the ground up — complete with a real control plane, a separate data plane, an ISIS routing protocol, a multi-VRF forwarding engine, an ACL/firewall subsystem, and now SRv6-based L3 VPN (VPNv4) data path.


What I Implemented: L3 VPNv4 Data Path over SRv6

L3 VPN (Layer 3 Virtual Private Network) allows customer IPv4 traffic to be transported across a service-provider's backbone, isolated in a customer VRF. Instead of MPLS labels (traditional VPNv4), this implementation uses SRv6 as the transport — a modern, scalable approach defined in RFC 8986.

Ingress PE — When customer IPv4 traffic arrives at the Ingress Provider Edge (PE) router and hits an IPv4 route with an SRv6 nexthop in the customer VRF:

1. Builds the SRH —  to construct a Segment Routing Header from the segment list 
2. SRv6 Encapsulates the IPv4 packet 
2.1 Prepends the SRH
2.2 Prepends an IPv6 outer header with DA = first active SID
2.3 Packet becomes: [IPv6 Hdr][SRH][Original IPv4 Pkt]
3. Forwards in the default VRF — the encapsulated packet is injected into the IPv6 forwarding pipeline of the provider's default VRF 

Transit P Routers — Do forward the pkt to destination PE routers based on locator-based forwarding. Locator is distributed in ISP core using IGP.

Egress PE — 
1. When the encapsulated packet arrives at the Egress PE whose SID matches the IPv6 DA:
2. Decapsulates — which strips both the outer IPv6 header and the SRH, exposing the original IPv4 packet
3. Routes in the customer VRF —  The IPv4 packet is now delivered to the correct customer routing domain


Multi-VRF FIB — The implementation supports default VRF and customer VRFs

Pkt-block abstraction — a zero-copy packet buffer model allows headers to be prepended/stripped in-place without memory copies across the L2/L3/SRv6 pipeline
RFC 8986 compliant — SRH shift, PSP/USP/USD flavors, encap/decap, and endpoint function dispatch all follow the RFC specification


There is no BGP control plane signalling support yet. VPNv4 routes over SRv6 SIDs needs to be installed using CLIs on PE routers. This is data-plane only implementation.

*/

/* This fn is called when pkt in Customer VRF hits the 
    ipv4 route which has SRv6 Nexthop 

    After this fn, the pk_block structure would be 
    <ipv6 hdr> <srh hdr> <original pkt payload>    
*/
int 
vpnv4_ingress_pe_encap_srv6 (dp_ctx_t *dp_ctx, 
                             dp_vrf_t *vrf, 
                             struct rte_mbuf *mbuf, 
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
    assert (pkt_mbuf_get_starting_hdr(mbuf) == IP_PROTO_IP_IN_IP);

    srh_hdr = srh_hdr_prepare(
        (ipv6_addr_t *)srv6_nh->fwd_info->u.v6_fwd.v6segment_lst,
        srv6_nh->fwd_info->u.v6_fwd.n_segment_list);

    Srv6_encapsulate(mbuf, srh_hdr);
    XFREE(srh_hdr);

    /* Have to do forwarding in Default VRF */
    ipv6_layer3_forward_nexthop(dp_ctx, dp_ctx->default_vrf, srv6_nh, mbuf);

    return 1;
}

int
vpnv4_ingress_pe_encap_mpls (dp_ctx_t *dp_ctx, 
                             dp_vrf_t *vrf, 
                             struct rte_mbuf *mbuf, 
                             fib_nh_t *sr_nh) {

    int i;
    int n_labels = 0;
    pkt_size_t pkt_size;
    mpls_label_wire_t *pkt_label;
    mpls_lstack_t *lstack;
    bool top_hdr_is_mpls;

    assert (sr_nh);
    assert (sr_nh->fwd_info);
    assert (sr_nh->fwd_info->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK);
    assert (pkt_mbuf_get_starting_hdr(mbuf) == IP_PROTO_IP_IN_IP);

    lstack = &sr_nh->fwd_info->u.mpls_fwd.label_stack;

    if (mpls_lstack_is_empty(lstack)) {
        return 0;
    }

    /* Impose the label stack bottom → top (index 0 is BoS/innermost). The
        packet is still bare IP here, so mpls_apply_nh_label_stack() detects
        that and gives the first imposed label the S-bit and TTL 255, then
        keeps stacking outward for every subsequent PUSH/SWAP entry. */
    top_hdr_is_mpls = mpls_apply_nh_label_stack(mbuf, lstack);

    for (i = 0; i <= lstack->curr_index; i++) {
        if (lstack->labels[i].op == MPLS_OP_STACK_OPS_UNKNOWN ||
            lstack->labels[i].op == MPLS_OP_POP) {
            continue;
        }
        n_labels++;
    }

    if (n_labels == 0) {
        return 0;
    }

    /* Ingress imposition always ends up on an MPLS header - the stack for
        this nexthop is expected to hold only PUSH entries */
    assert (top_hdr_is_mpls);
    pkt_mbuf_update_new_hdr_type(mbuf, IP_PROTO_MPLS_IN_IP);

    {
        char lbl_buf[256];
        int off = 0;

        /* Packet layout after impose: [outer] ... [inner|S] [IP]
            Trace outer → inner as they sit on the wire. */
        pkt_label = (mpls_label_wire_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
        lbl_buf[0] = '\0';
        for (i = 0; i < n_labels && off < (int)sizeof(lbl_buf) - 1; i++) {
            uint32_t val = mpls_wire_get_value(&pkt_label[i]);
            bool bos = mpls_wire_is_stack_bottom(&pkt_label[i]);
            off += snprintf(lbl_buf + off, sizeof(lbl_buf) - off,
                            "%s%u%s", i ? " -> " : "", val, bos ? "(S)" : "");
        }

        pkt_tracer(mbuf, dp_ctx->dptr, DL3FWD,
            "VRF %s: VPNv4 MPLS encap: %d label(s) outer→inner: [%s]\n",
            vrf->vrf_name, n_labels, lbl_buf);
    }

    return n_labels;
}