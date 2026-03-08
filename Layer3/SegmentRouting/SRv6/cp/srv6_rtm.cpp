#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include "../../../../lmm_enums.h"
#include "srv6_rtm.h"
#include "../../../../router_init.h"
#include "../../../../net.h"
#include "../../../../RTM/rtm.h"
#include "../../../../RTM/rtm_enums.h"
#include "../../../../RTM/rtm_nb_integ.h"
#include "../../../../RTM/rtm_proto.h"
#include "../../../../RTM/rtm_fib_common.h"
#include "../../../../common/cmn_prefix.h"
#include "../../../../Interface/InterfaceUApi.h"
#include "../../../layer3.h"
#include "../../../../tcpconst.h"
#include "../../../ipv6/ipv6_utils.h"

void
srv6_rtm_route_install (vrf_t *vrf,
                        ipv6_addr_t *prefix,
                        uint8_t prefix_len,
                        uint32_t rt_flags,
                        ipv6_addr_t *gw,
                        Interface* oif,
                        ipv6_addr_t (*segment_lst)[16],
                        uint32_t cost,
                        Srv6_endpcode_t endfn,
                        RTM_PROTO_T proto, 
                        bool install)
{
    int i = 0;
    rtm_t *rtm;
    rtm_error_t rc;
    char ipv6_str[48];
    cmn_prefix_t prefix_key;
    cp_nexthop_template_t nh_template;

    inet_ntop6(prefix, ipv6_str);

    rtm = cp_rtm_get_route_target_rtm (
            vrf,
            AF_IPV6, proto, RTM_SUB_PROTO_SRv6);
        
    if (!rtm) {
        cprintf("%s-%s : Error: No RTM localted for route %s/%d\n",
            vrf->node->node_name, vrf->vrf_name, ipv6_str, prefix_len);
        return;
    }

    /* Convert IPv6 prefix to common prefix format */
    cmn_prefix_initialize_v6(&prefix_key, &prefix->addr, prefix_len);

    /* Initialize nexthop template */
    memset(&nh_template, 0, sizeof(cp_nexthop_template_t));
    nh_template.is_indirect = true;

    nh_template.proto = proto;
    nh_template.sub_proto = RTM_SUB_PROTO_SRv6;

    nh_template.fwd_flags |= FIB_NH_FWD_F_IPV6;


    /* SRv6 prefix sids do not have OIF, but shift and forward still
        let them forward on oif obtained by lpm of next sid in SRH hdr*/
    if  (rt_flags & FIB_NH_FWD_F_SRv6_FORWARD) {

        nh_template.action = RTM_NH_ACTION_FORWARD;
        nh_template.is_indirect = false;
        nh_template.is_resolved = true;
        nh_template.oif = oif ? oif->ifindex : 0;
        nh_template.fwd_flags |= FIB_NH_FWD_F_SRv6_FORWARD;
    }

    /* For Locators, the behavior is normal ipv6 forwarding
        instead of SRv6 forwarding */
    else if  (rt_flags & FIB_NH_FWD_F_FORWARD) {

        nh_template.action = RTM_NH_ACTION_FORWARD;
        nh_template.is_indirect = false;
        nh_template.is_resolved = true;
        nh_template.oif = oif ? oif->ifindex : 0;
        nh_template.fwd_flags |= FIB_NH_FWD_F_FORWARD;
    }

    else if (rt_flags & FIB_NH_FWD_F_LOCAL) {

        nh_template.action = RTM_NH_ACTION_LOCAL;
        nh_template.is_indirect = false;
        nh_template.oif = 0;
        nh_template.is_resolved = true;
        nh_template.fwd_flags |= FIB_NH_FWD_F_LOCAL;
    }
    
    else if (rt_flags & FIB_NH_FWD_F_REJECT) {

        nh_template.action = RTM_NH_ACTION_REJECT;
        nh_template.is_indirect = false;
        nh_template.oif = 0;
        nh_template.is_resolved = true;
        nh_template.fwd_flags |= FIB_NH_FWD_F_REJECT;
    }

    nh_template.metric = cost;
    nh_template.rtm_nh_proto = NULL;

    /* Set gateway if provided */
    if (gw && !is_ipv6_addr_unspecified(&gw->addr)) {
        cmn_prefix_initialize_v6(&nh_template.gateway, &gw->addr, 128);
    }

    /* Set SRv6 specific information */
    nh_template.u.srv6_stack.endfn = endfn;
    nh_template.u.srv6_stack.n_segment_list = 0;
    nh_template.u.srv6_stack.v6segment_lst = NULL;

    nh_template.fwd_flags |= FIB_NH_FWD_F_IPV6_STCK;

    /* If segment list is provided, allocate and copy it */
    i = 0;
    if (segment_lst) {
        while ( !is_ipv6_addr_unspecified ( &((*segment_lst)[i]).addr ) ) i++;
    }

    nh_template.u.srv6_stack.n_segment_list = i;

    if (i) {

        nh_template.u.srv6_stack.v6segment_lst = (cmn_prefix_t *)XCALLOC2(0, i, cmn_prefix_t);

        for (i = 0; i < nh_template.u.srv6_stack.n_segment_list; i++) {

            cmn_prefix_initialize_v6(
                    nh_template.u.srv6_stack.v6segment_lst + i,
                    &((*segment_lst)[i]).addr, 128 );
        }
    }

    /* Now fill nexthop proto information */
    nh_template.rtm_nh_proto = (rtm_nh_proto_t *)XCALLOC2(0, 1, rtm_nh_proto_t);
    rtm_nh_proto_initialize(nh_template.rtm_nh_proto);
    nh_template.rtm_nh_proto->proto = proto;
    nh_template.rtm_nh_proto->sub_proto = RTM_SUB_PROTO_SRv6;
    nh_template.rtm_nh_proto->instance_no = 0;
    nh_template.rtm_nh_proto->vrf_id = vrf->vrf_id;

    /* (Un)Install route using new RTM API */
    rc = install ? cp_rtm_install_route(rtm, &prefix_key, &nh_template) : \
                   cp_rtm_uninstall_route(rtm, &prefix_key, &nh_template);

    if (rc != RTM_SUCCESS) {

        cprintf("%s : Warning: SRv6 route %sinstallation failed for prefix %s/%d, error code: %s\n",
               rtm->node->node_name, install ? "" : "(Un-)", 
	           ipv6_str, prefix_len, rtm_error_to_string(rc));
    }

    /* Destroy nexthop template resources */
    rtm_nh_template_free_internals(&nh_template);
}

/*
  config node R0 vrf red route-distinguisher 1:1
  config node R0 rtm-route prefix 121.1.1.1/32 3 5 0 l3vpn srv6-sid 2001:dbe8:3::1 
  IPV6 static route :  config node R1 rtm-route prefix 2001:dbe8::/32 0 0 0 2 10 gateway 2000:: interface eth2
*/

int8_t
srv6_rtm_route_install_vpnv4 (node_t *node, 
                    c_string prefix_mask, 
                    c_string ipv6_addr, bool install) {

    rtm_error_t rc;
    cp_nexthop_template_t nh_template;

    if (!node || !prefix_mask || !ipv6_addr) {
        cprintf("Error: Missing required arguments\n");
        return -1;
    }

    /* Parse the IPv4 customer prefix (e.g. "10.1.1.0/24") */
    cmn_prefix_t prefix_key;
    memset(&prefix_key, 0, sizeof(prefix_key));

    if (!cmn_parse_prefix_string((const char *)prefix_mask, &prefix_key)) {
        cprintf("Error: Invalid prefix/mask '%s'\n", prefix_mask);
        return -1;
    }

    if (prefix_key.afi != AF_IPV4) {
        cprintf("Error: L3VPN SRv6 requires an IPv4 customer prefix\n");
        return -1;
    }

    /* Validate and parse the SRv6 endpoint IPv6 address (tunnel gateway) */
    struct in6_addr v6_raw;
    if (inet_pton(AF_INET6, (const char *)ipv6_addr, &v6_raw) != 1) {
        cprintf("Error: Invalid IPv6 SRv6 endpoint address '%s'\n", ipv6_addr);
        return -1;
    }

    cmn_prefix_t gateway;
    cmn_prefix_initialize_v6(&gateway, (uint8_t (*)[16])v6_raw.s6_addr, 128);

    /* SRv6 L3VPN routes land in the default VRF's VPNv4 RIB (bgp.l3vpn.0),
     * exactly like plain BGP VPNv4 routes.  The only difference is that the
     * next-hop is an IPv6 SRv6 SID rather than an MPLS-labelled IPv4 address. */
    rtm_t *rtm = NODE_DEF_VRF_MEMBER(node, l3vpnv4);
    
    if (!rtm) {
        cprintf("Error: l3vpnv4 RIB not initialised on node %s\n", node->node_name);
        return -1;
    }

    memset(&nh_template, 0, sizeof(cp_nexthop_template_t));
    nh_template.is_indirect = true;
    nh_template.is_resolved = false;

    nh_template.proto = RTM_PROTO_BGP;
    nh_template.sub_proto = RTM_PROTO_BGP_VPN;

    nh_template.fwd_flags |= FIB_NH_FWD_F_IPV6;
    nh_template.oif = 0;

    nh_template.metric = 0;
    nh_template.rtm_nh_proto = NULL;

    memcpy (&nh_template.gateway, &gateway, sizeof (gateway));

    nh_template.u.srv6_stack.endfn = SRV6_END_FN_NONE;
    nh_template.u.srv6_stack.n_segment_list = 0;
    nh_template.u.srv6_stack.v6segment_lst = NULL;

    nh_template.fwd_flags |= FIB_NH_FWD_F_IPV6_STCK;
    nh_template.fwd_flags |= FIB_NH_FWD_F_TUNNEL;
    nh_template.fwd_flags |= FIB_NH_FWD_F_SRv6_FORWARD;
    
    nh_template.action = RTM_NH_ACTION_TUNNEL;

    nh_template.u.srv6_stack.n_segment_list = 1;

    nh_template.u.srv6_stack.v6segment_lst = 
        (cmn_prefix_t *)XCALLOC2(0, 1, cmn_prefix_t);

    cmn_prefix_initialize_v6(
        nh_template.u.srv6_stack.v6segment_lst + 0,
        (uint8_t (*)[16])v6_raw.s6_addr, 128);


    /* Now fill nexthop proto information */
    nh_template.rtm_nh_proto = (rtm_nh_proto_t *)XCALLOC2(0, 1, rtm_nh_proto_t);
    rtm_nh_proto_initialize(nh_template.rtm_nh_proto);
    nh_template.rtm_nh_proto->proto = RTM_PROTO_BGP;
    nh_template.rtm_nh_proto->sub_proto = RTM_PROTO_BGP_VPN;
    nh_template.rtm_nh_proto->instance_no = 0;
    nh_template.rtm_nh_proto->vrf_id = DEFAULT_VRF;

    /* (Un)Install route using new RTM API */
    rc = install ? cp_rtm_install_route(rtm, &prefix_key, &nh_template) : \
                   cp_rtm_uninstall_route(rtm, &prefix_key, &nh_template);

    if (rc != RTM_SUCCESS) {

        cprintf("%s : Warning: SRv6 route %sinstallation failed for prefix %s, error code: %s\n",
               rtm->node->node_name, install ? "" : "(Un-)", 
	           prefix_mask, rtm_error_to_string(rc));
    }

    /* Destroy nexthop template resources */
    rtm_nh_template_free_internals(&nh_template);

    return 0;
}