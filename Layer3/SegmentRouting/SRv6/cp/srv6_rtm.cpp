#include <assert.h>
#include <string.h>
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
#include "../../../ipv6/v6nexthop.h"
#include "../../../ipv6/ipv6_utils.h"


static InterfaceP 
srv6_return_virtual_interface (node_t *node, 
            Srv6_endpcode_t composite_endfn) {

    switch (composite_endfn) {

        case END:
        case END_w_PSP:
        case END_w_USP:
        case END_w_PSP_USP:
            return node->node_nw_prop.srv6_end_interface;;
        default:
            return nullptr;
    }

    return nullptr;
}

void
srv6_rtm_route_install (node_t *node,
                        ipv6_addr_t *prefix,
                        uint8_t prefix_len,
                        uint8_t rt_flags,
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

    rtm = cp_rtm_get_route_target_rtm (
            node, oif ? oif->vrf : NODE_DEF_VRF(node),
            AF_IPV6, proto, RTM_SUB_PROTO_SRv6);
        
    if (!rtm) {
        cprintf("Error: No RTM localted for this route\n");
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

    if (oif) {
        nh_template.action = RTM_NH_ACTION_FORWARD;
        nh_template.is_indirect = false;
        nh_template.oif = oif->ifindex;
        nh_template.is_resolved = true;
        nh_template.fwd_flags |= FIB_NH_FWD_F_FORWARD;
    }

    if (rt_flags & IPV6_LOCAL_RT) {
        nh_template.action = RTM_NH_ACTION_LOCAL;
        nh_template.is_indirect = false;
        nh_template.oif = 0;
        nh_template.is_resolved = true;
        nh_template.fwd_flags |= FIB_NH_FWD_F_LOCAL;
    }

    nh_template.metric = cost;

    nh_template.rtm_nh_proto = NULL;

    /* Set metric */
    nh_template.metric = cost;

    /* Set gateway if provided */
    if (gw && !is_ipv6_addr_unspecified(&gw->addr)) {
        cmn_prefix_initialize_v6(&nh_template.gateway, &gw->addr, 128);
    }

    /* Set SRv6 specific information */
    nh_template.u.srv6_stack.endfn = endfn;
    nh_template.u.srv6_stack.n_segment_list = 0;
    nh_template.u.srv6_stack.v6segment_lst = NULL;

    /* Always set, because endfn resides in nh_template.u.srv6_stack.endfn */
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
    nh_template.rtm_nh_proto->vrf_id = oif ? oif->vrf->vrf_id : NODE_DEF_VRF(node)->vrf_id;
    
    /* (Un)Install route using new RTM API */
    rc = install ? cp_rtm_install_route(rtm, &prefix_key, &nh_template) : \
                   cp_rtm_uninstall_route(rtm, &prefix_key, &nh_template);

    if (rc != RTM_SUCCESS) {
        
        inet_ntop6(prefix, ipv6_str);

        cprintf("Warning: SRv6 route installation failed for prefix %s/%d, error code: %d\n",
               ipv6_str, prefix_len, rc);
    }

    /* Destroy nexthop template resources */
    rtm_nh_template_free_internals(&nh_template);
}