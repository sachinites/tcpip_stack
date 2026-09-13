#include "vpnv4_bgp.h"

#include <cstdio>
#include <cstring>

#include "../../libs/Tracer/tracer.h"
#include "../../libs/common/cmn_prefix.h"
#include "../../router_init.h"
#include "../../net.h"
#include "../../RTM/rtm_nb_integ.h"
#include "../../RTM/rtm_nh.h"
#include "../../RTM/rtm_proto.h"
#include "../../RTM/rtm_priv_api.h"
#include "../../RTM/rtm_enums.h"
#include "../../RTM/rtm_error.h"
#include "../../vrf/vrf.h"
#include "../../Layer5/bgp_enums.h"
#include "../../Layer5/bgp_rtr.h"

static bool
bgp_route_build_vpn_nh_template(const bgp_route_info_t *route,
                                cp_nexthop_template_t *nh_template)
{
    char nh_cidr[72];
    cmn_prefix_t gateway;
    rt_t import_rt;
    rtm_error_t rc;

    if (!route || !nh_template) {
        return false;
    }

    if (route->rd[0] == '\0') {
        return false;
    }

    if (route->nexthop[0] == '\0') {
        return false;
    }

    if (strchr(route->nexthop, '/')) {
        strncpy(nh_cidr, route->nexthop, sizeof(nh_cidr) - 1);
        nh_cidr[sizeof(nh_cidr) - 1] = '\0';
    } else {
        snprintf(nh_cidr, sizeof(nh_cidr), "%s/32", route->nexthop);
    }

    if (!cmn_parse_prefix_string(nh_cidr, &gateway) ||
        gateway.afi != AF_IPV4) {
        return false;
    }

    if (!bgp_route_parse_rt_string(route->rt, &import_rt)) {
        return false;
    }

    memset(nh_template, 0, sizeof(*nh_template));
    nh_template->is_indirect = true;
    nh_template->is_resolved = false;
    nh_template->proto = RTM_PROTO_BGP;
    nh_template->sub_proto = RTM_PROTO_BGP_VPN;
    nh_template->action = RTM_NH_ACTION_FORWARD;
    nh_template->metric = route->med_present ? route->med : 0;
    nh_template->import_rt = import_rt;
    if (route->l3_vpn_label_present && route->l3_vpn_label) {
        nh_template->vpn_label = route->l3_vpn_label;
    }
    memcpy(&nh_template->gateway, &gateway, sizeof(gateway));

    rc = rtm_nh_proto_info_create(
            RTM_PROTO_BGP,
            RTM_PROTO_BGP_VPN,
            0,
            RTM_DEFAULT_VRF,
            &nh_template->rtm_nh_proto);
    if (rc != RTM_SUCCESS) {
        return false;
    }

    return true;
}

void
bgp_rtm_vpn_route_install(node_t *node, const bgp_route_info_t *route)
{
    bgp_inst_t *bgp;
    rtm_t *rtm;
    cmn_prefix_t prefix;
    cp_nexthop_template_t nh_template;
    rtm_error_t rc;

    if (!node || !route || route->prefix[0] == '\0') {
        return;
    }

    bgp = bgp_get_instance(node);
    if (!bgp) {
        return;
    }

    if (route->rd[0] == '\0') {
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "%s : vpn install skip %s — missing RD\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    if (!route->best) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "%s : vpn install skip %s — not best path\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    if (bgp_route_is_nh_self(node, route)) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "%s : vpn install skip %s — nh-self route (locally originated)\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    if (!cmn_parse_prefix_string(route->prefix, &prefix) ||
        prefix.afi != AF_IPV4) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : vpn install fail %s — invalid IPv4 prefix\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    if (!bgp_route_build_vpn_nh_template(route, &nh_template)) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : vpn install fail %s — invalid nexthop/RT\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    rtm = NODE_DEF_VRF_MEMBER(node, l3vpnv4);
    if (!rtm) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : vpn install fail %s — bgp.l3vpn.0 not found\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    rc = cp_rtm_install_route(rtm, &prefix, &nh_template);
    rtm_nh_template_free_internals(&nh_template);
    if (rc != RTM_SUCCESS) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "%s : vpn install FAILED %s nh %s rd %s rt %s into bgp.l3vpn.0 — %s\n",
               BGP_RTM_TAG, route->prefix, route->nexthop,
               route->rd, route->rt[0] ? route->rt : "-",
               rtm_error_to_string(rc));
        return;
    }

    tracer(bgp->tr, TR_BGP_RT_EVENTS,
           "%s : vpn installed %s nh %s rd %s rt %s into bgp.l3vpn.0\n",
           BGP_RTM_TAG, route->prefix, route->nexthop,
           route->rd, route->rt[0] ? route->rt : "-");
}

void
bgp_rtm_vpn_route_uninstall(node_t *node, const bgp_route_info_t *route)
{
    bgp_inst_t *bgp;
    rtm_t *rtm;
    cmn_prefix_t prefix;
    cp_nexthop_template_t nh_template;
    rtm_error_t rc;

    if (!node || !route || route->prefix[0] == '\0') {
        return;
    }

    bgp = bgp_get_instance(node);
    if (!bgp) {
        return;
    }

    if (route->rd[0] == '\0') {
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "%s : vpn uninstall skip %s — missing RD\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    if (!cmn_parse_prefix_string(route->prefix, &prefix) ||
        prefix.afi != AF_IPV4) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : vpn uninstall fail %s — invalid IPv4 prefix\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    rtm = NODE_DEF_VRF_MEMBER(node, l3vpnv4);
    if (!rtm) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : vpn uninstall fail %s — bgp.l3vpn.0 not found\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    if (bgp_route_build_vpn_nh_template(route, &nh_template)) {
        rc = cp_rtm_uninstall_route(rtm, &prefix, &nh_template);
        rtm_nh_template_free_internals(&nh_template);
        if (rc != RTM_SUCCESS) {
            tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
                   "%s : vpn uninstall FAILED %s from bgp.l3vpn.0 — %s\n",
                   BGP_RTM_TAG, route->prefix, rtm_error_to_string(rc));
            return;
        }
    } else {
        (void)cp_rtm_uninstall_route_by_proto(
                rtm, &prefix, RTM_PROTO_BGP, RTM_PROTO_BGP_VPN);
    }

    tracer(bgp->tr, TR_BGP_RT_EVENTS,
           "%s : vpn uninstalled %s nh %s from bgp.l3vpn.0\n",
           BGP_RTM_TAG, route->prefix,
           route->nexthop[0] ? route->nexthop : "-");
}

void
bgp_schedule_vpn_route_processing_job(node_t *node,
                                      const bgp_route_info_t *route,
                                      bool is_add)
{
    bgp_schedule_route_processing_job_af(node, route, is_add, true, false);
}
