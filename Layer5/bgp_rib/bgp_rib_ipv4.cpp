#include <stdio.h>
#include <string.h>

#include "../../libs/Tracer/tracer.h"
#include "../../libs/common/cmn_prefix.h"
#include "../../RTM/rtm.h"
#include "../../RTM/rtm_enums.h"
#include "../../RTM/rtm_error.h"
#include "../../RTM/rtm_nb_integ.h"
#include "../../RTM/rtm_proto.h"
#include "../../router_init.h"
#include "../../tcpconst.h"
#include "../../vrf/vrf.h"

#include "../bgp_enums.h"
#include "../bgp_route.h"
#include "../bgp_rtr.h"
#include "bgp_rib_ipv4.h"

static uint8_t
ipv4_prefix_byte_count(uint8_t prefix_len)
{
    return (uint8_t)((prefix_len + 7) / 8);
}

bgp_rib_err_t
bgp_ipv4_unicast_nlri_decode(const bgp_nlri_key_t *key,
                             bgp_ipv4_unicast_nlri_t *nlri_out)
{
    uint8_t prefix_bytes;
    uint8_t i;

    if (!key || !nlri_out || key->wire_len < 1) {
        return BGP_RIB_ERR_NULL;
    }

    memset(nlri_out, 0, sizeof(*nlri_out));
    nlri_out->prefix_len = key->wire[0];
    if (nlri_out->prefix_len > 32) {
        return BGP_RIB_ERR_DECODE;
    }

    prefix_bytes = ipv4_prefix_byte_count(nlri_out->prefix_len);
    if (key->wire_len < 1 + prefix_bytes) {
        return BGP_RIB_ERR_DECODE;
    }

    for (i = 0; i < prefix_bytes; i++) {
        nlri_out->prefix = (nlri_out->prefix << 8) | key->wire[1 + i];
    }
    if (nlri_out->prefix_len < 32) {
        nlri_out->prefix <<= (32 - nlri_out->prefix_len);
    }

    return BGP_RIB_OK;
}

void
bgp_ipv4_unicast_nlri_key_to_cmn_prefix(bgp_nlri_key_t *key,
                                        cmn_prefix_t *cmn_prefix)
{
    bgp_ipv4_unicast_nlri_t nlri;

    if (!cmn_prefix) {
        return;
    }

    memset(cmn_prefix, 0, sizeof(*cmn_prefix));
    if (!key) {
        return;
    }

    if (bgp_ipv4_unicast_nlri_decode(key, &nlri) != BGP_RIB_OK) {
        return;
    }

    cmn_prefix_initialize_v4(cmn_prefix, nlri.prefix, nlri.prefix_len);
}

bool
bgp_ipv4_unicast_build_nh_template(bgp_rib_attrs_t *attrs,
                                   cp_nexthop_template_t *cp_nh_template)
{
    char nh_cidr[72];
    cmn_prefix_t gateway;
    rtm_error_t rc;

    memset(cp_nh_template, 0, sizeof(*cp_nh_template));

    if (!attrs || attrs->nexthop[0] == '\0') {
        return false;
    }

    if (strchr(attrs->nexthop, '/')) {
        strncpy(nh_cidr, attrs->nexthop, sizeof(nh_cidr) - 1);
        nh_cidr[sizeof(nh_cidr) - 1] = '\0';
    } else {
        snprintf(nh_cidr, sizeof(nh_cidr), "%s/32", attrs->nexthop);
    }

    if (!cmn_parse_prefix_string(nh_cidr, &gateway) ||
        gateway.afi != AF_IPV4) {
        return false;
    }

    cp_nh_template->is_indirect = true;
    cp_nh_template->is_resolved = false;
    cp_nh_template->proto = RTM_PROTO_BGP;
    cp_nh_template->sub_proto = RTM_PROTO_BGP_INT;
    cp_nh_template->action = RTM_NH_ACTION_FORWARD;
    cp_nh_template->metric = attrs->med_present ? attrs->med : 0;
    memcpy(&cp_nh_template->gateway, &gateway, sizeof(gateway));

    rc = rtm_nh_proto_info_create(RTM_PROTO_BGP,
                                  RTM_PROTO_BGP_INT,
                                  0,
                                  RTM_DEFAULT_VRF,
                                  &cp_nh_template->rtm_nh_proto);
    if (rc != RTM_SUCCESS) {
        memset(cp_nh_template, 0, sizeof(*cp_nh_template));
        return false;
    }

    return true;
}

void
bgp_global_rib_export_ipv4_unicast_route_cb(void *ctx,
                                            uint8_t afi,
                                            uint8_t safi,
                                            bgp_nlri_key_t *key,
                                            bgp_rib_attrs_t *attrs,
                                            bool is_add,
                                            uint16_t target_vrf_id)
{
    rtm_error_t rc;
    char nh_str[48];
    char route_str[48];
    rtm_t *inet0;
    cmn_prefix_t cmn_prefix;
    cp_nexthop_template_t cp_nh_template;
    bgp_inst_t *bgp_inst = (bgp_inst_t *)ctx;
    node_t *node;

    (void)afi;
    (void)safi;

    if (!bgp_inst || !key || !attrs) {
        return;
    }

    node = bgp_inst->node;
    if (!node) {
        return;
    }

    /* Unicast downloads only into default VRF inet.0 */
    if (target_vrf_id != RTM_DEFAULT_VRF) {
        return;
    }

    {
        uint32_t nh_int = ip_pton((c_string)attrs->nexthop);
        if (nh_int == 0 || nh_int == NODE_RTR_ID_INT(node)) {
            return;
        }
    }

    if (is_add && !attrs->best) {
        return;
    }

    bgp_ipv4_unicast_nlri_key_to_cmn_prefix(key, &cmn_prefix);
    if (cmn_prefix.afi != AF_IPV4) {
        tracer(bgp_inst->tr, DRTM | DERR,
               "%s : [%s] : Failed to decode IPv4 unicast NLRI, "
               "%sinstallation failed\n",
               BGP_RTM_IM, BGP_IPV4_UNICAST_RIB_NAME,
               is_add ? "" : "un");
        return;
    }

    rtm_format_prefix(&cmn_prefix, route_str, sizeof(route_str));

    if (!bgp_ipv4_unicast_build_nh_template(attrs, &cp_nh_template)) {
        tracer(bgp_inst->tr, DRTM | DERR,
               "%s : [%s] : Route %s, failed to build nh_template, "
               "%sinstallation failed\n",
               BGP_RTM_IM, BGP_IPV4_UNICAST_RIB_NAME, route_str,
               is_add ? "" : "un");
        return;
    }

    inet0 = rtm_get(node, RTM_DEFAULT_VRF, AF_IPV4, 0);
    if (!inet0) {
        rtm_nh_template_free_internals(&cp_nh_template);
        tracer(bgp_inst->tr, DRTM | DERR,
               "%s : [%s] : Route %s, 0.inet.0 not found\n",
               BGP_RTM_IM, BGP_IPV4_UNICAST_RIB_NAME, route_str);
        return;
    }

    rtm_format_nexthop(&cp_nh_template.gateway, nh_str, sizeof(nh_str));

    if (is_add) {
        rc = cp_rtm_install_route(inet0, &cmn_prefix, &cp_nh_template);
    } else {
        rc = cp_rtm_uninstall_route(inet0, &cmn_prefix, &cp_nh_template);
    }

    tracer(bgp_inst->tr, DRTM_DET,
           "%s : [%s] : Route %s nh %s %sinstalled into 0.inet.0, result=%s\n",
           BGP_RTM_IM, BGP_IPV4_UNICAST_RIB_NAME, route_str, nh_str,
           is_add ? "" : "un", rtm_error_to_string(rc));

    tracer(node->cptr, DRTM_DET,
           "%s : [%s] : Route %s nh %s %sinstalled into 0.inet.0, result=%s\n",
           BGP_RTM_IM, BGP_IPV4_UNICAST_RIB_NAME, route_str, nh_str,
           is_add ? "" : "un", rtm_error_to_string(rc));

    rtm_nh_template_free_internals(&cp_nh_template);
}
