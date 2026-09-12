#include "bgp_route.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <pthread.h>

#include "../libs/Tracer/tracer.h"
#include "../libs/common/cmn_prefix.h"

#include "../router_init.h"
#include "../RTM/rtm_nb_integ.h"
#include "../RTM/rtm_nh.h"
#include "../RTM/rtm_proto.h"
#include "../RTM/rtm_priv_api.h"
#include "../RTM/rtm_enums.h"
#include "../RTM/rtm_error.h"
#include "../Interface/InterfacEnums.h"
#include "../tcpconst.h"
#include "../vrf/vrf.h"
#include "../net.h"
#include "../libs/EventDispatcher/event_dispatcher.h"
#include "bgp_config.h"
#include "bgp_rtr.h"
#include "bgp_enums.h"
#include "gobgp/sf_gobgp_grpc_client.h"
#include "../Layer2/Evpn/evpn_rt.h"
#include "../Layer2/Evpn/evpn_enums.h"
#include "../Layer2/Evpn/evpn.h"
#include "../Interface/Interface.h"
#include "../vrf/mac_vrf.h"
#include "../utils.h"

void
bgp_rtm_route_notif (vrf_t *vrf, rt_advert_info_t  *rt_advert);

static sf_gobgp_grpc_client_t *
bgp_route_get_grpc_client(node_t *node)
{
    bgp_inst_t *bgp = bgp_get_instance(node);

    if (!bgp) {
        return nullptr;
    }

    if (!bgp->bgp_grpc_client) {
        char endpoint[64];
        unsigned int grpc_port = node->udp_port_number + 1000;

        snprintf(endpoint, sizeof(endpoint), "127.0.0.1:%u", grpc_port);
        bgp->bgp_grpc_client = sf_gobgp_grpc_client_create(endpoint);
    }
    return (sf_gobgp_grpc_client_t *)bgp->bgp_grpc_client;
}

static bgp_node_config_t *
bgp_route_config_get(node_t *node)
{
    bgp_inst_t *bgp = bgp_get_instance(node);

    if (!bgp) {
        return nullptr;
    }
    return &bgp->bgp_config;
}

static int
bgp_route_parse_afi(const char *afi)
{
    if (!afi || strcmp(afi, "ipv4") == 0) {
        return AFI_IPV4;
    }
    if (strcmp(afi, "ipv6") == 0) {
        return AFI_IPV6;
    }
    if (strcmp(afi, "l2vpn") == 0 ||
        strcmp(afi, "l2vpn-evpn") == 0) {
        return AFI_L2VPN;
    }
    return -1;
}

static int
bgp_route_parse_safi(const char *safi)
{
    if (!safi || strcmp(safi, "unicast") == 0) {
        return SAFI_UNICAST;
    }
    if (strcmp(safi, "vpn") == 0 ||
        strcmp(safi, "mpls-vpn") == 0 ||
        strcmp(safi, "mpls_vpn") == 0) {
        return SAFI_MPLS_VPN;
    }
    if (strcmp(safi, "evpn") == 0 ||
        strcmp(safi, "mac") == 0) {
        return SAFI_MPLS_EVPN; /* SAFI_EVPN */
    }
    return -1;
}

static void
bgp_route_to_sf_params(const bgp_route_params_t *params,
                       int afi,
                       int safi,
                       sf_gobgp_route_params_t *out)
{
    memset(out, 0, sizeof(*out));
    strncpy(out->prefix, params->prefix, sizeof(out->prefix) - 1);
    strncpy(out->nexthop, params->nexthop, sizeof(out->nexthop) - 1);
    strncpy(out->rd, params->rd, sizeof(out->rd) - 1);
    strncpy(out->rt, params->rt, sizeof(out->rt) - 1);
    out->med = params->med;
    out->local_pref = params->local_pref;
    out->med_present = params->med_present;
    out->local_pref_present = params->local_pref_present;
    out->l3_vpn_label = params->l3_vpn_label;
    out->l3_vpn_label_present = params->l3_vpn_label_present;
    strncpy(out->mac_addr, params->mac_addr, sizeof(out->mac_addr) - 1);
    out->evpn_label = params->evpn_label;
    out->evpn_label_present = params->evpn_label_present;
    out->afi = afi;
    out->safi = safi;
}

static int
bgp_route_infer_safi(const bgp_route_params_t *params)
{
    if (params->rd[0] != '\0' || params->rt[0] != '\0') {
        return SAFI_MPLS_VPN;
    }
    return SAFI_UNICAST;
}

static AFI_T
bgp_route_rtm_target_afi(uint8_t afi)
{
    return (afi == AFI_IPV6) ? AF_IPV6 : AF_IPV4;
}

static bool
bgp_route_nh_is_local(const rtm_nh *nh)
{
    if (!nh) {
        return false;
    }

    if (nh->action == RTM_NH_ACTION_LOCAL ||
        nh->action == RTM_NH_ACTION_CONNECTED) {
        return true;
    }

    if (nh->prefix.afi == AF_IPV4 && nh->prefix.u.v4_addr == 0) {
        return true;
    }

    return false;
}

static rtm_nh *
bgp_route_resolve_nh(node_t *node, rt_advert_info_t *rt_advert)
{
    uint32_t nh_idx = (uint32_t)(rt_advert->Cnhidx & 0xFFFFFFFFULL);
    AFI_T afi = bgp_route_rtm_target_afi(rt_advert->afi);
    rtm_t *rtm;
    rtm_nh *nh;

    if (!node || nh_idx == 0) {
        return nullptr;
    }

    rtm = rtm_get(node, rt_advert->src_vrf_id, afi, 0);
    if (rtm) {
        nh = rtm_nh_lookup_by_idx(rtm, nh_idx);
        if (nh) {
            return nh;
        }
    }

    if (rt_advert->src_vrf_id != RTM_DEFAULT_VRF) {
        rtm = rtm_get(node, RTM_DEFAULT_VRF, afi, 0);
        if (rtm) {
            nh = rtm_nh_lookup_by_idx(rtm, nh_idx);
            if (nh) {
                return nh;
            }
        }
    }

    return nullptr;
}

/* Reachability check only: local/connected (0.0.0.0) are reachable;
 * remote NHs must exist in RTM. Advertised BGP NH is always self. */
static bool
bgp_route_is_reachable(rtm_nh *nh)
{
    if (!nh) {
        return false;
    }
    if (bgp_route_nh_is_local(nh)) {
        return true;
    }
    return true;
}

static bool
bgp_route_parse_rt_string(const char *rt_str, rt_t *out)
{
    char left[64];
    unsigned long right = 0;
    const char *colon;
    size_t left_len;

    if (!rt_str || !out || rt_str[0] == '\0') {
        return false;
    }

    colon = strchr(rt_str, ':');
    if (!colon || colon == rt_str) {
        return false;
    }

    left_len = (size_t)(colon - rt_str);
    if (left_len >= sizeof(left)) {
        return false;
    }

    memcpy(left, rt_str, left_len);
    left[left_len] = '\0';
    right = strtoul(colon + 1, NULL, 10);

    memset(out, 0, sizeof(*out));
    out->type = 1;
    out->sub_type = 0;

    if (strchr(left, '.')) {
        out->rtr_id = tcp_ip_convert_ip_p_to_n(left);
    } else {
        out->rtr_id = (uint32_t)strtoul(left, NULL, 10);
    }
    out->vrf_id = (uint16_t)right;
    return true;
}

static vrf_t *
bgp_route_get_src_vrf(vrf_t *target_vrf, rt_advert_info_t *rt_advert)
{
    if (!target_vrf || !rt_advert) {
        return NULL;
    }

    if (rt_advert->src_vrf_id == RTM_DEFAULT_VRF) {
        return target_vrf;
    }

    return vrf_get_by_id(target_vrf->node, rt_advert->src_vrf_id);
}

static bool
bgp_route_export_eligible(rt_advert_info_t *rt_advert, uint8_t safi)
{
    if (!rt_advert) {
        return false;
    }

    if (safi == SAFI_MPLS_VPN) {
        return rt_advert->src_vrf_id != RTM_DEFAULT_VRF;
    }

    if (safi == SAFI_UNICAST) {
        return rt_advert->src_vrf_id == RTM_DEFAULT_VRF;
    }

    return false;
}

static const char *
bgp_route_af_str_for_print(uint8_t afi, uint8_t safi)
{
    if (afi == AFI_IPV4 && safi == SAFI_UNICAST) {
        return IPV4_UNICAST_AF_STR;
    }
    if (afi == AFI_IPV4 && safi == SAFI_MPLS_VPN) {
        return VPNV4_UNICAST_AF_STR;
    }
    if (afi == AFI_IPV6 && safi == SAFI_UNICAST) {
        return IPV6_UNICAST_AF_STR;
    }
    if (afi == AFI_L2VPN && safi == SAFI_MPLS_EVPN) {
        return L2VPN_EVPN_AF_STR;
    }
    return "unknown";
}

static bool
bgp_route_af_enabled_in_local_config(bgp_node_config_t *cfg,
                                     int sf_afi,
                                     int sf_safi)
{
    int i;

    if (!cfg) {
        return false;
    }

    for (i = 0; i < cfg->num_neighbors; i++) {
        bgp_neighbor_config_t *nbr = &cfg->neighbors[i];

        if (!nbr->configured) {
            continue;
        }

        if (sf_afi == AFI_L2VPN && sf_safi == SAFI_MPLS_EVPN) {
            if (nbr->l2vpn_evpn) {
                return true;
            }
            continue;
        }

        if (sf_afi == AFI_IPV4 && sf_safi == SAFI_MPLS_VPN) {
            if (nbr->ipv4_vpn) {
                return true;
            }
            continue;
        }

        if (sf_safi == SAFI_UNICAST) {
            if (sf_afi == AFI_IPV4 && nbr->ipv4_unicast) {
                return true;
            }
        }
    }

    return false;
}

bool
bgp_route_is_af_enabled_on_any_neighbor(node_t *node, int sf_afi, int sf_safi)
{
    bgp_inst_t *bgp = bgp_get_instance(node);

    if (!bgp) {
        return false;
    }

    return bgp_route_af_enabled_in_local_config(&bgp->bgp_config,
                                                sf_afi, sf_safi);
}

static bool
bgp_route_af_enabled_via_grpc(node_t *node,
                              sf_gobgp_grpc_client_t *client,
                              int sf_afi,
                              int sf_safi)
{
    sf_gobgp_rpc_result_t result;
    bool enabled = false;

    if (!client) {
        return false;
    }

    result = sf_gobgp_is_address_family_enabled(client, sf_afi, sf_safi,
                                                &enabled);
    if (!result.ok) {
        return false;
    }

    return enabled;
}

static bool
bgp_route_is_af_configured_for_advertise(node_t *node,
                                         int sf_afi,
                                         int sf_safi)
{
    bgp_inst_t *bgp;
    bgp_node_config_t *cfg;
    sf_gobgp_grpc_client_t *client;

    bgp = bgp_get_instance(node);
    if (!bgp) {
        return false;
    }

    cfg = &bgp->bgp_config;
    if (!cfg->started) {
        return false;
    }

    if (bgp_route_af_enabled_in_local_config(cfg, sf_afi, sf_safi)) {
        return true;
    }

    client = bgp_route_get_grpc_client(node);
    return bgp_route_af_enabled_via_grpc(node, client, sf_afi, sf_safi);
}

static bool
bgp_route_notif_parse_af(uint8_t wire_afi, uint8_t *afi_out)
{
    if (!afi_out) {
        return false;
    }

    switch (wire_afi) {
        case AFI_IPV4:
        case AFI_IPV6:
            *afi_out = wire_afi;
            return true;
        default:
            return false;
    }
}

static bool
bgp_route_notif_parse_safi(uint8_t wire_safi, uint8_t *safi_out)
{
    if (!safi_out) {
        return false;
    }

    switch (wire_safi) {
        case SAFI_UNICAST:
        case SAFI_MPLS_VPN:
            *safi_out = wire_safi;
            return true;
        default:
            return false;
    }
}

static bool
bgp_route_vrf_fill_rd_rt(vrf_t *vrf,
                         uint8_t safi,
                         bgp_route_params_t *params)
{
    if (!vrf || !params) {
        return false;
    }

    /* IPv4/IPv6 unicast does not carry RD. VPNv4 requires RD + export RT. */
    if (safi != SAFI_MPLS_VPN) {
        params->rd[0] = '\0';
        params->rt[0] = '\0';
        params->l3_vpn_label = 0;
        params->l3_vpn_label_present = false;
        return true;
    }

    if (vrf->rd.rtr_id == 0 && vrf->rd.vrf_id == 0) {
        return false;
    }
    if (vrf->export_rt.rtr_id == 0 && vrf->export_rt.vrf_id == 0) {
        return false;
    }
    if (!vrf->l3_vpn_label) {
        return false;
    }

    snprintf(params->rd, sizeof(params->rd), "%u:%u",
             vrf->rd.rtr_id, vrf->rd.vrf_id);
    snprintf(params->rt, sizeof(params->rt), "%u:%u",
             vrf->export_rt.rtr_id, vrf->export_rt.vrf_id);
    params->l3_vpn_label = vrf->l3_vpn_label;
    params->l3_vpn_label_present = true;
    return true;
}

static int
bgp_route_apply_to_gobgp(node_t *node,
                         const bgp_route_params_t *params,
                         int sf_afi,
                         int sf_safi,
                         bool is_delete)
{
    sf_gobgp_grpc_client_t *client;
    sf_gobgp_route_params_t sf_params;
    sf_gobgp_rpc_result_t result;
    bgp_inst_t *bgp;
    tracer_t *tr;
    const char *op;

    bgp = bgp_get_instance(node);
    tr = bgp ? bgp->tr : nullptr;
    op = is_delete ? "DeletePath" : "AddPath";

    if (!bgp) {
        tracer(tr, TR_BGP_GRPC_TALK | TR_BGP_RT_EVENTS,
               "%s : %s aborted — no BGP instance for node %s (prefix %s)\n",
               BGP_RTM_TAG, op, node ? node->node_name : "?",
               params ? params->prefix : "?");
        return -1;
    }

    client = bgp_route_get_grpc_client(node);
    if (!client) {
        tracer(tr, TR_BGP_GRPC_TALK | TR_BGP_RT_EVENTS,
               "%s : %s aborted — no gRPC client for node %s (prefix %s)\n",
               BGP_RTM_TAG, op, node->node_name, params->prefix);
        return -1;
    }

    if (!is_delete &&
        !bgp_route_is_af_configured_for_advertise(node, sf_afi, sf_safi)) {
        tracer(tr, TR_BGP_GRPC_TALK | TR_BGP_RT_EVENTS,
               "%s : %s aborted — %s not configured on any BGP neighbor "
               "(local config / GoBGP gRPC) for node %s\n",
               BGP_RTM_TAG, op,
               bgp_route_af_str_for_print((uint8_t)sf_afi, (uint8_t)sf_safi),
               node->node_name);
        return -1;
    }

    bgp_route_to_sf_params(params, sf_afi, sf_safi, &sf_params);

    tracer(tr, TR_BGP_GRPC_TALK | TR_BGP_RT_EVENTS,
           "%s : %s RPC → prefix=%s nh=%s afi=%d safi=%d rd=%s rt=%s "
           "label=%s%u med=%s%u lp=%s%u\n",
           BGP_RTM_TAG, op, sf_params.prefix, sf_params.nexthop,
           sf_params.afi, sf_params.safi,
           sf_params.rd[0] ? sf_params.rd : "-",
           sf_params.rt[0] ? sf_params.rt : "-",
           sf_params.l3_vpn_label_present ? "" : "(none)",
           sf_params.l3_vpn_label_present ? sf_params.l3_vpn_label : 0,
           sf_params.med_present ? "" : "(none)",
           sf_params.med_present ? sf_params.med : 0,
           sf_params.local_pref_present ? "" : "(none)",
           sf_params.local_pref_present ? sf_params.local_pref : 0);

    result = is_delete ? sf_gobgp_delete_route(client, &sf_params)
                       : sf_gobgp_add_route(client, &sf_params);
    if (!result.ok) {
        tracer(tr, TR_BGP_GRPC_TALK | TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : %s RPC FAILED for %s — code=%d msg=\"%s\" "
               "(afi=%d safi=%d nh=%s rd=%s)\n",
               BGP_RTM_TAG, op, params->prefix,
               result.code,
               result.message[0] ? result.message : "(empty)",
               sf_params.afi, sf_params.safi,
               sf_params.nexthop,
               sf_params.rd[0] ? sf_params.rd : "-");
        return -1;
    }

    tracer(tr, TR_BGP_GRPC_TALK,
           "%s : %s RPC OK for %s (afi=%d safi=%d)\n",
           BGP_RTM_TAG, op, params->prefix, sf_params.afi, sf_params.safi);
    return 0;
}

struct bgp_route_walk_ctx {
    bgp_route_walk_cb callback;
    void *userdata;
};

static int
bgp_route_walk_adapter(const sf_gobgp_route_info_t *route, void *userdata)
{
    bgp_route_walk_ctx *ctx = (bgp_route_walk_ctx *)userdata;
    bgp_route_info_t info;

    if (!ctx || !ctx->callback || !route) {
        return 0;
    }

    memset(&info, 0, sizeof(info));
    strncpy(info.prefix, route->prefix, sizeof(info.prefix) - 1);
    strncpy(info.nexthop, route->nexthop, sizeof(info.nexthop) - 1);
    strncpy(info.rd, route->rd, sizeof(info.rd) - 1);
    strncpy(info.rt, route->rt, sizeof(info.rt) - 1);
    info.med = route->med;
    info.local_pref = route->local_pref;
    info.l3_vpn_label = route->l3_vpn_label;
    info.med_present = route->med_present;
    info.local_pref_present = route->local_pref_present;
    info.l3_vpn_label_present = route->l3_vpn_label_present;
    info.best = route->best;

    return ctx->callback(&info, ctx->userdata);
}

int
bgp_node_add_route(node_t *node, const bgp_route_params_t *params)
{
    int safi;

    if (!node || !params || params->prefix[0] == '\0' ||
        params->nexthop[0] == '\0') {
        return -1;
    }

    safi = bgp_route_infer_safi(params);
    return bgp_route_apply_to_gobgp(node, params, AFI_IPV4, safi, false);
}

int
bgp_node_delete_route(node_t *node, const bgp_route_params_t *params)
{
    int safi;

    if (!node || !params || params->prefix[0] == '\0') {
        return -1;
    }

    safi = bgp_route_infer_safi(params);
    return bgp_route_apply_to_gobgp(node, params, AFI_IPV4, safi, true);
}

int
bgp_node_walk_routes(node_t *node,
                     const char *afi,
                     const char *safi,
                     bgp_route_walk_cb callback,
                     void *userdata)
{
    sf_gobgp_grpc_client_t *client;
    bgp_route_walk_ctx ctx;
    sf_gobgp_rpc_result_t result;
    int parsed_afi;
    int parsed_safi;

    if (!node || !callback) {
        return -1;
    }

    parsed_afi = bgp_route_parse_afi(afi);
    parsed_safi = bgp_route_parse_safi(safi);
    if (parsed_afi < 0 || parsed_safi < 0) {
        return -1;
    }

    client = bgp_route_get_grpc_client(node);
    if (!client) {
        return -1;
    }

    ctx.callback = callback;
    ctx.userdata = userdata;
    result = sf_gobgp_walk_routes(client, parsed_afi, parsed_safi,
                                  bgp_route_walk_adapter, &ctx);
    return result.ok ? 0 : -1;
}

typedef struct bgp_withdraw_originated_ctx_ {
    node_t *node;
    const char *router_id;
} bgp_withdraw_originated_ctx_t;

static bool
bgp_route_is_locally_originated(const sf_gobgp_route_info_t *route,
                                const char *router_id)
{
    if (!route) {
        return false;
    }

    if (!route->is_from_external) {
        return true;
    }

    if (router_id && router_id[0] != '\0' &&
        route->nexthop[0] != '\0' &&
        strcmp(route->nexthop, router_id) == 0) {
        return true;
    }

    return false;
}

static int
bgp_route_withdraw_originated_walk_cb(const sf_gobgp_route_info_t *route,
                                      void *userdata)
{
    bgp_withdraw_originated_ctx_t *ctx =
        (bgp_withdraw_originated_ctx_t *)userdata;
    bgp_route_params_t params;

    if (!ctx || !route || !bgp_route_is_locally_originated(route,
                                                           ctx->router_id)) {
        return 0;
    }

    memset(&params, 0, sizeof(params));
    strncpy(params.nexthop, route->nexthop, sizeof(params.nexthop) - 1);
    strncpy(params.rd, route->rd, sizeof(params.rd) - 1);
    strncpy(params.rt, route->rt, sizeof(params.rt) - 1);
    params.med = route->med;
    params.local_pref = route->local_pref;
    params.med_present = route->med_present;
    params.local_pref_present = route->local_pref_present;
    params.l3_vpn_label = route->l3_vpn_label;
    params.l3_vpn_label_present = route->l3_vpn_label_present;

    if (route->safi == SAFI_MPLS_EVPN) {
        strncpy(params.mac_addr, route->prefix, sizeof(params.mac_addr) - 1);
        if (route->l3_vpn_label_present) {
            params.evpn_label = route->l3_vpn_label;
            params.evpn_label_present = true;
        }
    } else {
        strncpy(params.prefix, route->prefix, sizeof(params.prefix) - 1);
    }

    (void)bgp_route_apply_to_gobgp(ctx->node, &params,
                                   route->afi, route->safi, true);
    return 0;
}

void
bgp_route_withdraw_originated_routes(node_t *node, int sf_afi, int sf_safi)
{
    sf_gobgp_grpc_client_t *client;
    bgp_inst_t *bgp;
    bgp_withdraw_originated_ctx_t ctx;
    sf_gobgp_rpc_result_t result;

    if (!node) {
        return;
    }

    bgp = bgp_get_instance(node);
    if (!bgp || !bgp->bgp_config.started) {
        return;
    }

    client = bgp_route_get_grpc_client(node);
    if (!client) {
        return;
    }

    ctx.node = node;
    ctx.router_id = bgp->bgp_config.router_id;

    result = sf_gobgp_walk_routes(client, sf_afi, sf_safi,
                                  bgp_route_withdraw_originated_walk_cb, &ctx);
    if (!result.ok) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : withdraw originated routes walk failed for %s "
               "(afi=%d safi=%d) — %s\n",
               BGP_RTM_TAG,
               bgp_route_af_str_for_print((uint8_t)sf_afi, (uint8_t)sf_safi),
               sf_afi, sf_safi,
               result.message[0] ? result.message : "unknown error");
    }
}

/* ---- Monitor (WatchEvent) implementation ---- */

static const int kMonitorReconnectSec = 3;

struct bgp_monitor_thread_arg {
    node_t *node;
};

static void
bgp_monitor_dispatch(bgp_monitor_ctx_t *mon,
                     const sf_gobgp_route_update_t *update)
{
    pthread_mutex_lock(&mon->lock);

    for (int i = 0; i < mon->num_subs; i++) {
        bgp_monitor_sub_t *sub = &mon->subs[i];

        if (sub->afi != -1 && sub->afi != update->route.afi) {
            continue;
        }
        if (sub->safi != -1 && sub->safi != update->route.safi) {
            continue;
        }

        bgp_route_info_t info;
        memset(&info, 0, sizeof(info));
        strncpy(info.prefix, update->route.prefix, sizeof(info.prefix) - 1);
        strncpy(info.nexthop, update->route.nexthop, sizeof(info.nexthop) - 1);
        strncpy(info.rd, update->route.rd, sizeof(info.rd) - 1);
        strncpy(info.rt, update->route.rt, sizeof(info.rt) - 1);
        info.med = update->route.med;
        info.local_pref = update->route.local_pref;
        info.l3_vpn_label = update->route.l3_vpn_label;
        info.med_present = update->route.med_present;
        info.local_pref_present = update->route.local_pref_present;
        info.l3_vpn_label_present = update->route.l3_vpn_label_present;
        info.best = update->route.best;
        info.is_from_external = update->route.is_from_external;

        sub->callback(&info, update->is_withdraw, sub->userdata);
    }

    pthread_mutex_unlock(&mon->lock);
}

static void
bgp_monitor_watch_cb(const sf_gobgp_route_update_t *update, void *userdata)
{
    node_t *node = (node_t *)userdata;
    bgp_node_config_t *cfg = bgp_route_config_get(node);
    if (!cfg) {
        return;
    }
    bgp_monitor_dispatch(&cfg->monitor, update);
}

static void *
bgp_monitor_thread_fn(void *arg)
{
    bgp_monitor_thread_arg *targ = (bgp_monitor_thread_arg *)arg;
    node_t *node = targ->node;
    free(targ);

    bgp_node_config_t *cfg = bgp_route_config_get(node);
    if (!cfg) {
        return nullptr;
    }

    bgp_monitor_ctx_t *mon = &cfg->monitor;

    while (mon->running) {
        sf_gobgp_grpc_client_t *client = bgp_route_get_grpc_client(node);
        if (!client) {
            sleep(kMonitorReconnectSec);
            continue;
        }

        mon->watch_handle = sf_gobgp_watch_handle_create();

        sf_gobgp_rpc_result_t result =
            sf_gobgp_watch_routes(client, true,
                                  bgp_monitor_watch_cb, node,
                                  mon->watch_handle);

        sf_gobgp_watch_handle_destroy(mon->watch_handle);
        mon->watch_handle = nullptr;

        if (!mon->running) {
            break;
        }

        cprintf("[BGP-MON] %s: WatchEvent stream ended (%s), "
               "reconnecting in %ds...\n",
               node->node_name,
               result.ok ? "clean" : result.message,
               kMonitorReconnectSec);
        sleep(kMonitorReconnectSec);
    }

    return nullptr;
}

int
bgp_node_monitor_start(node_t *node)
{
    if (!node) {
        return -1;
    }

    bgp_node_config_t *cfg = bgp_route_config_get(node);
    if (!cfg) {
        return -1;
    }

    bgp_monitor_ctx_t *mon = &cfg->monitor;

    if (mon->running) {
        return 0;
    }

    pthread_mutex_init(&mon->lock, nullptr);
    mon->running = true;
    mon->watch_handle = nullptr;

    bgp_monitor_thread_arg *targ =
        (bgp_monitor_thread_arg *)calloc(1, sizeof(*targ));
    targ->node = node;

    int rc = pthread_create(&mon->thread, nullptr,
                            bgp_monitor_thread_fn, targ);
    if (rc != 0) {
        mon->running = false;
        free(targ);
        return -1;
    }

    return 0;
}

int
bgp_node_monitor_stop(node_t *node)
{
    if (!node || !bgp_get_instance(node)) {
        return -1;
    }

    bgp_node_config_t *cfg = bgp_route_config_get(node);
    if (!cfg) {
        return -1;
    }
    bgp_monitor_ctx_t *mon = &cfg->monitor;

    if (!mon->running) {
        return 0;
    }

    mon->running = false;

    if (mon->watch_handle) {
        sf_gobgp_watch_cancel(mon->watch_handle);
    }

    pthread_join(mon->thread, nullptr);
    pthread_mutex_destroy(&mon->lock);
    mon->num_subs = 0;

    return 0;
}

int
bgp_node_monitor_subscribe(node_t *node,
                            const char *afi,
                            const char *safi,
                            bgp_route_update_notify_cb callback,
                            void *userdata)
{
    if (!node || !callback) {
        return -1;
    }

    bgp_node_config_t *cfg = bgp_route_config_get(node);
    if (!cfg) {
        return -1;
    }

    bgp_monitor_ctx_t *mon = &cfg->monitor;

    int parsed_afi = afi ? bgp_route_parse_afi(afi) : -1;
    int parsed_safi = safi ? bgp_route_parse_safi(safi) : -1;

    pthread_mutex_lock(&mon->lock);

    if (mon->num_subs >= BGP_MONITOR_MAX_SUBS) {
        pthread_mutex_unlock(&mon->lock);
        return -1;
    }

    bgp_monitor_sub_t *sub = &mon->subs[mon->num_subs++];
    sub->afi = parsed_afi;
    sub->safi = parsed_safi;
    sub->callback = (bgp_monitor_notify_cb)callback;
    sub->userdata = userdata;

    pthread_mutex_unlock(&mon->lock);

    return 0;
}

int
bgp_node_monitor_subscribe_af(node_t *node,
                              int afi,
                              int safi,
                              bgp_route_update_notify_cb callback,
                              void *userdata)
{
    bgp_node_config_t *cfg = bgp_route_config_get(node);
    if (!cfg || !callback) {
        return -1;
    }

    bgp_monitor_ctx_t *mon = &cfg->monitor;

    pthread_mutex_lock(&mon->lock);

    if (mon->num_subs >= BGP_MONITOR_MAX_SUBS) {
        pthread_mutex_unlock(&mon->lock);
        return -1;
    }

    bgp_monitor_sub_t *sub = &mon->subs[mon->num_subs++];
    sub->afi = afi;
    sub->safi = safi;
    sub->callback = (bgp_monitor_notify_cb)callback;
    sub->userdata = userdata;

    pthread_mutex_unlock(&mon->lock);

    return 0;
}

void
bgp_rtm_route_notif (vrf_t *vrf, rt_advert_info_t  *rt_advert) {

    char prefix_str[48];
    char bgp_nbr_str[48];
    char label_buf[16] = "";
    bgp_route_params_t params;
    rtm_nh *nh;
    bgp_inst_t *bgp_inst;
    bgp_node_config_t *cfg;
    bool is_delete;
    uint8_t afi;
    uint8_t safi;

    if (!vrf || !rt_advert || !vrf->node) {
        return;
    }

    if (!bgp_route_notif_parse_af(rt_advert->afi, &afi) ||
        !bgp_route_notif_parse_safi(rt_advert->safi, &safi)) {
        bgp_inst = bgp_get_instance(vrf->node);
        if (bgp_inst) {
            tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
                   "%s : Unsupported addr-family afi=%u safi=%u for route %s, skip\n",
                   BGP_RTM_TAG, rt_advert->afi, rt_advert->safi,
                   cmn_prefix_to_string(&rt_advert->route, &prefix_str));
        }
        return;
    }

    bgp_inst = bgp_get_instance(vrf->node);
    if (!bgp_inst) {
        return;
    }

    cfg = &bgp_inst->bgp_config;

    tracer (bgp_inst->tr, TR_BGP_RT_EVENTS,
             "%s : Route %s notification received, Target-VRF:%s Src-VRF:%s addr-family:%s, BGP Nbr:%s, code:%s\n",
             BGP_RTM_TAG,
             cmn_prefix_to_string(&rt_advert->route, &prefix_str),
             vrf->vrf_name,
             vrf->node->vrf[rt_advert->src_vrf_id]->vrf_name,
             bgp_route_af_str_for_print(afi, safi),
             cmn_prefix_to_string(&rt_advert->bgp_nbr, &bgp_nbr_str),
             rt_advert->code == RTM_CLIENT_RT_ADD ? "Add" : "Del");

    if (!cfg->started || cfg->router_id[0] == '\0') {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
               "%s : BGP not started / no router-id on %s, skip route %s\n",
               BGP_RTM_TAG, vrf->node->node_name, prefix_str);
        return;
    }

    if (rt_advert->src_proto == RTM_PROTO_BGP) {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
               "%s : Route %s sourced by BGP, skip\n",
               BGP_RTM_TAG, prefix_str);
        return;
    }

    if (!bgp_route_export_eligible(rt_advert, safi)) {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
               "%s : Route %s from src-VRF:%s not eligible for %s export, skip\n",
               BGP_RTM_TAG, prefix_str, 
               vrf->node->vrf[rt_advert->src_vrf_id]->vrf_name,
               bgp_route_af_str_for_print(afi, safi));
        return;
    }

    {
        vrf_t *src_vrf = bgp_route_get_src_vrf(vrf, rt_advert);
        if (!src_vrf) {
            tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
                "%s : Src-VRF:%s not found for route %s being exported into BGP\n",
                BGP_RTM_TAG, 
                vrf->node->vrf[rt_advert->src_vrf_id]->vrf_name,
                prefix_str);
            return;
        }
        vrf = src_vrf;
    }

    /* Advertise only if still present/reachable in RTM.
     * Local/connected NHs are 0.0.0.0 — still reachable. */
    is_delete = (rt_advert->code == RTM_CLIENT_RT_DEL);
    nh = bgp_route_resolve_nh(vrf->node, rt_advert);
    if (!is_delete && (!nh || !bgp_route_is_reachable(nh))) {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : Route %s not reachable (Cnhidx 0x%llx), skip advertise\n",
               BGP_RTM_TAG, prefix_str,
               (unsigned long long)rt_advert->Cnhidx);
        return;
    }

    memset(&params, 0, sizeof(params));
    cmn_prefix_to_string(&rt_advert->route, (char (*)[48])params.prefix);

    /* BGP nexthop-self: always advertise our router-id, never RTM GW. */
    strncpy(params.nexthop, cfg->router_id, sizeof(params.nexthop) - 1);

    if (!bgp_route_vrf_fill_rd_rt(vrf, safi, &params)) {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : Eror : VRF %s missing RD/export-RT/L3VPN label required for VPN advertise of %s\n",
               BGP_RTM_TAG, vrf->vrf_name, prefix_str);
        return;
    }

    if (rt_advert->out_cost != 0) {
        params.med = rt_advert->out_cost;
        params.med_present = true;
    }

    if (bgp_route_apply_to_gobgp(vrf->node, &params, afi, safi, is_delete) != 0) {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : Failed to %s route %s nh-self %s to GoBGP (%s) peer %s\n",
               BGP_RTM_TAG,
               is_delete ? "withdraw" : "advertise",
               prefix_str, params.nexthop,
               bgp_route_af_str_for_print(afi, safi),
               bgp_nbr_str);
        return;
    }

    if (params.l3_vpn_label_present) {
        snprintf(label_buf, sizeof(label_buf), " label %u",
                 params.l3_vpn_label);
    }

    tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
           "%s : %s route %s nh-self %s to GoBGP (%s) peer %s"
           "%s%s%s%s%s\n",
           BGP_RTM_TAG,
           is_delete ? "Withdrew" : "Advertised",
           prefix_str, params.nexthop,
           bgp_route_af_str_for_print(afi, safi),
           bgp_nbr_str,
           params.rd[0] ? " RD " : "",
           params.rd[0] ? params.rd : "",
           params.rt[0] ? " RT " : "",
           params.rt[0] ? params.rt : "",
           label_buf);
}

int
bgp_evpn_type2_route_update(node_t *node,
                            rd_t *rd,
                            rt_t *export_rt,
                            evpn_rt_t *evpn_rt,
                            bool is_delete)
{
    bgp_route_params_t params;
    bgp_inst_t *bgp_inst;
    bgp_node_config_t *cfg;
    const unsigned char *mac;
    char mac_str[32];

    if (!node || !rd || !export_rt || !evpn_rt) {
        return -1;
    }

    if (evpn_rt->type != EVPN_RT_TYPE_MAC_ONLY) {
        return -1;
    }

    bgp_inst = bgp_get_instance(node);
    if (!bgp_inst) {
        return -1;
    }

    cfg = &bgp_inst->bgp_config;
    if (!cfg->started || cfg->router_id[0] == '\0') {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
               "%s : BGP not started / no router-id on %s, skip EVPN MAC export\n",
               BGP_RTM_TAG, node->node_name);
        return -1;
    }

    if (rd->rtr_id == 0 && rd->vrf_id == 0) {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : EVPN MAC export missing RD on %s\n",
               BGP_RTM_TAG, node->node_name);
        return -1;
    }

    if (export_rt->rtr_id == 0 && export_rt->vrf_id == 0) {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : EVPN MAC export missing export-RT on %s\n",
               BGP_RTM_TAG, node->node_name);
        return -1;
    }

    mac = evpn_rt->u.mac_only.mac.mac;
    snprintf(mac_str, sizeof(mac_str),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    memset(&params, 0, sizeof(params));
    strncpy(params.mac_addr, mac_str, sizeof(params.mac_addr) - 1);
    strncpy(params.nexthop, cfg->router_id, sizeof(params.nexthop) - 1);
    rd_type1_to_str(rd, params.rd, sizeof(params.rd));
    rt_type1_to_str(export_rt, params.rt, sizeof(params.rt));
    params.evpn_label = evpn_rt->u.mac_only.label;
    params.evpn_label_present = true;

    if (bgp_route_apply_to_gobgp(node, &params, AFI_L2VPN,
                                 SAFI_MPLS_EVPN, is_delete) != 0) {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : Failed to %s EVPN Type-2 MAC %s RD %s RT %s label %u\n",
               BGP_RTM_TAG,
               is_delete ? "withdraw" : "advertise",
               mac_str, params.rd, params.rt, params.evpn_label);
        return -1;
    }

    tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
           "%s : %s EVPN Type-2 MAC %s nh-self %s RD %s RT %s label %u\n",
           BGP_RTM_TAG,
           is_delete ? "Withdrew" : "Advertised",
           mac_str, params.nexthop, params.rd, params.rt, params.evpn_label);
    return 0;
}

/* ======================== BGP Remote routes installation==================== */

    /*
     * Route placement decision is based primarily on:
     *     AFI/SAFI
     *     Route Type (for EVPN)
     *     Route Targets
     *
     * RD is used for route uniqueness and bookkeeping,
     * not for VRF selection.
     */

    /*
     * AFI=1 SAFI=1 (IPv4 Unicast)
     *
     * No RD.
     * No Route Targets.
     *
     * Install directly into the IPv4 Unicast RIB associated
     * with the peer/VRF context.
     */
    
    /*
     * AFI=1 SAFI=128 (VPNv4)
     *
     * Store in local VPNv4 RIB:
     *      key = <RD, Prefix>
     *
     * Use Route Targets to determine importing VRFs.
     *
     * Import selected routes into:
     *      VRF.inet.0
     */
     
    /*
     * AFI=2 SAFI=128 (VPNv6)
     *
     * Same model as VPNv4.
     */

    /*
     * AFI=25 SAFI=70 (EVPN)
     *
     * Store in local EVPN RIB:
     *      key = <RD, Route-Type-specific-NLRI>
     *
     * Use Route Targets to determine importing MAC-VRFs
     * and/or IP-VRFs.
     *
     * RT-2 (MAC/IP Advertisement)
     *      -> Import into MAC-VRF
     *
     * RT-3 (IMET)
     *      -> Import into MAC-VRF
     *
     * RT-4 (Ethernet Segment)
     *      -> EVPN control-plane database
     *
     * RT-5 (IP Prefix)
     *      -> Import into IP-VRF (VRF.inet.0)
     */


static bool
bgp_route_is_nh_self(node_t *node, const bgp_route_info_t *route)
{
    bgp_inst_t *bgp;
    bgp_node_config_t *cfg;
    char nh_addr[64];

    if (!node || !route || route->nexthop[0] == '\0') {
        return false;
    }

    bgp = bgp_get_instance(node);
    if (!bgp) {
        return false;
    }

    cfg = &bgp->bgp_config;
    if (cfg->router_id[0] == '\0') {
        return false;
    }

    /* Nexthop may be "a.b.c.d" or "a.b.c.d/32" from GoBGP. */
    strncpy(nh_addr, route->nexthop, sizeof(nh_addr) - 1);
    nh_addr[sizeof(nh_addr) - 1] = '\0';
    {
        char *slash = strchr(nh_addr, '/');
        if (slash) {
            *slash = '\0';
        }
    }

    return strcmp(nh_addr, cfg->router_id) == 0;
}

/* We have recvd route ADD from GoBGP*/
void
bgp_rtm_route_install(node_t *node, const bgp_route_info_t *route)
{
    bgp_inst_t *bgp;
    rtm_t *rtm;
    cmn_prefix_t prefix;
    cmn_prefix_t gateway;
    rtm_error_t rc;
    uint32_t metric;
    char nh_cidr[72];

    if (!node || !route || route->prefix[0] == '\0') {
        return;
    }

    bgp = bgp_get_instance(node);
    if (!bgp) {
        return;
    }

    /*
     * AFI=1 SAFI=1 (IPv4 Unicast): no RD/RT.
     * VPNv4 / EVPN paths are handled separately later.
     */
    if (route->rd[0] != '\0') {
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "%s : install skip %s — RD present (not ipv4-unicast)\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    if (!route->best) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "%s : install skip %s — not best path\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    if (bgp_route_is_nh_self(node, route)) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "%s : install skip %s — nh-self route (locally originated)\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    if (!cmn_parse_prefix_string(route->prefix, &prefix) ||
        prefix.afi != AF_IPV4) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : install fail %s — invalid IPv4 prefix\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    if (route->nexthop[0] == '\0') {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : install fail %s — empty nexthop\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    /* Bare IPv4 NH (no /mask) must be forced to /32 for the parser. */
    if (strchr(route->nexthop, '/')) {
        strncpy(nh_cidr, route->nexthop, sizeof(nh_cidr) - 1);
        nh_cidr[sizeof(nh_cidr) - 1] = '\0';
    } else {
        snprintf(nh_cidr, sizeof(nh_cidr), "%s/32", route->nexthop);
    }

    if (!cmn_parse_prefix_string(nh_cidr, &gateway) ||
        gateway.afi != AF_IPV4) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : install fail %s — invalid IPv4 nexthop %s\n",
               BGP_RTM_TAG, route->prefix, route->nexthop);
        return;
    }

    /* 0.inet.0 — default VRF IPv4 unicast RIB */
    rtm = rtm_get(node, RTM_DEFAULT_VRF, AF_IPV4, 0);
    if (!rtm) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : install fail %s — 0.inet.0 not found\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    metric = route->med_present ? route->med : 0;

    /* Indirect NH: BGP peer NH resolves via IGP in inet.0 */
    rc = cp_rtm_install_route_advanced(
            rtm,
            &prefix,
            RTM_PROTO_BGP,
            RTM_PROTO_BGP_INT,
            0, 0,
            RTM_NH_ACTION_FORWARD,
            metric,
            &gateway,
            0,
            INTF_TYPE_UNKNOWN,
            NULL,
            0,
            0,
            MPLS_OP_STACK_OPS_UNKNOWN,
            0);

    if (rc != RTM_SUCCESS) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "%s : install FAILED %s nh %s into 0.inet.0 — %s\n",
               BGP_RTM_TAG, route->prefix, route->nexthop,
               rtm_error_to_string(rc));
        return;
    }

    tracer(bgp->tr, TR_BGP_RT_EVENTS,
           "%s : installed %s nh %s into 0.inet.0 (BGP/BGP-INT metric %u)\n",
           BGP_RTM_TAG, route->prefix, route->nexthop, metric);
}

/* We have recvd route DEL from GoBGP */
void
bgp_rtm_route_uninstall(node_t *node, const bgp_route_info_t *route)
{
    bgp_inst_t *bgp;
    rtm_t *rtm;
    cmn_prefix_t prefix;
    cmn_prefix_t gateway;
    rtm_error_t rc;
    uint32_t metric;
    char nh_cidr[72];

    if (!node || !route || route->prefix[0] == '\0') {
        return;
    }

    bgp = bgp_get_instance(node);
    if (!bgp) {
        return;
    }

    if (route->rd[0] != '\0') {
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "%s : uninstall skip %s — RD present (not ipv4-unicast)\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    if (!cmn_parse_prefix_string(route->prefix, &prefix) ||
        prefix.afi != AF_IPV4) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : uninstall fail %s — invalid IPv4 prefix\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    rtm = rtm_get(node, RTM_DEFAULT_VRF, AF_IPV4, 0);
    if (!rtm) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : uninstall fail %s — 0.inet.0 not found\n",
               BGP_RTM_TAG, route->prefix);
        return;
    }

    metric = route->med_present ? route->med : 0;

    if (route->nexthop[0] != '\0') {
        if (strchr(route->nexthop, '/')) {
            strncpy(nh_cidr, route->nexthop, sizeof(nh_cidr) - 1);
            nh_cidr[sizeof(nh_cidr) - 1] = '\0';
        } else {
            snprintf(nh_cidr, sizeof(nh_cidr), "%s/32", route->nexthop);
        }

        if (!cmn_parse_prefix_string(nh_cidr, &gateway) ||
            gateway.afi != AF_IPV4) {
            tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
                   "%s : uninstall fail %s — invalid IPv4 nexthop %s\n",
                   BGP_RTM_TAG, route->prefix, route->nexthop);
            return;
        }

        rc = cp_rtm_uninstall_route_advanced(
                rtm,
                &prefix,
                RTM_PROTO_BGP,
                RTM_PROTO_BGP_INT,
                0,
                RTM_NH_ACTION_FORWARD,
                metric,
                &gateway,
                0,
                INTF_TYPE_UNKNOWN,
                NULL,
                0,
                0,
                MPLS_OP_STACK_OPS_UNKNOWN,
                0);

        if (rc != RTM_SUCCESS) {
            tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
                   "%s : uninstall FAILED %s nh %s from 0.inet.0 — %s\n",
                   BGP_RTM_TAG, route->prefix, route->nexthop,
                   rtm_error_to_string(rc));
            return;
        }
    } else {
        /* No NH in withdraw — remove all BGP-INT nexthops for this prefix. */
        (void)cp_rtm_uninstall_route_by_proto(
                rtm, &prefix, RTM_PROTO_BGP, RTM_PROTO_BGP_INT);
    }

    tracer(bgp->tr, TR_BGP_RT_EVENTS,
           "%s : uninstalled %s nh %s from 0.inet.0 (BGP/BGP-INT)\n",
           BGP_RTM_TAG, route->prefix,
           route->nexthop[0] ? route->nexthop : "-");
}

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

typedef struct bgp_route_processing_info_ {

    node_t *node;
    bgp_route_info_t *route;
    bool is_add;
    bool is_vpn;
    bool is_evpn;

} bgp_route_processing_info_t;

static void
bgp_route_pkt_q_cbk(event_dispatcher_t *ev_dis,
                      void *data,
                      uint32_t data_size)
{
    bgp_route_processing_info_t *info;
    node_t *node = (node_t *)ev_dis->app_data;
    bgp_inst_t *bgp_inst = BGP_INST(node);

    (void)data;

    if (!bgp_inst) {
        return;
    }

    info = (bgp_route_processing_info_t *)task_get_next_pkt(ev_dis, &data_size);
    if (!info) {
        return;
    }

    tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
           "%s : Route processing job cbk invoked\n", BGP_RTM_TAG);

    for (; info;
         info = (bgp_route_processing_info_t *)task_get_next_pkt(ev_dis,
                                                                 &data_size)) {
        if (info->is_evpn) {
            info->is_add ? bgp_rtm_evpn_route_install(info->node, info->route) :
                           bgp_rtm_evpn_route_uninstall(info->node, info->route);
        } else if (info->is_vpn) {
            info->is_add ? bgp_rtm_vpn_route_install(info->node, info->route) :
                           bgp_rtm_vpn_route_uninstall(info->node, info->route);
        } else {
            info->is_add ? bgp_rtm_route_install(info->node, info->route) :
                           bgp_rtm_route_uninstall(info->node, info->route);
        }

        XFREE(info->route);
        XFREE(info);
    }
}

void
bgp_route_processing_pkt_q_init(node_t *node, bgp_inst_t *bgp)
{
    if (!node || !bgp) {
        return;
    }

    if (bgp->bgp_route_pkt_q.task) {
        return;
    }

    init_pkt_q(EV(node), &bgp->bgp_route_pkt_q, bgp_route_pkt_q_cbk);
}

static void
bgp_schedule_route_processing_job_common(node_t *node,
                                         const bgp_route_info_t *route,
                                         bool is_add,
                                         bool is_vpn,
                                         bool is_evpn)
{
    bgp_inst_t *bgp_inst = BGP_INST(node);
    bgp_route_processing_info_t *info;
    bgp_route_info_t *route_cpy;

    if (!bgp_inst) {
        return;
    }

    if (!bgp_inst->bgp_route_pkt_q.task) {
        bgp_route_processing_pkt_q_init(node, bgp_inst);
    }

    info = (bgp_route_processing_info_t *)
        XCALLOC2(0, 1, bgp_route_processing_info_t);
    route_cpy = (bgp_route_info_t *)XCALLOC2(0, 1, bgp_route_info_t);

    memcpy(route_cpy, route, sizeof(*route_cpy));

    info->node = node;
    info->route = route_cpy;
    info->is_add = is_add;
    info->is_vpn = is_vpn;
    info->is_evpn = is_evpn;

    if (!pkt_q_enqueue(EV(node),
                       &bgp_inst->bgp_route_pkt_q,
                       (char *)info,
                       sizeof(*info))) {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : Route processing pkt_q full, dropped %s\n",
               BGP_RTM_TAG, route->prefix);
        XFREE(route_cpy);
        XFREE(info);
        return;
    }

    tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
           "%s : Route processing job scheduled\n", BGP_RTM_TAG);
}

void 
bgp_schedule_route_processing_job (node_t *node, 
                                  const bgp_route_info_t *route, 
                                  bool is_add) 
{
    bgp_schedule_route_processing_job_common(node, route, is_add, false, false);
}

void
bgp_schedule_vpn_route_processing_job(node_t *node,
                                      const bgp_route_info_t *route,
                                      bool is_add)
{
    bgp_schedule_route_processing_job_common(node, route, is_add, true, false);
}

void
bgp_schedule_evpn_route_processing_job(node_t *node,
                                       const bgp_route_info_t *route,
                                       bool is_add)
{
    bgp_schedule_route_processing_job_common(node, route, is_add, false, true);
}

static bool
bgp_evpn_parse_mac_string(const char *mac_str, mac_addr_t *mac_out)
{
    unsigned int bytes[MAC_ADDR_SIZE];
    int count;
    int i;

    if (!mac_str || !mac_out || mac_str[0] == '\0') {
        return false;
    }

    count = sscanf(mac_str,
                   "%x:%x:%x:%x:%x:%x",
                   &bytes[0], &bytes[1], &bytes[2],
                   &bytes[3], &bytes[4], &bytes[5]);
    if (count != MAC_ADDR_SIZE) {
        count = sscanf(mac_str,
                       "%x-%x-%x-%x-%x-%x",
                       &bytes[0], &bytes[1], &bytes[2],
                       &bytes[3], &bytes[4], &bytes[5]);
    }
    if (count != MAC_ADDR_SIZE) {
        return false;
    }

    for (i = 0; i < MAC_ADDR_SIZE; i++) {
        mac_out->mac[i] = (uint8_t)bytes[i];
    }

    return true;
}

static bool
bgp_evpn_import_rt_matches(evpn_inst_t *evpn_inst, const rt_t *route_rt)
{
    if (!evpn_inst || !route_rt) {
        return false;
    }

    if (!evpn_inst->import_rt.rtr_id && !evpn_inst->import_rt.vrf_id) {
        return false;
    }

    return evpn_inst->import_rt.rtr_id == route_rt->rtr_id &&
           evpn_inst->import_rt.vrf_id == route_rt->vrf_id;
}

static bool
bgp_evpn_route_parse_nexthop(const bgp_route_info_t *route,
                               uint32_t *vtep_ip_out)
{
    char nh_addr[64];
    char *slash;

    if (!route || !vtep_ip_out || route->nexthop[0] == '\0') {
        return false;
    }

    strncpy(nh_addr, route->nexthop, sizeof(nh_addr) - 1);
    nh_addr[sizeof(nh_addr) - 1] = '\0';

    slash = strchr(nh_addr, '/');
    if (slash) {
        *slash = '\0';
    }

    *vtep_ip_out = tcp_ip_convert_ip_p_to_n(nh_addr);
    return (*vtep_ip_out != 0);
}

static void
bgp_evpn_remote_route_install(node_t *node,
                         const bgp_route_info_t *route,
                         bool install)
{
    bgp_inst_t *bgp;
    mac_addr_t mac_addr;
    rt_t import_rt;
    uint32_t vtep_ip;
    uint32_t label;
    int i;
    int installed = 0;

    if (!node || !route) {
        return;
    }

    bgp = bgp_get_instance(node);
    if (!bgp) {
        return;
    }

    if (!bgp_evpn_parse_mac_string(route->prefix, &mac_addr)) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : evpn %s skip %s — invalid MAC address\n",
               BGP_RTM_TAG, install ? "install" : "uninstall",
               route->prefix[0] ? route->prefix : "-");
        return;
    }

    if (route->rt[0] == '\0' ||
        !bgp_route_parse_rt_string(route->rt, &import_rt)) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : evpn %s skip %s — missing/invalid import RT\n",
               BGP_RTM_TAG, install ? "install" : "uninstall",
               route->prefix);
        return;
    }

    if (install) {
        if (!route->best) {
            tracer(bgp->tr, TR_BGP_RT_EVENTS,
                   "%s : evpn install skip %s — not best path\n",
                   BGP_RTM_TAG, route->prefix);
            return;
        }

        /* Same as ipv4-unicast / vpnv4: treat nh-self as local echo of our
         * own AddPath. Do not use is_from_external — GoBGP WatchEvent often
         * leaves it unset for remote best paths. */
        if (bgp_route_is_nh_self(node, route)) {
            tracer(bgp->tr, TR_BGP_RT_EVENTS,
                   "%s : evpn install skip %s — nh-self route (locally originated)\n",
                   BGP_RTM_TAG, route->prefix);
            return;
        }

        if (!bgp_evpn_route_parse_nexthop(route, &vtep_ip)) {
            tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
                   "%s : evpn install fail %s — invalid VTEP nexthop %s\n",
                   BGP_RTM_TAG, route->prefix,
                   route->nexthop[0] ? route->nexthop : "-");
            return;
        }
    }

    label = route->l3_vpn_label_present ? route->l3_vpn_label : 0;

    for (i = 0; i < MAX_EVPN_INDEX; i++) {
        evpn_inst_t *evpn_inst = node->evpn[i];
        BDInterface *bd_intf;
        mac_vrf_t *mac_vrf;

        if (!evpn_inst) {
            continue;
        }

        if (!bgp_evpn_import_rt_matches(evpn_inst, &import_rt)) {
            continue;
        }

        bd_intf = evpn_inst->bd_intf.get();
        if (!bd_intf || !bd_intf->vrf) {
            continue;
        }

        mac_vrf = bd_intf->vrf->mac_vrf[bd_intf->bd_id];
        if (!mac_vrf) {
            continue;
        }

        if (install) {
            mac_vrf_evpn_route_type2_remote_import(mac_vrf,
                                                   &mac_addr,
                                                   vtep_ip,
                                                   label);
        } else {
            mac_vrf_evpn_route_type2_remote_delete(mac_vrf, &mac_addr);
        }

        installed++;
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "%s : evpn %s MAC %s RT %s into EVI %u BD %u nh %s label %u\n",
               BGP_RTM_TAG,
               install ? "installed" : "uninstalled",
               route->prefix, route->rt,
               evpn_inst->evi, bd_intf->bd_id,
               route->nexthop[0] ? route->nexthop : "-",
               label);
    }

    if (!installed) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "%s : evpn %s MAC %s RT %s — no matching EVPN instance\n",
               BGP_RTM_TAG,
               install ? "install" : "uninstall",
               route->prefix, route->rt);
    }
}

void
bgp_rtm_evpn_route_install(node_t *node, const bgp_route_info_t *route)
{
    bgp_evpn_remote_route_install(node, route, true);
}

void
bgp_rtm_evpn_route_uninstall(node_t *node, const bgp_route_info_t *route)
{
    bgp_evpn_remote_route_install(node, route, false);
}