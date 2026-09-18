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
#include "../Layer2/Evpn/evpn_bgp.h"
#include "../utils.h"

void
bgp_rtm_route_notif (vrf_t *vrf, rt_advert_info_t  *rt_advert);

extern void
bgp_route_pkt_q_cbk(event_dispatcher_t *ev_dis,
                      void *data,
                      uint32_t data_size);
                      
static sf_gobgp_grpc_client_t *
bgp_route_get_grpc_client(node_t *node)
{
    bgp_inst_t *bgp = BGP_INST(node);

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
    bgp_inst_t *bgp = BGP_INST(node);

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
        strcmp(safi, "mac") == 0 ||
        strcmp(safi, "imet") == 0) {
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
    out->evpn_route_type = params->evpn_route_type;
    out->eth_tag_id = params->eth_tag_id;
    out->pmsi_label = params->pmsi_label;
    out->pmsi_label_present = params->pmsi_label_present;
    out->mac_mobility_seq = params->mac_mobility_seq;
    out->mac_mobility_seq_present = params->mac_mobility_seq_present;
    strncpy(out->pe_addr, params->pe_addr, sizeof(out->pe_addr) - 1);
    if (out->prefix[0] == '\0' && out->pe_addr[0] != '\0') {
        strncpy(out->prefix, out->pe_addr, sizeof(out->prefix) - 1);
    }
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

bool
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
        out->rtr_id = ip_pton((c_string)left);
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
    bgp_inst_t *bgp = BGP_INST(node);

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

    bgp = BGP_INST(node);
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

int
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

    bgp = BGP_INST(node);
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
    bgp_unified_rt_t info;

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
    info.afi = route->afi;
    info.safi = route->safi;
    info.nlri_wire_len = route->nlri_wire_len;
    if (route->nlri_wire_len > 0) {
        memcpy(info.nlri_wire, route->nlri_wire, route->nlri_wire_len);
    }
    info.pmsi_label = route->pmsi_label;
    info.pmsi_label_present = route->pmsi_label_present;
    info.pmsi_tunnel_type = route->pmsi_tunnel_type;
    info.evpn_label1 = route->evpn_label1;
    info.evpn_label1_present = route->evpn_label1_present;
    info.evpn_label1_from_ext_comm = route->evpn_label1_from_ext_comm;
    info.mac_mobility_seq = route->mac_mobility_seq;
    info.mac_mobility_seq_present = route->mac_mobility_seq_present;
    info.ext_comm_count = route->ext_comm_count;
    if (route->ext_comm_count > 0) {
        memcpy(info.ext_comms, route->ext_comms,
               route->ext_comm_count * sizeof(bgp_rib_ext_comm_t));
    }

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

    bgp = BGP_INST(node);
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

        bgp_unified_rt_t info;
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
        info.afi = update->route.afi;
        info.safi = update->route.safi;
        info.nlri_wire_len = update->route.nlri_wire_len;
        if (update->route.nlri_wire_len > 0) {
            memcpy(info.nlri_wire, update->route.nlri_wire,
                   update->route.nlri_wire_len);
        }
        info.ext_comm_count = update->route.ext_comm_count;
        if (update->route.ext_comm_count > 0) {
            memcpy(info.ext_comms, update->route.ext_comms,
                   update->route.ext_comm_count * sizeof(bgp_rib_ext_comm_t));
        }
        info.evpn_label1 = update->route.evpn_label1;
        info.evpn_label1_present = update->route.evpn_label1_present;
        info.evpn_label1_from_ext_comm =
            update->route.evpn_label1_from_ext_comm;
        info.mac_mobility_seq = update->route.mac_mobility_seq;
        info.mac_mobility_seq_present =
            update->route.mac_mobility_seq_present;
        info.pmsi_label = update->route.pmsi_label;
        info.pmsi_label_present = update->route.pmsi_label_present;
        info.pmsi_tunnel_type = update->route.pmsi_tunnel_type;
        info.tunnel_encap_type = update->route.tunnel_encap_type;
        info.tunnel_encap_present = update->route.tunnel_encap_present;

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
    if (!node || !BGP_INST(node)) {
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
        bgp_inst = BGP_INST(vrf->node);
        if (bgp_inst) {
            tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
                   "%s : Unsupported addr-family afi=%u safi=%u for route %s, skip\n",
                   BGP_RTM_TAG, rt_advert->afi, rt_advert->safi,
                   cmn_prefix_to_string(&rt_advert->route, &prefix_str));
        }
        return;
    }

    bgp_inst = BGP_INST(vrf->node);
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

void
bgp_route_processing_pkt_q_init(node_t *node, bgp_inst_t *bgp)
{

    if (bgp->bgp_route_pkt_q.task) {
        return;
    }    

    init_pkt_q(EV(node), &bgp->bgp_route_pkt_q, bgp_route_pkt_q_cbk);
}
