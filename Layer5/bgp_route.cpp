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
#include "../RTM/rtm_priv_api.h"
#include "../RTM/rtm_enums.h"
#include "../RTM/rtm_error.h"
#include "../Interface/InterfacEnums.h"
#include "../tcpconst.h"
#include "../vrf/vrf.h"
#include "bgp_config.h"
#include "bgp_rtr.h"
#include "bgp_enums.h"
#include "gobgp/sf_gobgp_grpc_client.h"

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

static bgp_route_config_t *
bgp_route_config_find(bgp_node_config_t *cfg, const char *prefix, const char *rd)
{
    for (int i = 0; i < cfg->num_routes; i++) {
        if (strcmp(cfg->routes[i].prefix, prefix) != 0) {
            continue;
        }
        if (strcmp(cfg->routes[i].rd, rd ? rd : "") != 0) {
            continue;
        }
        return &cfg->routes[i];
    }
    return NULL;
}

static bgp_route_config_t *
bgp_route_config_add(bgp_node_config_t *cfg,
                     const bgp_route_params_t *params)
{
    bgp_route_config_t *route =
        bgp_route_config_find(cfg, params->prefix, params->rd);

    if (route) {
        return route;
    }

    if (cfg->num_routes >= BGP_MAX_ROUTES) {
        return NULL;
    }

    route = &cfg->routes[cfg->num_routes++];
    memset(route, 0, sizeof(*route));
    strncpy(route->prefix, params->prefix, sizeof(route->prefix) - 1);
    strncpy(route->rd, params->rd, sizeof(route->rd) - 1);
    return route;
}

static void
bgp_route_config_remove(bgp_node_config_t *cfg,
                        const char *prefix,
                        const char *rd)
{
    for (int i = 0; i < cfg->num_routes; i++) {
        if (strcmp(cfg->routes[i].prefix, prefix) != 0) {
            continue;
        }
        if (strcmp(cfg->routes[i].rd, rd ? rd : "") != 0) {
            continue;
        }

        for (int j = i + 1; j < cfg->num_routes; j++) {
            cfg->routes[j - 1] = cfg->routes[j];
        }
        cfg->num_routes--;
        return;
    }
}

static bool
bgp_route_params_equal(const bgp_route_config_t *cached,
                       const bgp_route_params_t *params)
{
    return cached->configured &&
           strcmp(cached->prefix, params->prefix) == 0 &&
           strcmp(cached->nexthop, params->nexthop) == 0 &&
           strcmp(cached->rd, params->rd) == 0 &&
           strcmp(cached->rt, params->rt) == 0 &&
           cached->med_present == params->med_present &&
           cached->local_pref_present == params->local_pref_present &&
           cached->med == params->med &&
           cached->local_pref == params->local_pref;
}

static void
bgp_route_config_store(bgp_route_config_t *route,
                       const bgp_route_params_t *params)
{
    strncpy(route->prefix, params->prefix, sizeof(route->prefix) - 1);
    strncpy(route->nexthop, params->nexthop, sizeof(route->nexthop) - 1);
    strncpy(route->rd, params->rd, sizeof(route->rd) - 1);
    strncpy(route->rt, params->rt, sizeof(route->rt) - 1);
    route->med = params->med;
    route->local_pref = params->local_pref;
    route->med_present = params->med_present;
    route->local_pref_present = params->local_pref_present;
    route->configured = true;
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
    return -1;
}

static int
bgp_route_parse_safi(const char *safi)
{
    if (!safi || strcmp(safi, "unicast") == 0) {
        return SAFI_UNICAST;
    }
    if (strcmp(safi, "mpls-vpn") == 0 || strcmp(safi, "mpls_vpn") == 0) {
        return SAFI_MPLS_VPN;
    }
    if (strcmp(safi, "evpn") == 0) {
        return 70; /* SAFI_EVPN */
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
        return true;
    }

    if (vrf->rd.asn == 0 && vrf->rd.number == 0) {
        return false;
    }
    if (vrf->export_rt.asn == 0 && vrf->export_rt.number == 0) {
        return false;
    }

    snprintf(params->rd, sizeof(params->rd), "%u:%u",
             vrf->rd.asn, vrf->rd.number);
    snprintf(params->rt, sizeof(params->rt), "%u:%u",
             vrf->export_rt.asn, vrf->export_rt.number);
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
    bgp_node_config_t *cfg;
    bgp_route_config_t *route;
    sf_gobgp_route_params_t sf_params;
    sf_gobgp_rpc_result_t result;
    bgp_inst_t *bgp;
    tracer_t *tr;
    const char *op;

    bgp = bgp_get_instance(node);
    tr = bgp ? bgp->tr : nullptr;
    op = is_delete ? "DeletePath" : "AddPath";

    client = bgp_route_get_grpc_client(node);
    if (!client) {
        tracer(tr, TR_BGP_GRPC_TALK | TR_BGP_RT_EVENTS,
               "%s : %s aborted — no gRPC client for node %s (prefix %s)\n",
               BGP_RTM_TAG, op, node ? node->node_name : "?",
               params ? params->prefix : "?");
        return -1;
    }

    cfg = bgp_route_config_get(node);
    if (!cfg) {
        tracer(tr, TR_BGP_GRPC_TALK | TR_BGP_RT_EVENTS,
               "%s : %s aborted — no BGP config for node %s (prefix %s)\n",
               BGP_RTM_TAG, op, node->node_name, params->prefix);
        return -1;
    }

    route = bgp_route_config_find(cfg, params->prefix, params->rd);
    if (!is_delete) {
        if (route && bgp_route_params_equal(route, params)) {
            tracer(tr, TR_BGP_GRPC_TALK,
                   "%s : %s skip — route %s already programmed identically "
                   "(afi=%d safi=%d nh=%s rd=%s)\n",
                   BGP_RTM_TAG, op, params->prefix, sf_afi, sf_safi,
                   params->nexthop,
                   params->rd[0] ? params->rd : "-");
            return 0;
        }
    } else if (!route || !route->configured) {
        tracer(tr, TR_BGP_GRPC_TALK,
               "%s : %s skip — route %s not in local cache (afi=%d safi=%d)\n",
               BGP_RTM_TAG, op, params->prefix, sf_afi, sf_safi);
        return 0;
    }

    bgp_route_to_sf_params(params, sf_afi, sf_safi, &sf_params);

    tracer(tr, TR_BGP_GRPC_TALK | TR_BGP_RT_EVENTS,
           "%s : %s RPC → prefix=%s nh=%s afi=%d safi=%d rd=%s rt=%s "
           "med=%s%u lp=%s%u\n",
           BGP_RTM_TAG, op, sf_params.prefix, sf_params.nexthop,
           sf_params.afi, sf_params.safi,
           sf_params.rd[0] ? sf_params.rd : "-",
           sf_params.rt[0] ? sf_params.rt : "-",
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

    if (is_delete) {
        bgp_route_config_remove(cfg, params->prefix, params->rd);
        return 0;
    }

    route = bgp_route_config_add(cfg, params);
    if (!route) {
        tracer(tr, TR_BGP_GRPC_TALK | TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : AddPath RPC OK but local cache full — cannot store %s "
               "(num_routes=%d max=%d)\n",
               BGP_RTM_TAG, params->prefix, cfg->num_routes, BGP_MAX_ROUTES);
        return -1;
    }

    bgp_route_config_store(route, params);
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
    info.med_present = route->med_present;
    info.local_pref_present = route->local_pref_present;
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
        info.med_present = update->route.med_present;
        info.local_pref_present = update->route.local_pref_present;
        info.best = update->route.best;

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

void
bgp_rtm_route_notif (vrf_t *vrf, rt_advert_info_t  *rt_advert) {

    char prefix_str[48];
    char bgp_nbr_str[48];
    bgp_route_params_t params;
    rtm_nh *nh;
    bgp_inst_t *bgp_inst;
    bgp_node_config_t *cfg;
    bool is_delete;

    if (!vrf || !rt_advert || !vrf->node) {
        return;
    }

    bgp_inst = bgp_get_instance(vrf->node);
    if (!bgp_inst) {
        return;
    }

    cfg = &bgp_inst->bgp_config;

    tracer (bgp_inst->tr, TR_BGP_RT_EVENTS,
             "%s : Route %s notification received for VRF %s, addr-family:%s, BGP Nbr:%s, code:%s\n",
             BGP_RTM_TAG,
             cmn_prefix_to_string(&rt_advert->route, &prefix_str),
             vrf->vrf_name,
             bgp_addr_family_str(rt_advert->afi, rt_advert->safi),
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

    if (!bgp_route_vrf_fill_rd_rt(vrf, rt_advert->safi, &params)) {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : VRF %s missing RD/export-RT required for VPN advertise of %s\n",
               BGP_RTM_TAG, vrf->vrf_name, prefix_str);
        return;
    }

    if (rt_advert->out_cost != 0) {
        params.med = rt_advert->out_cost;
        params.med_present = true;
    }

    if (bgp_route_apply_to_gobgp(vrf->node, &params,
                                 rt_advert->afi, rt_advert->safi,
                                 is_delete) != 0) {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : Failed to %s route %s nh-self %s to GoBGP (%s) peer %s\n",
               BGP_RTM_TAG,
               is_delete ? "withdraw" : "advertise",
               prefix_str, params.nexthop,
               bgp_addr_family_str(rt_advert->afi, rt_advert->safi),
               bgp_nbr_str);
        return;
    }

    tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
           "%s : %s route %s nh-self %s to GoBGP (%s) peer %s"
           "%s%s%s%s\n",
           BGP_RTM_TAG,
           is_delete ? "Withdrew" : "Advertised",
           prefix_str, params.nexthop,
           bgp_addr_family_str(rt_advert->afi, rt_advert->safi),
           bgp_nbr_str,
           params.rd[0] ? " RD " : "",
           params.rd[0] ? params.rd : "",
           params.rt[0] ? " RT " : "",
           params.rt[0] ? params.rt : "");
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
            0,
            RTM_NH_ACTION_FORWARD,
            metric,
            &gateway,
            0,
            INTF_TYPE_UNKNOWN,
            NULL,
            0,
            0,
            MPLS_OP_STACK_OPS_UNKNOWN);

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
                MPLS_OP_STACK_OPS_UNKNOWN);

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

typedef struct bgp_route_processing_info_ {

    node_t *node;
    bgp_route_info_t *route;
    bool is_add;
    glthread_t glue;

} bgp_route_processing_info_t;
GLTHREAD_TO_STRUCT(glue_to_bgp_route_processing_info, bgp_route_processing_info_t, glue);

static void 
bgp_schedule_route_processing_job_cbk (event_dispatcher_t *ev_dis, 
                                       void *arg, uint32_t arg_size) {

    glthread_t *curr;
    bgp_route_info_t *route;
    bgp_route_processing_info_t *info;

    bgp_inst_t *bgp_inst = (bgp_inst_t *)arg;

    bgp_inst->recvd_route_processing_task = NULL;

    while ((curr = dequeue_glthread_first (&bgp_inst->pending_routes_list.head))) {

        info = glue_to_bgp_route_processing_info(curr);

        if (info->is_add) {
            bgp_rtm_route_install (info->node, info->route);
        }
        else {
            bgp_rtm_route_uninstall (info->node, info->route);
        }

        XFREE (info->route);
        XFREE(info);        
    }
}

void 
bgp_schedule_route_processing_job (node_t *node, 
                                  const bgp_route_info_t *route, 
                                  bool is_add) 
{

    bgp_inst_t *bgp_inst = BGP_INST(node);

    if (!bgp_inst) return;

    bgp_route_processing_info_t *info = (bgp_route_processing_info_t *)
            XCALLOC2(0,1,bgp_route_processing_info_t);

    bgp_route_info_t *route_cpy = (bgp_route_info_t *)
            XCALLOC2(0, 1, bgp_route_info_t);

    memcpy (route_cpy, route, sizeof (*route_cpy));

    info->node = node;
    info->route = route_cpy;
    info->is_add = is_add;
    init_glthread(&info->glue);

    Fglthread_add_last(&bgp_inst->pending_routes_list, &info->glue);

    if (bgp_inst->recvd_route_processing_task) {

        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
            "%s : Route processing job is already scheduled\n", BGP_RTM_TAG);

        return;
    }

    bgp_inst->recvd_route_processing_task = 
        task_create_new_job (EV(node), (void *)bgp_inst, 
                             bgp_schedule_route_processing_job_cbk,
                             TASK_ONE_SHOT,
                             TASK_PRIORITY_LOW); // We are Queing the work, ok to have low prio

    tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
            "%s : Route processing job scheduled\n", BGP_RTM_TAG);
}