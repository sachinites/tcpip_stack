#include "evpn_bgp.h"

#include <cstdio>
#include <cstring>

#include "../../libs/Tracer/tracer.h"
#include "../../router_init.h"
#include "../../net.h"
#include "../../utils.h"
#include "../../Interface/Interface.h"
#include "../../Layer5/bgp_enums.h"
#include "../../Layer5/bgp_rtr.h"
#include "evpn.h"
#include "evpn_enums.h"
#include "../../vrf/mac_vrf.h"

void
evpn_route_export_to_bgp(node_t *node,
                         rd_t *rd,
                         rt_t *export_rt,
                         evpn_rt_t *evpn_rt,
                         bool is_delete)
{
    if (!node || !rd || !export_rt || !evpn_rt) {
        return;
    }

    bgp_evpn_type2_route_update(node, rd, export_rt, evpn_rt, is_delete);
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

    *vtep_ip_out = tcp_ip_convert_ip_p_to_n((c_string)nh_addr);
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
    uint32_t vtep_ip = 0;
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

        mac_vrf = evpn_inst->mac_vrf;
        if (!mac_vrf) continue;

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

void
bgp_schedule_evpn_route_processing_job(node_t *node,
                                       const bgp_route_info_t *route,
                                       bool is_add)
{
    bgp_schedule_route_processing_job_af(node, route, is_add, false, true);
}
