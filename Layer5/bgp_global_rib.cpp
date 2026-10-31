#include <cstring>

#include "../libs/Tracer/tracer.h"
#include "../libs/LinuxMemoryManager/uapi_mm.h"
#include "../libs/EventDispatcher/event_dispatcher.h"

#include "../tcpconst.h"
#include "../vrf/vrf.h"
#include "../net.h"
#include "../RTM/rtm_nhtracker.h"
#include "../RTM/rtm_priv_api.h"
#include "../RTM/rtm_show.h"

#include "bgp_enums.h"
#include "bgp_global_rib.h"
#include "bgp_rib/bgp_rib.h"
#include "bgp_rib/bgp_rib_types.h"
#include "bgp_rtr.h"

static void
bgp_global_rib_nhtracker_callback(cmn_prefix_t *prefix,
                                  rtm_tracker_client_id_t *client_id,
                                  rtm_tracker_client_data_t *client_data)
{
    tracer_t *tr;
    char inh_str[64];
    char tracked_str[64];
    char route_str[64];
    char client_key[160];
    char vrf_str[16];
    const char *proto_str = "?";
    const char *sub_proto_str = "?";
    unsigned vrf_id = 0;
    unsigned instance_no = 0;
    unsigned dnhidx = 0;
    const char *add_str = "?";

    bgp_inst_t *bgp = (bgp_inst_t *)client_id->opaque_data;

    tr = bgp->tr;

    if (prefix) {
        rtm_format_prefix(prefix, inh_str, sizeof(inh_str));
    } else {
        strncpy(inh_str, "-", sizeof(inh_str) - 1);
        inh_str[sizeof(inh_str) - 1] = '\0';
    }

    if (client_data) {
        rtm_format_prefix(&client_data->tracked_prefix,
                          tracked_str, sizeof(tracked_str));
        rtm_format_prefix(&client_data->route, route_str, sizeof(route_str));
        dnhidx = client_data->dnhidx;
        add_str = client_data->add ? "true" : "false";
    } else {
        strncpy(tracked_str, "-", sizeof(tracked_str) - 1);
        tracked_str[sizeof(tracked_str) - 1] = '\0';
        strncpy(route_str, "-", sizeof(route_str) - 1);
        route_str[sizeof(route_str) - 1] = '\0';
    }

    client_key[0] = '\0';
    if (client_id) {
        proto_str = rtm_proto_to_string(client_id->proto);
        sub_proto_str = rtm_sub_proto_to_string(client_id->sub_proto);
        vrf_id = (unsigned)client_id->vrf_id;
        instance_no = (unsigned)client_id->instance_no;
        snprintf(vrf_str, sizeof(vrf_str), "%u", vrf_id);
        rtm_format_redist_target_client_id(
            client_id->proto,
            vrf_str,
            client_id->instance_no,
            client_key,
            sizeof(client_key));
    }

    tracer(tr, TR_BGP_RT_EVENTS,
           "%s : nh-tracker callback "
           "INH=%s client_key=%s "
           "proto=%s sub_proto=%s vrf_id=%u instance_no=%u "
           "tracked_prefix=%s route=%s dnhidx=%u add=%s\n",
           BGP_RTM_TAG,
           inh_str,
           client_key[0] ? client_key : "-",
           proto_str,
           sub_proto_str,
           vrf_id,
           instance_no,
           tracked_str,
           route_str,
           dnhidx,
           add_str);
}

/*
 * RTM used for nh-tracker registration / track / untrack, by global RIB AFI/SAFI:
 *   IPv4 unicast  -> def_vrf->inet0
 *   VPNv4         -> def_vrf->inet0
 *   L2VPN EVPN    -> def_vrf->inet0
 */
static rtm_t *
bgp_global_rib_nhtracker_rtm(node_t *node, int afi, int safi)
{
    def_vrf_t *def_vrf;

    if (!node) {
        return NULL;
    }

    def_vrf = (def_vrf_t *)NODE_DEF_VRF(node);
    if (!def_vrf) {
        return NULL;
    }

    if (afi == AFI_IPV4 && safi == SAFI_UNICAST) {
        return def_vrf->vrf.inet0;
    }
    if (afi == AFI_IPV4 && safi == SAFI_MPLS_VPN) {
        return def_vrf->vrf.inet0;
    }
    if (afi == AFI_L2VPN && safi == SAFI_MPLS_EVPN) {
        return def_vrf->vrf.inet0;
    }

    return NULL;
}

static bool
bgp_global_rib_nhtracker_client_id(int afi,
                                   int safi,
                                   uint16_t vrf_id,
                                   rtm_tracker_client_id_t *client_id)
{
    if (!client_id) {
        return false;
    }

    memset(client_id, 0, sizeof(*client_id));
    client_id->proto = RTM_PROTO_BGP;
    client_id->vrf_id = vrf_id;
    client_id->instance_no = 0;

    if (afi == AFI_IPV4 && safi == SAFI_UNICAST) {
        client_id->sub_proto = RTM_SUB_PROTO_BGP_INT;
        return true;
    }
    if (afi == AFI_IPV4 && safi == SAFI_MPLS_VPN) {
        client_id->sub_proto = RTM_SUB_PROTO_BGP_VPN;
        return true;
    }
    if (afi == AFI_L2VPN && safi == SAFI_MPLS_EVPN) {
        client_id->sub_proto = RTM_SUB_PROTO_BGP_EVPN;
        return true;
    }

    return false;
}

static void
bgp_global_rib_nhtracker_register(bgp_inst_t *bgp,
                                  bgp_rib_t *rib,
                                  int afi,
                                  int safi)
{
    rtm_t *rtm;
    def_vrf_t *def_vrf;
    rtm_tracker_client_id_t client_id;
    uintptr_t reg_id;

    if (!bgp || !rib || bgp_rib_nh_tracker_reg_id(rib)) {
        return;
    }

    rtm = bgp_global_rib_nhtracker_rtm(bgp->node, afi, safi);
    if (!rtm) {
        return;
    }

    def_vrf = (def_vrf_t *)NODE_DEF_VRF(bgp->node);
    if (!bgp_global_rib_nhtracker_client_id(
            afi, safi,
            def_vrf ? def_vrf->vrf.vrf_id : 0,
            &client_id)) {
        return;
    }

    client_id.opaque_data = (uintptr_t)bgp;

    reg_id = rtm_tracker_register_client(
        rtm, &client_id, bgp_global_rib_nhtracker_callback);
    if (!reg_id) {
        return;
    }

    bgp_rib_set_nh_tracker(rib, reg_id);
}

typedef struct bgp_route_processing_info_ {

    node_t *node;
    bgp_unified_rt_t *route;
    bool is_add;

} bgp_route_processing_info_t;

static bgp_rib_t **
bgp_global_rib_slot(bgp_inst_t *bgp, int afi, int safi)
{
    if (!bgp) {
        return NULL;
    }

    if (afi == AFI_IPV4 && safi == SAFI_UNICAST) {
        return &bgp->ipv4_unicast_rib;
    }
    if (afi == AFI_IPV4 && safi == SAFI_MPLS_VPN) {
        return &bgp->vpnv4_rib;
    }
    if (afi == AFI_L2VPN && safi == SAFI_MPLS_EVPN) {
        return &bgp->evpn_rib;
    }

    return NULL;
}

static void
bgp_global_rib_fill_attrs(const bgp_unified_rt_t *route,
                          bgp_rib_attrs_t *attrs)
{
    memset(attrs, 0, sizeof(*attrs));

    if (!route) {
        return;
    }

    strncpy(attrs->nexthop, route->nexthop, sizeof(attrs->nexthop) - 1);
    attrs->origin_present = false;
    attrs->med = route->med;
    attrs->med_present = route->med_present;
    attrs->local_pref = route->local_pref;
    attrs->local_pref_present = route->local_pref_present;
    if (route->rt[0] != '\0') {
        strncpy(attrs->import_rt, route->rt, sizeof(attrs->import_rt) - 1);
        attrs->rt_present = true;
    }
    attrs->best = route->best;
    attrs->is_from_external = route->is_from_external;
    attrs->ext_comm_count = route->ext_comm_count;
    if (route->ext_comm_count > 0) {
        memcpy(attrs->ext_comms, route->ext_comms,
               route->ext_comm_count * sizeof(bgp_rib_ext_comm_t));
    }
    attrs->evpn_label1 = route->evpn_label1;
    attrs->evpn_label1_present = route->evpn_label1_present;
    attrs->evpn_label1_from_ext_comm = route->evpn_label1_from_ext_comm;
    attrs->mac_mobility_seq = route->mac_mobility_seq;
    attrs->mac_mobility_seq_present = route->mac_mobility_seq_present;
    attrs->pmsi_label = route->pmsi_label;
    attrs->pmsi_label_present = route->pmsi_label_present;
    attrs->pmsi_flags = route->pmsi_flags;
    attrs->pmsi_tunnel_type = route->pmsi_tunnel_type;
    attrs->pmsi_tunnel_id_len = route->pmsi_tunnel_id_len;
    if (route->pmsi_tunnel_id_len > 0) {
        memcpy(attrs->pmsi_tunnel_id, route->pmsi_tunnel_id,
               route->pmsi_tunnel_id_len);
    }
    attrs->tunnel_encap_type = route->tunnel_encap_type;
    attrs->tunnel_encap_present = route->tunnel_encap_present;
}

int
bgp_global_rib_af_enable(node_t *node, int afi, int safi, bgp_rib_export_route_cb cbk)
{
    bgp_inst_t *bgp;
    bgp_rib_t **rib_slot;
    bgp_rib_t *rib;

    if (!node) {
        return -1;
    }

    bgp = BGP_INST(node);
    if (!bgp) {
        return -1;
    }

    rib_slot = bgp_global_rib_slot(bgp, afi, safi);
    if (!rib_slot) {
        return -1;
    }

    if (*rib_slot) {
        if (cbk) {
            bgp_rib_set_export_route(*rib_slot, bgp, cbk);
        }
        bgp_global_rib_nhtracker_register(bgp, *rib_slot, afi, safi);
        return 0;
    }

    rib = bgp_rib_create((uint8_t)afi, (uint8_t)safi);
    if (!rib) {
        return -1;
    }

    bgp_rib_set_export_route(rib, bgp, cbk);
    bgp_global_rib_nhtracker_register(bgp, rib, afi, safi);

    *rib_slot = rib;

    if (bgp_node_monitor_subscribe_af(
            node, afi, safi,
            bgp_monitor_recv_global_rib_cbk,
            node) != 0) {
        bgp_rib_destroy(rib);
        *rib_slot = NULL;
        return -1;
    }

    return 0;
}

void
bgp_global_rib_af_disable(node_t *node, int afi, int safi)
{
    bgp_inst_t *bgp;
    bgp_rib_t **rib_slot;

    if (!node) {
        return;
    }

    bgp = BGP_INST(node);
    if (!bgp) {
        return;
    }

    rib_slot = bgp_global_rib_slot(bgp, afi, safi);
    if (!rib_slot || !*rib_slot) {
        return;
    }

    bgp_rib_destroy(*rib_slot);
    *rib_slot = NULL;
}

void
bgp_global_rib_deinit(bgp_inst_t *bgp)
{
    if (!bgp) {
        return;
    }

    if (bgp->ipv4_unicast_rib) {
        bgp_rib_destroy(bgp->ipv4_unicast_rib);
        bgp->ipv4_unicast_rib = NULL;
    }
    if (bgp->vpnv4_rib) {
        bgp_rib_destroy(bgp->vpnv4_rib);
        bgp->vpnv4_rib = NULL;
    }
    if (bgp->evpn_rib) {
        bgp_rib_destroy(bgp->evpn_rib);
        bgp->evpn_rib = NULL;
    }
}

void
bgp_global_rib_route_update(node_t *node,
                            const bgp_unified_rt_t *route,
                            bool is_add)
{
    bgp_inst_t *bgp;
    bgp_rib_t *rib;
    bgp_nlri_key_t key;
    bgp_rib_attrs_t attrs;
    bgp_rib_err_t rc;

    if (!node || !route) {
        return;
    }

    bgp = BGP_INST(node);

    if (route->nlri_wire_len == 0) {
        if (bgp && bgp->tr) {
            tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_RT_ERRORS,
                   "%s : Route %s skipped — empty NLRI wire (%s)\n",
                   BGP_RTM_IM, route->prefix,
                   is_add ? "add" : "del");
        }
        return;
    }

    rib = NULL;
    if (route->afi == AFI_IPV4 && route->safi == SAFI_UNICAST) {
        rib = bgp->ipv4_unicast_rib;
    } else if (route->afi == AFI_IPV4 && route->safi == SAFI_MPLS_VPN) {
        rib = bgp->vpnv4_rib;
    } else if (route->afi == AFI_L2VPN && route->safi == SAFI_MPLS_EVPN) {
        rib = bgp->evpn_rib;
    }

    if (!rib) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS | TR_BGP_RT_ERRORS ,
            "%s : Route %s import failed, no Global Exist\n", 
            BGP_RTM_IM, route->prefix);
        return;
    }

    memset(&key, 0, sizeof(key));
    key.wire_len = route->nlri_wire_len;
    memcpy(key.wire, route->nlri_wire, route->nlri_wire_len);

    if (is_add) {
        bgp_global_rib_fill_attrs(route, &attrs);
        rc = bgp_rib_route_add(rib, &key, &attrs);
        if (rc != BGP_RIB_OK && bgp->tr) {
            tracer(bgp->tr, TR_BGP_RT_EVENTS,
                   "%s : failed to add route %s , error = (%s)\n",
                   BGP_RTM_IM, 
                   route->prefix,
                   bgp_rib_err_to_string(rc));
        }
        return;
    }

    rc = bgp_rib_route_delete(rib, &key);
    if (rc != BGP_RIB_OK && rc != BGP_RIB_ERR_NOT_FOUND && bgp->tr) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "%s : failed to delete route %s, error = (%s)\n",
               BGP_RTM_IM, 
               route->prefix, 
               bgp_rib_err_to_string(rc));
    }
}

void
bgp_route_pkt_q_cbk(event_dispatcher_t *ev_dis,
                      void *data,
                      uint32_t data_size) {

    bgp_route_processing_info_t *info;
    node_t *node = (node_t *)ev_dis->app_data;
    bgp_inst_t *bgp_inst = BGP_INST(node);

    (void)data;

    info = (bgp_route_processing_info_t *)task_get_next_pkt(ev_dis, &data_size);

    tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
        "%s : Route processing job cbk invoked\n", BGP_RTM_IM);    

    for (; info;
         info = (bgp_route_processing_info_t *)task_get_next_pkt(
                    ev_dis, &data_size)) {

         bgp_global_rib_route_update(node, 
                (const bgp_unified_rt_t *)info->route, 
                info->is_add);

        XFREE(info->route);
        XFREE(info);
    }
}

void
bgp_monitor_recv_global_rib_cbk(const bgp_unified_rt_t *route,
                                bool is_withdraw,
                                void *userdata)
{
    node_t *node = (node_t *)userdata;
    bgp_inst_t *bgp_inst = BGP_INST(node);

    bgp_route_processing_info_t *bgp_rt_info2 =
        (bgp_route_processing_info_t *)XCALLOC2(0, 1,  bgp_route_processing_info_t);

    bgp_unified_rt_t *route_cpy = 
        (bgp_unified_rt_t *)XCALLOC2(0, 1, bgp_unified_rt_t);

    memcpy (route_cpy, route, sizeof (*route_cpy));
    bgp_rt_info2->node = (node_t *)userdata;
    bgp_rt_info2->route = route_cpy;
    bgp_rt_info2->is_add = !is_withdraw;

    if (!pkt_q_enqueue(EV(node),
                       &bgp_inst->bgp_route_pkt_q,
                       (char *)bgp_rt_info2,
                       sizeof(*bgp_rt_info2))) {

        tracer(bgp_inst->tr, TR_BGP_GRPC_TALK|TR_BGP_RT_ERRORS,
               "%s : FATAL : Route processing pkt_q full, dropped %s\n",
               BGP_RTM_IM, route->prefix);
        XFREE(route_cpy);
        XFREE(bgp_rt_info2);
        return;
    }

    tracer(bgp_inst->tr, TR_BGP_GRPC_TALK,
        "%s : Route %s submit to pkt Q for thread handoff\n",
        BGP_RTM_IM, route->prefix);
}

bgp_rib_t *
bgp_global_rib_get(node_t *node, int afi, int safi)
{
    bgp_inst_t *bgp;
    bgp_rib_t **rib_slot;

    if (!node) {
        return NULL;
    }

    bgp = BGP_INST(node);
    if (!bgp) {
        return NULL;
    }

    rib_slot = bgp_global_rib_slot(bgp, afi, safi);
    if (!rib_slot) {
        return NULL;
    }

    return *rib_slot;
}

void
bgp_global_rib_export_all(bgp_inst_t *bgp,
                          uint8_t afi,
                          uint8_t safi,
                          uint16_t target_vrf_id,
                          uint8_t export_route_type)
{
    bgp_rib_t **rib_slot;
    bgp_rib_t *rib;

    if (!bgp) {
        return;
    }

    rib_slot = bgp_global_rib_slot(bgp, afi, safi);
    if (!rib_slot) {
        return;
    }

    rib = *rib_slot;
    if (!rib) {
        return;
    }

    bgp_rib_export_all(rib, target_vrf_id, export_route_type);
}
