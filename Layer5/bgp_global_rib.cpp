#include <cstring>

#include "../libs/Tracer/tracer.h"
#include "../tcpconst.h"
#include "../vrf/vrf.h"

#include "bgp_enums.h"
#include "bgp_global_rib.h"
#include "bgp_rib/bgp_rib.h"
#include "bgp_rib/bgp_rib_types.h"
#include "bgp_rtr.h"

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
bgp_global_rib_fill_attrs(const bgp_route_info_t *route,
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
    attrs->tunnel_encap_type = route->tunnel_encap_type;
    attrs->tunnel_encap_present = route->tunnel_encap_present;
}

int
bgp_global_rib_af_enable(node_t *node, int afi, int safi)
{
    bgp_inst_t *bgp;
    bgp_rib_t **rib_slot;
    bgp_rib_t *rib;

    if (!node) {
        return -1;
    }

    bgp = bgp_get_instance(node);
    if (!bgp) {
        return -1;
    }

    rib_slot = bgp_global_rib_slot(bgp, afi, safi);
    if (!rib_slot) {
        return -1;
    }

    if (*rib_slot) {
        return 0;
    }

    rib = bgp_rib_create((uint8_t)afi, (uint8_t)safi);
    if (!rib) {
        return -1;
    }

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

    bgp = bgp_get_instance(node);
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
                            const bgp_route_info_t *route,
                            bool is_add)
{
    bgp_inst_t *bgp;
    bgp_rib_t *rib;
    bgp_nlri_key_t key;
    bgp_rib_attrs_t attrs;
    bgp_rib_err_t rc;

    if (!node || !route || route->nlri_wire_len == 0) {
        return;
    }

    bgp = bgp_get_instance(node);
    if (!bgp) {
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
                   "Global RIB: failed to add route (%s)\n",
                   bgp_rib_err_to_string(rc));
        }
        return;
    }

    rc = bgp_rib_route_delete(rib, &key);
    if (rc != BGP_RIB_OK && rc != BGP_RIB_ERR_NOT_FOUND && bgp->tr) {
        tracer(bgp->tr, TR_BGP_RT_EVENTS,
               "Global RIB: failed to delete route (%s)\n",
               bgp_rib_err_to_string(rc));
    }
}

void
bgp_monitor_recv_global_rib_cbk(const bgp_route_info_t *route,
                                bool is_withdraw,
                                void *userdata)
{
    node_t *node = (node_t *)userdata;

    bgp_global_rib_route_update(node, route, !is_withdraw);
}

bgp_rib_t *
bgp_global_rib_get(node_t *node, int afi, int safi)
{
    bgp_inst_t *bgp;
    bgp_rib_t **rib_slot;

    if (!node) {
        return NULL;
    }

    bgp = bgp_get_instance(node);
    if (!bgp) {
        return NULL;
    }

    rib_slot = bgp_global_rib_slot(bgp, afi, safi);
    if (!rib_slot) {
        return NULL;
    }

    return *rib_slot;
}
