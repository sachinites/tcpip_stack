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
                            evpn_exp_rt_t *evpn_rt,
                            bool is_delete)
{
    char mac_str[32];
    char pe_str[16];
    bgp_inst_t *bgp_inst;
    bgp_node_config_t *cfg;
    const unsigned char *mac;
    bgp_route_params_t params;

    bgp_inst = BGP_INST(node);

    if (!bgp_inst) {
        return;
    }

    cfg = &bgp_inst->bgp_config;
    if (!cfg->started || cfg->router_id[0] == '\0') {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
               "%s : BGP not started / no router-id on %s, skip EVPN export\n",
               BGP_RTM_TAG, node->node_name);
        return;
    }

    if (rd->rtr_id == 0 && rd->vrf_id == 0) {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : EVPN export missing RD on %s\n",
               BGP_RTM_TAG, node->node_name);
        return;
    }

    if (export_rt->rtr_id == 0 && export_rt->vrf_id == 0) {
        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
               "%s : EVPN export missing export-RT on %s\n",
               BGP_RTM_TAG, node->node_name);
        return;
    }

    memset(&params, 0, sizeof(params));
    strncpy(params.nexthop, cfg->router_id, sizeof(params.nexthop) - 1);
    rd_type1_to_str(rd, params.rd, sizeof(params.rd));
    rt_type1_to_str(export_rt, params.rt, sizeof(params.rt));

    if (evpn_rt->type == EVPN_RT_TYPE_MAC_ONLY) {

        mac = evpn_rt->u.mac_only.mac.mac;
        snprintf(mac_str, sizeof(mac_str),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        params.evpn_route_type = EVPN_RT_TYPE_MAC_ONLY;
        strncpy(params.mac_addr, mac_str, sizeof(params.mac_addr) - 1);
        params.evpn_label = evpn_rt->u.mac_only.label;
        params.evpn_label_present = true;
        if (evpn_rt->u.mac_only.ip_addr)
            ip_ntop(evpn_rt->u.mac_only.ip_addr, (c_string)params.pe_addr);

        if (bgp_route_apply_to_gobgp(node, &params, AFI_L2VPN,
                                     SAFI_MPLS_EVPN, is_delete) != 0) {
            tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
                   "%s : Failed to %s EVPN Type-2 MAC %s RD %s RT %s label %u\n",
                   BGP_RTM_TAG,
                   is_delete ? "withdraw" : "advertise",
                   mac_str, params.rd, params.rt, params.evpn_label);
            return;
        }

        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
               "%s : %s EVPN Type-2 MAC %s nh-self %s RD %s RT %s label %u\n",
               BGP_RTM_TAG,
               is_delete ? "Withdrew" : "Advertised",
               mac_str, params.nexthop, params.rd, params.rt,
               params.evpn_label);
        return;
    }

    if (evpn_rt->type == EVPN_RT_TYPE_IMET) {

        ip_ntop(evpn_rt->u.imet.pe_addr, (c_string)pe_str);

        params.evpn_route_type = EVPN_RT_TYPE_IMET;
        strncpy(params.pe_addr, pe_str, sizeof(params.pe_addr) - 1);
        strncpy(params.prefix, pe_str, sizeof(params.prefix) - 1);
        params.eth_tag_id = rd->vrf_id;
        params.pmsi_label = evpn_rt->u.imet.evpn_label;
        params.pmsi_label_present = true;

        if (bgp_route_apply_to_gobgp(node, &params, AFI_L2VPN,
                                     SAFI_MPLS_EVPN, is_delete) != 0) {
            tracer(bgp_inst->tr, TR_BGP_RT_EVENTS | TR_BGP_EVENTS,
                   "%s : Failed to %s EVPN Type-3 IMET PE %s RD %s RT %s "
                   "BUM label %u\n",
                   BGP_RTM_TAG,
                   is_delete ? "withdraw" : "advertise",
                   pe_str, params.rd, params.rt, params.pmsi_label);
            return;
        }

        tracer(bgp_inst->tr, TR_BGP_RT_EVENTS,
               "%s : %s EVPN Type-3 IMET PE %s nh-self %s RD %s RT %s "
               "eth-tag %u BUM label %u\n",
               BGP_RTM_TAG,
               is_delete ? "Withdrew" : "Advertised",
               pe_str, params.nexthop, params.rd, params.rt,
               params.eth_tag_id, params.pmsi_label);
        return;
    }
}
