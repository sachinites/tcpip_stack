
#include <assert.h>
#include "../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../../LabelMgr/label_mgr.h"

#include "../../router_init.h"

#include "evpn.h"
#include "evpn_priv_api.h"
#include "../../vrf/mac_vrf.h"
#include "../../RTM/rtm.h"

extern int cprintf (const char* format, ...);

static mac_vrf_t *
evpn_inst_mac_vrf (evpn_inst_t *evpn_inst)
{
    assert (evpn_inst && evpn_inst->node);
    return (mac_vrf_t *)evpn_inst->node->vrf[evpn_inst->mac_vrf_id];
}

evpn_inst_t *
evpn_instance_init (node_t *node, uint8_t evpn_id) {

    evpn_inst_t *evpn_inst;

    if (evpn_id >= MAX_EVPN_INDEX) {
        cprintf("Error : EVPN instance id must be 0-%d\n", MAX_EVPN_INDEX - 1);
        return NULL;
    }

    if (node->evpn[evpn_id]) {
        return node->evpn[evpn_id];
    }

    int mac_vrf_id = vrf_alloc_new_vrf_id (node);

    if (mac_vrf_id < 0) {

        cprintf("Error : Cannot create EVPN instance, VRF IDs exhausted\n");
        return NULL;
    }

    evpn_inst = (evpn_inst_t *)XCALLOC2 (0, 1 , evpn_inst_t);
    evpn_inst->evi = evpn_id;
    evpn_inst->mac_vrf_id = (uint8_t)mac_vrf_id;
    evpn_inst->node = node;

    mac_vrf_t *mac_vrf = (mac_vrf_t *)XCALLOC2(0, 1, mac_vrf_t);

    /* Link VRF and the owning Router */
    node->vrf[evpn_inst->mac_vrf_id] = &mac_vrf->vrf;
    mac_vrf->vrf.node = node;
    mac_vrf->vrf.vrf_id = evpn_inst->mac_vrf_id;

    /* Mac VRF Name : evpn-<evpn-id> */
    snprintf (mac_vrf->vrf.vrf_name, sizeof (mac_vrf->vrf.vrf_name), 
        "evpn-%d", evpn_inst->evi);

    /* Initialize RIB */
    mac_vrf->mac_rib = rtm_initialize(node, evpn_inst->mac_vrf_id, mac_vrf->vrf.vrf_name, AF_MAC, 0);

    /* initialize VRF Interface DBs*/
    mac_vrf->vrf.intf_by_name = new std::unordered_map<std::string, InterfaceP>();
    mac_vrf->vrf.intf_by_ifindex = new std::unordered_map<uint32_t, InterfaceP>();

    /* Allocate L2VPN EVPN service label to this MAC VRF */
    assert (label_mgr_block_alloc_label(
            node->l2vpn_lbl_block, &mac_vrf->l2vpn_evpn_uc_lbl) == LABEL_MGR_OK);

    assert (label_mgr_block_alloc_label(
            node->l2vpn_lbl_block, &mac_vrf->l2vpn_evpn_mc_lbl) == LABEL_MGR_OK);

    node->evpn[evpn_id] = evpn_inst;

    return evpn_inst;
}

void
evpn_instance_deinit (evpn_inst_t **evpn_inst)
{
    evpn_inst_t *inst;
    mac_vrf_t *mac_vrf;
    node_t *node;

    if (!evpn_inst || !*evpn_inst)
        return;

    inst = *evpn_inst;
    node = inst->node;

    if (inst->bd_index)
        evpn_disconnect_bd (inst, inst->bd_index);

    mac_vrf = evpn_inst_mac_vrf (inst);

    if (mac_vrf) {
        if (mac_vrf->mac_rib) {
            rtm_stop (mac_vrf->mac_rib);
            rtm_check_and_delete (mac_vrf->mac_rib, true);
            mac_vrf->mac_rib = NULL;
        }

        if (mac_vrf->l2vpn_evpn_uc_lbl)
            label_mgr_block_release_label (node->l2vpn_lbl_block,
                                           mac_vrf->l2vpn_evpn_uc_lbl);
        if (mac_vrf->l2vpn_evpn_mc_lbl)
            label_mgr_block_release_label (node->l2vpn_lbl_block,
                                           mac_vrf->l2vpn_evpn_mc_lbl);

        if (mac_vrf->vrf.intf_by_name) {
            delete mac_vrf->vrf.intf_by_name;
            mac_vrf->vrf.intf_by_name = nullptr;
        }
        if (mac_vrf->vrf.intf_by_ifindex) {
            delete mac_vrf->vrf.intf_by_ifindex;
            mac_vrf->vrf.intf_by_ifindex = nullptr;
        }

        node->vrf[inst->mac_vrf_id] = NULL;
        XFREE (mac_vrf);
    }

    node->evpn[inst->evi] = NULL;
    XFREE (inst);
    *evpn_inst = NULL;
}

bool 
evpn_config_rd (evpn_inst_t *evpn_inst, rd_t rd)
{
    mac_vrf_t *mac_vrf = evpn_inst_mac_vrf (evpn_inst);

    if (!mac_vrf)
        return false;

    mac_vrf->vrf.rd = rd;
    return true;
}

bool 
evpn_unconfig_rd (evpn_inst_t *evpn_inst, rd_t rd)
{
    mac_vrf_t *mac_vrf = evpn_inst_mac_vrf (evpn_inst);

    if (!mac_vrf)
        return false;

    if (mac_vrf->vrf.rd.rtr_id != rd.rtr_id ||
        mac_vrf->vrf.rd.vrf_id != rd.vrf_id)
        return false;

    mac_vrf->vrf.rd.rtr_id = 0;
    mac_vrf->vrf.rd.vrf_id = 0;
    return true;
}

bool 
evpn_config_rt (evpn_inst_t *evpn_inst, rt_t rt, bool import)
{
    mac_vrf_t *mac_vrf = evpn_inst_mac_vrf (evpn_inst);
    rt_t *tgt;

    if (!mac_vrf)
        return false;

    tgt = import ? &mac_vrf->vrf.import_rt : &mac_vrf->vrf.export_rt;
    *tgt = rt;
    return true;
}

bool 
evpn_unconfig_rt (evpn_inst_t *evpn_inst, rt_t rt, bool import)
{
    mac_vrf_t *mac_vrf = evpn_inst_mac_vrf (evpn_inst);
    rt_t *tgt;

    if (!mac_vrf)
        return false;

    tgt = import ? &mac_vrf->vrf.import_rt : &mac_vrf->vrf.export_rt;

    if (tgt->rtr_id != rt.rtr_id || tgt->vrf_id != rt.vrf_id)
        return false;

    tgt->rtr_id = 0;
    tgt->vrf_id = 0;
    return true;
}

void
evpn_connect_bd (evpn_inst_t *evpn_inst, uint32_t bd_index) {

    node_t *node;
    mac_vrf_t *mac_vrf;

    assert (evpn_inst->bd_index == 0);
    evpn_inst->bd_index = bd_index;

    node = evpn_inst->node;

    /* Install EVPN labels for UC/MC for this evpn instance in LFIB */
    mac_vrf = (mac_vrf_t *)node->vrf[evpn_inst->mac_vrf_id];
    assert (mac_vrf->rtm_local_bd_uc_rt_mpls_idx == 0);
    assert (mac_vrf->rtm_local_bd_mc_rt_mpls_idx == 0);

    if (mac_vrf->l2vpn_evpn_uc_lbl)
        mac_vrf->rtm_local_bd_uc_rt_mpls_idx = 
            evpn_bd_install_local_label (mac_vrf->mac_rib, mac_vrf->l2vpn_evpn_uc_lbl);

    if (mac_vrf->l2vpn_evpn_mc_lbl)
        mac_vrf->rtm_local_bd_mc_rt_mpls_idx = 
            evpn_bd_install_local_label (mac_vrf->mac_rib, mac_vrf->l2vpn_evpn_mc_lbl);
}

bool 
evpn_disconnect_bd (evpn_inst_t *evpn_inst, uint32_t bd_index)
{
    mac_vrf_t *mac_vrf;

    if (!evpn_inst || evpn_inst->bd_index != bd_index)
        return false;

    mac_vrf = evpn_inst_mac_vrf (evpn_inst);

    if (mac_vrf) {
        if (mac_vrf->l2vpn_evpn_uc_lbl && mac_vrf->rtm_local_bd_uc_rt_mpls_idx) {
            evpn_bd_uninstall_local_label (mac_vrf->mac_rib, mac_vrf->l2vpn_evpn_uc_lbl);
            mac_vrf->rtm_local_bd_uc_rt_mpls_idx = 0;
        }
        if (mac_vrf->l2vpn_evpn_mc_lbl && mac_vrf->rtm_local_bd_mc_rt_mpls_idx) {
            evpn_bd_uninstall_local_label (mac_vrf->mac_rib, mac_vrf->l2vpn_evpn_mc_lbl);
            mac_vrf->rtm_local_bd_mc_rt_mpls_idx = 0;
        }
    }

    evpn_inst->bd_index = 0;
    return true;
}
