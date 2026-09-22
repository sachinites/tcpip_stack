
#include <assert.h>
#include "../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../../LabelMgr/label_mgr.h"

#include "../../router_init.h"
#include "../../Interface/InterfaceUApi.h"
#include "../../dpal/cp2dp.h"

#include "evpn.h"
#include "evpn_priv_api.h"
#include "../../vrf/mac_vrf.h"
#include "../../RTM/rtm.h"
#include "../../Layer5/bgp_rtr.h"
#include "../../Layer5/bgp_global_rib.h"

extern int cprintf (const char* format, ...);

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

    evpn_inst = (evpn_inst_t *)XCALLOC2 (0, 1 , evpn_inst_t);
    evpn_inst->evi = evpn_id;
    node->evpn[evpn_id] = evpn_inst;
    evpn_inst->node = node;
    evpn_inst->bd_intf = nullptr;

    /* Allocate default RD/RT, RD RT will be derived when BD will be
        connected to evpn instance, for now leave then 0 */  
    
    return evpn_inst;
}

void
evpn_instance_deinit (evpn_inst_t *evpn_inst)
{
    node_t *node = evpn_inst->node;

    assert (node->evpn[evpn_inst->evi] == evpn_inst);

    /* Disconnect BD */
    evpn_disconnect_bd(evpn_inst, evpn_inst->bd_intf.get());
    assert (evpn_inst->mac_vrf == NULL);
    
    node->evpn[evpn_inst->evi] = NULL;
    evpn_inst->node = NULL;

    XFREE(evpn_inst);
}


bool 
evpn_config_rd (evpn_inst_t *evpn_inst, rd_t rd)
{
    if (!evpn_inst->bd_intf) {
        return false;
    }

    evpn_inst->rd = rd;
}

bool 
evpn_unconfig_rd (evpn_inst_t *evpn_inst, rd_t rd)
{
    evpn_inst->rd.rtr_id = 0;
    evpn_inst->rd.vrf_id = 0;
    return true;
}

bool 
evpn_config_rt (evpn_inst_t *evpn_inst, rt_t rt, bool import)
{
    if (!evpn_inst->bd_intf) {
        return false;
    }

    if (import) {
        evpn_inst->import_rt = rt;
    }
    else {
        evpn_inst->export_rt = rt;
    }
    return true;
}

bool 
evpn_unconfig_rt (evpn_inst_t *evpn_inst, rt_t rt, bool import)
{
    if (import) {
        evpn_inst->import_rt.rtr_id = 0;
        evpn_inst->import_rt.sub_type = 0;
        evpn_inst->import_rt.vrf_id = 0;
    }
    else {
        evpn_inst->export_rt.rtr_id = 0;
        evpn_inst->export_rt.sub_type = 0;
        evpn_inst->export_rt.vrf_id = 0;
    }
    return true;
}

void
evpn_connect_bd (evpn_inst_t *evpn_inst, BDInterface *bd_intf) {

    assert (!evpn_inst->bd_intf);
    assert (!bd_intf->evi_id);
    assert (bd_intf->vrf);

    evpn_inst->bd_intf =
        std::dynamic_pointer_cast<BDInterface>(bd_intf->GetSharedPtr());
    bd_intf->evi_id = evpn_inst->evi;

    /* Now Assign RD/RT to evpn since evpn now has a soul (BD ) */
     /* Auto generate RD/RT, should be overridden by user config */
    evpn_inst->rd.type = 1;
    evpn_inst->rd.rtr_id = NODE_RTR_ID_INT(bd_intf->vrf->node);
    evpn_inst->rd.vrf_id = bd_intf->bd_id;

    /* Generate import/export RT (Type-1: IPv4:uint16) */
    rt_type1_fill(&evpn_inst->import_rt,
                  0,
                  bd_intf->bd_id);

    evpn_inst->export_rt = evpn_inst->import_rt;

    bd_intf->enable_lmac_queue();
    cp2dp_enable_bd_lmac_learning_queue(bd_intf, true);
    evpn_inst->mac_vrf =  mac_vrf_create(bd_intf->vrf, bd_intf->bd_id);
    evpn_inst->mac_vrf->evpn_inst = evpn_inst;

    mac_vrf_evpn_route_type3_local_import(bd_intf->vrf->node, evpn_inst->mac_vrf);

    if (BGP_INST(evpn_inst->node))
    {
        bgp_global_rib_export_all(
            BGP_INST(evpn_inst->node),
            AFI_L2VPN,
            SAFI_MPLS_EVPN,
            evpn_inst->evi);
    }
}

/* 
1. Delete local Routes from MAC VRF - Type 2 and 3 both 
2. They never installed in RTM in the first place, do dont bother to delete from RTM
3. Withdraw local route advertisement from BGP for both Type 2 and Type 3
4. BGP will withdraw and delete Imet/Mac local routes from Global RIBs
5. Delete Remote routes Type2/3 from MAC VRF
6. Withdraw all Remote Routes from RTM
7. Delete MAC VRF
8. All Remote Routes must stay in BGP GLobal RIB
*/
bool 
evpn_disconnect_bd (evpn_inst_t *evpn_inst, BDInterface *bd_intf)
{
    assert (evpn_inst->bd_intf.get() == bd_intf);
    assert (evpn_inst->mac_vrf);

    node_t *node = evpn_inst->node;
    mac_vrf_t *mac_vrf = evpn_inst->mac_vrf;

    /* Stop learning before tearing down MAC VRF routes */
    cp2dp_enable_bd_lmac_learning_queue(bd_intf, false);
    bd_intf->disable_lmac_queue();

    /*
     * 1-3. Delete local Type-2/3 from MAC VRF and withdraw from BGP.
     *      Locals were never installed in RTM.
     * Must happen before clearing RD/RT used by BGP withdraw.
     */
    mac_vrf_delete_all_local_evpn_routes(node, mac_vrf);

    /*
     * 4-5. Delete remote Type-2/3 from MAC VRF and uninstall them from RTM.
     * 7.   Do not touch BGP Global RIB — remotes stay there.
     */
    mac_vrf_delete_all_remote_evpn_routes(mac_vrf);

    /* 6. Delete MAC VRF */
    mac_vrf_destroy(mac_vrf);
    evpn_inst->mac_vrf = NULL;

    bd_intf->evi_id = 0;
    evpn_inst->bd_intf = nullptr;

    return true;
}
