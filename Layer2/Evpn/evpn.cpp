
#include <assert.h>
#include "../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../../LabelMgr/label_mgr.h"

#include "../../router_init.h"
#include "../../Interface/InterfaceUApi.h"

#include "evpn.h"
#include "evpn_priv_api.h"
#include "../../vrf/mac_vrf.h"
#include "../../RTM/rtm.h"

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
evpn_instance_deinit (evpn_inst_t **_evpn_inst)
{
    evpn_inst_t *evpn_inst;
    node_t *node;

    evpn_inst = *_evpn_inst;
    node = evpn_inst->node;

    /* BD should be disconnected from EVI*/
    assert (evpn_inst->bd_intf == nullptr);
    assert (node->evpn[evpn_inst->evi] == evpn_inst);

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
}

bool 
evpn_disconnect_bd (evpn_inst_t *evpn_inst, BDInterface *bd_intf)
{
    assert (evpn_inst->bd_intf.get() == bd_intf);

    bd_intf->evi_id = 0;
    evpn_inst->bd_intf = nullptr;

    /* Reset RT */
    evpn_inst->export_rt.rtr_id = 0;
    evpn_inst->export_rt.sub_type = 0;
    evpn_inst->export_rt.vrf_id = 0;
    evpn_inst->import_rt = evpn_inst->export_rt;

    return true;
}
