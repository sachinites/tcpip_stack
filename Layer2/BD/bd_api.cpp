
#include "../../libs/EventDispatcher/event_dispatcher.h"
#include "../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../../dpcp_cmn.h"
#include "../../router_init.h"
#include "../../Interface/InterfaceUApi.h"

#include "../../vrf/mac_vrf.h"
#include "bd_api.h"

extern int cprintf (const char* format, ...);

void 
bd_recv_mac_learning_cbk(
        event_dispatcher_t *ev_dis, 
        void *arg, 
        uint32_t pkt_size) {

    node_t *node = (node_t *)ev_dis->app_data;

    bd_lmac_data_t *lmac_data  = 
	        (bd_lmac_data_t *)task_get_next_pkt(ev_dis, &pkt_size);    

    if (!lmac_data) return;

    for (; lmac_data;
         lmac_data = (bd_lmac_data_t *)task_get_next_pkt(ev_dis, &pkt_size)) {

        cprintf("MAC Recvd : %02x:%02x:%02x:%02x:%02x:%02x, BD = %u, op:%s\n",
                lmac_data->mac.mac[0], lmac_data->mac.mac[1],
                lmac_data->mac.mac[2], lmac_data->mac.mac[3],
                lmac_data->mac.mac[4], lmac_data->mac.mac[5],
                lmac_data->bd_ifindex,
                lmac_data->add ? "add" : "del");

        BDInterface *bd_intf = dynamic_cast<BDInterface *>(node_get_intf_by_ifindex(node, lmac_data->bd_ifindex));
        assert (bd_intf);

        if (lmac_data->add) {
                mac_vrf_evpn_route_type2_local_import (
                    bd_intf->vrf->mac_vrf[bd_intf->bd_id],
                    &lmac_data->mac);
        }
        else {
                mac_vrf_evpn_route_type2_delete (
                    bd_intf->vrf->mac_vrf[bd_intf->bd_id],
                    &lmac_data->mac);
        }

        XFREE(lmac_data);
    }
}