
#include "../../libs/EventDispatcher/event_dispatcher.h"
#include "../../libs/LinuxMemoryManager/uapi_mm.h"
#include "bd_api.h"
#include "../../dpcp_cmn.h"

extern int cprintf (const char* format, ...);

void 
bd_recv_mac_learning_cbk(
        event_dispatcher_t *ev_dis, 
        void *arg, 
        uint32_t pkt_size) {

	bd_lmac_data_t *lmac_data  = 
			(bd_lmac_data_t *)task_get_next_pkt(ev_dis, &pkt_size);    

    if (!lmac_data) return;

    for (; lmac_data;
         lmac_data = (bd_lmac_data_t *)task_get_next_pkt(ev_dis, &pkt_size)) {

        cprintf("MAC Recvd : %02x:%02x:%02x:%02x:%02x:%02x, BD = 0x%u, op:%s\n",
                lmac_data->mac.mac[0], lmac_data->mac.mac[1],
                lmac_data->mac.mac[2], lmac_data->mac.mac[3],
                lmac_data->mac.mac[4], lmac_data->mac.mac[5],
                lmac_data->bd_ifindex,
                lmac_data->add ? "add" : "del");

        XFREE(lmac_data);
    }
}