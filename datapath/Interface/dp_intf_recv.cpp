#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include "../../EventDispatcher/event_dispatcher.h"
#include "../dp_ctx.h"
#include "dp_intf.h"
#include "../../tcp_ip_trace.h"
#include "../Vrfs/dp_vrf.h"
#include "../../pkt_block.h"
#include "../Layer2/l2fwd/ipv4-l2fwd.h"
#include "../../c-hashtable/hashtable.h"
#include "../../c-hashtable/hashtable_itr.h"
#include "../../Tracer/tracer.h"
#include "dp_intf_log.h"
#include "../../common/l2_hdrs.h"
#include "../Layer2/switching/mac_table.h"
#include "../dp_uapi.h"
#include "../../common/cmn_api.h"
#include "dp_intf_store.h"

extern int cprintf (const char* format, ...);

static void 
dp_pkt_receive(dp_ctx_t *dp_ctx, 
                    dp_vrf_t *vrf,
                    dp_intf_t *interface,
                    pkt_block_t *pkt_block)
{

    vlan_id_t vlan_id_to_tag = 0;
  
      if (!interface->is_up){
        return;
    }
    
    interface->pkt_recv++;
    tcp_dump_recv_logger(dp_ctx, interface, pkt_block, ETH_HDR);

    /* Access List Evaluation at Layer 2 Entry point*/ 
    #if 0
    if (access_list_evaluate_ethernet_packet (
                node, interface, pkt_block, true) 
                == ACL_DENY) {
        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
            "Pkt : %s : Pkt Dropped : L2 ACL Denied on ingress interface %s\n", 
            pkt_block_str(pkt_block), interface->if_name);
        return;
    }
    #endif

    if (l2_frame_recv_qualify_on_interface(dp_ctx,
                                          vrf,
                                          interface, 
                                          pkt_block,
                                          &vlan_id_to_tag) == false){
        
        cprintf("Error : L2 Frame Rejected on node %s(%s)\n", 
            dp_ctx->ctx_name, interface->if_name);
            
        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
            "Pkt : %s : L2 Frame Rejected in Interface %s, qualification Test Failed\n", 
            pkt_block_str(pkt_block), interface->if_name);

        return;
    }

    if ((interface->switchport &&
            interface->l2_mode != DP_LAN_MODE_NONE)) {

        pkt_block->ingress_intf = interface;

        if (vlan_id_to_tag) {
           
            tag_pkt_with_vlan_id (pkt_block, vlan_id_to_tag);
            tracer (dp_ctx->dptr, DL2FWD | DFLOW, "Pkt : %s : Tagged with VLAN ID %d\n", 
                pkt_block_str(pkt_block), vlan_id_to_tag);
        }

        if (vlan_id_to_tag == 0) {

            /* We did not tag the pkt because pkt was already tagged.*/
            vlan_8021q_hdr_t *vlan_8021q_hdr;

            assert ((vlan_8021q_hdr = 
                is_pkt_vlan_tagged ((ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, NULL))));

            vlan_id_to_tag = (vlan_id_t)GET_802_1Q_VLAN_ID(vlan_8021q_hdr);
        }

        l2_switch_recv_frame(dp_ctx,
                    vlan_id_to_tag,
                    interface, pkt_block);
    }

    /* If packet is Recvd on GRE interface and pkt is vlan tagged, 
        it means GRE is being used for VLAN extension */
    else if (interface->if_type == DP_INTF_TYPE_GRE_TUNNEL &&
                pkt_block_verify_pkt (pkt_block, ETH_HDR) &&
                is_pkt_vlan_tagged (pkt_block_get_ethernet_hdr(pkt_block))) {

        tracer (dp_ctx->dptr, DL2FWD | DFLOW, "Pkt : %s : Being recieved on GRE Interface %s\n", 
            pkt_block_str(pkt_block), interface->if_name);  

        dp_pkt_receive (dp_ctx, interface->virtual_port->vrf, interface->virtual_port, pkt_block);
    }

    else if (interface->ip_addr){

        tracer (dp_ctx->dptr, DL2FWD | DFLOW, 
            "Pkt : %s : Recvd on L3 Interface %s, being protmoted to L3Fwding\n", 
            pkt_block_str(pkt_block), interface->if_name);
            
        pkt_block->ingress_intf = interface;
        promote_pkt_to_layer2(dp_ctx, interface->vrf, interface, pkt_block);
    }

    else {
        /* We dont know what to do with the pkt*/
        tracer (dp_ctx->dptr, DL2FWD | DFLOW | DERR, 
            "Pkt : %s : pkt dropped, Unknown pkt recvd on Interface %s\n", 
            pkt_block_str(pkt_block), interface->if_name);
        interface->recvd_pkt_dropped++;
    }
}

extern void
dp_pkt_recvr_job_cbk (event_dispatcher_t *ev_dis, void *pkt, uint32_t pkt_size){

    dp_ctx_t *dp_ctx;
    pkt_block_t *pkt_block;
	dp_intf_t *recv_intf;

	ev_dis_pkt_data_t *ev_dis_pkt_data  = 
			(ev_dis_pkt_data_t *)task_get_next_pkt(ev_dis, &pkt_size);

	if(!ev_dis_pkt_data) {
		return;
	}

    dp_ctx = (dp_ctx_t *)(ev_dis->app_data);

	for ( ; ev_dis_pkt_data; 
			ev_dis_pkt_data = (ev_dis_pkt_data_t *) task_get_next_pkt(ev_dis, &pkt_size)) {

		recv_intf = dp_look_up_interface(dp_ctx->dp_intf_ht, ev_dis_pkt_data->ifindex);
        assert(recv_intf);

		pkt = ev_dis_pkt_data->pkt;		

        pkt_block = pkt_block_get_new((uint8_t *)pkt, ev_dis_pkt_data->pkt_size);
        pkt_block_set_starting_hdr_type(pkt_block, ETH_HDR);

		dp_pkt_receive(dp_ctx, recv_intf->vrf,
                    recv_intf, 
                    pkt_block);

        pkt_block_dereference(pkt_block);
		free (ev_dis_pkt_data);
		ev_dis_pkt_data = NULL;
	}
}

int
dp_inject_packet (dp_ctx_t *dp_ctx,
                  pkt_block_t *pkt_block,
                  dp_intf_t *interface){
 
    uint8_t *pkt;
    pkt_size_t pkt_size;

    if (!interface->is_up){
        return 0;
    }

    dp_ctx_t  *nbr_dp_ctx = dp_ctx;
    dp_intf_t *peer_intf = interface;

	ev_dis_pkt_data_t *ev_dis_pkt_data;

    pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

	ev_dis_pkt_data =  (ev_dis_pkt_data_t *)calloc(1, sizeof(ev_dis_pkt_data_t));

	ev_dis_pkt_data->ifindex = peer_intf->port_id;
	ev_dis_pkt_data->pkt = tcp_ip_get_new_pkt_buffer(pkt_size);
	memcpy(ev_dis_pkt_data->pkt, pkt, pkt_size);
	ev_dis_pkt_data->pkt_size = pkt_size;

	pkt_q_enqueue(EV_DP(nbr_dp_ctx), 
                  DP_PKT_Q(nbr_dp_ctx),
                  (char *)ev_dis_pkt_data,
                  sizeof(ev_dis_pkt_data_t));

    return pkt_size; 
}

int
send_pkt_flood(dp_ctx_t *dp_ctx, 
               dp_intf_t *exempted_intf, 
               pkt_block_t *pkt_block) {

    dp_intf_t *intf; 

    struct hashtable_itr *itr = hashtable_iterator(dp_ctx->dp_intf_ht);

    while ((intf = (dp_intf_t *)hashtable_iterator_value(itr))) {
    
        if(!intf) {
            free(itr);
            return 0;
        }

        if(intf == exempted_intf) {
            hashtable_iterator_advance(itr);
            continue;
        }
        dp_send_pkt_out(dp_ctx, intf, pkt_block);
        hashtable_iterator_advance(itr);
    } 
    free(itr);
    
    return 0;
}