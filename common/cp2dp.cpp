#include <assert.h>
#include "../graph.h"
#include "l3_hdrs.h"
#include "cp2dp.h"
#include "../EventDispatcher/event_dispatcher.h"
#include "../dpdk/layer3/dp_rtm.h"
#include "../Layer3/layer3.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../pkt_block.h"
#include "../Interface/InterfaceUApi.h"
#include "../Tracer/tracer.h"

static void 
np_recv_cp_pkt_block (node_t *node, dp_msg_t *dp_msg) {

    pkt_block_t *pkt_block;

    pkt_block = *(pkt_block_t **)dp_msg->data;

    switch (dp_msg->opr_type) {

        case DP_L3_NORTHBOUND_IN:
            assert (pkt_block_verify_pkt (pkt_block, IP_HDR));
            np_tcp_ip_send_ip_data (node, pkt_block);
            break;
        default:
            break;
    }

    pkt_block_dereference(pkt_block);
    cp2dp_msg_free (node, dp_msg);
}

static void 
cp2dp_task_handler  (event_dispatcher_t *ev_dis,  void *arg, uint32_t arg_size) {

    // This function is the task handler for the task submitted to the Data Path (DP)
    // The task handler is called when the task is executed by the DP's event dispatcher
    // The task handler is called with the task data as arg

    dp_msg_t *dp_msg = (dp_msg_t *)arg;
    node_t *node = (node_t *)ev_dis->app_data;

    switch (dp_msg->component_type) {

        case RT_TABLE_IPV4:
            np_rt_table_process_msg (node, dp_msg);
            break;
        case PKT_BLOCK:
            np_recv_cp_pkt_block (node, dp_msg);
            break;
        default:
            break;
    }
}

dp_msg_t *
cp2dp_msg_alloc (node_t *node, uint32_t data_size) {

    return (dp_msg_t *)XCALLOC_BUFF (NULL, (sizeof(dp_msg_t) + data_size));
}

void
cp2dp_msg_free (node_t *node, dp_msg_t *dp_msg) {
    
        XFREE (dp_msg);
}


void 
dp_pkt_xmit_intf_job_cbk (event_dispatcher_t *ev_dis, void *pkt, uint32_t pkt_size){

    node_t *node;
    pkt_block_t *pkt_block;
	node_t *receving_node;
	Interface *xmit_intf;

	ev_dis_pkt_data_t *ev_dis_pkt_data  = 
			(ev_dis_pkt_data_t *)task_get_next_pkt(ev_dis, &pkt_size);

	if(!ev_dis_pkt_data) {
		return;
	}

    node = (node_t *)ev_dis->app_data;

	for ( ; ev_dis_pkt_data; 
			ev_dis_pkt_data = (ev_dis_pkt_data_t *) task_get_next_pkt(ev_dis, &pkt_size)) {

		receving_node = ev_dis_pkt_data->recv_node;
		xmit_intf = ev_dis_pkt_data->recv_intf;
		pkt_block = (pkt_block_t *)ev_dis_pkt_data->pkt;		
        tracer (node->dptr,  DIPC | DFLOW, "Pkt : %s : Recvd by Data path\n", pkt_block_str(pkt_block));
        xmit_intf->SendPacketOut (pkt_block);
        pkt_block_dereference(pkt_block);
        xmit_intf->InterfaceUnLockDynamic();
		XFREE(ev_dis_pkt_data);
	}
}

/* Fix me : cp2dp_xmit_pkt is allocated by CP but freed by DP. This is not a desirable thing to do.
    For now its not a problem, but in future when CP and DP will have separate memory mgr, 
    this would create problem.*/
void
cp2dp_xmit_pkt (node_t *node, pkt_block_t *pkt_block, Interface *xmit_interface) {
    
        ev_dis_pkt_data_t *ev_dis_pkt_data = (ev_dis_pkt_data_t *)XCALLOC(0, 1, ev_dis_pkt_data_t);
        ev_dis_pkt_data->recv_node = node;
        ev_dis_pkt_data->recv_intf = xmit_interface;
        ev_dis_pkt_data->pkt = (byte *)pkt_block;
        xmit_interface->InterfaceLockDynamic();
        pkt_block_reference(pkt_block);
        tracer (node->cptr,  DIPC | DFLOW, "Pkt : %s : Xmit to Data path\n", pkt_block_str(pkt_block));
        pkt_q_enqueue(EV_DP(node), &node->cp_to_dp_xmit_intf_pkt_q ,
                  (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t));
}

/* This is Control plane API to push IP data to be sent out from L4+ layer down to L3.
    pkt_block must contain IP payload . If there is no ip payload, then send NULL*/
void 
cp2dp_send_ip_data ( node_t *node, 
                                    pkt_block_t *pkt_block,
                                    uint32_t dest_ip_addr,
                                    uint16_t std_ip_protocol) {

    if (!pkt_block) {
        pkt_block = pkt_block_get_new_pkt_buffer(sizeof(ip_hdr_t));
    }
    else {
        pkt_block_expand_buffer_left (pkt_block, sizeof (ip_hdr_t));
    }

    pkt_block_set_starting_hdr_type (pkt_block, IP_HDR);

    ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt_block);
    pkt_size_t pkt_size = pkt_block->pkt_size;

    initialize_ip_hdr (ip_hdr);

    ip_hdr->protocol = std_ip_protocol;
    ip_hdr->src_ip = tcp_ip_convert_ip_p_to_n(NODE_LO_ADDR(node));
    ip_hdr->dst_ip = dest_ip_addr;
    ip_hdr->total_length = 
        IP_HDR_COMPUTE_DEFAULT_TOTAL_LEN((pkt_size - sizeof (ip_hdr_t)));
    dp_msg_t *dp_msg = cp2dp_msg_alloc (node, sizeof (uintptr_t));
    dp_msg->component_type = PKT_BLOCK;
    dp_msg->opr_type = DP_L3_NORTHBOUND_IN;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(pkt_block_t *);
    memcpy (dp_msg->data, &pkt_block, sizeof(pkt_block_t *));
    pkt_block_reference(pkt_block);
    cp2dp_submit (node, dp_msg, true);
    pkt_block_dereference(pkt_block);
}

void 
cp2dp_submit (node_t *node, dp_msg_t *dp_msg, bool async) {

    // This function is used to submit a task to the DP
    // The task is submitted to the DP's event dispatcher
    // The task is submitted with the highest priority
    // The task is submitted as a one-shot task
    // The task is submitted with the task data as arg
    // The task data size is arg_size

    // Get the event dispatcher of the DP
    if (async) {
            task_create_new_job(EV_DP(node), (void *)dp_msg,
                cp2dp_task_handler, 
                TASK_ONE_SHOT, 
                TASK_PRIORITY_CP_TO_DP);
    }
    else {
        task_create_new_job_synchronous(EV_DP(node), (void *)dp_msg,
                cp2dp_task_handler, 
                TASK_ONE_SHOT, 
                TASK_PRIORITY_CP_TO_DP);
    }
}
