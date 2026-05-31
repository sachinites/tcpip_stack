/*
 * =============================================================================
 * File: dp_uapi.cpp
 * Description: Implementation of datapath UAPI (lookup, etc.).
 * =============================================================================
 *
 * Design:
 *   - Thin wrappers around store/lookup functions; keeps a single public
 *     entry point (dp_uapi_look_up_interface) for interface lookup by port_id.
 * =============================================================================
 */

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include "dp_ctx.h"
#include "dp-program/dp-prog-struct.h"

#include "../libs/pkt-block/pkt_mbuf.h"

#include "dp_uapi.h"
#include "dp_ctx.h"
#include "Interface/dp_intf_store.h"
#include "Interface/dp_intf.h"

#include <rte_lcore.h>
                  
void 
dp_uapi_link_connect (dp_ctx_t *dp_ctx1, uint32_t ifindex1, 
                 dp_ctx_t *dp_ctx2, uint32_t ifindex2){


    dp_intf_t *dp_intf1 = dp_ctx1->intf_table[ifindex1];
    dp_intf_t *dp_intf2 = dp_ctx2->intf_table[ifindex2];

    dp_intf1->dp_ctx = dp_ctx1;
    dp_intf1->nbr_intf = dp_intf2;

    dp_intf2->dp_ctx = dp_ctx2;
    dp_intf2->nbr_intf = dp_intf1;    
}

int
dp_uapi_inject_packet(dp_ctx_t *dp_ctx,
                      struct rte_mbuf *mbuf,
                      uint32_t ifindex) {

    dp_intf_t *recv_intf = dp_ctx->intf_table[ifindex];

    if (!recv_intf) return -1;

    dp_pkt_entry_point(dp_ctx, recv_intf->vrf, recv_intf, mbuf);
                      
    return 0;
}

extern void 
cp2dp_task_handler  (event_dispatcher_t *ev_dis,  void *arg, uint32_t arg_size);

void
dp_uapi_submit_dp_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg, bool async) {

    // This function is used to submit a task to the DP
    // The task is submitted to the DP's event dispatcher
    // The task is submitted with the highest priority
    // The task is submitted as a one-shot task
    // The task is submitted with the task data as arg
    // The task data size is arg_size

    assert (dp_msg->data_size < sizeof(dp_msg->data));

    // Get the event dispatcher of the DP
    if (async) {
            task_create_new_job(EV_DP(dp_ctx), (void *)dp_msg,
                cp2dp_task_handler, 
                TASK_ONE_SHOT, 
                TASK_PRIORITY_CP_TO_DP);
    }
    else {
        task_create_new_job_synchronous(EV_DP(dp_ctx), (void *)dp_msg,
                cp2dp_task_handler, 
                TASK_ONE_SHOT, 
                TASK_PRIORITY_CP_TO_DP);
    }    
}

void 
dp_register_l2_pkt_trap_rule (dp_ctx_t *dp_ctx, 
                nfc_pkt_trap pkt_trap_cb,
                nfc_app_cb app_cb) {


	notif_chain_elem_t nfce_template;

	memset(&nfce_template, 0, sizeof(notif_chain_elem_t));
	nfce_template.is_key_set = false;
	nfce_template.app_cb = app_cb;
	nfce_template.pkt_trap_cb = pkt_trap_cb;	
	init_glthread(&nfce_template.glue);

	nfc_register_notif_chain(&dp_ctx->layer2_proto_reg_db, &nfce_template);
}

void
dp_de_register_l2_pkt_trap_rule(
		dp_ctx_t *dp_ctx, 
		nfc_pkt_trap pkt_trap_cb,
		nfc_app_cb app_cb) {

	notif_chain_elem_t nfce_template;

	memset(&nfce_template, 0, sizeof(notif_chain_elem_t));
	nfce_template.is_key_set = false;
	nfce_template.app_cb = app_cb;
	nfce_template.pkt_trap_cb = pkt_trap_cb;	
	init_glthread(&nfce_template.glue);

	nfc_de_register_notif_chain(&dp_ctx->layer2_proto_reg_db, &nfce_template);	
}

event_dispatcher_t *
dp_uapi_get_dp_scheduler (dp_ctx_t *dp_ctx) {

    return &dp_ctx->dp_ev_dis;
}

struct rte_mempool *
dp_uapi_get_current_socket_mpool(dp_ctx_t *dp_ctx) {

    int socket_id = (int)rte_socket_id();
    
    if (socket_id < 0) socket_id = 0;

    if (dp_ctx->mbuf_pools)
        return dp_ctx->mbuf_pools[socket_id];

    return NULL;
}