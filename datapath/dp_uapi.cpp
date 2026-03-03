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

#include "../pkt_block.h"

#include "dp_uapi.h"
#include "dp_ctx.h"
#include "Interface/dp_intf_store.h"
#include "Interface/dp_intf.h"

extern int
dp_inject_packet (dp_ctx_t *dp_ctx,
                  pkt_block_t *pkt_block,
                  dp_intf_t *interface);
                  
void 
dp_uapi_link_connect (dp_ctx_t *dp_ctx1, uint32_t ifindex1, 
                 dp_ctx_t *dp_ctx2, uint32_t ifindex2){


    dp_intf_t *dp_intf1 = dp_look_up_interface(dp_ctx1->dp_intf_ht, ifindex1);
    dp_intf_t *dp_intf2 = dp_look_up_interface(dp_ctx2->dp_intf_ht, ifindex2);

    dp_intf1->dp_ctx = dp_ctx1;
    dp_intf1->nbr_intf = dp_intf2;

    dp_intf2->dp_ctx = dp_ctx2;
    dp_intf2->nbr_intf = dp_intf1;    
}

int
dp_uapi_inject_packet(dp_ctx_t *dp_ctx,
                      pkt_block_t *pkt_block,
                      uint32_t ifindex) {

    dp_intf_t *recv_intf = dp_look_up_interface(dp_ctx->dp_vrf_ht, ifindex);

    if (!recv_intf) return -1;

    dp_inject_packet (dp_ctx, 
                      pkt_block, recv_intf);
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