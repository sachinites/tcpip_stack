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
#include <string.h>
#include "dp_ctx.h"
#include "dp-program/dp-prog-struct.h"
#include "dp-program/dp-prog-api.h"

#include "../libs/pkt-block/pkt_mbuf.h"
#include "../libs/EventDispatcher/event_dispatcher.h"

#include "dp_uapi.h"
#include "dp_ctx.h"
#include "Vrfs/dp_vrf.h"
#include "Interface/dp_intf_store.h"
#include "Interface/dp_intf.h"
#include "Layer2/switching/mac_table.h"
#include "Layer2/arp/arp.h"

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

/* -------------------------------------------------------------------------
 * Async job posting helpers (safe from any thread / DPDK poll threads)
 * ---------------------------------------------------------------------- */

void
dp_post_mac_learn_job(dp_ctx_t *dp_ctx,
                      uint8_t *mac_addr,
                      uint16_t vlan_id,
                      uint32_t oif_ifindex,
                      uint32_t src_ip)
{
    dp_msg_t *dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = MAC_TABLE;
    dp_msg->opr_type       = DP_CREATE;
    dp_msg->data_size      = sizeof(mac_update_msg_t);

    mac_update_msg_t *m = (mac_update_msg_t *)dp_msg->data;
    memcpy(m->mac_addr, mac_addr, 6);
    m->vlan_id       = vlan_id;
    m->ifindex       = oif_ifindex;
    m->flags         = MAC_DYNAMIC;
    m->remote_dst_ip = src_ip;

    task_create_new_job(EV_DP(dp_ctx), (void *)dp_msg,
                        cp2dp_task_handler,
                        TASK_ONE_SHOT,
                        TASK_PRIORITY_PKT_PROCESSING);
}

void
dp_post_arp_resolve_job(dp_ctx_t *dp_ctx,
                        dp_vrf_t *vrf,
                        uint32_t oif_ifindex,
                        uint32_t target_ip,
                        struct rte_mbuf *mbuf)
{
    dp_msg_t *dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = ARP_TABLE;
    dp_msg->opr_type       = DP_CREATE;
    dp_msg->vrf_id         = vrf->vrf_id;
    dp_msg->data_size      = sizeof(arp_update_msg_t);

    arp_update_msg_t *a = (arp_update_msg_t *)dp_msg->data;
    a->op          = ARP_MSG_RESOLVE;
    a->vrf_id      = vrf->vrf_id;
    a->ip_addr     = target_ip;
    a->oif_ifindex = oif_ifindex;
    a->mbuf_ptr    = (uintptr_t)mbuf;   /* caller already ref-incremented */

    task_create_new_job(EV_DP(dp_ctx), (void *)dp_msg,
                        cp2dp_task_handler,
                        TASK_ONE_SHOT,
                        TASK_PRIORITY_PKT_PROCESSING);
}

void
dp_post_arp_update_from_pkt_job(dp_ctx_t *dp_ctx,
                                dp_vrf_t *vrf,
                                uint32_t iif_ifindex,
                                uint32_t sender_ip,
                                uint8_t *sender_mac)
{
    dp_msg_t *dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = ARP_TABLE;
    dp_msg->opr_type       = DP_UPDATE;
    dp_msg->vrf_id         = vrf->vrf_id;
    dp_msg->data_size      = sizeof(arp_update_msg_t);

    arp_update_msg_t *a = (arp_update_msg_t *)dp_msg->data;
    a->op          = ARP_MSG_UPDATE_FROM_PKT;
    a->vrf_id      = vrf->vrf_id;
    a->ip_addr     = sender_ip;
    a->oif_ifindex = iif_ifindex;
    memcpy(a->src_mac, sender_mac, 6);

    task_create_new_job(EV_DP(dp_ctx), (void *)dp_msg,
                        cp2dp_task_handler,
                        TASK_ONE_SHOT,
                        TASK_PRIORITY_PKT_PROCESSING);
}

/* -------------------------------------------------------------------------
 * CLI/management sync helpers — run on dp_ev_dis, block caller until done.
 * ---------------------------------------------------------------------- */

typedef struct show_mac_job_data_ {
    mac_table_t *mac_table;
    uint16_t vlan_id;
} show_mac_job_data_t;

static void
show_mac_job_cbk(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size)
{
    show_mac_job_data_t *d = (show_mac_job_data_t *)arg;
    show_mac_table(d->mac_table, d->vlan_id);
}

void
dp_show_mac_table_sync(dp_ctx_t *dp_ctx, uint16_t vlan_id)
{
    show_mac_job_data_t data = { dp_ctx->mac_table, vlan_id };
    task_create_new_job_synchronous(EV_DP(dp_ctx),
                                    (void *)&data,
                                    show_mac_job_cbk,
                                    TASK_ONE_SHOT,
                                    TASK_PRIORITY_CP_TO_DP);
}

typedef struct show_arp_job_data_ {
    arp_table_t *arp_table;
} show_arp_job_data_t;

static void
show_arp_job_cbk(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size)
{
    show_arp_job_data_t *d = (show_arp_job_data_t *)arg;
    show_arp_table(d->arp_table);
}

void
dp_show_arp_table_sync(dp_ctx_t *dp_ctx, void *arp_table)
{
    show_arp_job_data_t data = { (arp_table_t *)arp_table };
    task_create_new_job_synchronous(EV_DP(dp_ctx),
                                    (void *)&data,
                                    show_arp_job_cbk,
                                    TASK_ONE_SHOT,
                                    TASK_PRIORITY_CP_TO_DP);
}

typedef struct arp_cli_resolve_job_data_ {
    dp_vrf_t *vrf;
    uint32_t ip_addr;
} arp_cli_resolve_job_data_t;

static void
arp_cli_resolve_job_cbk(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size)
{
    arp_cli_resolve_job_data_t *d = (arp_cli_resolve_job_data_t *)arg;
    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;
    send_arp_broadcast_request(dp_ctx, d->vrf, NULL, d->ip_addr);
}

void
dp_arp_cli_resolve_sync(dp_ctx_t *dp_ctx, dp_vrf_t *vrf, uint32_t ip_addr)
{
    dp_vrf_t *target_vrf = vrf ? vrf : dp_ctx->default_vrf;
    if (!target_vrf) return;
    arp_cli_resolve_job_data_t data = { target_vrf, ip_addr };
    task_create_new_job_synchronous(EV_DP(dp_ctx),
                                    (void *)&data,
                                    arp_cli_resolve_job_cbk,
                                    TASK_ONE_SHOT,
                                    TASK_PRIORITY_CP_TO_DP);
}