/*
 * =============================================================================
 * File: dp_init.cpp
 * Description: Datapath context initialization - queues, timer, tables, tracer.
 * =============================================================================
 *
 * Design:
 *   - dp_uapi_ctx_init() allocates and initializes the per-node datapath context.
 *   - Starts the main DP event dispatcher (and optionally pins to a core).
 *   - Starts a separate purger dispatcher for object cleanup.
 *   - Initializes packet queues (recv, CP-to-DP xmit, IPC), wheel timer,
 *     tracer, MAC table, interface/VRF/VLAN hashtables, vlan_vni_ht, netfilter
 *     hooks, L2 proto registration, and packet logging. Special interface
 *     pointers and default_vrf are left for the control plane to set.
 * =============================================================================
 */

#include <memory.h>
#include <stdlib.h>
#include <string.h>
#include "../libtimer/WheelTimer.h"
#include "../Tracer/tracer.h"
#include "Layer2/switching/mac_table.h"
#include "dp_ctx.h"

typedef struct hashtable hashtable_t;
typedef struct nf_hook_db_ nf_hook_db_t;

extern void dp_init_intf_hashtable(hashtable_t **ht);
extern void dp_init_vrf_hashtable(hashtable_t **ht);
extern void dp_init_vlan_intf_hashtable(hashtable_t **ht);
extern int debug_infra_tracer_bits_to_str(char *buffer, uint64_t bits);
extern void dp_pkt_recvr_job_cbk(event_dispatcher_t *ev_dis,
                                 void *pkt, uint32_t pkt_size);
extern void dp_pkt_xmit_intf_job_cbk(event_dispatcher_t *ev_dis,
                                     void *pkt, uint32_t pkt_size);
extern bool LinuxRtr;
extern void tcp_ip_register_default_l3_pkt_trap_rules(nf_hook_db_t *nf_hook_db);
void init_nfc_layer2_proto_reg_db2(notif_chain_t *nfc);
extern void dp_pkt_xmit_intf_job_cbk(event_dispatcher_t *ev_dis,
                              void *pkt, uint32_t pkt_size);

/**
 * Initialize datapath context: event loops, queues, timer, tracer, tables,
 * netfilter, and logging. Special interfaces and default_vrf are set by CP.
 */
void
dp_uapi_ctx_init(dp_ctx_t **_dp_ctx, void *arg, char *ctx_name)
{
    char file_name[64];
    char ev_dis_name[EV_DIS_NAME_LEN];

    *_dp_ctx = (dp_ctx_t *)calloc(1, sizeof(dp_ctx_t));
    dp_ctx_t *dp_ctx = (*_dp_ctx);

    strncpy(dp_ctx->ctx_name, ctx_name, sizeof(dp_ctx->ctx_name));

    /* Start main datapath event dispatcher (DP thread) */
    snprintf(ev_dis_name, EV_DIS_NAME_LEN, "DP-%s", ctx_name);
    event_dispatcher_init(&dp_ctx->dp_ev_dis, (const char *)ev_dis_name);
    event_dispatcher_run(&dp_ctx->dp_ev_dis, LinuxRtr ? true : false);
    dp_ctx->dp_ev_dis.app_data = (void *)dp_ctx;

    /* Start purger event dispatcher (cleanup / refcount) */
    event_dispatcher_init(&dp_ctx->dp_purger_ev_dis, (const char *)ev_dis_name);
    event_dispatcher_run(&dp_ctx->dp_purger_ev_dis, false);
    dp_ctx->dp_purger_ev_dis.app_data = (void *)dp_ctx;

    /* Initialize packet queues */
    init_pkt_q(&dp_ctx->dp_ev_dis, &dp_ctx->dp_recvr_pkt_q, dp_pkt_recvr_job_cbk);
    init_pkt_q(&dp_ctx->dp_ev_dis, &dp_ctx->cp_to_dp_xmit_intf_pkt_q,
               dp_pkt_xmit_intf_job_cbk);
    init_pkt_q(&dp_ctx->dp_ev_dis, &dp_ctx->dp_ipc_q, 0);

    /* Start wheel timer (e.g. for ARP expiry) */
    dp_ctx->dp_wt = init_wheel_timer(60, 1, TIMER_SECONDS);
    wt_set_user_data(dp_ctx->dp_wt, &dp_ctx->dp_ev_dis);
    start_wheel_timer(dp_ctx->dp_wt);

    /* Initialize tracer and file logging */
    memset(file_name, 0, sizeof(file_name));
    sprintf(file_name, "logs/%s-dp.txt", ctx_name);
    dp_ctx->dptr = tracer_init(ctx_name, file_name,
                               ctx_name, STDOUT_FILENO,
                               debug_infra_tracer_bits_to_str);
    tracer_enable_file_logging(dp_ctx->dptr, true);

    /* Initialize MAC table and hashtables */
    init_mac_table(&(dp_ctx->mac_table));
    dp_init_intf_hashtable(&dp_ctx->dp_intf_ht);
    dp_init_vrf_hashtable(&dp_ctx->dp_vrf_ht);
    dp_init_vlan_intf_hashtable(&dp_ctx->dp_vlan_intf_ht);
    dp_ctx->vlan_vni_ht.store(nullptr);

    /* Netfilter (L3) and L2 protocol registration */
    nf_init_netfilters(&dp_ctx->nf_hook_db);
    tcp_ip_register_default_l3_pkt_trap_rules(&dp_ctx->nf_hook_db);
    init_nfc_layer2_proto_reg_db2(&dp_ctx->layer2_proto_reg_db);

    /* Packet logging (optional dump to file) */
    memset(file_name, 0, sizeof(file_name));
    snprintf(file_name, sizeof(file_name), "logs/%s.txt", ctx_name);
    dp_ctx->log.all       = true;
    dp_ctx->log.recv      = true;
    dp_ctx->log.send      = true;
    dp_ctx->log.is_stdout = false;
    dp_ctx->log.l3_fwd    = true;
    dp_ctx->log.acc_lst_filter = NULL;
    dp_ctx->log.log_file  = fopen(file_name, "w");

    dp_ctx->ctx_pvt_data = arg;

    /* Members below are filled by control plane */
    memset(&dp_ctx->rmac, 0, sizeof(dp_ctx->rmac));
    dp_ctx->default_vrf = NULL;
    dp_ctx->dp_rmac_intf       = NULL;
    dp_ctx->dp_vlan_flood_intf = NULL;
    dp_ctx->dp_host_path_intf  = NULL;
    dp_ctx->dp_nve_intf        = NULL;

    dp_ctx->send_log_buffer = (unsigned char *)calloc(1, TCP_PRINT_BUFFER_SIZE);
    dp_ctx->recv_log_buffer = (unsigned char *)calloc(1, TCP_PRINT_BUFFER_SIZE);
}
