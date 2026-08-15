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
#include "../libs/libtimer/WheelTimer.h"
#include "../libs/Tracer/tracer.h"
#include "Layer2/switching/mac_table.h"
#include "dp_ctx.h"
#include "dp_table_gc.h"
#include "dp_const.h"
#include "../libs/mtrie/atomic_mtrie.h"
#include <rte_errno.h>
#include "dp_uapi.h"

typedef struct hashtable hashtable_t;
typedef struct nf_hook_db_ nf_hook_db_t;

extern int cprintf (const char* format, ...);

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
extern dp_intf_t *bd_flood_intf_create () ;

extern uint8_t 
system_get_max_numa_node_count ();

#define NUM_MBUFS_PER_PORT 8191
#define MBUF_CACHE_SIZE 250

static void
dp_init_pkt_mbuf_memory_pools(dp_ctx_t *dp_ctx)
{
    char mpool_name[64];

    uint8_t max_numa_nodes = system_get_max_numa_node_count ();

    dp_ctx->mbuf_pools = 
        (struct rte_mempool **) calloc (max_numa_nodes, sizeof (struct rte_mempool *));

    for (int i = 0; i < max_numa_nodes; i++) {

        memset (mpool_name, 0, sizeof (mpool_name));
        snprintf (mpool_name, 
            sizeof (mpool_name), 
            "MP_%s_%u", dp_ctx->ctx_name, i);

        dp_ctx->mbuf_pools[i] = rte_pktmbuf_pool_create(
                    (const char *)mpool_name,
                    NUM_MBUFS_PER_PORT *  32 /* port cnt on device*/,
                    MBUF_CACHE_SIZE, 
                    sizeof (pkt_mbuf_pvt_data_t), 
                    RTE_MBUF_DEFAULT_BUF_SIZE, i );

        if (!dp_ctx->mbuf_pools[i]) {
            cprintf ("%s : Error : Memory pool creation failed on Numa Node %d, err=%s\n", 
                dp_ctx->ctx_name, i, rte_strerror(rte_errno));
        }
        //assert (dp_ctx->mbuf_pools[i]);
    }
}

static void 
dp_init_fib_memory_pools (dp_ctx_t *dp_ctx) {

    char mempool_name[64];

    /* We dont maintain a FIB per numa node, but it is a centralized
        entity in datapath, hence allocate pool on Default Numa node only */
    snprintf (mempool_name, 
             sizeof(mempool_name), 
             "%s-%d", 
             dp_ctx->ctx_name, 
             DEFAULT_NUMA_NODE);
    
    dp_ctx->fib_mops.fib_mempool = rte_mempool_create(
                (const char *)mempool_name,
                MAX_FIB_MTRIE_NODES,
                sizeof(atomic_mtrie_node_t),
                0,
                0,
                NULL,
                NULL,
                NULL,
                NULL,
                DEFAULT_NUMA_NODE,
                0);

    //assert (dp_ctx->fib_mops.fib_mempool);
}


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

    /* Start main datapath event dispatcher (DP thread) 
        This thread become DP Management thread on LinuxRtr */
    snprintf(ev_dis_name, EV_DIS_NAME_LEN, LinuxRtr ? "DP-Mgr-%s" : "DP-%s", ctx_name);
    event_dispatcher_init(&dp_ctx->dp_ev_dis, (const char *)ev_dis_name);
    event_dispatcher_run(&dp_ctx->dp_ev_dis, true, 0);
    dp_ctx->dp_ev_dis.app_data = (void *)dp_ctx;

    /* Start purger event dispatcher (cleanup / refcount) */
    event_dispatcher_init(&dp_ctx->dp_purger_ev_dis, (const char *)ev_dis_name);
    event_dispatcher_run(&dp_ctx->dp_purger_ev_dis, true, 0);
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
    init_mac_table(&(dp_ctx->mac_table), dp_ctx->ctx_name, NULL);
    memset(dp_ctx->intf_table, 0, sizeof(dp_ctx->intf_table));
    dp_init_vrf_hashtable(&dp_ctx->dp_vrf_ht);
    dp_init_vlan_intf_hashtable(&dp_ctx->dp_vlan_intf_ht);
    dp_ctx->vlan_vni_ht.store(nullptr);

    /* Start the single periodic GC scan timer (replaces per-entry timers). */
    dp_table_gc_start(dp_ctx);

    /* Netfilter (L3) and L2 protocol registration */
    nf_init_netfilters(&dp_ctx->nf_hook_db);
    tcp_ip_register_default_l3_pkt_trap_rules(&dp_ctx->nf_hook_db);
    init_nfc_layer2_proto_reg_db2(&dp_ctx->layer2_proto_reg_db);

    /* intialize memory pools per Numa node*/
    dp_init_pkt_mbuf_memory_pools (dp_ctx);

    /* Initialize Memory pools to allocate nodes for FIB Mtrie*/
    dp_init_fib_memory_pools (dp_ctx);

    /* Packet logging — flags and log_file are set by tcp_ip_init_node_log_info() */
    dp_ctx->ctx_pvt_data = arg;

    /* Members below are filled by control plane */
    memset(&dp_ctx->rmac, 0, sizeof(dp_ctx->rmac));
    dp_ctx->default_vrf = NULL;
    dp_ctx->intf_table[BD_FLOOD_IFINDEX] = bd_flood_intf_create ();
    dp_ctx->send_log_buffer = (unsigned char *)calloc(1, TCP_PRINT_BUFFER_SIZE);
    dp_ctx->recv_log_buffer = (unsigned char *)calloc(1, TCP_PRINT_BUFFER_SIZE);
}
