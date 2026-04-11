/*
 * =============================================================================
 * File: dp_ctx.h
 * Description: Datapath context (DP context) - central per-node dataplane state.
 * =============================================================================
 *
 * Design:
 *   - Each network node has one dp_ctx_t instance.
 *   - Holds packet queues, timer wheel, tracer, MAC table, interface/VRF
 *     hashtables, netfilter hooks, and references to special interfaces
 *     (RMAC, VLAN flood, host path, SRv6, NVE).
 *   - Used by both control-plane (CP) and data-plane (DP) code; CP configures
 *     it, DP uses it for forwarding and packet I/O.
 *
 * Key members:
 *   - dp_ev_dis / dp_purger_ev_dis : Event dispatchers (DP thread, purger).
 *   - dp_recvr_pkt_q / cp_to_dp_xmit_intf_pkt_q / dp_ipc_q : Packet queues.
 *   - dp_intf_ht / dp_vrf_ht / dp_vlan_intf_ht : Lookup tables.
 *   - vlan_vni_ht : VLAN–VNI mapping (atomic for lock-free access).
 * =============================================================================
 */

#ifndef __DP_CTX__
#define __DP_CTX__

#ifdef __cplusplus
#include <atomic>
#endif

typedef struct _wheel_timer_t wheel_timer_t;
typedef struct tracer_ tracer_t;
typedef struct hashtable hashtable_t;
typedef struct mac_table_ mac_table_t;
typedef struct vlan_vni_ht_db_ vlan_vni_ht_db_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct dp_vrf_ dp_vrf_t;
struct ping_ctx_;

#include "../libs/EventDispatcher/event_dispatcher.h"
#include "../tcp_ip_trace.h"
#include "../Layer3/netfilter.h"
#include "../libs/notifc/notif.h"
#include "../libs/common/cmn_struct.h"

#pragma pack(push, 8)

typedef struct dp_ctx_ {

    char ctx_name[32];

    /* Data path scheduler (main DP event loop) */
    event_dispatcher_t dp_ev_dis;
    /* Object purger / cleanup dispatcher */
    event_dispatcher_t dp_purger_ev_dis;

    /* Ingress packet queue (received on interfaces) */
    pkt_q_t dp_recvr_pkt_q;
    /* CP-to-DP interface transmit queue */
    pkt_q_t cp_to_dp_xmit_intf_pkt_q;
    /* IPC queue within data plane */
    pkt_q_t dp_ipc_q;

    /* Datapath timer wheel (e.g. ARP expiry, etc.) */
    wheel_timer_t *dp_wt;

    /* Datapath tracer for logging */
    tracer_t *dptr;

    /* L2 MAC table */
    mac_table_t *mac_table;

    /* Interface table (key: port_id / ifindex) */
    hashtable_t *dp_intf_ht;
    /* VRF table */
    hashtable_t *dp_vrf_ht;
    /* VLAN interface table (key: vlan-id) */
    hashtable_t *dp_vlan_intf_ht;
    /* VLAN–VNI mapping (VXLAN); atomic for lock-free updates */
#ifdef __cplusplus
    std::atomic<vlan_vni_ht_db_t *> vlan_vni_ht;
#else
    vlan_vni_ht_db_t *vlan_vni_ht;
#endif

    /* L3 netfilter hook database */
    nf_hook_db_t nf_hook_db;
    /* L2 protocol registration (notification chain) */
    notif_chain_t layer2_proto_reg_db;

    /* Packet logging state */
    log_t log;

    void *ctx_pvt_data;

    /* Router MAC and router ID (control-plane configured) */
    mac_addr_t rmac;
    uint32_t rtr_id;

    dp_vrf_t *default_vrf;

    /* Special interfaces (RMAC, VLAN flood, host path, SRv6 end, NVE) */
    dp_intf_t *dp_rmac_intf;
    dp_intf_t *dp_vlan_flood_intf;
    dp_intf_t *dp_host_path_intf;
    dp_intf_t *dp_nve_intf;
    
    /* Logging buffers (send/recv packet dump) */
    unsigned char *send_log_buffer;
    unsigned char *recv_log_buffer;

    /* Active ping session; set by ping_send4, 
    cleared when done, read by DP ICMP handler */
    struct ping_ctx_ *active_ping_ctx;

} dp_ctx_t;

#pragma pack(pop)

/* Convenience macros for dp_ctx members */
#define EV_DP(dp_ctx_ptr)        (&(dp_ctx_ptr)->dp_ev_dis)
#define DP_PKT_Q(dp_ctx_ptr)     (&(dp_ctx_ptr)->dp_recvr_pkt_q)
#define DP_TIMER(dp_ctx_ptr)     ((dp_ctx_ptr)->dp_wt)
#define EV_DP_PURGER(dp_ctx_ptr) (&(dp_ctx_ptr)->dp_purger_ev_dis)

#endif /* __DP_CTX__ */
