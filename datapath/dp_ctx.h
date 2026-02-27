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

#include "../EventDispatcher/event_dispatcher.h"
#include "../tcp_ip_trace.h"
#include "../Layer3/netfilter.h"
#include "../notif.h"

#pragma pack(push, 8)

typedef struct dp_ctx_ {

    char ctx_name[32];
    /* Data path scheduler */
    event_dispatcher_t dp_ev_dis;
    /* Objects Purger */
    event_dispatcher_t dp_purger_ev_dis;  
    
    /* Data Path ingress Pkt Queue */
    pkt_q_t dp_recvr_pkt_q;    
    /* CptoDp Interface Xmit Global Queue*/
    pkt_q_t cp_to_dp_xmit_intf_pkt_q;
    /*IPC in a data plane */
    pkt_q_t dp_ipc_q;
    
    /* Data Path Timer */
    wheel_timer_t *dp_wt;    

    /* Data-Path Tracer*/
    tracer_t *dptr;

    /* Mac Table*/
    mac_table_t *mac_table;  

    /* DP hash table storage of interfacs*/
    hashtable_t *dp_intf_ht;
    /* DP hash table storage of VRFs*/
    hashtable_t *dp_vrf_ht;    
    /* Vlan-VNI mapping DP hash table*/
#ifdef __cplusplus
    std::atomic<vlan_vni_ht_db_t *> vlan_vni_ht;
#else
    vlan_vni_ht_db_t *vlan_vni_ht;
#endif

    /* Net filter hook DB*/
    nf_hook_db_t nf_hook_db;
    /*L2 net-filter hook (simplified) */
	notif_chain_t layer2_proto_reg_db;

    /* Packet Logging */
    log_t log;

    void *ctx_pvt_data;

    mac_addr_t rmac;
    uint32_t rtr_id;
    
    dp_vrf_t *default_vrf;

    /* Special interfaces */
    dp_intf_t *dp_rmac_intf;
    dp_intf_t *dp_vlan_flood_intf;
    dp_intf_t *dp_host_path_intf;
    dp_intf_t *dp_srv6_end_intf;
    dp_intf_t *dp_nve_intf;

} dp_ctx_t;

#pragma pack(pop)

void 
dp_ctx_init (dp_ctx_t **dp_ctx, void *arg, char *ctx_name);

#define DP_CTX(vrf_ptr)  dp_ctx_t *dp_ctx = (vrf_ptr)->dp_ctx

#endif 