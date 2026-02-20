#ifndef __DP_CTX__
#define __DP_CTX__

typedef struct _wheel_timer_t wheel_timer_t;
typedef struct tracer_ tracer_t;
typedef  struct hashtable hashtable_t;
typedef struct arp_table_ arp_table_t;
typedef struct mac_table_ mac_table_t;

#include "../EventDispatcher/event_dispatcher.h"

#pragma pack(push, 8)

typedef struct dp_ctx_ {

    /* Data path scheduler */
    event_dispatcher_t dp_ev_dis;
    
    /* Data Path ingress Pkt Queue */
    pkt_q_t dp_recvr_pkt_q;    

    /* Objects Purger */
    event_dispatcher_t purger_ev_dis;    
    
    /* CptoDp Interface Xmit Global Queue*/
    pkt_q_t cp_to_dp_xmit_intf_pkt_q;

    /*IPC in a data plane */
    pkt_q_t dp_ipc_q;
    
    /* Data Path Timer */
    wheel_timer_t *dp_wt;    

    /* Data-Path Tracer*/
    tracer_t *dptr;

    /* ARP table */
    arp_table_t *arp_table;

    /* Mac Table*/
    mac_table_t *mac_table;  

    /* DP hash table storage of interfacs*/
    hashtable_t *dp_intf_ht;

    /* DP hash table storage of VRFs*/
    hashtable_t *dp_vrf_ht;    

    /* Vlan-VNI mapping DP hash table*/
    std::atomic<vlan_vni_ht_db_t *> vlan_vni_ht; 

} dp_ctx_t;

#pragma pack(pop)

void 
dp_ctx_init (dp_ctx_t *dp_ctx, void *arg, char *ctx_name);

#endif 