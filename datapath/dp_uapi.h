/*
 * =============================================================================
 * File: dp_uapi.h
 * Description: Datapath user/API layer - context init, packet inject, send, lookup.
 * =============================================================================
 *
 * Design:
 *   - Public API for initializing the DP context and for sending/injecting
 *     packets through the datapath.
 *   - ev_dis_pkt_data_t: wrapper passed with packets to the event dispatcher
 *     (packet buffer, ifindex, size).
 *   - Macros EV_DP, DP_PKT_Q, DP_TIMER, EV_DP_PURGER provide quick access
 *     to dispatcher and timer from dp_ctx.
 * =============================================================================
 */

#ifndef __DP_UAPI__
#define __DP_UAPI__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dp_ctx_ dp_ctx_t;
typedef struct rte_mbuf pkt_mbuf_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct dp_msg_ dp_msg_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct event_dispatcher_ event_dispatcher_t;
typedef struct pkt_q_ pkt_q_t;
struct rte_mempool;

/*
 * Assert that the calling thread is the dp_ev_dis management thread.
 * Use this in all write-path functions that must be dp_ev_dis-only.
 */
#include <pthread.h>
#include <assert.h>
#define ASSERT_ON_DP_EV_DIS(dp_ctx) \
    assert((dp_ctx)->dp_ev_dis.thread && \
           pthread_equal(pthread_self(), *(dp_ctx)->dp_ev_dis.thread))

#include "../libs/notifc/notif.h"

#include <stdint.h>

/* APIs available to Control plane */
void
dp_uapi_ctx_init(dp_ctx_t **dp_ctx, void *arg, char *ctx_name);

/** Inject a packet into the datapath on the given interface (e.g. from CP). */
int
dp_uapi_inject_packet(dp_ctx_t *dp_ctx,
                      struct rte_mbuf *mbuf,
                      uint32_t ifindex);

/* The Control plane use this API to send the pkt out of interface*/
void 
dp_uapi_xmit_pkt(dp_ctx_t *dp_ctx, 
                 uint32_t ifindex, 
                 struct rte_mbuf *mbuf);

void 
dp_uapi_link_connect (dp_ctx_t *dp_ctx1, uint32_t ifindex1, 
                      dp_ctx_t *dp_ctx2, uint32_t ifindex2);

void
dp_uapi_submit_dp_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg, bool async);

void
dp_uapi_trace_dp_msg ( dp_ctx_t *dp_ctx, dp_msg_t *dp_msg);

void dp_register_l2_pkt_trap_rule(dp_ctx_t *dp_ctx,
                                  nfc_pkt_trap pkt_trap_cb,
                                  nfc_app_cb app_cb);

void dp_de_register_l2_pkt_trap_rule(
                dp_ctx_t *dp_ctx,
                nfc_pkt_trap pkt_trap_cb,
                nfc_app_cb app_cb);

event_dispatcher_t *
dp_uapi_get_dp_scheduler (dp_ctx_t *dp_ctx);

void
Linux_listen_interfaces (dp_ctx_t *dp_ctx);

void
DPDK_ConfigureInterfaces(dp_ctx_t *dp_ctx);

void 
DPDK_PollInterfaces (dp_ctx_t *dp_ctx);

void
DPDK_PollInterfaces_load_balancing (dp_ctx_t *dp_ctx);

struct rte_mempool *
dp_uapi_get_current_socket_mpool(dp_ctx_t *dp_ctx);

void 
dp_pkt_entry_point(dp_ctx_t *dp_ctx, 
                    dp_vrf_t *vrf,
                    dp_intf_t *interface,
                    struct rte_mbuf *mbuf);

/* -------------------------------------------------------------------------
 * Async job posting helpers — safe to call from any thread (DPDK workers).
 * The actual table mutations run on dp_ev_dis.
 * ---------------------------------------------------------------------- */

/*
 * Post a MAC learning job to dp_ev_dis.
 * Caller must NOT hold the mbuf reference for this (MAC learning doesn't
 * queue packets; it only installs the forwarding entry).
 */
void dp_post_mac_learn_job(dp_ctx_t *dp_ctx,
                           uint8_t *mac_addr,
                           uint16_t vlan_id,
                           uint32_t oif_ifindex,
                           uint32_t src_ip);
void
dp_post_bd_mac_learn_job(dp_ctx_t *dp_ctx,
                      uint32_t bd_ifindex,
                      uint8_t *mac_addr,
                      uint32_t oif_ifindex);
                      
/*
 * Post an ARP resolution job to dp_ev_dis.
 * mbuf MUST already be ref-incremented by the caller (pkt_mbuf_ref_inc).
 * dp_ev_dis handler will create/update a sane entry + send ARP request.
 */
void dp_post_arp_resolve_job(dp_ctx_t *dp_ctx,
                             dp_vrf_t *vrf,
                             uint32_t oif_ifindex,
                             uint32_t target_ip,
                             struct rte_mbuf *mbuf);

/*
 * Post an ARP table update job (from received ARP reply/request) to dp_ev_dis.
 * No mbuf needed — the ARP packet has already been parsed.
 */
void dp_post_arp_update_from_pkt_job(dp_ctx_t *dp_ctx,
                                     dp_vrf_t *vrf,
                                     uint32_t iif_ifindex,
                                     uint32_t sender_ip,
                                     uint8_t *sender_mac);

/*
 * CLI/management helpers — synchronous, block until dp_ev_dis executes them.
 * Safe to call from any thread (CP, CLI, etc.).
 */

/* Show the MAC table on dp_ev_dis and return.  vlan_id=0 shows all VLANs. */
void dp_show_mac_table_sync(dp_ctx_t *dp_ctx, uint16_t vlan_id);

/* Show the ARP table for the given arp_table_t on dp_ev_dis and return. */
void dp_show_arp_table_sync(dp_ctx_t *dp_ctx, void *arp_table);

/* Send an ARP broadcast request for ip_addr (CLI-originated resolve).
 * Runs on dp_ev_dis (sync).  vrf=NULL uses the default VRF. */
void dp_arp_cli_resolve_sync(dp_ctx_t *dp_ctx, dp_vrf_t *vrf,
                             uint32_t ip_addr);



#ifdef __cplusplus
}
#endif

#endif /* __DP_UAPI__ */
