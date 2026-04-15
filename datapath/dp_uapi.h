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

typedef struct dp_ctx_ dp_ctx_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct dp_msg_ dp_msg_t;
typedef struct event_dispatcher_ event_dispatcher_t;

#include "../libs/notifc/notif.h"

#include <stdint.h>

/* APIs available to Control plane */
void
dp_uapi_ctx_init(dp_ctx_t **dp_ctx, void *arg, char *ctx_name);

/** Inject a packet into the datapath on the given interface (e.g. from CP). */
int
dp_uapi_inject_packet(dp_ctx_t *dp_ctx,
                      pkt_block_t *pkt_block,
                      uint32_t ifindex);

/* The Control plane use this API to send the pkt out of interface*/
void 
dp_uapi_xmit_pkt(dp_ctx_t *dp_ctx, 
                 uint32_t ifindex, 
                 pkt_block_t *pkt_block);

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



#endif /* __DP_UAPI__ */
