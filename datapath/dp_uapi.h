#ifndef __DP_UAPI__
#define __DP_UAPI__

typedef struct dp_ctx_ dp_ctx_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct dp_intf_ dp_intf_t;

#include <stdint.h>

/* Interfaces recv and send pkts using this wrapper
    structure */
typedef struct ev_dis_pkt_data_{

    unsigned char *pkt;
    uint32_t ifindex;
    uint32_t pkt_size;

}ev_dis_pkt_data_t;

void 
dp_ctx_init (dp_ctx_t **dp_ctx, void *arg, char *ctx_name);

extern int
dp_inject_packet (dp_ctx_t *dp_ctx,
                  pkt_block_t *pkt_block,
                  dp_intf_t *interface);


#define EV_DP(dp_ctx_ptr)    (&dp_ctx_ptr->dp_ev_dis)
#define DP_PKT_Q(dp_ctx_ptr) (&dp_ctx_ptr->dp_recvr_pkt_q)
#define DP_TIMER(dp_ctx_ptr)  (dp_ctx_ptr->dp_wt)
#define EV_DP_PURGER(dp_ctx_ptr) (&dp_ctx_ptr->dp_purger_ev_dis)

void 
dp_send_pkt_out (dp_ctx_t *dp_ctx, dp_intf_t *intf, pkt_block_t *pkt_block);

dp_intf_t *
dp_uapi_look_up_interface (dp_ctx_t *dp_ctx, uint32_t port_id);


#endif 