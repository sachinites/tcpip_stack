#include "dpcp_cmn.h"

/* Libs */
#include "libs/pkt-block/pkt_mbuf.h"

/* Data plane header files */
#include <datapath/dp_ctx.h>

/* Control plane header files */
#include "router_init.h"

void 
dp_punt_pkt_to_cp(dp_ctx_t *dp_ctx, struct rte_mbuf *mbuf) {

    node_t *node = (node_t *)dp_ctx->ctx_pvt_data;

    pkt_q_enqueue(EV(node), 
                  &node->dp2cp_pkt_punt_q, 
                  (char *)mbuf, sizeof (struct rte_mbuf));
}