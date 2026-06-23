#ifndef __DPCP_COMN__
#define __DPCP_COMN__

typedef struct dp_ctx_ dp_ctx_t;
struct rte_mbuf;

void 
dp_punt_pkt_to_cp(dp_ctx_t *dp_ctx, struct rte_mbuf *mbuf);

#endif 