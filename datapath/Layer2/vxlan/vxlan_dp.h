#ifndef __VXLAN_DP_H__
#define __VXLAN_DP_H__

#include <stdint.h>

typedef struct rte_mbuf pkt_mbuf_t;
typedef struct dp_ctx_ dp_ctx_t;

void vxlan_encapsulate (dp_ctx_t *dp_ctx, struct rte_mbuf *mbuf);
void vxlan_decapsulate (dp_ctx_t *dp_ctx, struct rte_mbuf *mbuf, uint32_t src_vtep_ip);

#endif /* __VXLAN_DP_H__ */
