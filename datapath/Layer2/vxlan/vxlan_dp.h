#ifndef __VXLAN_DP_H__
#define __VXLAN_DP_H__

#include <stdint.h>

typedef struct pkt_block_ pkt_block_t;
typedef struct dp_ctx_ dp_ctx_t;

void vxlan_encapsulate (dp_ctx_t *dp_ctx, pkt_block_t *pkt_block);
void vxlan_decapsulate (dp_ctx_t *dp_ctx, pkt_block_t *pkt_block, uint32_t src_vtep_ip);

#endif /* __VXLAN_DP_H__ */
