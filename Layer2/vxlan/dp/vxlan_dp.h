#ifndef __VXLAN_DP_H__
#define __VXLAN_DP_H__

#include <stdint.h>

typedef struct pkt_block_ pkt_block_t;
typedef struct dp_ctx_ dp_ctx_t;

#pragma pack (push,1)

typedef struct vxlan_hdr_ {
    uint8_t flags;
    uint8_t reserved[3];
    uint8_t vni[3];
    uint8_t reserved2;
} vxlan_hdr_t;

#pragma pack(pop)

void vxlan_encapsulate (dp_ctx_t *dp_ctx, pkt_block_t *pkt_block);
void vxlan_decapsulate (dp_ctx_t *dp_ctx, pkt_block_t *pkt_block, uint32_t src_vtep_ip);

#endif /* __VXLAN_DP_H__ */
