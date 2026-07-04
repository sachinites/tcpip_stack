#ifndef __GRE_FWD__
#define __GRE_FWD__

#include <stdint.h>

typedef struct dp_ctx_ dp_ctx_t;
typedef struct rte_mbuf pkt_mbuf_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_intf_ dp_intf_t;

uint16_t
gre_encasulate (struct rte_mbuf *mbuf, 
                cmn_prefix_t *src_ip, 
                cmn_prefix_t *dst_ip);

void 
gre_decapsulate (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, struct rte_mbuf *mbuf, dp_intf_t *gre_interface) ;

dp_intf_t *
gre_lookup_tunnel_intf(dp_ctx_t *dp_ctx, uint32_t src_ip, uint32_t dst_ip) ;

#endif