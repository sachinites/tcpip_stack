#ifndef __LAYER3__
#define  __LAYER3__

#include <stdint.h>

typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct pkt_block_ pkt_block_t;

void
dp_promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,               /*Current node on which the pkt is received*/
                      dp_intf_t *interface,        /*ingress interface*/
                      pkt_block_t *pkt_block,      /*L3 payload*/
                      int L3_protocol_number) ;


void layer3_ip_route_pkt(dp_ctx_t *dp_ctx,
                         dp_vrf_t *vrf,
                         dp_intf_t *interface,
                         pkt_block_t *pkt_block);


void layer3_ipv6_route_pkt(dp_ctx_t *dp_ctx, 
                           dp_vrf_t *vrf,
                           dp_intf_t *interface,
                           pkt_block_t *pkt_block);

void
dp_send_ip_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, pkt_block_t *pkt_block);

void
dp_send_ip6_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, pkt_block_t *pkt_block);

#endif 
