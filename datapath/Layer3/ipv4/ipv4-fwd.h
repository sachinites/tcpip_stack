#ifndef __IPV4_FWD__
#define __IPV4_FWD__

#include <stdint.h>
#include <stdbool.h>

typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct pkt_block_ pkt_block_t;

void layer3_ip_route_pkt(dp_ctx_t *dp_ctx,
                         dp_vrf_t *vrf,
                         dp_intf_t *interface,
                         pkt_block_t *pkt_block);

void dp_send_ip_data(dp_ctx_t *dp_ctx,
                     dp_vrf_t *vrf,
                     pkt_block_t *pkt_block);

#endif /* __IPV4_FWD__ */
