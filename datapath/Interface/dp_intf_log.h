
#ifndef __DP_INTF_LOG__
#define __DP_INTF_LOG__

#include "../../tcpconst.h"

typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct pkt_block_ pkt_block_t;

void 
tcp_dump_recv_logger(dp_ctx_t * dp_ctx, 
              dp_intf_t *intf,
              pkt_block_t *pkt_block,
              hdr_type_t hdr_type);

void 
tcp_dump_send_logger(dp_ctx_t *dp_ctx, 
              dp_intf_t *intf,
              pkt_block_t *pkt_block,
              hdr_type_t hdr_type);

void
tcp_dump_l3_fwding_logger(
            dp_ctx_t *dp_ctx,
            dp_vrf_t *vrf,
            unsigned char* oif_name, 
            unsigned char *gw_ip);

#endif