/*
 * =============================================================================
 * File: dp_intf_log.h
 * Description: Datapath interface packet logging (recv/send/L3 forward).
 * =============================================================================
 *
 * Design:
 *   - tcp_dump_recv_logger: log packet received on an interface.
 *   - tcp_dump_send_logger: log packet sent on an interface.
 *   - tcp_dump_l3_fwding_logger: log L3 forwarding decision (oif, gw).
 *   Used when DP packet logging is enabled for debugging.
 * =============================================================================
 */

#ifndef __DP_INTF_LOG__
#define __DP_INTF_LOG__

#include "../../tcpconst.h"

typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct pkt_block_ pkt_block_t;

void 
tcp_dump_recv_logger(dp_ctx_t * dp_ctx, 
              dp_intf_t *intf,
              pkt_block_t *pkt_block,
              gen_proto_id_t hdr_type);

void 
tcp_dump_send_logger(dp_ctx_t *dp_ctx, 
              dp_intf_t *intf,
              pkt_block_t *pkt_block,
              gen_proto_id_t hdr_type);

void
tcp_dump_l3_fwding_logger(
            dp_ctx_t *dp_ctx,
            dp_vrf_t *vrf,
            unsigned char* oif_name, 
            unsigned char *gw_ip);

#endif /* __DP_INTF_LOG__ */
