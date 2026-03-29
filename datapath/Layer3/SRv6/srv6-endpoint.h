#ifndef __INET_SRv6ENDPOINT_H
#define __INET_SRv6ENDPOINT_H

#include "../../../libs/common/ipv6_hdrs.h"
#include "../../../Layer3/SegmentRouting/SRv6/common/srv6_const.h"

typedef struct ipv6_hdr_ ipv6_hdr_t;
typedef struct srh_hdr_ srh_hdr_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct fib_nh_ fib_nh_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_intf_ dp_intf_t;

void
Process_Srv6_Packet (   dp_ctx_t *dp_ctx,
                        dp_vrf_t *vrf,
                        dp_intf_t *recv_intf,
                        pkt_block_t *orig_pkt,
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh,
                        fib_nh_t *nexthop) ;

pkt_block_t *
Srv6_apply_flavor(dp_ctx_t *dp_ctx,
                  dp_vrf_t *dp_vrf,
                  pkt_block_t *orig_pkt,
                  uint8_t flavor);

void 
ipv6_process_v6_payload (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, pkt_block_t *pkt_block);

void 
Srv6_decapsulate (pkt_block_t *pkt_block);

void 
Srv6_encapsulate (pkt_block_t *pkt_block, srh_hdr_t *srh);

void 
Srv6_copy_current_sid_to_DA (srh_hdr_t *srh, ipv6_hdr_t *ipv6_hdr);

ipv6_addr_t 
srv6_srh_get_destination_segment (srh_hdr_t *srh);

srh_hdr_t *
srh_hdr_prepare (ipv6_addr_t *segment_lst, uint8_t n);

void Srv6_apply_penultimate_processing(dp_ctx_t *dp_ctx,
                                       dp_vrf_t *vrf,
                                       pkt_block_t *pkt_block,
                                       ipv6_hdr_t *ipv6_hdr,
                                       srh_hdr_t *srh);

void 
Srv6_apply_endpoint_fn (
        dp_ctx_t *dp_ctx,
        dp_vrf_t *vrf,
        dp_intf_t *recv_intf, 
        pkt_block_t *pkt_block, 
        ipv6_hdr_t *ipv6_hdr, 
        srh_hdr_t *srh, 
        fib_nh_t *nexthop);

#endif // __INET_SRv6ENDPOINT_H