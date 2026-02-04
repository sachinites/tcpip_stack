#ifndef __INET_SRv6ENDPOINT_H
#define __INET_SRv6ENDPOINT_H

#include "../../../ipv6/ipv6_hdrs.h"
#include "../common/srv6_const.h"

class Interface;

typedef struct ipv6_hdr_ ipv6_hdr_t;
typedef struct srh_hdr_ srh_hdr_t;
typedef struct node_ node_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct ipv6_route_ ipv6_route_t;
typedef struct v6nexthop_ v6nexthop_t;
typedef struct fib_nh_ fib_nh_t;

void
Process_Srv6_Packet (
                        node_t *node, 
                        Interface* recv_intf,
                        pkt_block_t *orig_pkt,
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh,
                        fib_nh_t *nexthop) ;

pkt_block_t *
Srv6_apply_flavor (node_t *node, 
                                pkt_block_t *orig_pkt, 
                                uint8_t flavor);

void 
ipv6_process_v6_payload (node_t *node, pkt_block_t *pkt_block);

void 
Srv6_decapsulate (node_t *node, pkt_block_t *pkt_block);

void 
Srv6_encapsulate (pkt_block_t *pkt_block, srh_hdr_t *srh);

void 
Srv6_copy_current_sid_to_DA (srh_hdr_t *srh, ipv6_hdr_t *ipv6_hdr);

ipv6_addr_t 
srv6_srh_get_destination_segment (srh_hdr_t *srh);

srh_hdr_t *
srh_hdr_prepare (ipv6_addr_t *segment_lst, uint8_t n);

void 
Srv6_apply_penultimate_processing (node_t *node, 
                                                pkt_block_t *pkt_block, 
                                                ipv6_hdr_t *ipv6_hdr, 
                                                srh_hdr_t *srh) ;

void 
Srv6_apply_endpoint_fn (
        node_t *node, 
        Interface *recv_intf, 
        pkt_block_t *pkt_block, 
        ipv6_hdr_t *ipv6_hdr, 
        srh_hdr_t *srh, 
        fib_nh_t *nexthop);

#endif // __INET_SRv6ENDPOINT_H