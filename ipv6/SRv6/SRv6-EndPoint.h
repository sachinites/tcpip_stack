#ifndef __INET_SRv6ENDPOINT_H
#define __INET_SRv6ENDPOINT_H

#include "../ipv6_hdrs.h"

class Interface;

typedef struct ipv6_hdr_ ipv6_hdr_t;
typedef struct srh_hdr_ srh_hdr_t;
typedef struct node_ node_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct ipv6_route_ ipv6_route_t;
typedef struct v6nexthop_ v6nexthop_t;

typedef enum Srv6_flavor_ {

    PSP = 1,
    PSD = 2,
    USD = 4

} Srv6_flavor_t;

#define DEFAULT_FLAVOR (PSP | USD)

typedef enum Srv6_endpcode_ {
    
    END = 0,
    END_X = 1,
    END_T = 2,
    END_DX6 = 3,
    END_DX4 = 4,
    END_DT6 = 5,
    END_DT4 = 6

} Srv6_endpcode_t;

void
Process_END(node_t *node, 
                        pkt_block_t *orig_pkt,
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh,
                        v6nexthop_t *nexthop) ;

void
Process_END_X (node_t *node, 
                        Interface* recv_intf,
                        pkt_block_t *orig_pkt,
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh,
                        v6nexthop_t *nexthop) ;

void
Process_Srv6_Packet (
                        node_t *node, 
                        Interface* recv_intf,
                        pkt_block_t *orig_pkt,
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh,
                        v6nexthop_t *nexthop) ;

pkt_block_t *
Srv6_apply_flavor (node_t *node, 
                                pkt_block_t *orig_pkt, 
                                uint8_t flavor, uint8_t segments_left);

void 
SRv6_process_payload (node_t *node, pkt_block_t *pkt_block);

void 
Srv6_decapsulate (node_t *node, pkt_block_t *pkt_block);

void 
Srv6_copy_current_sid_to_DA (srh_hdr_t *srh, ipv6_hdr_t *ipv6_hdr);

ipv6_addr_t 
srv6_srh_get_destination_segment (srh_hdr_t *srh);

void 
Srv6_apply_endpoint_fn (
        node_t *node, 
        Interface *recv_intf, 
        pkt_block_t *pkt_block, 
        ipv6_hdr_t *ipv6_hdr, 
        srh_hdr_t *srh, 
        v6nexthop_t *nexthop);

const char *
end_fn_str(Srv6_endpcode_t end_fn);

const char *
flavor_str(uint8_t flavors);

#endif // __INET_SRv6ENDPOINT_H