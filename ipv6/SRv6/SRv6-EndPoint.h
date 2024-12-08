#ifndef __INET_SRv6ENDPOINT_H
#define __INET_SRv6ENDPOINT_H

class Interface;

typedef struct ipv6_hdr_ ipv6_hdr_t;
typedef struct srh_hdr_ srh_hdr_t;
typedef struct node_ node_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct ipv6_route_ ipv6_route_t;

typedef enum Srv6_flavor_ {

    PSP = 1,
    PSD = 2,
    USD = 3

} Srv6_flavor_t;

typedef enum Vrv6_endpcode_ {
    
    END = 1,
    END_X = 2

} Srv6_endpcode_t;

void
Process_END(node_t *node, 
                        pkt_block_t *orig_pkt,
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh,
                        ipv6_route_t *route) ;

void
Process_END_X (node_t *node, 
                        Interface* recv_intf,
                        pkt_block_t *orig_pkt,
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh,
                        ipv6_route_t *route) ;

void
Process_Srv6_Packet (
                        node_t *node, 
                        Interface* recv_intf,
                        pkt_block_t *orig_pkt,
                        ipv6_hdr_t *ipv6_hdr, 
                        srh_hdr_t *srh);

/* Fn to check if self_sid is penultimate of next_sid*/
bool 
Am_I_penultimate (node_t *node, ipv6_addr_t self_sid, ipv6_addr_t next_sid);

ipv6_addr_t 
Srv6_self_locator (node_t *node);

pkt_block_t *
Srv6_apply_flavor (node_t *node, pkt_block_t *orig_pkt, Srv6_flavor_t flavor, uint8_t segments_left);

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
        Srv6_endpcode_t endfn,
        ipv6_route_t *route);

#endif // __INET_SRv6ENDPOINT_H