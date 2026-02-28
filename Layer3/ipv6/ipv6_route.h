#ifndef __IPV6_ROUTE__
#define __IPV6_ROUTE__


typedef struct fib_nh_ fib_nh_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct dp_intf_ dp_intf_t;

void 
ipv6_layer3_forward_nexthop (dp_ctx_t *dp_ctx, 
                            dp_vrf_t *vrf, 
                            fib_nh_t *nexthop, 
                            pkt_block_t *pkt_block);

void layer3_ipv6_route_pkt(dp_ctx_t *dp_ctx,
                           dp_vrf_t *vrf,
                           dp_intf_t *interface,
                           pkt_block_t *pkt_block);

#endif