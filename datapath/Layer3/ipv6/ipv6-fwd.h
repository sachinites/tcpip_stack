#ifndef __IPV6_ROUTE__
#define __IPV6_ROUTE__


typedef struct fib_nh_ fib_nh_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct rte_mbuf pkt_mbuf_t;
typedef struct dp_intf_ dp_intf_t;

void 
ipv6_layer3_forward_nexthop (dp_ctx_t *dp_ctx, 
                            dp_vrf_t *vrf, 
                            fib_nh_t *nexthop, 
                            struct rte_mbuf *mbuf);


#endif