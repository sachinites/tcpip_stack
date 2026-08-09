#ifndef __L3VPN__
#define __L3VPN__

typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct rte_mbuf pkt_mbuf_t;
typedef struct fib_nh_ fib_nh_t;

void 
vpnv4_ingress_pe_encap_srv6 (dp_ctx_t *dp_ctx, 
                             dp_vrf_t *vrf, 
                             struct rte_mbuf *mbuf, 
                             fib_nh_t *srv6_nh);

int
vpnv4_ingress_pe_encap_mpls (dp_ctx_t *dp_ctx, 
                             dp_vrf_t *vrf, 
                             struct rte_mbuf *mbuf, 
                             fib_nh_t *sr_nh);

#endif 