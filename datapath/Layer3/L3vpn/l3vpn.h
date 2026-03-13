#ifndef __L3VPN__
#define __L3VPN__

typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct fib_nh_ fib_nh_t;

void 
vpnv4_ingress_pe_encap_srv6 (dp_ctx_t *dp_ctx, 
                             dp_vrf_t *vrf, 
                             pkt_block_t *pkt_block, 
                             fib_nh_t *srv6_nh);


#endif 