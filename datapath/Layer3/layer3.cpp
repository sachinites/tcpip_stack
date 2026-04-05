#include <assert.h>

#include "layer3.h"
#include "../../tcpconst.h"
#include "../../libs/pkt-block/pkt_block.h"

#include "../../libs/common/l2_hdrs.h"
#include "../../libs/Tracer/tracer.h"

#include "../dp_ctx.h"
#include "ipv4/ipv4-fwd.h"
#include "../Vrfs/dp_vrf.h"

extern void
layer3_ipv6_route_pkt(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      dp_intf_t *interface,
                      pkt_block_t *pkt_block,
                      fib_nh_t *nh);

static void
_layer3_pkt_recv_from_layer2(dp_ctx_t *dp_ctx,
                             dp_vrf_t *vrf,
                             dp_intf_t *interface,
                             pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    char ip_addr_str[IPV4_ADDR_LEN_STR];
    gen_proto_id_t hdr_type = pkt_block_get_starting_hdr (pkt_block);

    switch(hdr_type){
        
        case IP_PROTO_IP_IN_IP:

            tracer (dp_ctx->dptr, DL3FWD, 
                "VRF:%s: Dest : %s :  Pkt Arrived in L3-land from Layer 2\n",
	            vrf->vrf_name,
                pkt_ip(pkt_block, ip_addr_str));

            layer3_ip_route_pkt(dp_ctx, vrf, interface, pkt_block);
            break;


        case IP_PROTO_IPv6:

            tracer (dp_ctx->dptr, DL3FWD, 
                "VRF:%s: Dest : %s :  V6Pkt Arrived in L3-land from Layer 2\n",
	            vrf->vrf_name, pkt_block_str(pkt_block));
            layer3_ipv6_route_pkt(dp_ctx, vrf, interface, pkt_block, NULL);            
            break;

        default:
            assert(0);
    }
}


/* A public API to be used by L2 or other lower Layers to promote
 * pkts to Layer 3 in TCP IP Stack*/
void dp_promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                              dp_vrf_t *vrf,        /*Current node on which the pkt is received*/
                              dp_intf_t *interface, /*ingress interface*/
                              pkt_block_t *pkt_block)
{ 

    _layer3_pkt_recv_from_layer2(dp_ctx, vrf, interface, pkt_block);
}
