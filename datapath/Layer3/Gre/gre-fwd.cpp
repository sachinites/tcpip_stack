#include <assert.h>
#include <arpa/inet.h>
#include "../../../libs/pkt-block/pkt_block.h"
#include "../../../libs/Tracer/tracer.h"
#include "../../dp_ctx.h"
#include "../../Interface/dp_intf.h"
#include "../../Vrfs/dp_vrf.h"
#include "../../dp_uapi.h"

extern void
layer3_ip_route_pkt(dp_ctx_t *dp_ctx,
                    dp_vrf_t *vrf,
					dp_intf_t *interface,
					pkt_block_t *pkt_block);

extern int
dp_submit_packet (dp_ctx_t *dp_ctx,
                  pkt_block_t *pkt_block,
                  dp_intf_t *interface);
                  
void 
gre_encasulate (dp_ctx_t *dp_ctx, pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    gen_proto_id_t hdr_type = pkt_block_get_starting_hdr(pkt_block);

    /* Expand the size of the pkt by GRE HDR size */
    pkt_block_expand_buffer_left (pkt_block, sizeof (gre_hdr_t) ); 
    gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    /* Fill GRE packet Hdr contents*/
    memset (gre_hdr, 0, sizeof (gre_hdr_t));
    gre_hdr->protocol_type = htons(hdr_type);
    pkt_block_update_new_hdr_type (pkt_block, IP_PROTO_GRE);        
    tracer (dp_ctx->dptr, DTUNNEL | DFLOW, 
        "GRE Encapsulation %s\n", pkt_block_str (pkt_block));    
}

void 
gre_decapsulate (dp_ctx_t *dp_ctx, 
                dp_vrf_t *vrf, 
                pkt_block_t *pkt_block, 
                dp_intf_t *gre_intf) {

    uint8_t *pkt;
    pkt_size_t pkt_size;

    assert (pkt_block_get_starting_hdr(pkt_block) == IP_PROTO_GRE);

    if (!gre_intf) {
         tracer (dp_ctx->dptr, DTUNNEL | DFLOW | DERR, 
            "VRF %s: Error : Pkt %s : Arrived on non-existant GRE Tunnel Interface\n", 
                vrf->vrf_name, pkt_block_str (pkt_block));
        return;
    }
    
    gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt_block_get_pkt(pkt_block, NULL);

    gre_intf->pkt_recv++;

    if (!gre_intf->is_tunnel_up || !gre_intf->is_up) {
        tracer (dp_ctx->dptr, DTUNNEL | DFLOW | DERR, 
            "VRF %s: Error : Pkt : %s : Dropped, GRE Tunnel %s is not Active/Up\n", 
                vrf->vrf_name, pkt_block_str (pkt_block), gre_intf->if_name);
        return;
    }

    pkt = pkt_block_get_pkt (pkt_block, &pkt_size);
    pkt_block_set_new_pkt (pkt_block, 
        (uint8_t *)(gre_hdr + 1), pkt_size - sizeof (gre_hdr_t));

    switch (ntohs(gre_hdr->protocol_type)) {

        case IP_PROTO_IP_IN_IP:
        {
            pkt_block_update_new_hdr_type (pkt_block, IP_PROTO_IP_IN_IP);
            tracer (dp_ctx->dptr, DTUNNEL | DFLOW, 
                "VRF %s: GRE Decapsulation %s\n", vrf->vrf_name, pkt_block_str (pkt_block));    
            layer3_ip_route_pkt (dp_ctx, vrf, gre_intf, pkt_block);
        }
        break;

        case ETH_TYPE_GRE:
        {
             pkt_block_update_new_hdr_type (pkt_block, ETHERNET_HEADER);
            tracer (dp_ctx->dptr, DTUNNEL | DFLOW, 
                "VRF %s: GRE Decapsulation %s\n", vrf->vrf_name, pkt_block_str (pkt_block));
             dp_submit_packet(dp_ctx, pkt_block, gre_intf);
        }
        break;
    }
}

dp_intf_t*
gre_lookup_tunnel_intf (dp_ctx_t *dp_ctx, uint32_t src_ip, uint32_t dst_ip) {

    return NULL;
}
