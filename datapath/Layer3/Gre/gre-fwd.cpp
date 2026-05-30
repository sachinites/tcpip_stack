#include <assert.h>
#include <arpa/inet.h>
#include "../../../libs/pkt-block/pkt_mbuf.h"
#include "../../../libs/Tracer/tracer.h"
#include "../../dp_ctx.h"
#include "../../Interface/dp_intf.h"
#include "../../Vrfs/dp_vrf.h"
#include "../../dp_uapi.h"

extern void
layer3_ip_route_pkt(dp_ctx_t *dp_ctx,
                    dp_vrf_t *vrf,
					dp_intf_t *interface,
					struct rte_mbuf *mbuf);
                  
void 
gre_encasulate (dp_ctx_t *dp_ctx, struct rte_mbuf *mbuf) {

    pkt_size_t pkt_size;
    gen_proto_id_t hdr_type = pkt_mbuf_get_starting_hdr(mbuf);

    /* Expand the size of the pkt by GRE HDR size */
    pkt_mbuf_expand_buffer_left (mbuf, sizeof (gre_hdr_t) ); 
    gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    /* Fill GRE packet Hdr contents*/
    memset (gre_hdr, 0, sizeof (gre_hdr_t));
    gre_hdr->protocol_type = htons(hdr_type);
    pkt_mbuf_update_new_hdr_type (mbuf, IP_PROTO_GRE);        
    tracer (dp_ctx->dptr, DTUNNEL | DFLOW, 
        "GRE Encapsulation %s\n", pkt_mbuf_str (mbuf));    
}

void 
gre_decapsulate (dp_ctx_t *dp_ctx, 
                dp_vrf_t *vrf, 
                struct rte_mbuf *mbuf, 
                dp_intf_t *gre_intf) {

    uint8_t *pkt;
    pkt_size_t pkt_size;

    assert (pkt_mbuf_get_starting_hdr(mbuf) == IP_PROTO_GRE);

    if (!gre_intf) {
         tracer (dp_ctx->dptr, DTUNNEL | DFLOW | DERR, 
            "VRF %s: Error : Pkt %s : Arrived on non-existant GRE Tunnel Interface\n", 
                vrf->vrf_name, pkt_mbuf_str (mbuf));
        return;
    }
    
    gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt_mbuf_get_pkt(mbuf, NULL);

    gre_intf->pkt_recv++;

    if (!gre_intf->is_tunnel_up || !gre_intf->is_up) {
        tracer (dp_ctx->dptr, DTUNNEL | DFLOW | DERR, 
            "VRF %s: Error : Pkt : %s : Dropped, GRE Tunnel %s is not Active/Up\n", 
                vrf->vrf_name, pkt_mbuf_str (mbuf), gre_intf->if_name);
        return;
    }

    pkt = pkt_mbuf_get_pkt (mbuf, &pkt_size);
    /* Strip the GRE header: shrink head by sizeof(gre_hdr_t). */
    pkt_mbuf_slide(mbuf, -1, 1, (uint16_t)sizeof(gre_hdr_t));

    switch (ntohs(gre_hdr->protocol_type)) {

        case IP_PROTO_IP_IN_IP:
        {
            pkt_mbuf_update_new_hdr_type (mbuf, IP_PROTO_IP_IN_IP);
            tracer (dp_ctx->dptr, DTUNNEL | DFLOW, 
                "VRF %s: GRE Decapsulation %s\n", vrf->vrf_name, pkt_mbuf_str (mbuf));    
            layer3_ip_route_pkt (dp_ctx, vrf, gre_intf, mbuf);
        }
        break;

        case ETH_TYPE_GRE:
        {
             pkt_mbuf_update_new_hdr_type (mbuf, ETHERNET_HEADER);
            tracer (dp_ctx->dptr, DTUNNEL | DFLOW, 
                "VRF %s: GRE Decapsulation %s\n", vrf->vrf_name, pkt_mbuf_str (mbuf));
             dp_pkt_entry_point(dp_ctx, gre_intf->vrf, gre_intf, mbuf);
        }
        break;
    }
}

dp_intf_t*
gre_lookup_tunnel_intf (dp_ctx_t *dp_ctx, uint32_t src_ip, uint32_t dst_ip) {

    return NULL;
}
