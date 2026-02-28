
#include "vxlan_dp.h"
#include "../../../common/l2_hdrs.h"
#include "../../../pkt_block.h"
#include "../../../router_init.h"
#include "../../../common/l4_hdrs.h"
#include "../../../Tracer/tracer.h"
#include <netinet/in.h>  // for htonl
#include "../../../Interface/InterfaceUApi.h"
#include "../../Layer2/l2fwd/ipv4-l2fwd.h"
#include "vlan_vni_ht.h"
#include "../../Interface/dp_intf.h"

extern void
l2_switch_perform_mac_learning (dp_ctx_t *dp_ctx,
                                uint16_t vlan_id, 
                                c_string src_mac, 
                                dp_intf_t *oif, uint32_t src_ip) ;
extern void
l2_switch_forward_frame(
                        dp_ctx_t *dp_ctx,
                        dp_intf_t *recv_intf, 
                        pkt_block_t *pkt_block);

void
vxlan_encapsulate (dp_ctx_t *dp_ctx, pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;

    /* Vxlan is MAC/IP encapsulation inside VxLAN */
    assert (pkt_block_get_starting_hdr (pkt_block) == ETH_HDR);

    /* Expland the size of the pkt by VxLAN HDR size */
    pkt_block_expand_buffer_left (pkt_block, sizeof (vxlan_hdr_t) + sizeof (udp_hdr_t)); 
    pkt_block_set_starting_hdr_type (pkt_block, UDP_HDR);

    udp_hdr_t *udp_hdr = (udp_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);
    udp_hdr->src_port_no = 0;
    udp_hdr->dst_port_no = htons(VXLAN_PROTO);
    udp_hdr->udp_length = htons(sizeof (udp_hdr_t));
    udp_hdr->udp_checksum = 0;

    vxlan_hdr_t *vxlan_hdr = (vxlan_hdr_t *)(udp_hdr + 1);
    
    /* Fill VxLAN packet Hdr contents*/
    memset (vxlan_hdr, 0, sizeof (vxlan_hdr_t));
    vxlan_hdr->flags = 0;
    vxlan_hdr->reserved[0] = 0;
    vxlan_hdr->reserved[1] = 0;
    vxlan_hdr->reserved[2] = 0;
    
    /* Convert VNI to network byte order for VXLAN header */
    uint32_t temp_vni = htonl(pkt_block->encap_data->u.vxlan.vni);
    vxlan_hdr->vni[0] = (temp_vni >> 24) & 0xFF;  /* MSB */
    vxlan_hdr->vni[1] = (temp_vni >> 16) & 0xFF;  /* Middle byte */
    vxlan_hdr->vni[2] = (temp_vni >> 8) & 0xFF;   /* LSB */
    vxlan_hdr->reserved2 = 0;

    tracer (dp_ctx->dptr, DTUNNEL | DFLOW, 
        "VxLAN Encapsulation : VNI %u \n", pkt_block->encap_data->u.vxlan.vni);    
}

void vxlan_decapsulate (dp_ctx_t *dp_ctx, pkt_block_t *pkt_block, uint32_t src_vtep_ip) 
{
    pkt_size_t pkt_size;

    if (dp_ctx->dp_nve_intf == NULL) {

        tracer (dp_ctx->dptr, DTUNNEL | DFLOW | DERR,
              "VxLAN Decapsulation : Error : NVE Interface not found, Vxlan pkt dropped\n");
        return;
    }

     assert ( pkt_block_get_starting_hdr(pkt_block) == UDP_HDR );

     udp_hdr_t *udp_hdr = (udp_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

     assert (htons(udp_hdr->dst_port_no) == VXLAN_PROTO);

     vxlan_hdr_t *vxlan_hdr = (vxlan_hdr_t *)(udp_hdr + 1);

     uint32_t vni = 0;
     uint8_t *vni_ptr = (uint8_t *)&vni;
     vni_ptr[3] = vxlan_hdr->vni[0];
     vni_ptr[2] = vxlan_hdr->vni[1];
     vni_ptr[1] = vxlan_hdr->vni[2];

     vni = htonl (vni);

     tracer (dp_ctx->dptr, DTUNNEL | DFLOW, 
        "VxLAN Decapsulation : VNI %u \n", vni);

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)(vxlan_hdr + 1); 
    pkt_size -= (pkt_size_t)((char *)eth_hdr - (char *)udp_hdr);

    pkt_block_set_new_pkt (pkt_block, (uint8_t *) eth_hdr, pkt_size);
    pkt_block_set_starting_hdr_type (pkt_block, ETH_HDR);

    uint16_t vlan_id = vlan_vni_ht_vni_to_vlan_lookup (dp_ctx, vni);

    if (!vlan_id) {

        tracer (dp_ctx->dptr, DTUNNEL | DFLOW | DERR,
              "VxLAN Decapsulation : Error : VNI %u not found in vlan_vni_ht, Vxlan pkt dropped\n", vni);
              dp_ctx->dp_nve_intf->recvd_pkt_dropped++;

        return;
    }

    tag_pkt_with_vlan_id  (pkt_block, vlan_id);

    l2_switch_perform_mac_learning (dp_ctx, vlan_id,
                            eth_hdr->src_mac.mac,
                            dp_ctx->dp_nve_intf,
                            src_vtep_ip) ;

    tracer (dp_ctx->dptr, DTUNNEL | DFLOW, 
        "VxLAN Decapsulation : Forwarding pkt to L2 Switching\n");
        
    l2_switch_forward_frame (dp_ctx, dp_ctx->dp_nve_intf,  pkt_block);
    dp_ctx->dp_nve_intf->pkt_recv++;
}
