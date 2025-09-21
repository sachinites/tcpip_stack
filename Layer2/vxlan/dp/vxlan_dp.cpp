#include "vxlan_dp.h"
#include "../../../pkt_block.h"
#include "../../../graph.h"
#include "../../../common/l4_hdrs.h"
#include "../../../Tracer/tracer.h"
#include <netinet/in.h>  // for htonl

void
vxlan_encapsulate (node_t *node, pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;

    /* Vxlan is MAC/IP encapsulation inside VxLAN */
    assert (pkt_block_get_starting_hdr (pkt_block) == ETH_HDR);

    /* Expland the size of the pkt by VxLAN HDR size */
    pkt_block_expand_buffer_left (pkt_block, sizeof (vxlan_hdr_t) + sizeof (udp_hdr_t)); 
    pkt_block_set_starting_hdr_type (pkt_block, UDP_HDR);

    udp_hdr_t *udp_hdr = (udp_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);
    udp_hdr->src_port_no = 0;
    udp_hdr->dst_port_no = VXLAN_PROTO;
    udp_hdr->udp_length = sizeof (udp_hdr_t);
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

    tracer (node->dptr, DTUNNEL | DFLOW, 
        "VxLAN Encapsulation : VNI %u \n", pkt_block->encap_data->u.vxlan.vni);    
}
