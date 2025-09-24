#include <stdio.h>
#include <arpa/inet.h>
#include "udp.h"
#include "../tcpconst.h"
#include "../Layer2/vxlan/dp/vxlan_dp.h"
#include "../Layer2/layer2.h"
#include "../tcp_ip_trace.h"

uint16_t 
tcp_dump_transport_udp_protocol (
                          char *out_buff , 
                          udp_hdr_t *udp_hdr, 
                          uint16_t udp_hr_size) {

    uint16_t rc = 0;
    rc += sprintf (out_buff + rc, "UDP Hdr : Sport : %d   Dort : %d\n", 
                            udp_hdr->src_port_no, udp_hdr->dst_port_no);

    switch (udp_hdr->dst_port_no) {

        case VXLAN_PROTO:
            {
                // Extract VNI from VXLAN header that follows UDP header
                vxlan_hdr_t *vxlan_hdr = (vxlan_hdr_t *)(udp_hdr + 1);
                
                // Convert VNI from network byte order (3 bytes in VXLAN header)
                uint32_t vni = 0;
                uint8_t *vni_ptr = (uint8_t *)&vni;
                vni_ptr[3] = vxlan_hdr->vni[0];
                vni_ptr[2] = vxlan_hdr->vni[1]; 
                vni_ptr[1] = vxlan_hdr->vni[2];
                vni = ntohl(vni);
                
                rc += sprintf (out_buff + rc, "VXLAN Encap : vni %u\n", vni);
                
                // Call existing function to dump inner Ethernet header and all nested headers
                ethernet_hdr_t *inner_eth = (ethernet_hdr_t *)(vxlan_hdr + 1);
                pkt_size_t inner_pkt_size = udp_hr_size - sizeof(udp_hdr_t) - sizeof(vxlan_hdr_t);
                rc += tcp_dump_ethernet_hdr(out_buff + rc, inner_eth, inner_pkt_size);
            }
            break;

        default:
            ;
    }
    return rc;
}