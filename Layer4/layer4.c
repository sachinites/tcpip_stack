/*
 * =====================================================================================
 *
 *       Filename:  layer4.c
 *
 *    Description:  This file implements the routines for Transport Layer
 *
 *        Version:  1.0
 *        Created:  Thursday 26 September 2019 06:52:37  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *        
 *        This file is part of the NetworkGraph distribution (https://github.com/sachinites).
 *        Copyright (c) 2017 Abhishek Sagar.
 *        This program is free software: you can redistribute it and/or modify
 *        it under the terms of the GNU General Public License as published by  
 *        the Free Software Foundation, version 3.
 *
 *        This program is distributed in the hope that it will be useful, but 
 *        WITHOUT ANY WARRANTY; without even the implied warranty of 
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *        General Public License for more details.
 *
 *        You should have received a copy of the GNU General Public License 
 *        along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * =====================================================================================
 */

#include <stdint.h>
#include "../router_init.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../pkt_block.h"
#include "../tcpconst.h"
#include "../common/l4_hdrs.h"
#include "../common/l3_hdrs.h"

extern void layer4_mem_init() ;
extern void vxlan_decapsulate (node_t *node, pkt_block_t *pkt_block, uint32_t src_vtep_ip);

class Interface;

/*Public APIs to be used by Lower layers of TCP/IP Stack to promote
 * the pkt to Layer 4. Starting hdr is ip hdr*/
void
promote_pkt_to_layer4 (node_t *node,
                                        Interface *recv_intf,
                                        pkt_block_t *pkt_block,
                                        int L4_protocol_number) {                      /*= TCP/UDP or what */
        
    switch (L4_protocol_number) {

        case UDP_PROTO:
        {
           pkt_size_t pkt_size;
           ip_hdr_t *ip_hdr = (ip_hdr_t *) pkt_block_get_pkt(pkt_block, &pkt_size);
           udp_hdr_t *udp_hdr =  (udp_hdr_t *)INCREMENT_IPHDR(ip_hdr);

           if (udp_hdr->dst_port_no == VXLAN_PROTO) {

                pkt_size -= (pkt_size_t )((char *)udp_hdr  - (char *)ip_hdr);
                pkt_block_set_new_pkt (pkt_block, (uint8_t *)udp_hdr, pkt_size);
                pkt_block_set_starting_hdr_type (pkt_block , UDP_HDR);
                vxlan_decapsulate (node, pkt_block, htonl(ip_hdr->src_ip));
           }
        }
        break;

        default:
            break;
    }
}

/* Public APIs to be used by Higher/Application layers of TCP/IP Stack to demote
* the pkt to Layer 4*/
void
demote_pkt_to_layer4(node_t *node,
        char *pkt, uint32_t pkt_size,
        int L4_protocol_number) {  /*L5 (The application) need to tell L4-layer which transport layer protcol to be used - UDP or TCP or other*/

}

void layer4_mem_init() { }
