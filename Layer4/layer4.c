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
#include "../libs/LinuxMemoryManager/uapi_mm.h"
#include "../libs/pkt-block/pkt_mbuf.h"
#include "../tcpconst.h"
#include "../libs/common/l4_hdrs.h"
#include "../libs/common/l3_hdrs.h"

extern void vxlan_decapsulate (dp_ctx_t *dp_ctx, struct rte_mbuf *mbuf, uint32_t src_vtep_ip);

class Interface;

/*Public APIs to be used by Lower layers of TCP/IP Stack to promote
 * the pkt to Layer 4. Starting hdr is ip hdr*/
void 
dp2cp_punt_pkt_to_layer4(  void *_node,
                           Interface *recv_intf,
                           struct rte_mbuf *mbuf,
                           int L4_protocol_number)
{

    pkt_size_t pkt_size;
    udp_hdr_t *udp_hdr;
    node_t *node = (node_t *)_node;

    switch (L4_protocol_number)
    {

        case IP_PROTO_UDP:
        {
            udp_hdr = (udp_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
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

