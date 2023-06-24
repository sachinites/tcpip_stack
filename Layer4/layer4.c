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
#include "../graph.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../pkt_block.h"
#include "../tcpconst.h"

extern void layer4_mem_init() ;
class Interface;

/*Public APIs to be used by Lower layers of TCP/IP Stack to promote
 * the pkt to Layer 4*/
void
promote_pkt_to_layer4(node_t *node,
                      Interface *recv_intf,
                      pkt_block_t *pkt_block,
                      int L4_protocol_number){ /*= TCP/UDP or what */

        //cprintf ("%s() : Protocol %d. Pkt Consumed\n", __FUNCTION__, L4_protocol_number);
        pkt_block_dereference(pkt_block);
}

/* Public APIs to be used by Higher/Application layers of TCP/IP Stack to demote
* the pkt to Layer 4*/
void
demote_pkt_to_layer4(node_t *node,
        char *pkt, uint32_t pkt_size,
        int L4_protocol_number){  /*L5 (The application) need to tell L4-layer which transport layer protcol to be used - UDP or TCP or other*/

}

void layer4_mem_init() { }
