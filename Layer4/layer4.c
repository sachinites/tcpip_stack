/*
 * =====================================================================================
 *
 *       Filename:  layer4.c
 *
 *    Description:  This file implemets the routines for Transport Layer
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

#include "graph.h"

/*Public APIs to be used by Lower layers of TCP/IP Stack to promote
 * the pkt to Layer 4*/
void
promote_pkt_to_layer4(node_t *node, interface_t *recv_intf,
                      char *l4_hdr, unsigned int pkt_size,
                      int L4_protocol_number){ /*= TCP/UDP or what */


}

/* Public APIs to be used by Higher/Application layers of TCP/IP Stack to demote
* the pkt to Layer 4*/
void
demote_pkt_to_layer4(node_t *node,
        char *pkt, unsigned int pkt_size,
        int L4_protocol_number){  /*L5 (The application) need to tell L4-layer which transport layer protcocol to be used - UDP or TCP or other*/

}
