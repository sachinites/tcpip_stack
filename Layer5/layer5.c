/*
 * =====================================================================================
 *
 *       Filename:  Layer5.c
 *
 *    Description:  This file represents the application making use of our virtual TCP/IP stack
 *
 *        Version:  1.0
 *        Created:  Thursday 26 September 2019 07:48:10  IST
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
#include "../tcpconst.h"
#include <stdint.h>
#include "ddcp/ddcp.h"

void
promote_pkt_to_layer5(node_t *node, interface_t *recv_intf,
        char *l5_hdr, uint32_t pkt_size,
        uint32_t L5_protocol){

    switch(L5_protocol){
        case USERAPP1:
            break;
        case DDCP_MSG_TYPE_UCAST_REPLY:
           ddcp_process_ddcp_reply_msg(node, l5_hdr);
            break;
        case DDCP_MSG_TYPE_FLOOD_QUERY:
           ddcp_process_ddcp_query_msg(node, recv_intf, l5_hdr, pkt_size);
        default:
            ;
    }
}
