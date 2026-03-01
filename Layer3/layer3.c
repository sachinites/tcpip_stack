/*
 * =====================================================================================
 *
 *       Filename:  layer3.c
 *
 *    Description:  This file defines the routines for Layer 3
 *
 *        Version:  1.0
 *        Created:  Friday 20 September 2019 05:24:38  IST
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

#include <stdio.h>
#include <arpa/inet.h>
#include <memory.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>

#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"

#include "../router_init.h"
#include "../common/l3_hdrs.h"
#include "../utils.h"
#include "../common/cp2dp.h"
#include "../pkt_block.h"

extern graph_t *topo;


/* This fn sends a dummy packet to test L3 and L2 routing
 * in the project. We send dummy Packet starting from Network
 * Layer on node 'node' to destination address 'dst_ip_addr'
 * using below fn*/
void
layer3_ping_fn(node_t *node, c_string dst_ip_addr, uint32_t count){

    uint32_t i;
    uint32_t addr_int;

    addr_int = tcp_ip_convert_ip_p_to_n(dst_ip_addr);
    cprintf("\nSrc node : %s, Ping ip : %s", node->node_name, dst_ip_addr);

    for (i = 0; i < count ; i ++) {
        cp2dp_send_ip_data (node, NULL, addr_int, ICMP_PROTO);
    }
}

void
layer3_ero_ping_fn(node_t *node, 
                    c_string dst_ip_addr, 
                    c_string ero_ip_address){

    pkt_block_t *pkt_block = pkt_block_get_new_pkt_buffer (sizeof (ip_hdr_t));
    pkt_block_set_starting_hdr_type (pkt_block, IP_HDR);
    ip_hdr_t *inner_ip_hdr = (ip_hdr_t *)pkt_block_get_ip_hdr (pkt_block);
    initialize_ip_hdr(inner_ip_hdr);
    inner_ip_hdr->total_length = htons(IP_HDR_DEFAULT_SIZE);
    inner_ip_hdr->protocol = ICMP_PROTO;
    uint32_t addr_int = tcp_ip_convert_ip_p_to_n(NODE_RTRID_ADDR(node));
    inner_ip_hdr->src_ip = htonl(addr_int);
    addr_int =  tcp_ip_convert_ip_p_to_n(dst_ip_addr);
    inner_ip_hdr->dst_ip = htonl(addr_int);
    addr_int = tcp_ip_convert_ip_p_to_n(ero_ip_address);
    cp2dp_send_ip_data (node, pkt_block, addr_int, PROTO_IP_IN_IP);
    pkt_block_dereference(pkt_block);
}



extern int 
ip_traffic_generate_handler(int cmdcode,
    Stack_t *tlv_stack,
    op_mode enable_or_disable) {

    int i;
    uint32_t count = 1;
    uint8_t protocol;
    uint32_t addr_int;
    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    char *src_addr_str = NULL;
    char *dst_addr_str = NULL;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if  (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "src-addr"))
            src_addr_str = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "dst-addr"))
            dst_addr_str = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "count"))
            count = atoi(tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "protocol"))
            protocol = atoi(tlv->value);

   } TLV_LOOP_END;
   
   node = node_get_node_by_name(topo, node_name);

   addr_int = tcp_ip_convert_ip_p_to_n(dst_addr_str );

   for (i = 0; i < count ; i ++) {
        cp2dp_send_ip_data (node, NULL, addr_int, protocol);
    }
    
    return 0;
}
