/*
 * =====================================================================================
 *
 *       Filename:  net.c
 *
 *    Description:  This file contains general pupose Networking routines
 *
 *        Version:  1.0
 *        Created:  Wednesday 18 September 2019 08:36:50  IST
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
#include <memory.h>
#include "utils.h"
#include <stdio.h>
#include <arpa/inet.h>

/*Heuristics, Assign a unique mac address to interface*/
static unsigned int
hash_code(void *ptr, unsigned int size){

    unsigned int value = 0, i = 0;
    char *str = (char *)ptr;
    while(i < size)
    {
        value += *str;
        value *= 97;
        str++;
        i++;
    }
    return value;

}
void
interface_assign_mac_address(interface_t *interface){

    node_t *node = interface->att_node;
    if(!node) return;
    unsigned int hash_code_val = hash_code(node->node_name, NODE_NAME_SIZE);
    hash_code_val *= hash_code(interface->if_name, IF_NAME_SIZE);
    
    memset(IF_MAC(interface), 0, MAC_LEN);
    strncpy(IF_MAC(interface), (char *)&hash_code_val, sizeof(unsigned int));
    //strcat(IF_MAC(interface), interface->if_name);
}

bool_t node_set_device_type(node_t *node, unsigned int F){

    SET_BIT(node->node_nw_prop.flags, F);
    return TRUE;
}

bool_t node_set_loopback_address(node_t *node, char *ip_addr){

    assert(ip_addr);

    if(IS_BIT_SET(node->node_nw_prop.flags, HUB))
        ;//assert(0); /*Wrong Config : A HUB do not have any IP addresses*/

    if(!IS_BIT_SET(node->node_nw_prop.flags, L3_ROUTER))
        ;//assert(0); /*You must enable L3 routing on device first*/

    node->node_nw_prop.is_lb_addr_config = TRUE;
    strncpy(NODE_LO_ADDR(node), ip_addr, IP_LEN);
    NODE_LO_ADDR(node)[IP_LEN - 1] = '\0';
    
    return TRUE;
}

bool_t node_set_intf_ip_address(node_t *node, char *local_if, 
                                char *ip_addr, char mask) {

    interface_t *interface = get_node_if_by_name(node, local_if);
    if(!interface) 
        ;//assert(0);

    strncpy(IF_IP(interface), ip_addr, IP_LEN);
    IF_IP(interface)[IP_LEN - 1] = '\0';
    interface->intf_nw_props.mask = mask; 
    interface->intf_nw_props.is_ipadd_config = TRUE;
    return TRUE;
}

bool_t node_unset_intf_ip_address(node_t *node, char *local_if){

    return TRUE;
}

interface_t *
node_get_matching_subnet_interface(node_t *node, char *ip_addr){

    for(int i = 0; i < MAX_INTF_PER_NODE || node ->intf[i]; i++)
    {
        if(node ->intf[i]->intf_nw_props.is_ipadd_config)
        {
            char intf_subnet[IP_LEN];
            char ip_subnet[IP_LEN];
            memset(intf_subnet, 0, IP_LEN);
            memset(ip_subnet, 0, IP_LEN);
            apply_mask(node ->intf[i]->intf_nw_props.ip_add.ip_addr, node ->intf[i]->intf_nw_props.mask, intf_subnet);
            apply_mask(ip_addr, node ->intf[i]->intf_nw_props.mask, ip_subnet);
            if(strcmp(intf_subnet, ip_subnet) == 0)
                return node ->intf[i];
        }
    }
    return NULL;
}

void dump_node_nw_props(node_t *node){

    printf("\nNode Name = %s, udp_port_no = %u\n", node->node_name, node->udp_port_number);
    printf("\t node flags : %u", node->node_nw_prop.flags);
    if(node->node_nw_prop.is_lb_addr_config){
        printf("\t  lo addr : %s/32\n", NODE_LO_ADDR(node));
    }
}

void dump_intf_props(interface_t *interface){

    dump_interface(interface);

    if(interface->intf_nw_props.is_ipadd_config){
        printf("\t IP Addr = %s/%u", IF_IP(interface), interface->intf_nw_props.mask);
        
    }
    else{
         printf("\t IP Addr = %s/%u", "Nil", 0);
    }

    printf("\t MAC : %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n", 
        (unsigned int)IF_MAC(interface)[0], (unsigned int)IF_MAC(interface)[1],
        (unsigned int)IF_MAC(interface)[2], (unsigned int)IF_MAC(interface)[3],
        (unsigned int)IF_MAC(interface)[4], (unsigned int)IF_MAC(interface)[5]);
}

void dump_nw_graph(graph_t *graph){

    node_t *node;
    glthread_t *curr;
    interface_t *interface;
    unsigned int i;
    
    printf("Topology Name = %s\n", graph->topology_name);

    ITERATE_GLTHREAD_BEGIN(&graph->node_list, curr){

        node = graph_glue_to_node(curr);
        dump_node_nw_props(node);
        for( i = 0; i < MAX_INTF_PER_NODE; i++){
            interface = node->intf[i];
            if(!interface) break;
            dump_intf_props(interface);
        }
    } ITERATE_GLTHREAD_END(&graph->node_list, curr);

}

unsigned int
convert_ip_from_str_to_int(char *ip_addr){

    struct in_addr addr;

    addr.s_addr = inet_addr(ip_addr);
    return (unsigned int)addr.s_addr;
}

void
convert_ip_from_int_to_str(unsigned int ip_addr, char *output_buffer){

    struct in_addr addr;
    addr.s_addr = ip_addr;
    memset(output_buffer, 0, strlen(output_buffer));
    //memcpy(output_buffer, inet_ntoa(addr), strlen(output_buffer));
    inet_ntop(AF_INET, &ip_addr, output_buffer, IP_LEN);
    //puts(output_buffer);

}

char *
pkt_buffer_shift_right(char *pkt, unsigned int pkt_size, unsigned int total_buffer_size)
{
    char *buf_start = pkt;
    char *buf_end = pkt + total_buffer_size;

    char *new_pos = buf_end - pkt_size;
    memcpy(new_pos, pkt, pkt_size);
    memset(buf_start, 0, pkt_size);
    return new_pos;
}