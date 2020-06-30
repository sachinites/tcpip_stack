/*
 * =====================================================================================
 *
 *       Filename:  graph.c
 *
 *    Description:  This file contains the routines to construct the Network Graph
 *
 *        Version:  1.0
 *        Created:  Wednesday 18 September 2019 02:41:27  IST
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <memory.h>
#include "tcp_ip_trace.h"

extern void 
init_udp_socket(node_t *node);

void
insert_link_between_two_nodes(node_t *node1,
        node_t *node2,
        char *from_if_name,
        char *to_if_name,
        unsigned int cost){

    link_t *link = calloc(1, sizeof(link_t));

    /*Set interface properties*/
    strncpy(link->intf1.if_name, from_if_name, IF_NAME_SIZE);
    link->intf1.if_name[IF_NAME_SIZE - 1] = '\0';
    strncpy(link->intf2.if_name, to_if_name, IF_NAME_SIZE);
    link->intf2.if_name[IF_NAME_SIZE - 1] = '\0';
    
    link->intf1.link= link; /*set back pointer to link*/
    link->intf2.link= link; /*set back pointer to link*/

    link->intf1.att_node = node1;
    link->intf2.att_node = node2;
    link->cost = cost;

    int empty_intf_slot;

    /*Plugin interface ends into Node*/
    empty_intf_slot = get_node_intf_available_slot(node1);
    node1->intf[empty_intf_slot] = &link->intf1;

    empty_intf_slot = get_node_intf_available_slot(node2);
    node2->intf[empty_intf_slot] = &link->intf2;

    init_intf_nw_prop(&link->intf1.intf_nw_props);
    init_intf_nw_prop(&link->intf2.intf_nw_props);

    /*Now Assign Random generated Mac address to the Interfaces*/
    interface_assign_mac_address(&link->intf1);
    interface_assign_mac_address(&link->intf2);

    tcp_ip_init_intf_log_info(&link->intf1);
    tcp_ip_init_intf_log_info(&link->intf2);
}

graph_t *
create_new_graph(char *topology_name){

    graph_t *graph = calloc(1, sizeof(graph_t));
    strncpy(graph->topology_name, topology_name, 32);
    graph->topology_name[32] = '\0';

    init_glthread(&graph->node_list);
    graph->gstdout = FALSE;
    return graph;
}

node_t *
create_graph_node(graph_t *graph, char *node_name){

    node_t *node = calloc(1, sizeof(node_t));
    strncpy(node->node_name, node_name, NODE_NAME_SIZE);
    node->node_name[NODE_NAME_SIZE] = '\0';

    init_udp_socket(node);

    init_node_nw_prop(&node->node_nw_prop);
    init_glthread(&node->graph_glue);
    node->spf_data = NULL;
    tcp_ip_init_node_log_info(node);
    glthread_add_next(&graph->node_list, &node->graph_glue);
    return node;
}

void dump_graph(graph_t *graph){

    node_t *node;
    glthread_t *curr;
    
    printf("Topology Name = %s\n", graph->topology_name);

    ITERATE_GLTHREAD_BEGIN(&graph->node_list, curr){

        node = graph_glue_to_node(curr);
        dump_node(node);    
    } ITERATE_GLTHREAD_END(&graph->node_list, curr);
}

void dump_node(node_t *node){

    unsigned int i = 0;
    interface_t *intf;

    printf("Node Name = %s : \n", node->node_name);
    for( ; i < MAX_INTF_PER_NODE; i++){
        
        intf = node->intf[i];
        if(!intf) break;
        dump_interface(intf);
    }
}

void dump_interface(interface_t *interface){

   link_t *link = interface->link;
   node_t *nbr_node = get_nbr_node(interface);

   printf("Interface Name = %s\n\tNbr Node %s, Local Node : %s, cost = %u\n", 
            interface->if_name,
            nbr_node->node_name, 
            interface->att_node->node_name, 
            link->cost);
}
