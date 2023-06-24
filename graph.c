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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <memory.h>
#include <ctype.h>
#include "configdb.h"
#include "graph.h"
#include "tcp_ip_trace.h"
#include "FireWall/acl/acldb.h"
#include "packet-tracer/packet_tracer.h"
#include "c-hashtable/hashtable.h"
#include "Interface/InterfaceUApi.h"


void
insert_link_between_two_nodes(node_t *node1,
        node_t *node2,
        const char *from_if_name,
        const char *to_if_name,
        unsigned int cost){

    linkage_t *link = (linkage_t *)calloc(1, sizeof(linkage_t));
    link->Intf1 = new PhysicalInterface(std::string (from_if_name) , INTF_TYPE_P2P, NULL);
    link->Intf2 = new PhysicalInterface(std::string (to_if_name) , INTF_TYPE_P2P, NULL);
    
    link->Intf1->link = link;
    link->Intf2->link = link;

    link->Intf1->att_node = node1;
    link->Intf2->att_node = node2;

    int empty_intf_slot;

    /*Plugin interface ends into Node*/
    empty_intf_slot = node_get_intf_available_slot(node1);
    node1->intf[empty_intf_slot] = link->Intf1;

    empty_intf_slot = node_get_intf_available_slot(node2);
    node2->intf[empty_intf_slot] = link->Intf2;

    /*Now Assign Random generated Mac address to the Interfaces*/
    interface_assign_mac_address(link->Intf1);
    interface_assign_mac_address(link->Intf2);
 
    //intf_init_bit_rate_sampling_timer(&link->intf1);

    tcp_ip_init_intf_log_info(link->Intf1);
    tcp_ip_init_intf_log_info(link->Intf2);
}

graph_t *
create_new_graph (const char *topology_name){

    graph_t *graph = (graph_t *)calloc(1, sizeof(graph_t));
    string_copy((char *)graph->topology_name, topology_name, 32);
    graph->topology_name[31] = '\0';

    init_glthread(&graph->node_list);
    graph->gstdout = false;
    return graph;
}

extern void
tcp_ip_register_default_l3_pkt_trap_rules(node_t *node);
extern void 
node_init_udp_socket(node_t *node);
extern void
dp_pkt_recvr_job_cbk(event_dispatcher_t *ev_dis, void *pkt, uint32_t pkt_size);
extern struct hashtable *object_network_create_new_ht() ;
extern struct hashtable *object_group_create_new_ht() ;
extern void init_nfc_layer2_proto_reg_db2(node_t *node);

node_t *
create_graph_node(graph_t *graph, const c_string node_name){

    char ev_dis_name[EV_DIS_NAME_LEN];

    node_t *node = (node_t *)calloc(1, sizeof(node_t));
    string_copy((char *)node->node_name, node_name, NODE_NAME_SIZE);
    node->node_name[NODE_NAME_SIZE -1] = '\0';

    node_init_udp_socket(node);

    init_node_nw_prop(node, &node->node_nw_prop);

    node->spf_data = NULL;

    tcp_ip_init_node_log_info(node);

    /* L3 pkt trapping to application is implemented using Netfilter
    hooks built over NFC*/
	nf_init_netfilters(&node->nf_hook_db);
    tcp_ip_register_default_l3_pkt_trap_rules(node);
    
    /* L2 pkt trapping to application is implemented using pure NFCs only*/
    init_nfc_layer2_proto_reg_db2(node);

    node->print_buff = (unsigned char *)calloc(1, NODE_PRINT_BUFF_LEN);

    init_glthread(&node->access_lists_db);
    init_glthread(&node->prefix_lst_db);
    node->object_network_ght = object_network_create_new_ht();
    node->object_group_ght = object_group_create_new_ht();
    init_glthread(&node->graph_glue);
    
    /* Start Control plane Thread/Scheduler */
    snprintf (ev_dis_name, EV_DIS_NAME_LEN, "CP-%s", node_name);
    event_dispatcher_init(&node->ev_dis, (const char *)ev_dis_name);
    event_dispatcher_run(&node->ev_dis);
    node->ev_dis.app_data = (void *)node;

    /* Start Data Path Thread/Scheduler */
    snprintf (ev_dis_name, EV_DIS_NAME_LEN, "DP-%s", node_name);
    event_dispatcher_init(&node->dp_ev_dis, (const char *)ev_dis_name);
    event_dispatcher_run(&node->dp_ev_dis);
    node->dp_ev_dis.app_data = (void *)node;
    init_pkt_q(&node->dp_ev_dis, &node->dp_recvr_pkt_q, dp_pkt_recvr_job_cbk);

    /* Start Object purger Thread/Scheduler */
    snprintf (ev_dis_name, EV_DIS_NAME_LEN, "Purger-%s", node_name);
    event_dispatcher_init(&node->purger_ev_dis, (const char *)ev_dis_name);
    event_dispatcher_run(&node->purger_ev_dis);
    node->purger_ev_dis.app_data = (void *)node;

    /* Start Control Plane Timer */
    node->cp_wt = init_wheel_timer(60, 1, TIMER_SECONDS);
    wt_set_user_data(node->cp_wt, EV(node));
    start_wheel_timer(node->cp_wt);

    /* Start DP Timer */
    node->dp_wt = init_wheel_timer(60, 1, TIMER_SECONDS);
    wt_set_user_data(node->dp_wt, EV_DP(node));
    start_wheel_timer(node->dp_wt);

    pkt_tracer_init (&node->pkt_tracer);
    
    node_config_db_init (node);

    glthread_add_next(&graph->node_list, &node->graph_glue);
    return node;
}

void dump_graph(graph_t *graph){

    node_t *node;
    glthread_t *curr;
    
    cprintf("Topology Name = %s\n", graph->topology_name);

    ITERATE_GLTHREAD_BEGIN(&graph->node_list, curr){

        node = graph_glue_to_node(curr);
        dump_node(node);    
    } ITERATE_GLTHREAD_END(&graph->node_list, curr);
}

void dump_node(node_t *node){

    unsigned int i = 0;
    Interface *intf;

    cprintf("Node Name = %s(%p) UDP Port # : %u\n",
        node->node_name, node, node->udp_port_number);

    for( ; i < MAX_INTF_PER_NODE; i++){
        
        intf = node->intf[i];
        if(!intf) break;
        dump_interface(intf);
    }
}

void dump_interface(Interface *interface){

    interface->PrintInterfaceDetails();
}

Interface *
node_get_intf_by_name(node_t *node, const char *if_name){

    int i ;
    Interface *intf;

    for( i = 0 ; i < MAX_INTF_PER_NODE; i++){
        intf = node->intf[i];
        if(!intf) return NULL;
        if(string_compare(intf->if_name.c_str(), if_name, IF_NAME_SIZE) == 0){
            return intf;
        }
    }   
    return NULL;
}

Interface *
node_get_intf_by_ifindex(node_t *node, uint32_t ifindex) {

    int i ;
    Interface *intf;

    for( i = 0 ; i < MAX_INTF_PER_NODE; i++){
        intf = node->intf[i];
        if(!intf) return NULL;
        if (intf->ifindex == ifindex)
            return intf;
    }
    return NULL;
}
