/*
 * =====================================================================================
 *
 *       Filename:  graph.h
 *
 *    Description:  This file contains the definition of all structures required to create a NetworkGraph
 *
 *        Version:  1.0
 *        Created:  Wednesday 18 September 2019 02:17:17  IST
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

/* Visit my Website for more wonderful assignments and projects :
 * www.csepracticals.com
 * if above URL dont work, then try visit : https://csepracticals.com*/

#ifndef __GRAPH__
#define __GRAPH__

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include "gluethread/glthread.h"
#include "net.h"
#include "tcp_ip_trace.h"
#include "Layer3/netfilter.h"
#include "EventDispatcher/event_dispatcher.h"

#define NODE_NAME_SIZE   16
#define IF_NAME_SIZE     16
#define MAX_INTF_PER_NODE   10

/*Forward Declarations*/
typedef struct node_ node_t;
typedef struct link_ link_t;
class Interface;

typedef struct interface_ {

    byte if_name[IF_NAME_SIZE];
    struct node_ *att_node;
    struct link_ *link;
    intf_nw_props_t intf_nw_props;
    log_t log_info;
} interface_t;

struct link_ {

    interface_t intf1;
    interface_t intf2;
    unsigned int cost;
}; 

static inline uint32_t
get_link_cost(interface_t *interface){

    return interface->link->cost;
}

typedef struct spf_data_ spf_data_t;
typedef struct pkt_tracer_ pkt_tracer_t;
typedef struct hashtable hashtable_t;

struct node_ {

    char node_name[NODE_NAME_SIZE];
    interface_t *intf[MAX_INTF_PER_NODE];
    Interface *Intf[MAX_INTF_PER_NODE];

    /* For Network Sockets */
    unsigned int udp_port_number;
    int udp_sock_fd;

    node_nw_prop_t node_nw_prop;

    /*SPF Calculation*/
    spf_data_t *spf_data;

    /*Node Logging*/
    log_t log_info;

	/*net-filter hooks DB*/
	nf_hook_db_t nf_hook_db;

	/*L2 net-filter hook (simplified) */
	notif_chain_t layer2_proto_reg_db2;

    /* Control plane Scheduler */
    event_dispatcher_t ev_dis;
    /* Data path scheduler */
    event_dispatcher_t dp_ev_dis;
    /* Objects Purger */
    event_dispatcher_t purger_ev_dis;
    /* Data Path ingress Pkt Queue */
    pkt_q_t dp_recvr_pkt_q;
     /*CP Timer*/
    wheel_timer_t *cp_wt;
    /* Data Path Timer */
    wheel_timer_t *dp_wt;
    
    unsigned char *print_buff;

    glthread_t access_lists_db;
    glthread_t prefix_lst_db;

    /* Network Object Hashtable */
    hashtable_t *object_network_ght;
     /* Object Group Hashtable */
    hashtable_t *object_group_ght;
    
    /* List of route-maps created on this node*/
    glthread_t route_map_headtype;

    /* Packet Tracer Object */
    pkt_tracer_t *pkt_tracer;
    glthread_t graph_glue;
};
GLTHREAD_TO_STRUCT(graph_glue_to_node, node_t, graph_glue);

typedef struct graph_{

    char topology_name[32];
    glthread_t node_list;
    bool gstdout;
} graph_t;

node_t *
create_graph_node(graph_t *graph, const c_string node_name);

graph_t *
create_new_graph(const char *topology_name);

void
insert_link_between_two_nodes(node_t *node1, 
                             node_t *node2,
                             const char *from_if_name, 
                             const char *to_if_name, 
                             unsigned int cost);
void
insert_link_between_two_nodes2(node_t *node1,
        node_t *node2,
        const char *from_if_name,
        const char *to_if_name,
        unsigned int cost);

/*Helper functions*/
static inline node_t *
get_nbr_node(interface_t *interface){

    assert(interface->att_node);
    assert(interface->link);
    
    link_t *link = interface->link;
    if(&link->intf1 == interface)
        return link->intf2.att_node;
    else
        return link->intf1.att_node;
}

static inline int
get_node_intf_available_slot(node_t *node){

    int i ;
    for( i = 0 ; i < MAX_INTF_PER_NODE; i++){
        if(node->intf[i])
            continue;
        return i;
    }
    return -1;
}

static inline int
get_node_intf_available_slot2(node_t *node){

    int i ;
    for( i = 0 ; i < MAX_INTF_PER_NODE; i++){
        if(node->Intf[i])
            continue;
        return i;
    }
    return -1;
}

interface_t *
node_get_intf_by_name(node_t *node, const char *if_name);

interface_t *
node_get_intf_by_ifindex(node_t *node, uint32_t ifindex);

Interface *
node_get_intf_by_name2(node_t *node, const char *if_name);

Interface *
node_get_intf_by_ifindex2(node_t *node, uint32_t ifindex);

static inline node_t *
node_get_node_by_name(graph_t *topo, c_string node_name){

    node_t *node;
    glthread_t *curr;    

    ITERATE_GLTHREAD_BEGIN(&topo->node_list, curr){

        node = graph_glue_to_node(curr);
        if(string_compare(node->node_name, node_name, NODE_NAME_SIZE) == 0)
            return node;
    } ITERATE_GLTHREAD_END(&topo->node_list, curr);
    return NULL;
}

/*Display Routines*/
void dump_graph(graph_t *graph);
void dump_node(node_t *node);
void dump_interface(interface_t *interface);

#define ITERATE_NODE_INTERFACES_BEGIN(node_ptr, intf_ptr) \
{                                                         \
    int _i = 0;                                           \
    for(; _i < MAX_INTF_PER_NODE; _i++){                  \
        intf_ptr = node_ptr->intf[_i];                     \
        if(!intf_ptr) continue;

#define ITERATE_NODE_INTERFACES_END(node_ptr, intf_ptr) }}
    



#endif /* __NW_GRAPH_ */
