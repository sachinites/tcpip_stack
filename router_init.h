/*
 * =====================================================================================
 *
 *       Filename:  router_init.h
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
 * if above URL dont work, then try visit : https://www.csepracticals.com*/

#ifndef __GRAPH__
#define __GRAPH__

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include "libs/gluethread/glthread.h"
#include "net.h"
#include "tcp_ip_trace.h"
#include "Layer3/netfilter.h"
#include "libs/EventDispatcher/event_dispatcher.h"
#include <unordered_map>
#include "Interface/InterfaceFwd.h"
#include "cp_ipc.h"
#include "vrf/vrf.h"
#include "libs/BitOp/bitmap.h"

/*Forward Declarations*/
typedef struct node_ node_t;
typedef struct link_ link_t;

class TransportService;

typedef struct spf_data_ spf_data_t;
typedef struct pkt_tracer_ pkt_tracer_t;
typedef struct hashtable hashtable_t;
typedef struct tracer_ tracer_t;
typedef struct BPlusTree BPlusTree_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct dist_mgr_ dist_mgr_t;
typedef struct prefix_lst_client_ prefix_lst_client_t;
typedef struct acl_client_ acl_client_t;
typedef struct acl_builder_ acl_builder_t;

struct node_ {

    char node_name[NODE_NAME_SIZE];

    /* For Network Sockets */
    unsigned int udp_port_number;
    int udp_sock_fd;

    node_nw_prop_t node_nw_prop;

    /*SPF Calculation*/
    spf_data_t *spf_data;

    /* Control plane Scheduler */
    event_dispatcher_t ev_dis;

    /* Objects Purger */
    event_dispatcher_t purger_ev_dis;

    /* IPC in a control plane */
    pkt_q_t cp_ipc_q;

    /* IPC Database*/
    glthread_t cp_ipc_data_base [IPC_MSG_TYPE_MAX];
     /*CP Timer*/
    wheel_timer_t *cp_wt;

    unsigned char *print_buff;
    glthread_t access_lists_db;
    glthread_t prefix_lst_db;
    /* ACL Builder*/
    acl_builder_t *acl_builder;

    /* Control Plane Tracer*/
    tracer_t *cptr;
    /* Network Object Hashtable */
    hashtable_t *object_network_ght;
     /* Object Group Hashtable */
    hashtable_t *object_group_ght; 
    /* ACL/NAT/OBJECT-G Tracer */
    tracer_t *acl_cptr;
    /* VRFs*/
    vrf_t* vrf[MAX_VRF_PER_NODE];
    /* SQL DB*/
    BPlusTree_t *sql_db;
    /* Data Path */
    dp_ctx_t *dp_ctx;
    /* Route distribution manager */
    dist_mgr_t *dist_mgr;
    /* Transport Svc profiles DB*/
    std::unordered_map<std::string , TransportService *> *TransPortSvcDB;
    /* Vlan Interface Created*/
     std::unordered_map<uint16_t , VlanInterfaceP> *vlan_intf_db;
    /* List of route-maps created on this node*/
    glthread_t route_map_headtype;
    /* Packet Tracer Object */
    pkt_tracer_t *pkt_tracer;
    /* Interfaces in this VRF - hashmap keyed by interface name*/
    std::unordered_map<std::string, InterfaceP> *intf_by_name;
    /* Interfaces in this VRF - hashmap keyed by interface index*/
    std::unordered_map<uint32_t, InterfaceP> *intf_by_ifindex;    
    /*bitmap_t for bounded ifindex generation*/
    bitmap_t if_index_bm;
    /* Prefix list client for updates */
    std::vector<prefix_lst_client_t *> prefix_lst_clients;
    /* Access-list change notification clients */
    std::vector<acl_client_t *> acl_clients;

    glthread_t graph_glue;
    /* Random Number Generator*/
    uint32_t sequence_gen;
};
GLTHREAD_TO_STRUCT(graph_glue_to_node, node_t, graph_glue);

typedef struct graph_{

    char topology_name[32];
    glthread_t node_list;
    bool gstdout;
} graph_t;

node_t *
Router_Create(graph_t *graph, const c_string node_name);

graph_t *
create_new_graph(const char *topology_name);

void
insert_link_between_two_nodes(node_t *node1,
        node_t *node2,
        const char *from_if_name,
        const char *to_if_name,
        unsigned int cost);

uint32_t 
node_get_sequence_no(node_t *node);

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
void dump_interface(Interface *interface);

#define ITERATE_NODE_INTERFACES_BEGIN(node_ptr, intf_ptr)            \
{                                                                    \
    if (node_ptr->intf_by_name) {                                       \
        for (auto _it = node_ptr->intf_by_name->begin();                \
             _it != node_ptr->intf_by_name->end(); _it++) {             \
            intf_ptr = _it->second.get();                            \
            if(!intf_ptr) continue;

#define ITERATE_NODE_INTERFACES_END(node_ptr, intf_ptr)              \
        }                                                            \
    }                                                                \
}

#endif /* __NW_GRAPH_ */
