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
#include <memory>
#include <ctype.h>
#include "configdb.h"
#include "graph.h"
#include "tcp_ip_trace.h"
#include "FireWall/acl/acldb.h"
#include "packet-tracer/packet_tracer.h"
#include "c-hashtable/hashtable.h"
#include "Interface/InterfaceUApi.h"
#include "Tracer/tracer.h"
#include "Layer3/ipv6/ipv6_utils.h"
#include "Layer3/ipv6/ipv6_route.h"
#include "common/cp2dp.h"
#include "Layer3/SegmentRouting/SRv6/common/srv6_const.h"
#include "../RDBMSImplementation/uapi/sql_api.h"

void
insert_link_between_two_nodes(node_t *node1,
        node_t *node2,
        const char *from_if_name,
        const char *to_if_name,
        unsigned int __attribute__((unused)) cost){

    linkage_t *link = new linkage_t;
    link->Intf1 = std::make_shared<PhysicalInterface>(from_if_name, INTF_TYPE_PHY, nullptr);
    link->Intf1->SetSharedPtr(link->Intf1);
    link->Intf2 = std::make_shared<PhysicalInterface>(to_if_name, INTF_TYPE_PHY, nullptr);
    link->Intf2->SetSharedPtr(link->Intf2);

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
    interface_assign_mac_address(link->Intf1.get());
    interface_assign_mac_address(link->Intf2.get());

    /* Generate ipv6 link local address */
    mac_addr_t *mac_addr = link->Intf1->GetMacAddr();
    link->Intf1->InterfaceSetIpv6LinkLocalAddress(&mac_addr->mac);
    
    /* Install link local as a direct static route in ipv6 routing table*/
    ipv6_addr_t v6_addr = {0};
    link->Intf1->InterfaceGetIpv6LinkLocalAddress(&v6_addr.addr);
     ipv6_route_install  (node1,
                        &v6_addr, 128, 
                        0, 0, 0, 0, 0, 0, SRV6_END_FN_NONE);

    
    mac_addr = link->Intf2->GetMacAddr();
    link->Intf2->InterfaceSetIpv6LinkLocalAddress(&mac_addr->mac);
    link->Intf2->InterfaceGetIpv6LinkLocalAddress(&v6_addr.addr);
    ipv6_route_install  (node2,
                        &v6_addr, 128, 
                        0, 0, 0, 0, 0, 0, SRV6_END_FN_NONE);

    //intf_init_bit_rate_sampling_timer(&link->intf1);

    tcp_ip_init_intf_log_info(link->Intf1.get());
    tcp_ip_init_intf_log_info(link->Intf2.get());
}

graph_t *
create_new_graph (const char *topology_name){

    graph_t *graph = (graph_t *)calloc(1, sizeof(graph_t));
    string_copy((char *)graph->topology_name, topology_name, sizeof(graph->topology_name));
    graph->topology_name[sizeof(graph->topology_name) - 1] = '\0';
    init_glthread(&graph->node_list);
    graph->gstdout = false;
    return graph;
}

extern void tcp_ip_register_default_l3_pkt_trap_rules(node_t *node);
extern void node_init_udp_socket(node_t *node);
extern void dp_pkt_recvr_job_cbk(event_dispatcher_t *ev_dis, void *pkt, uint32_t pkt_size);
extern void  dp_pkt_xmit_intf_job_cbk (event_dispatcher_t *ev_dis, void *pkt, uint32_t pkt_size);
extern struct hashtable *object_network_create_new_ht() ;
extern struct hashtable *object_group_create_new_ht() ;
extern void init_nfc_layer2_proto_reg_db2(node_t *node);
extern int debug_dp_bits_to_str (char *buffer, uint64_t bits) ;
extern void ipc_event_signal (event_dispatcher_t *, void *, uint32_t );
extern void dp_ipc_event (event_dispatcher_t *, void *, uint32_t );
extern void init_node_nw_prop(node_t *node, node_nw_prop_t *node_nw_prop) ;

node_t *
create_graph_node(graph_t *graph, const c_string node_name){

    char file_name[64];
    char ev_dis_name[EV_DIS_NAME_LEN];

    node_t *node = (node_t *)calloc(1, sizeof(node_t));
    string_copy((char *)node->node_name, node_name, NODE_NAME_SIZE);
    node->node_name[NODE_NAME_SIZE -1] = '\0';

    node_init_udp_socket(node);

    node->spf_data = NULL;

    tcp_ip_init_node_log_info(node);

    /* Initialize Control Plane Tracers*/
    memset(file_name, 0, sizeof(file_name));
    sprintf(file_name, "logs/%s-cp.txt", node->node_name);
    node->cptr = tracer_init ((const char *)node_name, file_name, (const char *)node->node_name, STDOUT_FILENO,  0 );
    tracer_enable_file_logging (node->cptr, true);

    /* Initialize Data Plane Tracers*/
    memset(file_name, 0, sizeof(file_name));
    sprintf(file_name, "logs/%s-dp.txt", node->node_name);
    node->dptr = tracer_init ((const char *)node_name, file_name, (const char *)node->node_name, STDOUT_FILENO, debug_dp_bits_to_str );
    tracer_enable_file_logging (node->dptr, true);

    init_node_nw_prop(node, &node->node_nw_prop);

    /* L3 pkt trapping to application is implemented using Netfilter hooks built over NFC*/
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

    /* initialize ACL/NAT/OBJECT-G Tracer*/
    memset(file_name, 0, sizeof(file_name));
    sprintf(file_name, "logs/%s-cp-acl.txt", node->node_name);
    node->acl_cptr = tracer_init ((const char *)node_name, file_name, (const char *)node->node_name, STDOUT_FILENO,  0 );
    tracer_enable_file_logging (node->acl_cptr, true);

    /* initialize SQL Table Catalog*/
    sql_init_db(&node->sql_db);
    
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
    init_pkt_q(&node->dp_ev_dis, &node->cp_to_dp_xmit_intf_pkt_q, dp_pkt_xmit_intf_job_cbk);

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

    /* Start IPC Message Queue of Control Plane*/
    init_pkt_q (&node->ev_dis, &node->cp_ipc_q, ipc_event_signal);
    /* Start IPC Message Queue of Data  Plane*/
    init_pkt_q (&node->dp_ev_dis, &node->dp_ipc_q, 0);

    pkt_tracer_init (&node->pkt_tracer);
    
    node_config_db_init (node);

    glthread_add_next(&graph->node_list, &node->graph_glue);
    return node;
}

void dump_interface(Interface *interface){

    interface->PrintInterfaceDetails();
}


Interface *
node_get_intf_by_name(node_t *node, const char *if_name){

    Interface *intf;

    if (string_compare(if_name, NODE_RMAC_INTF(node)->if_name.c_str(), IF_NAME_SIZE) == 0) {
        return NODE_RMAC_INTF(node).get();
    }

    else if (string_compare(if_name, NODE_VLAN_FLOOD_INTF(node)->if_name.c_str(), IF_NAME_SIZE) == 0) {
        return NODE_VLAN_FLOOD_INTF(node).get();
    }

    else if (NODE_NVE_INTF(node) && 
             string_compare(if_name, NODE_NVE_INTF(node)->if_name.c_str(), IF_NAME_SIZE) == 0) {
        return NODE_NVE_INTF(node).get();
    }

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if(!intf) return NULL;

        if(string_compare(intf->if_name.c_str(), if_name, IF_NAME_SIZE) == 0){
            return intf;
        }

    }  ITERATE_NODE_INTERFACES_END(node, intf);

    /* Get vlan interface by name */
    if (node->vlan_intf_db) {

        for (auto it = node->vlan_intf_db->begin(); it != node->vlan_intf_db->end(); it++) {
            if (string_compare(it->second->if_name.c_str(), if_name, IF_NAME_SIZE) == 0) {
                return it->second.get();
            }
        }
    }

    return NULL;
}

Interface *
node_get_intf_by_name_with_idx_pos (node_t *node, const char *if_name, int *if_pos) {

    int i = 0;
    Interface *intf;

    for(; i < MAX_INTF_PER_NODE; i++) {

        intf = node->intf[i].get();                  

        if(!intf) { 
            if (*if_pos) *if_pos = 0;
            return NULL;
        }

        if(string_compare(intf->if_name.c_str(), if_name, IF_NAME_SIZE) == 0){
            if (*if_pos) *if_pos = i;
            return intf;
        }
    } 

    /* Get vlan interface by name */
    if (node->vlan_intf_db) {

        for (auto it = node->vlan_intf_db->begin(); it != node->vlan_intf_db->end(); it++) {
            if (string_compare(it->second->if_name.c_str(), if_name, IF_NAME_SIZE) == 0) {
                if (*if_pos) *if_pos = 0;
                return it->second.get();
            }
        }
    }

    if (*if_pos) *if_pos = -1;
    return NULL;    
}

Interface *
node_get_intf_by_ifindex(node_t *node, uint32_t ifindex) {

    Interface *intf;

    if (ifindex ==NODE_RMAC_INTF(node)->ifindex) {
        return NODE_RMAC_INTF(node).get();
    }
    else if (ifindex == NODE_VLAN_FLOOD_INTF(node)->ifindex) {
        return NODE_VLAN_FLOOD_INTF(node).get();
    }

    else if (NODE_NVE_INTF(node) && 
             ifindex == NODE_NVE_INTF(node)->ifindex) {
        return NODE_NVE_INTF(node).get();
    }
    
    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if(!intf) return NULL;
        if (intf->ifindex == ifindex) return intf;

    }  ITERATE_NODE_INTERFACES_END(node, intf);

    /* Check for vlan interface */

    if (node->vlan_intf_db) {

        for (auto it = node->vlan_intf_db->begin(); it != node->vlan_intf_db->end(); it++) {
            if (it->second->ifindex == ifindex) return it->second.get();
        }
    }

    return NULL;
}
