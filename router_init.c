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
#include "router_init.h"
#include "tcp_ip_trace.h"
#include "FireWall/acl/acldb.h"
#include "packet-tracer/packet_tracer.h"
#include "c-hashtable/hashtable.h"
#include "Interface/InterfaceUApi.h"
#include "Tracer/tracer.h"
#include "Layer3/ipv6/ipv6_utils.h"
#include "dpal/cp2dp.h"
#include "RTM/rtm.h"
#include "RTM/rtm_nb_integ.h"
#include "common/cmn_prefix.h"
#include "datapath/dp_uapi.h"
#include "../RDBMSImplementation/uapi/sql_api.h"

extern bool LinuxRtr;

void
insert_link_between_two_nodes(node_t *node1,
        node_t *node2,
        const char *from_if_name,
        const char *to_if_name,
        unsigned int cost){

    linkage_t *link = new linkage_t;
    link->Intf1 = std::make_shared<PhysicalInterface>(from_if_name, INTF_TYPE_PHY, nullptr);
    link->Intf1->SetSharedPtr(link->Intf1);
    link->Intf2 = std::make_shared<PhysicalInterface>(to_if_name, INTF_TYPE_PHY, nullptr);
    link->Intf2->SetSharedPtr(link->Intf2);

    link->Intf1->link = link;
    link->Intf2->link = link;

    link->Intf1->att_node = node1;
    link->Intf2->att_node = node2;

    /*Plugin interface ends into Node*/
    link->Intf1->ifindex = interface_get_new_ifindex(node1);
    node_global_intf_map_insert(node1, link->Intf1.get());

    link->Intf2->ifindex = interface_get_new_ifindex(node2);
    node_global_intf_map_insert(node2, link->Intf2.get());

    /*Now Assign Random generated Mac address to the Interfaces*/
    interface_assign_mac_address(link->Intf1.get());
    interface_assign_mac_address(link->Intf2.get());

    /* Data path Updates*/
    cp2dp_interface_create(node1, link->Intf1.get());
    cp2dp_interface_create(node2, link->Intf2.get());
    dp_uapi_link_connect (node1->dp_ctx, link->Intf1->ifindex, 
                     node2->dp_ctx, link->Intf2->ifindex);

    vrf_add_interface(NODE_DEF_VRF(node1), link->Intf1.get());
    vrf_add_interface(NODE_DEF_VRF(node2), link->Intf2.get());
    
    cp2dp_send_intf_admin_status_update(node1, link->Intf1->ifindex, false);
    cp2dp_send_intf_admin_status_update(node2, link->Intf2->ifindex, false);
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

extern void tcp_ip_register_default_l3_pkt_trap_rules(nf_hook_db_t *nf_hook_db);
extern void node_init_udp_socket(node_t *node);
extern struct hashtable *object_network_create_new_ht() ;
extern struct hashtable *object_group_create_new_ht() ;
extern void init_nfc_layer2_proto_reg_db2(notif_chain_t *nfc);
extern int debug_infra_tracer_bits_to_str (char *buffer, uint64_t bits) ;
extern void ipc_event_signal (event_dispatcher_t *, void *, uint32_t );
extern void dp_ipc_event (event_dispatcher_t *, void *, uint32_t );
extern void init_node_nw_prop(node_t *node, node_nw_prop_t *node_nw_prop) ;
void dp_init (node_t *node);
extern void dp_uapi_ctx_init (dp_ctx_t **dp_ctx, void *arg, char *ctx_name);


static FILE *
initialize_node_log_file(node_t *node){

    char file_name[64];

    memset(file_name, 0, sizeof(file_name));
    sprintf(file_name, "logs/%s.txt", node->node_name);

    FILE *fptr = fopen(file_name, "w");

    if(!fptr){
        cprintf("Error : Could not open log file %s, errno = %d\n", 
            file_name, errno);
        return 0;
    }

    return fptr;
}

static void
tcp_ip_init_node_log_info(node_t *node){

    log_t *log_info     = &node->dp_ctx->log;
    log_info->all       = false;
    log_info->recv      = false;
    log_info->send      = false;
    log_info->is_stdout = false;
    log_info->l3_fwd    = false;
    log_info->log_file  = initialize_node_log_file(node); 
    log_info->acc_lst_filter = NULL;
}

node_t *
Router_Create(graph_t *graph, const c_string node_name){

    char file_name[64];
    char ev_dis_name[EV_DIS_NAME_LEN];

    node_t *node = (node_t *)calloc(1, sizeof(node_t));
    string_copy((char *)node->node_name, node_name, NODE_NAME_SIZE);
    node->node_name[NODE_NAME_SIZE -1] = '\0';

    node_init_udp_socket(node);

    node->spf_data = NULL;

    /* Initialize the Data path before control plane (log lives in dp_ctx) */
    dp_uapi_ctx_init (&node->dp_ctx, (void *)node, node->node_name);
    tcp_ip_init_node_log_info(node);

    /* L3/L2 netfilter and proto reg are initialized inside dp_uapi_ctx_init; no longer on node */

    /* Initialize Control Plane Tracers*/
    memset(file_name, 0, sizeof(file_name));
    sprintf(file_name, "logs/%s-cp.txt", node->node_name);
    node->cptr = tracer_init (node_name, file_name, node->node_name, 
        STDOUT_FILENO, debug_infra_tracer_bits_to_str );
    tracer_enable_file_logging (node->cptr, true);

    bitmap_init(&node->if_index_bm, MAX_INTF_IFINDEX + 1);
    bitmap_set_bit_at(&node->if_index_bm, 0);

    init_node_nw_prop(node, &node->node_nw_prop);

    /* Initialize global interface maps */
    node->intf_by_name = NULL;
    node->intf_by_ifindex = NULL;

    /* L3 pkt trapping and L2 proto reg are in dp_ctx (initialized in dp_uapi_ctx_init) */

    node->print_buff = (unsigned char *)calloc(1, NODE_PRINT_BUFF_LEN);

    init_glthread(&node->access_lists_db);
    init_glthread(&node->prefix_lst_db);
    node->object_network_ght = object_network_create_new_ht();
    node->object_group_ght = object_group_create_new_ht();
    init_glthread(&node->graph_glue);

    /* initialize ACL/NAT/OBJECT-G Tracer*/
    memset(file_name, 0, sizeof(file_name));
    sprintf(file_name, "logs/%s-cp-acl.txt", node->node_name);
    node->acl_cptr = tracer_init (node_name, file_name, node->node_name, STDOUT_FILENO,  debug_infra_tracer_bits_to_str );
    tracer_enable_file_logging (node->acl_cptr, true);

    /* initialize SQL Table Catalog*/
    sql_init_db(&node->sql_db);
    
    /* Start Control plane Thread/Scheduler */
    snprintf (ev_dis_name, EV_DIS_NAME_LEN, "CP-%s", node_name);
    event_dispatcher_init(&node->ev_dis, (const char *)ev_dis_name);
    event_dispatcher_run(&node->ev_dis, false);
    node->ev_dis.app_data = (void *)node;

    /* Start Object purger Thread/Scheduler */
    snprintf (ev_dis_name, EV_DIS_NAME_LEN, "Purger-%s", node_name);
    event_dispatcher_init(&node->purger_ev_dis, (const char *)ev_dis_name);
    event_dispatcher_run(&node->purger_ev_dis, false);  /* Purger doesn't need high-perf core */
    node->purger_ev_dis.app_data = (void *)node;

    /* Start Control Plane Timer */
    node->cp_wt = init_wheel_timer(60, 1, TIMER_SECONDS);
    wt_set_user_data(node->cp_wt, EV(node));
    start_wheel_timer(node->cp_wt);

    /* Start IPC Message Queue of Control Plane*/
    init_pkt_q (&node->ev_dis, &node->cp_ipc_q, ipc_event_signal);

    pkt_tracer_init (&node->pkt_tracer);

    //node_config_db_init (node);

    /* Turn on Default Logging */
    #if 0
    tracer_log_bit_set(node->cptr,  DRTM | DRTM_DET);
    tracer_log_bit_set(dp_ctx->dptr,  DFIB | DFIB_DET);
    tracer_log_bit_set(node->cptr,  DERR);
    tracer_log_bit_set(dp_ctx->dptr,  DERR);  
    #endif 
    tracer_enable_always_flush(node->cptr, true);
    tracer_enable_always_flush(node->dp_ctx->dptr, true);
    tracer_log_bit_set(node->dp_ctx->dptr, DCONF);
    
    node->sequence_gen = 1;
    glthread_add_next(&graph->node_list, &node->graph_glue);
    return node;
}

void dump_interface(Interface *interface){

    interface->PrintInterfaceDetails();
}

uint32_t 
node_get_sequence_no(node_t *node) {
    return node->sequence_gen++;
}
