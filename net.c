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

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <arpa/inet.h>
#include "Layer3/ipv6/ipv6_utils.h"
#include "net.h"
#include "utils.h"
#include "tcpconst.h"
#include "notif.h"
#include "LinuxMemoryManager/uapi_mm.h"
#include "router_init.h"
#include "Tracer/tracer.h"
#include "Layer3/rt_table/nexthop.h"
#include "Layer3/layer3.h"
#include "Layer2/layer2.h"
#include "Layer2/transport_svc.h"
#include "Layer2/mac_table.h"
#include "Interface/InterfaceUApi.h"
#include "CLIBuilder/libcli.h"
#include "common/cp2dp.h"
#include "datapath/dp_ctx.h"
#include "datapath/Vrfs/dp_vrf.h"
#include "datapath/Interface/dp_intf.h"
#include "datapath/Interface/dp_intf_store.h"
#include "datapath/Interface/dp_intf_update.h"

typedef struct def_vrf_ def_vrf_t;

extern void init_rt_table(node_t *node, rt_table_t **rt_table);
extern void init_rtv6_table(node_t *node, rt_table_t **rt_table);
extern void mpls_rt_table_init (node_t *node, mpls_rt_table_t **mpls_rt_table) ;
extern void ipv4_mpls_rt_table_init (node_t *node, rt_table_t **ipv4_mpls_rt_table);
extern void rt_table_set_active_status(rt_table_t *rt_table, bool active);
extern void stp_init_stp_node_info(stp_node_info_t **stp_node_info);
extern void init_tcp_logging(node_t *);
extern void srv6_pool_init_srv6_pools (srv6_sid_pools_t **srv6_sid_pools) ;
extern void lfa_init (node_t *node, lfa_t **lfa) ;
void  node_assign_router_mac (node_t *node) ;
extern bool mac_table_entry_add(dp_ctx_t *dp_ctx, mac_table_t *mac_table, 
        mac_table_entry_t *mac_table_entry);
extern void l2_switch_perform_mac_learning (node_t *node, vlan_id_t vlan_id, 
        c_string src_mac, dp_intf_t *oif, uint32_t src_ip) ;
extern void node_init_default_rtm(node_t *node) ;
extern void node_init_default_fib(node_t *node);
extern def_vrf_t* vrf_def_init (node_t *node);

void
interface_assign_mac_address (Interface *interface){

    mac_addr_t mac_addr;
    tcp_ip_generate_random_mac_address (&mac_addr.mac);
    interface->SetMacAddr(&mac_addr);
}

uint16_t
interface_get_new_ifindex (node_t *node) {

    uint16_t ifindex = bitmap_get_unset_bit(&node->if_index_bm);
    assert (ifindex != UINT16_MAX);
    bitmap_set_bit_at(&node->if_index_bm, ifindex);
    return ifindex;
};

void 
interface_release_index(node_t *node, uint16_t ifindex) {

    assert (ifindex);
    assert (bitmap_at (&node->if_index_bm, ifindex));
    bitmap_unset_bit_at(&node->if_index_bm, ifindex);
}

void 
node_assign_router_mac (node_t *node) {

    mac_table_entry_t *mac_table_entry = NULL;

    tcp_ip_generate_random_mac_address (
            &node->node_nw_prop.rmac.mac);

    node->node_nw_prop.rmac_interface = 
        std::make_shared<RmacInterface>();
    node->node_nw_prop.rmac_interface->SetSharedPtr(
                node->node_nw_prop.rmac_interface);
    node->node_nw_prop.rmac_interface->att_node = node;
    node->node_nw_prop.rmac_interface->ifindex = interface_get_new_ifindex(node);
    node->node_nw_prop.rmac_interface->vrf = NODE_DEF_VRF(node);
    cp2dp_interface_create(node, node->node_nw_prop.rmac_interface.get());
}

void 
node_create_vlan_flood_interface(node_t *node) {

    node->node_nw_prop.vlan_flood_interface = 
        std::make_shared<VlanFloodInterface>();
    node->node_nw_prop.vlan_flood_interface->SetSharedPtr(
                node->node_nw_prop.vlan_flood_interface);
    node->node_nw_prop.vlan_flood_interface->att_node = node;
    node->node_nw_prop.vlan_flood_interface->ifindex = interface_get_new_ifindex(node);
    node->node_nw_prop.vlan_flood_interface->vrf = NODE_DEF_VRF(node);
   cp2dp_interface_create(node, node->node_nw_prop.vlan_flood_interface.get());
}

void 
node_create_host_path_interface (node_t *node) {

    node->node_nw_prop.host_path_interface = 
        std::make_shared<HostPathInterface>();
    node->node_nw_prop.host_path_interface->SetSharedPtr(
                node->node_nw_prop.host_path_interface);
    node->node_nw_prop.host_path_interface->att_node = node;
    node->node_nw_prop.host_path_interface->ifindex = interface_get_new_ifindex(node);
    node->node_nw_prop.host_path_interface->vrf = NODE_DEF_VRF(node);
    cp2dp_interface_create(node, node->node_nw_prop.host_path_interface.get());
}

typedef struct l3_route_ l3_route_t;

bool node_set_rtr_id(node_t *node, const char *ip_addr){

    uint32_t nh_idx = 0;
    assert(ip_addr);
    string_copy((char *)NODE_RTRID_ADDR(node), ip_addr, 16);
    NODE_RTRID_ADDR(node)[15] = '\0';
    return true;
}

void 
node_set_v6_rtr_id(node_t *node, const char *ipv6_addr ){

    assert(ipv6_addr);
    inet_pton(AF_INET6, ipv6_addr, node->node_nw_prop.ipv6_rtr_id);
    ipv6_addr_t prefix;
    memcpy (prefix.addr, node->node_nw_prop.ipv6_rtr_id, 16);
}

void 
node_set_intf_ip_address(node_t *node, const char *local_if, 
                                const char *ip_addr, char mask) {

    Interface *intf = node_interface_lookup_by_name(node, local_if);
    interface_set_ip_addr(node, intf, (c_string)ip_addr, mask);
}

void dump_node_nw_props(node_t *node){

    cprintf("\nNode Name = %s UDP Port # : %u  ",
        node->node_name, 
        node->udp_port_number);

    cprintf("\n");
}

static void
dump_node_vrf_interfaces(node_t *node) {

    /* Dump all interfaces from global interface map */
    if (node->intf_by_name && !node->intf_by_name->empty()) {
        for (auto& pair : *node->intf_by_name) {
            Interface *intf = pair.second.get();
            if (intf) {
                dump_intf_props(intf);
            }
        }
    }

    /* Dump special interfaces */
    //dump_intf_props(NODE_RMAC_INTF(node).get());
    //ump_intf_props(NODE_VLAN_FLOOD_INTF(node).get());
    //if (NODE_NVE_INTF(node)) dump_intf_props(NODE_NVE_INTF(node).get());
}

void 
dump_nw_graph(graph_t *graph, node_t *node1){

    node_t *node;
    glthread_t *curr;

    cprintf("Topology Name = %s\n", graph->topology_name);
    
    if(!node1){
        ITERATE_GLTHREAD_BEGIN(&graph->node_list, curr){

            node = graph_glue_to_node(curr);
            dump_node_nw_props(node);
            dump_intf_props_header();
            dump_node_vrf_interfaces(node);

        } ITERATE_GLTHREAD_END(&graph->node_list, curr);
    }
    else{

        dump_node_nw_props(node1);
        dump_intf_props_header();
        dump_node_vrf_interfaces(node1);
    }
}

/*Returns the local interface of the node which is configured 
 * with subnet in which 'ip_addr' lies
 * */
dp_intf_t *
node_get_matching_subnet_interface(dp_ctx_t *dp_ctx, dp_vrf_t *vrf, uint32_t ip_addr){

    uint8_t mask;
    dp_intf_t *intf;
    cmn_prefix_t prefix;
    
    cmn_prefix_initialize_v4(&prefix, ip_addr, 32);

    fib_nh_t *nh = fib_get_forwarding_nh(vrf->fib_inet0, &prefix);

    if(!nh){
        return NULL;
    }   

    if (nh->fwd_info->fwd_flags & 
        (FIB_NH_FWD_F_CONNECTED | FIB_NH_FWD_F_LOCAL)) {
        
        return nh->fwd_info->oif;
    }

    return NULL;
}

void
dump_interface_stats_header(){
    cprintf("\n%-20s | %10s | %10s | %15s | %9s\n", 
            "Interface Name", "PktTx", "PktRx", "Egress Dropped", "Ref Count");
    cprintf("%-20s-+-%10s-+-%10s-+-%15s-+-%9s\n", 
            "--------------------", "----------", "----------", "---------------", "---------");
}

void
dump_interface_stats(dp_intf_t *interface){

    cprintf("%-20s | %10u | %10u | %15u\n",
        interface->if_name, 
        interface->pkt_sent,
        interface->pkt_recv,
        interface->xmit_pkt_dropped);
}

void
dump_node_interface_stats(node_t *node){

    dp_intf_t *interface;

    // Print table header
    dump_interface_stats_header();

    struct hashtable_itr *itr = hashtable_iterator(node->dp_ctx->dp_intf_ht);

    while (1) {

        interface = (dp_intf_t *)hashtable_iterator_value(itr);
        dump_interface_stats(interface);
        if (!hashtable_iterator_advance(itr)) break;
    }
    free(itr);
    
    //dump_interface_stats(NODE_RMAC_INTF(node));
    //dump_interface_stats(NODE_VLAN_FLOOD_INTF(node));
    //if (NODE_NVE_INTF(node) ) dump_interface_stats(NODE_NVE_INTF(node));

    cprintf ("Ingress Pkt Drops : %u\n", ptk_q_drop_count(&node->dp_ctx->dp_recvr_pkt_q));
}

void
init_node_nw_prop(node_t *node, node_nw_prop_t *node_nw_prop) {

    node_nw_prop->flags = 0;
    memset(node_nw_prop->rtr_id.ip_addr, 0, 16);
    node_nw_prop->nve = nullptr;  /* Initialize NVE interface pointer */
    node_nw_prop->def_vrf = vrf_def_init(node);
    cp2dp_vrf_create(node, DEF_VRF_NAME, RTM_DEFAULT_VRF);
    node_assign_router_mac (node);
    node_create_vlan_flood_interface(node);
    node_create_host_path_interface (node);

    node_nw_prop->srv6_end_interface = std::make_shared<SRv6EndPointENDInterface>();
    node_nw_prop->srv6_end_interface->SetSharedPtr(node_nw_prop->srv6_end_interface);
    node_nw_prop->srv6_end_interface->att_node - node;
    node_nw_prop->srv6_end_interface->ifindex = interface_get_new_ifindex(node);
    node_nw_prop->srv6_end_interface->vrf = NODE_DEF_VRF(node);
    
    node_nw_prop->send_log_buffer = (c_string)calloc(1, TCP_PRINT_BUFFER_SIZE);
    node_nw_prop->recv_log_buffer = (c_string)calloc(1, TCP_PRINT_BUFFER_SIZE);
    node_nw_prop->log_buffer =  (c_string)calloc(1, TCP_LOG_BUFFER_LEN);
    init_tcp_logging(node);
    srv6_pool_init_srv6_pools (&node_nw_prop->srv6_sid_pools);
    lfa_init(node, &node_nw_prop->lfa);
}

