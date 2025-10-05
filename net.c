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
#include "graph.h"
#include "Layer3/rt_table/nexthop.h"
#include "Layer3/layer3.h"
#include "Layer2/layer2.h"
#include "Layer2/transport_svc.h"
#include "Layer2/mac_table.h"
#include "Interface/InterfaceUApi.h"
#include "CLIBuilder/libcli.h"
#include "common/cp2dp.h"

extern void init_arp_table(arp_table_t **arp_table);
extern void init_mac_table(mac_table_t **mac_table);
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
extern bool mac_table_entry_add(node_t *node, mac_table_t *mac_table, 
        mac_table_entry_t *mac_table_entry);
extern void l2_switch_perform_mac_learning (node_t *node, vlan_id_t vlan_id, 
        c_string src_mac, Interface *oif, uint32_t src_ip) ;
void
interface_assign_mac_address (Interface *interface){

    mac_addr_t mac_addr;
    tcp_ip_generate_random_mac_address (&mac_addr.mac);
    interface->SetMacAddr(&mac_addr);
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
}

void 
node_create_vlan_flood_interface(node_t *node) {

    node->node_nw_prop.vlan_flood_interface = 
        std::make_shared<VlanFloodInterface>();
    node->node_nw_prop.vlan_flood_interface->SetSharedPtr(
                node->node_nw_prop.vlan_flood_interface);
    node->node_nw_prop.vlan_flood_interface->att_node = node;
}

typedef struct l3_route_ l3_route_t;

bool node_set_loopback_address(node_t *node, const char *ip_addr){

    assert(ip_addr);

    node->node_nw_prop.is_lb_addr_config = true;
    string_copy((char *)NODE_LO_ADDR(node), ip_addr, 16);
    NODE_LO_ADDR(node)[15] = '\0';

    /*Add it as direct route in routing table*/
    rt_ipv4_route_add (node, 
                                    tcp_ip_convert_ip_p_to_n(ip_addr), 32, 
                                    0, 0, 0, PROTO_STATIC, true);        
    return true;
}

void 
node_set_v6_loopback_address(node_t *node, const char *ipv6_addr ){

    assert(ipv6_addr);

    inet_pton(AF_INET6, ipv6_addr, node->node_nw_prop.ipv6_addr);

    ipv6_addr_t prefix;
    memcpy (prefix.addr, node->node_nw_prop.ipv6_addr, 16);
    ipv6_route_install (node, &prefix, 128, 0, 
        0, 0, 0, 0, 0, PROTO_STATIC);
}


void 
node_set_intf_ip_address(node_t *node, const char *local_if, 
                                const char *ip_addr, char mask) {

    Interface *intf = node_get_intf_by_name(node, local_if);
    interface_set_ip_addr(node, intf, 
                                    ip_addr, mask);
}

void dump_node_nw_props(node_t *node){

    unsigned char buffer[48];

    memset (buffer, 0, sizeof(buffer));

    cprintf("\nNode Name = %s(%s) UDP Port # : %u  ",
        node->node_name, 
        tcp_ip_covert_ip_n_to_p(NODE_LO_ADDR(node),  buffer),
        node->udp_port_number);

    if (!is_ipv6_addr_unspecified (&node->node_nw_prop.ipv6_addr)) {
        
        ipv6_addr_t temp_v6_addr;
        memcpy (&temp_v6_addr.addr, node->node_nw_prop.ipv6_addr, 16);
        cprintf ("  v6lo addr : %s/128", inet_ntop6 (&temp_v6_addr, buffer));
    }

    cprintf("\n");
}

void 
dump_nw_graph(graph_t *graph, node_t *node1){

    node_t *node;
    glthread_t *curr;
    Interface *interface;

    cprintf("Topology Name = %s\n", graph->topology_name);
    
    if(!node1){
        ITERATE_GLTHREAD_BEGIN(&graph->node_list, curr){

            node = graph_glue_to_node(curr);
            dump_node_nw_props(node);
            
            ITERATE_NODE_INTERFACES_BEGIN(node, interface) {

                if(!interface) break;
                dump_intf_props(interface);

            } ITERATE_NODE_INTERFACES_END(node, interface);

            dump_intf_props (NODE_RMAC_INTF(node).get());
            dump_intf_props (NODE_VLAN_FLOOD_INTF(node).get());
            if (NODE_NVE_INTF(node)) dump_intf_props (NODE_NVE_INTF(node).get());

        } ITERATE_GLTHREAD_END(&graph->node_list, curr);
    }
    else{

        dump_node_nw_props(node1);

        ITERATE_NODE_INTERFACES_BEGIN(node1, interface) {

            if(!interface) break;
            dump_intf_props(interface);

        } ITERATE_NODE_INTERFACES_END(node1, interface);

        dump_intf_props (NODE_RMAC_INTF(node1).get());
        dump_intf_props (NODE_VLAN_FLOOD_INTF(node1).get());
        if (NODE_NVE_INTF(node1)) dump_intf_props (NODE_NVE_INTF(node1).get());

    }
}

/*Returns the local interface of the node which is configured 
 * with subnet in which 'ip_addr' lies
 * */
Interface *
node_get_matching_subnet_interface(node_t *node, c_string ip_addr){

    Interface *intf;
    uint32_t ip_addr_int;
    uint8_t mask;

    ip_addr_int =  tcp_ip_convert_ip_p_to_n (ip_addr);

     ITERATE_NODE_INTERFACES_BEGIN(node, intf) {
    
        if (!intf) continue;

        if (!intf->IsIpConfigured()) continue;
        
        if (intf->IsSameSubnet (ip_addr_int)) return intf;

    }  ITERATE_NODE_INTERFACES_END(node, intf);
    return NULL;
}

bool 
is_same_subnet(c_string ip_addr,
               char mask, 
               c_string other_ip_addr){

    byte intf_subnet[IPV4_ADDR_LEN_STR];
    byte subnet2[IPV4_ADDR_LEN_STR];

    memset(intf_subnet, 0 , 16);
    memset(subnet2, 0 , 16);

    apply_mask(ip_addr, mask, (unsigned char*)intf_subnet);
    apply_mask(other_ip_addr, mask, (unsigned char*)subnet2);

    if (string_compare(intf_subnet, subnet2, 16) == 0){
        return true;
    }
    assert(0);
    return false;
}

void
dump_interface_stats_header(){
    cprintf("\n%-20s | %10s | %10s | %15s | %9s\n", 
            "Interface Name", "PktTx", "PktRx", "Egress Dropped", "Ref Count");
    cprintf("%-20s-+-%10s-+-%10s-+-%15s-+-%9s\n", 
            "--------------------", "----------", "----------", "---------------", "---------");
}

void
dump_interface_stats(Interface *interface){

    cprintf("%-20s | %10u | %10u | %15u | %9u\n",
        interface->if_name.c_str(), 
        interface->pkt_sent,
        interface->pkt_recv,
        interface->xmit_pkt_dropped, 
        interface->GetSharedPtr().use_count() - 1);
}

void
dump_node_interface_stats(node_t *node){

    Interface *interface;

    // Print table header
    dump_interface_stats_header();

    ITERATE_NODE_INTERFACES_BEGIN(node, interface) {

        if(!interface) continue;
        dump_interface_stats(interface);

    }  ITERATE_NODE_INTERFACES_END(node, interface);
    
    dump_interface_stats(NODE_RMAC_INTF(node).get());
    dump_interface_stats(NODE_VLAN_FLOOD_INTF(node).get());
    if (NODE_NVE_INTF(node) ) dump_interface_stats(NODE_NVE_INTF(node).get());

    cprintf ("Ingress Pkt Drops : %u\n", ptk_q_drop_count(&node->dp_recvr_pkt_q));
}

void
init_node_nw_prop(node_t *node, node_nw_prop_t *node_nw_prop) {

    node_nw_prop->flags = 0;
    node_nw_prop->is_lb_addr_config = false;
    memset(node_nw_prop->lb_addr.ip_addr, 0, 16);
    init_arp_table(&(node_nw_prop->arp_table));
    init_mac_table(&(node_nw_prop->mac_table));
    node_nw_prop->vlan_vni_ht.store(nullptr);  /* Initialize atomic hashtable pointer */
    node_nw_prop->nve = nullptr;  /* Initialize NVE interface pointer */
    init_rt_table(node, &(node_nw_prop->rt_table));
    init_rtv6_table(node, &(node_nw_prop->ipv6_rt_table));
    mpls_rt_table_init (node, &(node_nw_prop->mpls_rt_table));
    ipv4_mpls_rt_table_init (node, &(node_nw_prop->ipv4_mpls_rt_table));
    node_assign_router_mac (node);
    node_create_vlan_flood_interface(node);
    node_nw_prop->send_log_buffer = (c_string)calloc(1, TCP_PRINT_BUFFER_SIZE);
    node_nw_prop->recv_log_buffer = (c_string)calloc(1, TCP_PRINT_BUFFER_SIZE);
    node_nw_prop->log_buffer =  (c_string)calloc(1, TCP_LOG_BUFFER_LEN);
    init_tcp_logging(node);
    srv6_pool_init_srv6_pools (&node_nw_prop->srv6_sid_pools);
    lfa_init(node, &node_nw_prop->lfa);
}
