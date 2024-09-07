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
#include "utils.h"
#include "tcpconst.h"
#include "notif.h"
#include "LinuxMemoryManager/uapi_mm.h"
#include "graph.h"
#include "Layer3/rt_table/nexthop.h"
#include "Layer3/layer3.h"
#include "Layer2/transport_svc.h"
#include "Interface/InterfaceUApi.h"
#include "CLIBuilder/libcli.h"

/*Just some Random number generator*/
static uint32_t
hash_code(void *ptr, uint32_t size){
    uint32_t value=0, i =0;
    char *str = (char*)ptr;
    while(i < size)
    {
        value += *str;
        value*=97;
        str++;
        i++;
    }
    return value;
}

void
interface_assign_mac_address (Interface *interface){

    mac_addr_t mac_addr;
    node_t *node = interface->att_node;
    
    if(!node) return;

    uint64_t hash_code_val = 0;
    hash_code_val = hash_code(node->node_name, NODE_NAME_SIZE);
    hash_code_val *= hash_code(interface->if_name.c_str(), IF_NAME_SIZE);
    memset (&mac_addr, 0, sizeof(mac_addr_t));
    hash_code_val = hash_code_val << 15;
    memcpy((void *)mac_addr.mac, (void *)&hash_code_val, MAC_ADDR_SIZE);
    interface->SetMacAddr(&mac_addr);
}

void 
node_assign_router_mac (node_t *node) {

    uint32_t hash_code_val = 0;
    hash_code_val = hash_code(node->node_name, NODE_NAME_SIZE );
    hash_code_val *= hash_code_val;
    hash_code_val = hash_code_val << 15;
    memcpy((void *)node->node_nw_prop.rmac.mac, (void *)&hash_code_val, MAC_ADDR_SIZE );
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
node_set_intf_ip_address(node_t *node, const char *local_if, 
                                const char *ip_addr, char mask) {

    Interface *intf = node_get_intf_by_name(node, local_if);
    interface_set_ip_addr(node, intf, 
                                    ip_addr, mask);
}

void dump_node_nw_props(node_t *node){

    cprintf("\nNode Name = %s(%p) UDP Port # : %u\n",
        node->node_name, node, node->udp_port_number);

    cprintf("\t node flags : %u", node->node_nw_prop.flags);

    if(node->node_nw_prop.is_lb_addr_config){
        cprintf("\t  lo addr : %s/32", NODE_LO_ADDR(node));
    }

    cprintf("\n");
}

void 
dump_intf_props (Interface *interface){

    uint8_t intf_mask;
    uint32_t intf_ip_addr;
    byte intf_ip_addr_str[16];
    mac_addr_t *mac_addr;

    dump_interface(interface);

    cprintf("\t If Status : %s\n", interface->is_up ? "UP" : "DOWN");

    if (interface->IsIpConfigured()) {

        interface->InterfaceGetIpAddressMask(&intf_ip_addr, &intf_mask);
        tcp_ip_covert_ip_n_to_p(intf_ip_addr, intf_ip_addr_str);
        cprintf("\t IP Addr = %s/%u", intf_ip_addr_str, intf_mask);

        mac_addr = interface->GetMacAddr();
        if (!mac_addr) {
            cprintf("\t MAC : Nil\n");
        }
        else {
            cprintf("\t MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
                   mac_addr->mac[0], mac_addr->mac[1],
                   mac_addr->mac[2], mac_addr->mac[3],
                   mac_addr->mac[4], mac_addr->mac[5]);
        }
    }
    else
    {
        cprintf("\t l2 mode = %s", PhysicalInterface::L2ModeToString(interface->GetL2Mode()).c_str());

        PhysicalInterface *phyIntf = dynamic_cast<PhysicalInterface *>(interface);

        if (phyIntf) {

            if (interface->GetL2Mode() == LAN_ACCESS_MODE) {
                 cprintf("\t vlan membership : %u", phyIntf->access_vlan_intf->GetVlanId());
            }
            else if (interface->GetL2Mode() == LAN_TRUNK_MODE) {
                cprintf ("\t transport svc profile : %s", phyIntf->trans_svc->trans_svc.c_str());
            }
        }
        cprintf("\n");
    }
}

void 
dump_nw_graph(graph_t *graph, node_t *node1){

    uint32_t i;
    node_t *node;
    glthread_t *curr;
    Interface *interface;

    cprintf("Topology Name = %s\n", graph->topology_name);
    
    if(!node1){
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
    else{
        dump_node_nw_props(node1);
        for( i = 0; i < MAX_INTF_PER_NODE; i++){
            interface = node1->intf[i];
            if(!interface) break;
            dump_intf_props(interface);
        }
    }
}

/*Returns the local interface of the node which is configured 
 * with subnet in which 'ip_addr' lies
 * */
Interface *
node_get_matching_subnet_interface(node_t *node, c_string ip_addr){

    uint32_t i = 0;
    Interface *intf;
    uint32_t ip_addr_int;
    uint8_t mask;

    ip_addr_int =  tcp_ip_convert_ip_p_to_n (ip_addr);

    for( ; i < MAX_INTF_PER_NODE; i++){
    
        intf = node->intf[i];
        if (!intf) continue;

        if (!intf->IsIpConfigured()) continue;
        
        if (intf->IsSameSubnet (ip_addr_int)) return intf;
    }
    return NULL;
}

bool 
is_same_subnet(c_string ip_addr,
               char mask, 
               c_string other_ip_addr){

    byte intf_subnet[16];
    byte subnet2[16];

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
dump_interface_stats(Interface *interface){

    cprintf("%s   ::  PktTx : %u, PktRx : %u, Pkt Egress Dropped : %u",
        interface->if_name.c_str(), interface->pkt_sent,
        interface->pkt_recv,
		interface->xmit_pkt_dropped);
}

void
dump_node_interface_stats(node_t *node){

    Interface *interface;

    uint32_t i = 0;

    for(; i < MAX_INTF_PER_NODE; i++){
        interface = node->intf[i];
        if(!interface)
            continue;
        dump_interface_stats(interface);
        cprintf("\n");
    }
    cprintf ("Ingress Pkt Drops : %u\n", ptk_q_drop_count(&node->dp_recvr_pkt_q));
}
