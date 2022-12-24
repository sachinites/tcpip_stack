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
#include "Interface/InterfaceUApi.h"

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


/*Heuristics, Assign a unique mac address to interface*/
void
interface_assign_mac_address(Interface *interface){

    node_t *node = interface->att_node;
    
    if(!node)
        return;

    uint32_t hash_code_val = 0;
    hash_code_val = hash_code(node->node_name, NODE_NAME_SIZE);
    hash_code_val *= hash_code(interface->if_name.c_str(), IF_NAME_SIZE);
    memset(IF_MAC(interface), 0, sizeof(IF_MAC(interface)));
    memcpy(IF_MAC(interface), (char *)&hash_code_val, sizeof(uint32_t));
}

void
interface_assign_mac_address2 (Interface *interface){

    mac_addr_t mac_addr;
    node_t *node = interface->att_node;
    
    if(!node) return;

    uint32_t hash_code_val = 0;
    hash_code_val = hash_code(node->node_name, NODE_NAME_SIZE);
    hash_code_val *= hash_code(interface->if_name.c_str(), IF_NAME_SIZE);
    memcpy((void *)mac_addr.mac, (void *)hash_code_val, MAC_ADDR_SIZE);
    interface->SetMacAddr(&mac_addr);
}

typedef struct l3_route_ l3_route_t;

extern void
rt_table_add_direct_route(rt_table_t *rt_table, const c_string ip_addr, char mask); 

bool node_set_loopback_address(node_t *node, const char *ip_addr){

    assert(ip_addr);

    node->node_nw_prop.is_lb_addr_config = true;
    string_copy((char *)NODE_LO_ADDR(node), ip_addr, 16);
    NODE_LO_ADDR(node)[15] = '\0';

    /*Add it as direct route in routing table*/
    rt_table_add_direct_route(NODE_RT_TABLE(node), ip_addr, 32);     
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

    printf("\nNode Name = %s UDP Port # : %u\n",
        node->node_name, node->udp_port_number);

    printf("\t node flags : %u", node->node_nw_prop.flags);

    if(node->node_nw_prop.is_lb_addr_config){
        printf("\t  lo addr : %s/32", NODE_LO_ADDR(node));
    }

    printf("\n");
}

void dump_intf_props (Interface *interface){

    uint8_t intf_mask;
    uint32_t intf_ip_addr;
    byte intf_ip_addr_str[16];

    dump_interface(interface);

    printf("\t If Status : %s\n", interface->is_up ? "UP" : "DOWN");

    if(interface->IsIpConfigured()){
        interface->InterfaceGetIpAddressMask(&intf_ip_addr, &intf_mask);
        tcp_ip_covert_ip_n_to_p(intf_ip_addr, intf_ip_addr_str);
        printf("\t IP Addr = %s/%u", intf_ip_addr_str, intf_mask);
        printf("\t MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", 
                IF_MAC(interface)[0], IF_MAC(interface)[1],
                IF_MAC(interface)[2], IF_MAC(interface)[3],
                IF_MAC(interface)[4], IF_MAC(interface)[5]);
    }
    else
    {
        printf("\t l2 mode = %s", PhysicalInterface::L2ModeToString(interface->GetL2Mode()).c_str());
        int i = 0;
        PhysicalInterface *phyIntf = dynamic_cast<PhysicalInterface *>(interface);
        if (phyIntf)
        {
            printf("\t vlan membership : ");
            for (; i < INTF_MAX_VLAN_MEMBERSHIP; i++)
            {
                if (phyIntf->vlans[i])
                {
                    printf("%u  ", phyIntf->vlans[i]);
                }
            }
        }
        printf("\n");
    }
}

void dump_nw_graph(graph_t *graph, node_t *node1){

    node_t *node;
    glthread_t *curr;
    Interface *interface;
    uint32_t i;
    
    printf("Topology Name = %s\n", graph->topology_name);
    
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

    ip_addr_int =  tcp_ip_covert_ip_p_to_n (ip_addr);

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

/*When pkt moves from top to down in TCP/IP stack, we would need
  room in the pkt buffer to attach more new headers. Below function
  simply shifts the pkt content present in the start of the pkt buffer
  towards right so that new room is created*/
byte *
pkt_buffer_shift_right(byte *pkt,
                                    uint32_t pkt_size, 
                                    uint32_t total_buffer_size){

    byte *temp = NULL;
    bool need_temp_memory = false;

    if(pkt_size * 2 > (total_buffer_size - PKT_BUFFER_RIGHT_ROOM)){
        need_temp_memory = true;
    }
    
    if(need_temp_memory){
        temp = (byte *)calloc(1, pkt_size);
        memcpy(temp, pkt, pkt_size);
        memset(pkt, 0, total_buffer_size);
        memcpy(pkt + (total_buffer_size - pkt_size - PKT_BUFFER_RIGHT_ROOM), 
            temp, pkt_size);
        free(temp);
        return pkt + (total_buffer_size - pkt_size - PKT_BUFFER_RIGHT_ROOM);
    }
    
    memcpy(pkt + (total_buffer_size - pkt_size - PKT_BUFFER_RIGHT_ROOM), 
        pkt, pkt_size);
    memset(pkt, 0, pkt_size);
    return pkt + (total_buffer_size - pkt_size - PKT_BUFFER_RIGHT_ROOM);
}

void
dump_interface_stats(Interface *interface){

    printf("%s   ::  PktTx : %u, PktRx : %u, Pkt Egress Dropped : %u,  send rate = %lu bps",
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
        printf("\n");
    }
    printf ("Ingress Pkt Drops : %u\n", ptk_q_drop_count(&node->dp_recvr_pkt_q));
}

#if 0
static void
interface_bit_rate_sample_update(event_dispatcher_t*ev_dis,
                                                        void *arg, uint32_t arg_size) {

    (unused)ev_dis;
    (unused)arg_size;

    if (!arg) return;
    
    Interface *interface = (Interface *)arg;

    interface->intf_nw_props.bit_rate.bit_rate = 
         interface->intf_nw_props.bit_rate.new_bit_stats - 
         interface->intf_nw_props.bit_rate.old_bit_stats;

    interface->intf_nw_props.bit_rate.old_bit_stats = 
         interface->intf_nw_props.bit_rate.new_bit_stats;
}

void
intf_init_bit_rate_sampling_timer(Interface *interface) {

    wheel_timer_elem_t *wt_elem =
        interface->intf_nw_props.bit_rate.bit_rate_sampling_timer;

    assert(!wt_elem);

    wheel_timer_t *timer = DP_TIMER(interface->att_node);
    assert(timer);

    interface->intf_nw_props.bit_rate.bit_rate_sampling_timer =
        timer_register_app_event(timer, 
                                                 interface_bit_rate_sample_update,
                                                (void *)interface,
                                                sizeof(*interface),
                                                1000,
                                                1);
}
#endif