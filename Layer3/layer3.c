/*
 * =====================================================================================
 *
 *       Filename:  layer3.c
 *
 *    Description:  This file defines the routines for Layer 3
 *
 *        Version:  1.0
 *        Created:  Friday 20 September 2019 05:24:38  IST
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
#include "graph.h"
#include "../Layer2/layer2.h"
#include "layer3.h"
#include <sys/socket.h>
#include <memory.h>
#include <stdlib.h>
#include "tcpconst.h"
#include "comm.h"
#include <arpa/inet.h> /*for inet_ntop & inet_pton*/

/*Layer 3 Globals : */

/* to decide that whenever layer promote pkt to upper layer of
 * TCP/IP stack, should layer 3 chop-off ip hdr or handover the pkt
 * to upper layer along with ip hdr intact*/
static uint8_t
l3_proto_include_l3_hdr[MAX_L3_PROTO_INCLUSION_SUPPORTED];

static bool_t
should_include_l3_hdr(uint32_t L3_protocol_no){

    int i = 0;
    for( ; i < MAX_L3_PROTO_INCLUSION_SUPPORTED; i++){
        if(l3_proto_include_l3_hdr[i] == L3_protocol_no)
            return TRUE;
    }
    return FALSE;
}

void
tcp_ip_stack_register_l3_proto_for_l3_hdr_inclusion(
        uint8_t L3_protocol_no){

    int i = 0, j = 0;
    for( ; i < MAX_L3_PROTO_INCLUSION_SUPPORTED; i++){
        if(l3_proto_include_l3_hdr[i] == L3_protocol_no)
            return;
        if(l3_proto_include_l3_hdr[i] == 0){
            j = i;
        }
    }
    if(j){
        l3_proto_include_l3_hdr[j] = L3_protocol_no;
        return;
    }
    printf("Error : Could not register L3 protocol %d for l3 Hdr inclusion",
            L3_protocol_no);
}

void
tcp_ip_stack_unregister_l3_proto_for_l3_hdr_inclusion(
        uint8_t L3_protocol_no){

    int i = 0;
    for( ; i < MAX_L3_PROTO_INCLUSION_SUPPORTED; i++){
        if(l3_proto_include_l3_hdr[i] == L3_protocol_no){
            l3_proto_include_l3_hdr[i] = 0;
            return;
        }
    }
}

extern void
spf_flush_nexthops(nexthop_t **nexthop);

/*L3 layer recv pkt from below Layer 2. Layer 2 hdr has been
 * chopped off already.*/
static bool_t
l3_is_direct_route(l3_route_t *l3_route){

    return (l3_route->is_direct);
}

static bool_t
is_layer3_local_delivery(node_t *node, uint32_t dst_ip){

    /* Check if dst_ip exact matches with any locally configured
     * ip address of the router*/

    /*checking with node's loopback address*/
    char dest_ip_str[16];
    dest_ip_str[15] = '\0';
    char *intf_addr = NULL;

    dst_ip = htonl(dst_ip);
    inet_ntop(AF_INET, &dst_ip, dest_ip_str, 16);

    if(strncmp(NODE_LO_ADDR(node), dest_ip_str, 16) == 0)
        return TRUE;

    /*checking with interface IP Addresses*/

    uint32_t i = 0;
    interface_t *intf;

    for( ; i < MAX_INTF_PER_NODE; i++){
        
        intf = node->intf[i];
        if(!intf) return FALSE;

        if(intf->intf_nw_props.is_ipadd_config == FALSE)
            continue;

        intf_addr = IF_IP(intf);

        if(strncmp(intf_addr, dest_ip_str, 16) == 0)
            return TRUE;
    }
    return FALSE;
}

extern void
promote_pkt_to_layer4(node_t *node, interface_t *recv_intf, 
                      char *l4_hdr, uint32_t pkt_size,
                      int L4_protocol_number, uint32_t flags);

extern void
promote_pkt_to_layer5(node_t *node, interface_t *recv_intf, 
                      char *l5_hdr, uint32_t pkt_size,
                      uint32_t L5_protocol, uint32_t flags);

/*import function from layer 2*/
extern void
demote_pkt_to_layer2(node_t *node,
                     uint32_t next_hop_ip,
                     char *outgoing_intf, 
                     char *pkt, uint32_t pkt_size,
                     int protocol_number);


static void
layer3_ip_pkt_recv_from_layer2(node_t *node, interface_t *interface,
        char *pkt, uint32_t pkt_size, uint32_t flags){

    char *l4_hdr, *l5_hdr;
    char dest_ip_addr[16];
    ip_hdr_t *ip_hdr = NULL;
    ethernet_hdr_t *eth_hdr = NULL;
    bool_t include_ip_hdr;

    if(flags & DATA_LINK_HDR_INCLUDED){
        eth_hdr = (ethernet_hdr_t *)pkt;
        ip_hdr = (ip_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr); 
    }
    else{
        ip_hdr = (ip_hdr_t *)pkt;
    }

    uint32_t dst_ip = htonl(ip_hdr->dst_ip);
    inet_ntop(AF_INET, &dst_ip, dest_ip_addr, 16);

    /*Implement Layer 3 forwarding functionality*/

    l3_route_t *l3_route = l3rib_lookup_lpm(NODE_RT_TABLE(node), ip_hdr->dst_ip);

    if(!l3_route){
        /*Router do not know what to do with the pkt. drop it*/
        printf("Router %s : Cannot Route IP : %s\n", 
                    node->node_name, dest_ip_addr);
        return;
    }

    /*L3 route exist, 3 cases now : 
     * case 1 : pkt is destined to self(this router only)
     * case 2 : pkt is destined for host machine connected to directly attached subnet
     * case 3 : pkt is to be forwarded to next router*/

    if(l3_is_direct_route(l3_route)){

        /* case 1 and case 2 are possible here*/

        /* case 1 : local delivery:  dst ip address in pkt must exact match with
         * ip of any local interface of the router, including loopback*/

        if(is_layer3_local_delivery(node, ip_hdr->dst_ip)){

            l4_hdr = (char *)INCREMENT_IPHDR(ip_hdr);
            l5_hdr = l4_hdr;

            switch(ip_hdr->protocol){
                /* chop off the L3 hdr and promote the pkt to transport layer. If transport Layer
                 * Protocol is not specified, then promote the packet directly to application layer
                 * */
                case MTCP:
                    include_ip_hdr = should_include_l3_hdr(ip_hdr->protocol); 
                    promote_pkt_to_layer4(node, interface, 
                        eth_hdr ? (char *)eth_hdr : (include_ip_hdr ? (char *)ip_hdr : l4_hdr),
                        eth_hdr ? pkt_size : include_ip_hdr ? pkt_size : IP_HDR_PAYLOAD_SIZE(ip_hdr),
                        ip_hdr->protocol, flags | (include_ip_hdr ? IP_HDR_INCLUDED : 0));
                    break;
                case ICMP_PRO:
                    printf("\nIP Address : %s, ping success\n", dest_ip_addr);
                    break;
                case IP_IN_IP:
                    /*Packet has reached ERO, now set the packet onto its new 
                      Journey from ERO to final destination*/
                    layer3_ip_pkt_recv_from_layer2(node, interface, 
                            (char *)INCREMENT_IPHDR(ip_hdr),
                            IP_HDR_PAYLOAD_SIZE(ip_hdr), 0);
                    return;
                //case DDCP_MSG_TYPE_UCAST_REPLY:
                case USERAPP1:
                    include_ip_hdr = should_include_l3_hdr(ip_hdr->protocol);
                    promote_pkt_to_layer5(node, interface, 
                        eth_hdr ? (char *)eth_hdr : (include_ip_hdr ? (char *)ip_hdr : l5_hdr),
                        eth_hdr ? pkt_size : include_ip_hdr ? pkt_size : IP_HDR_PAYLOAD_SIZE(ip_hdr),
                        ip_hdr->protocol, flags | (include_ip_hdr) ? IP_HDR_INCLUDED : 0);
                    break;
                default:
                    include_ip_hdr = should_include_l3_hdr(ip_hdr->protocol);
                    promote_pkt_to_layer5(node, interface, 
                        eth_hdr ? (char *)eth_hdr : include_ip_hdr ? (char *)ip_hdr : l5_hdr,
                        eth_hdr ? pkt_size : include_ip_hdr ? pkt_size : IP_HDR_PAYLOAD_SIZE(ip_hdr),
                        ip_hdr->protocol, flags | (include_ip_hdr) ? IP_HDR_INCLUDED : 0);
                    ;
            }
            return;
        }
        /* case 2 : It means, the dst ip address lies in direct connected
         * subnet of this router, time for l2 routing*/

        demote_pkt_to_layer2(
                node,           /*Current processing node*/
                0,              /*Dont know next hop IP as dest is present in local subnet*/
                NULL,           /*No oif as dest is present in local subnet*/
                (char *)ip_hdr, pkt_size,  /*Network Layer payload and size*/
                ETH_IP);        /*Network Layer need to tell Data link layer, what type of payload it is passing down*/
        return;
    }

    /*case 3 : L3 forwarding case*/

    ip_hdr->ttl--;

    if(ip_hdr->ttl == 0){
        /*drop the pkt*/
        return;
    }

    /* If route is non direct, then ask LAyer 2 to send the pkt
     * out of all ecmp nexthops of the route*/
    uint32_t next_hop_ip;
    nexthop_t *nexthop = NULL;

    nexthop = l3_route_get_active_nexthop(l3_route);
    assert(nexthop);
    
    inet_pton(AF_INET, nexthop->gw_ip, &next_hop_ip);
    next_hop_ip = htonl(next_hop_ip);
   
    tcp_dump_l3_fwding_logger(node, 
        nexthop->oif->if_name, nexthop->gw_ip);

    demote_pkt_to_layer2(node, 
            next_hop_ip,
            nexthop->oif->if_name,
            (char *)ip_hdr, pkt_size,
            ETH_IP); /*Network Layer need to tell Data link layer, 
                       what type of payload it is passing down*/
}


/*Implementing Routing Table APIs*/
void
init_rt_table(rt_table_t **rt_table){

    *rt_table = calloc(1, sizeof(rt_table_t));
    init_glthread(&((*rt_table)->route_list));
}

l3_route_t *
rt_table_lookup(rt_table_t *rt_table, char *ip_addr, char mask){
    
    glthread_t *curr;
    l3_route_t *l3_route;

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, curr){

        l3_route = rt_glue_to_l3_route(curr);
        if(strncmp(l3_route->dest, ip_addr, 16) == 0 && 
                l3_route->mask == mask){
            return l3_route;
        }
    } ITERATE_GLTHREAD_END(&rt_table->route_list, curr);
}

static void
l3_route_free(l3_route_t *l3_route){

    assert(IS_GLTHREAD_LIST_EMPTY(&l3_route->rt_glue));
    spf_flush_nexthops(l3_route->nexthops);
    free(l3_route);
}

void
clear_rt_table(rt_table_t *rt_table){

    glthread_t *curr;
    l3_route_t *l3_route;

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, curr){

        l3_route = rt_glue_to_l3_route(curr);
        if(l3_is_direct_route(l3_route))
            continue;
        remove_glthread(curr);
        l3_route_free(l3_route);
    } ITERATE_GLTHREAD_END(&rt_table->route_list, curr);
}

nexthop_t *
l3_route_get_active_nexthop(l3_route_t *l3_route){

    if(l3_is_direct_route(l3_route))
        return NULL;
    
    nexthop_t *nexthop = l3_route->nexthops[l3_route->nxthop_idx];
    assert(nexthop);

    l3_route->nxthop_idx++;

    if(l3_route->nxthop_idx == MAX_NXT_HOPS || 
        !l3_route->nexthops[l3_route->nxthop_idx]){
        l3_route->nxthop_idx = 0;
    }
    return nexthop;
}


void
delete_rt_table_entry(rt_table_t *rt_table, 
        char *ip_addr, char mask){

    char dst_str_with_mask[16];
    
    apply_mask(ip_addr, mask, dst_str_with_mask); 
    l3_route_t *l3_route = rt_table_lookup(rt_table, dst_str_with_mask, mask);

    if(!l3_route)
        return;

    remove_glthread(&l3_route->rt_glue);
    l3_route_free(l3_route);
}

/*Look up L3 routing table using longest prefix match*/
l3_route_t *
l3rib_lookup_lpm(rt_table_t *rt_table, 
                 uint32_t dest_ip){

    l3_route_t *l3_route = NULL,
    *lpm_l3_route = NULL,
    *default_l3_rt = NULL;

    glthread_t *curr = NULL;
    char subnet[16];
    char dest_ip_str[16];
    char longest_mask = 0;
   
    dest_ip = htonl(dest_ip); 
    inet_ntop(AF_INET, &dest_ip, dest_ip_str, 16);
    dest_ip_str[15] = '\0';
     
    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, curr){

        l3_route = rt_glue_to_l3_route(curr);
        memset(subnet, 0, 16);
        apply_mask(dest_ip_str, l3_route->mask, subnet);

        if(strncmp("0.0.0.0", l3_route->dest, 16) == 0 &&
                l3_route->mask == 0){
            default_l3_rt = l3_route;
        }
        else if(strncmp(subnet, l3_route->dest, strlen(subnet)) == 0){
            if( l3_route->mask > longest_mask){
                longest_mask = l3_route->mask;
                lpm_l3_route = l3_route;
            }
        }
    }ITERATE_GLTHREAD_END(&rt_table->route_list, curr);
    return lpm_l3_route ? lpm_l3_route : default_l3_rt;
}

void
dump_rt_table(rt_table_t *rt_table){

    int i = 0;
    glthread_t *curr = NULL;
    l3_route_t *l3_route = NULL;
    int count = 0;
    printf("L3 Routing Table:\n");
    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, curr){

        l3_route = rt_glue_to_l3_route(curr);
        count++;
        if(l3_route->is_direct){
            if(count != 1){
                printf("\t|===================|=======|====================|==============|==========|\n");
            }
            else{
                printf("\t|======= IP ========|== M ==|======== Gw ========|===== Oif ====|== Cost ==|\n");
            }
            printf("\t|%-18s |  %-4d | %-18s | %-12s |          |\n", 
                    l3_route->dest, l3_route->mask, "NA", "NA");
            continue;
        }

        for( i = 0; i < MAX_NXT_HOPS; i++){
            if(l3_route->nexthops[i]){
                if(i == 0){
                    if(count != 1){
                        printf("\t|===================|=======|====================|==============|==========|\n");
                    }
                    else{
                        printf("\t|======= IP ========|== M ==|======== Gw ========|===== Oif ====|== Cost ==|\n");
                    }
                    printf("\t|%-18s |  %-4d | %-18s | %-12s |  %-4u    |\n", 
                            l3_route->dest, l3_route->mask,
                            l3_route->nexthops[i]->gw_ip, 
                            l3_route->nexthops[i]->oif->if_name, l3_route->spf_metric);
                }
                else{
                    printf("\t|                   |       | %-18s | %-12s |          |\n", 
                            l3_route->nexthops[i]->gw_ip, 
                            l3_route->nexthops[i]->oif->if_name);
                }
            }
        }
    } ITERATE_GLTHREAD_END(&rt_table->route_list, curr); 
    printf("\t|===================|=======|====================|==============|==========|\n");
}

static bool_t
_rt_table_entry_add(rt_table_t *rt_table, l3_route_t *l3_route){

    init_glthread(&l3_route->rt_glue);
    glthread_add_next(&rt_table->route_list, &l3_route->rt_glue);
    return TRUE;
}

void
rt_table_add_direct_route(rt_table_t *rt_table,
                          char *dst, char mask){

    rt_table_add_route(rt_table, dst, mask, 0, 0, 0);
}

l3_route_t *
l3rib_lookup(rt_table_t *rt_table, 
             uint32_t dest_ip, 
             char mask){

    char dest_ip_str[16];
    glthread_t *curr = NULL;
    char dst_str_with_mask[16];
    l3_route_t *l3_route = NULL;

    tcp_ip_covert_ip_n_to_p(dest_ip, dest_ip_str);

    apply_mask(dest_ip_str, mask, dst_str_with_mask);

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, curr){

        l3_route = rt_glue_to_l3_route(curr);
        
        if(strncmp(dst_str_with_mask, l3_route->dest, 16) == 0 &&
            l3_route->mask == mask){
            return l3_route;
        }
    } ITERATE_GLTHREAD_END(&rt_table->route_list, curr);

    return NULL;
}


void
rt_table_add_route(rt_table_t *rt_table,
                   char *dst, char mask,
                   char *gw, interface_t *oif,
                   uint32_t spf_metric){

   uint32_t dst_int;
   char dst_str_with_mask[16];
   bool_t new_route = FALSE;

   apply_mask(dst, mask, dst_str_with_mask); 
   inet_pton(AF_INET, dst_str_with_mask, &dst_int);
   dst_int = htonl(dst_int);

   l3_route_t *l3_route = l3rib_lookup(rt_table, dst_int, mask);

   if(!l3_route){
       l3_route = calloc(1, sizeof(l3_route_t));
       strncpy(l3_route->dest, dst_str_with_mask, 16);
       l3_route->dest[15] = '\0';
       l3_route->mask = mask;
       new_route = TRUE;
       l3_route->is_direct = TRUE;
   }
   
   int i = 0;

   /*Get the index into nexthop array to fill the new nexthop*/
   if(!new_route){
       for( ; i < MAX_NXT_HOPS; i++){

           if(l3_route->nexthops[i]){
                if(strncmp(l3_route->nexthops[i]->gw_ip, gw, 16) == 0 && 
                    l3_route->nexthops[i]->oif == oif){ 
                    printf("Error : Attempt to Add Duplicate Route\n");
                    return;
                }
           }
           else break;
       }
   }

   if( i == MAX_NXT_HOPS){
        printf("Error : No Nexthop space left for route %s/%u\n", 
            dst_str_with_mask, mask);
        return;
   }

   if(gw && oif){
        nexthop_t *nexthop = calloc(1, sizeof(nexthop_t));
        l3_route->nexthops[i] = nexthop;
        l3_route->is_direct = FALSE;
        l3_route->spf_metric = spf_metric;
        nexthop->ref_count++;
        strncpy(nexthop->gw_ip, gw, 16);
        nexthop->gw_ip[15] = '\0';
        nexthop->oif = oif;
   }

   if(new_route){
       if(!_rt_table_entry_add(rt_table, l3_route)){
           printf("Error : Route %s/%d Installation Failed\n", 
                   dst_str_with_mask, mask);
           l3_route_free(l3_route);   
       }
   }
}

static void
_layer3_pkt_recv_from_layer2(node_t *node, interface_t *interface,
                            char *pkt, uint32_t pkt_size, 
                            int L3_protocol_type, uint32_t flags){

    switch(L3_protocol_type){
        
        case ETH_IP:
        case IP_IN_IP:
#if 0
        case DDCP_MSG_TYPE_UCAST_REPLY:
#endif
            layer3_ip_pkt_recv_from_layer2(node, interface, pkt, pkt_size, flags);
            break;
        default:
            ;
    }
}

/* A public API to be used by L2 or other lower Layers to promote
 * pkts to Layer 3 in TCP IP Stack*/
void
promote_pkt_to_layer3(node_t *node,            /*Current node on which the pkt is received*/
                      interface_t *interface,  /*ingress interface*/
                      char *pkt, uint32_t pkt_size, /*L3 payload*/
                      int L3_protocol_number, uint32_t flags){  /*obtained from eth_hdr->type field*/

        _layer3_pkt_recv_from_layer2(node, interface, pkt, pkt_size, L3_protocol_number, flags);
}

/* An API to be used by L4 or L5 to push the pkt down the TCP/IP
 * stack to layer 3*/
void
demote_packet_to_layer3(node_t *node, 
                        char *pkt, uint32_t size,
                        int protocol_number, /*L4 or L5 protocol type*/
                        uint32_t dest_ip_address){
    ip_hdr_t iphdr;
    initialize_ip_hdr(&iphdr);  
      
    /*Now fill the non-default fields*/
    iphdr.protocol = protocol_number;

    uint32_t addr_int = 0;
    inet_pton(AF_INET, NODE_LO_ADDR(node), &addr_int);
    addr_int = htonl(addr_int);
    iphdr.src_ip = addr_int;
    iphdr.dst_ip = dest_ip_address;

    iphdr.total_length = IP_HDR_COMPUTE_DEFAULT_TOTAL_LEN(size);

    char *new_pkt = NULL;
    uint32_t new_pkt_size = 0 ;

    new_pkt_size = IP_HDR_TOTAL_LEN_IN_BYTES((&iphdr));
    new_pkt = calloc(1, MAX_PACKET_BUFFER_SIZE);

    memcpy(new_pkt, (char *)&iphdr, IP_HDR_LEN_IN_BYTES((&iphdr)));

    if(pkt && size)
        memcpy(new_pkt + IP_HDR_LEN_IN_BYTES((&iphdr)), pkt, size);

    /*Now Resolve Next hop*/
    l3_route_t *l3_route = l3rib_lookup_lpm(NODE_RT_TABLE(node), 
                                iphdr.dst_ip);
    
    if(!l3_route){
        printf("Node : %s : No L3 route\n",  node->node_name);   
		free(new_pkt);
        return;
    }

    bool_t is_direct_route = l3_is_direct_route(l3_route);
    
    char *shifted_pkt_buffer = pkt_buffer_shift_right(new_pkt, 
                    new_pkt_size, MAX_PACKET_BUFFER_SIZE);

    if(is_direct_route){
        demote_pkt_to_layer2(node,
                         dest_ip_address,
                         0,
                         shifted_pkt_buffer, new_pkt_size,
                         ETH_IP);
        return;
    }

    /* If route is non direct, then ask LAyer 2 to send the pkt
     * out of all ecmp nexthops of the route*/
    uint32_t next_hop_ip;
    nexthop_t *nexthop = NULL;

    nexthop = l3_route_get_active_nexthop(l3_route);
    
    if(!nexthop){
        free(new_pkt);
        return;
    }
    
    inet_pton(AF_INET, nexthop->gw_ip, &next_hop_ip);
    next_hop_ip = htonl(next_hop_ip);

    tcp_dump_l3_fwding_logger(node,
        nexthop->oif->if_name, nexthop->gw_ip);

    demote_pkt_to_layer2(node,
            next_hop_ip,
            nexthop->oif->if_name,
            shifted_pkt_buffer, new_pkt_size,
            ETH_IP);
    free(new_pkt);
}

/* This fn sends a dummy packet to test L3 and L2 routing
 * in the project. We send dummy Packet starting from Network
 * Layer on node 'node' to destination address 'dst_ip_addr'
 * using below fn*/
void
layer3_ping_fn(node_t *node, char *dst_ip_addr){

    uint32_t addr_int;
    
    printf("Src node : %s, Ping ip : %s\n", node->node_name, dst_ip_addr);
    
    inet_pton(AF_INET, dst_ip_addr, &addr_int);
    addr_int = htonl(addr_int);

    /* We dont have any application or transport layer paylod, so, directly prepare
     * L3 hdr*/
    demote_packet_to_layer3(node, NULL, 0, ICMP_PRO, addr_int);
}

void
layer3_ero_ping_fn(node_t *node, char *dst_ip_addr, 
                    char *ero_ip_address){

    /*Prepare the payload and push it down to the network layer.
     The payload shall be inner ip hdr*/
    ip_hdr_t *inner_ip_hdr = calloc(1, sizeof(ip_hdr_t));
    initialize_ip_hdr(inner_ip_hdr);
    inner_ip_hdr->total_length = sizeof(ip_hdr_t)/4;
    inner_ip_hdr->protocol = ICMP_PRO;
    
    uint32_t addr_int = 0;
    inet_pton(AF_INET, NODE_LO_ADDR(node), &addr_int);
    addr_int = htonl(addr_int);
    inner_ip_hdr->src_ip = addr_int;
    
    addr_int = 0;
    inet_pton(AF_INET, dst_ip_addr, &addr_int);
    addr_int = htonl(addr_int);
    inner_ip_hdr->dst_ip = addr_int;

    addr_int = 0;
    inet_pton(AF_INET, ero_ip_address, &addr_int);
    addr_int = htonl(addr_int);

    demote_packet_to_layer3(node, (char *)inner_ip_hdr, 
                            inner_ip_hdr->total_length * 4, 
                            IP_IN_IP, addr_int);
    free(inner_ip_hdr);
}

/*Wrapper fn to be used by Applications*/
void
tcp_ip_send_ip_data(node_t *node, char *app_data, uint32_t data_size,
                    int L5_protocol_id, uint32_t dest_ip_address){

    demote_packet_to_layer3(node, app_data, data_size,
            L5_protocol_id, dest_ip_address);
}
