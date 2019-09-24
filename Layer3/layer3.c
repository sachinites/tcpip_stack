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
#include "layer3.h"
#include <sys/socket.h>
#include <memory.h>
#include <stdlib.h>

void
layer3_ping_fn(node_t *node, char *dst_ip_addr){

    printf("Src node : %s, ping ip : %s\n", node->node_name, dst_ip_addr);
}

/*L3 layer recv pkt from below Layer 2. Layer 2 hdr has been
 * chopped off already.*/

static bool_t
l3_is_direct_route(l3_route_t *l3_route){

    return (l3_route->is_direct);
}

static bool_t
is_layer3_local_delivery(node_t *node, unsigned int dst_ip){

    return TRUE;
}

void
promote_pkt_to_layer4(node_t *node, interface_t *recv_intf, 
                      char *l4_hdr, unsigned int pkt_size){

}

void
layer3_pkt_push_down_to_layer2_for_l2routing(node_t *node, unsigned int dst_ip,
                                             char *outgoing_intf, 
                                             char *pkt, unsigned int pkt_size){

}
void
layer3_pkt_recv_from_layer2(node_t *node, interface_t *interface,
                char *pkt, unsigned int pkt_size){

    printf("Layer 3 Packet Recvd : Rcv Node %s, Intf : %s, data recvd : %s, pkt size : %u\n",
            node->node_name, interface->if_name, pkt, pkt_size);
    
    char *l4_hdr;

    ip_hdr_t *ip_hdr = (ip_hdr_t *)pkt;

    /*Implement Layer 3 forwarding functionality*/

    l3_route_t *l3_route = l3rib_lookup_lpm(NODE_RT_TABLE(node), ip_hdr->dst_ip);
    
    if(!l3_route){
        /*Router do not know what to do with the pkt. drop it*/
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

            l4_hdr = (char *)ip_hdr + (ip_hdr->ihl * 4);
        
            /*chop off the L3 hdr and promote the pkt to transport layer*/
            promote_pkt_to_layer4(node, interface, l4_hdr,
                ip_hdr->total_length - (ip_hdr->ihl * 4));
            return;
        }

        /* case 2 : It means, the dst ip address lies in direct connected
         * subnet of this router, time for l2 routing*/

        layer3_pkt_push_down_to_layer2_for_l2routing(
                            node,           /*Current processing node*/
                            ip_hdr->dst_ip, /*Dst ip address*/
                            NULL,           /*No oif from L3 routing table*/
                            (char *)ip_hdr, pkt_size);  /*Network Layer payload and size*/
        
        return;
    }

    /*case 3 : L3 forwarding case*/

    ip_hdr->ttl--;

    if(ip_hdr->ttl == 0){
        /*drop the pkt*/
        return;
    }

    unsigned int next_hop_ip;
    inet_pton(AF_INET, l3_route->gw_ip, &next_hop_ip);

    layer3_pkt_push_down_to_layer2_for_l2routing(node, 
                                                 htonl(next_hop_ip),
                                                 l3_route->oif,
                                                 (char *)ip_hdr, pkt_size);
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

void
clear_rt_table(rt_table_t *rt_table){

    glthread_t *curr;
    l3_route_t *l3_route;

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, curr){

        l3_route = rt_glue_to_l3_route(curr);
        remove_glthread(curr);
        free(l3_route);
    } ITERATE_GLTHREAD_END(&rt_table->route_list, curr);
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
    free(l3_route);
}

/*Look up L3 routing table using longest prefix match*/
l3_route_t *
l3rib_lookup_lpm(rt_table_t *rt_table, 
                 unsigned int dest_ip){

    l3_route_t *l3_route = NULL,
    *lpm_l3_route = NULL,
    *default_l3_rt = NULL;

    glthread_t *curr = NULL;
    char subnet[16];
    char dest_ip_str[16];
    char longest_mask = 0;

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

    glthread_t *curr = NULL;
    l3_route_t *l3_route = NULL;

    printf("L3 Routing Table:\n");
    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, curr){

        l3_route = rt_glue_to_l3_route(curr);
        printf("\t%-18s %-4d %-18s %s\n", 
                l3_route->dest, l3_route->mask,
                l3_route->is_direct ? "NA" : l3_route->gw_ip, 
                l3_route->is_direct ? "NA" : l3_route->oif);

    } ITERATE_GLTHREAD_END(&rt_table->route_list, curr); 
}

static bool_t
_rt_table_entry_add(rt_table_t *rt_table, l3_route_t *l3_route){

    l3_route_t *l3_route_old = rt_table_lookup(rt_table,
            l3_route->dest, l3_route->mask);

    if(l3_route_old &&
            IS_L3_ROUTES_EQUAL(l3_route_old, l3_route)){

        return FALSE;
    }

    if(l3_route_old){
        delete_rt_table_entry(rt_table, l3_route_old->dest, l3_route_old->mask);
    }
    init_glthread(&l3_route->rt_glue);
    glthread_add_next(&rt_table->route_list, &l3_route->rt_glue);
    return TRUE;
}

void
rt_table_add_direct_route(rt_table_t *rt_table,
                          char *dst, char mask){

    rt_table_add_route(rt_table, dst, mask, 0, 0);
}

void
rt_table_add_route(rt_table_t *rt_table,
                   char *dst, char mask,
                   char *gw, char *oif){

   unsigned int dst_int;
   char dst_str_with_mask[16];

   apply_mask(dst, mask, dst_str_with_mask); 

   inet_pton(AF_INET, dst_str_with_mask, &dst_int);
   dst_int = htonl(dst_int);

   l3_route_t *l3_route = l3rib_lookup_lpm(rt_table, dst_int);

   /*Trying to add duplicate route!!*/
   assert(!l3_route);

   l3_route = calloc(1, sizeof(l3_route_t));
   strncpy(l3_route->dest, dst_str_with_mask, 16);
   l3_route->dest[15] = '\0';
   l3_route->mask = mask;

   if(!gw && !oif)
       l3_route->is_direct = TRUE;
   else
       l3_route->is_direct = FALSE;
   
   if(gw && oif){
        strncpy(l3_route->gw_ip, gw, 16);
        l3_route->gw_ip[15] = '\0';
        strncpy(l3_route->oif, oif, IF_NAME_SIZE);
        l3_route->oif[IF_NAME_SIZE - 1] = '\0';
   }

   if(!_rt_table_entry_add(rt_table, l3_route)){
        printf("Error : Direct Route %s/%d Installation Failed\n", 
            dst_str_with_mask, mask);
        free(l3_route);   
   }
}
