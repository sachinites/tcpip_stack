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
#include <arpa/inet.h> /*for inet_ntop & inet_pton*/
#include <memory.h>
#include <stdlib.h>
#include "graph.h"
#include "../Layer2/layer2.h"
#include "../Layer5/layer5.h"
#include "layer3.h"
#include "tcpconst.h"
#include "comm.h"
#include "netfilter.h"
#include "../notif.h"
#include "rt_notif.h"
#include "../LinuxMemoryManager/uapi_mm.h"

extern void
spf_flush_nexthops(nexthop_t **nexthop);

extern void
rt_table_kick_start_notif_job(rt_table_t *rt_table) ;

extern void
rt_table_add_route_to_notify_list (
                rt_table_t *rt_table, 
                l3_route_t *l3route,
                uint8_t flag);

/*L3 layer recv pkt from below Layer 2. Layer 2 hdr has been
 * chopped off already.*/
static bool
l3_is_direct_route(l3_route_t *l3_route){

    return (l3_route->is_direct);
}

/* 
 * Check if dst_ip exact matches with any locally configured
 * ip address of the router
*/
static bool
is_layer3_local_delivery(node_t *node, uint32_t dst_ip){

    char dest_ip_str[16];
    dest_ip_str[15] = '\0';
    char *intf_addr = NULL;

    dst_ip = htonl(dst_ip);
    inet_ntop(AF_INET, &dst_ip, dest_ip_str, 16);

    /*checking with node's loopback address*/
    if(strncmp(NODE_LO_ADDR(node), dest_ip_str, 16) == 0)
        return true;

    /*checking with interface IP Addresses*/
    uint32_t i = 0;
    interface_t *intf;

    for( ; i < MAX_INTF_PER_NODE; i++){
        
        intf = node->intf[i];
        if(!intf) return false;

        if(intf->intf_nw_props.is_ipadd_config == false)
            continue;

        intf_addr = IF_IP(intf);

        if(strncmp(intf_addr, dest_ip_str, 16) == 0)
            return true;
    }
    return false;
}

extern void
promote_pkt_to_layer4(node_t *node, interface_t *recv_intf, 
                      char *l4_hdr, uint32_t pkt_size,
                      int L4_protocol_number);

/*import function from layer 2*/
extern void
demote_pkt_to_layer2(node_t *node,
                     uint32_t next_hop_ip,
                     char *outgoing_intf, 
                     char *pkt, uint32_t pkt_size,
                     int protocol_number);


static void
layer3_ip_pkt_recv_from_layer2(node_t *node,
							   interface_t *interface,
					           char *pkt,
							   uint32_t pkt_size) {

    int8_t nf_result;
    char *l4_hdr, *l5_hdr;
    char dest_ip_addr[16];
    ip_hdr_t *ip_hdr = NULL;
    ethernet_hdr_t *eth_hdr = NULL;
    
	eth_hdr = (ethernet_hdr_t *)pkt;
    ip_hdr = (ip_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr); 

    uint32_t dst_ip = htonl(ip_hdr->dst_ip);
    inet_ntop(AF_INET, &dst_ip, dest_ip_addr, 16);

    nf_result = nf_invoke_netfilter_hook(
            NF_IP_PRE_ROUTING,
            pkt, pkt_size, node,
            interface,
            ETH_HDR);

    switch(nf_result) {
        case NF_ACCEPT:
        break;
        case NF_DROP:
        case NF_STOLEN:
        case NF_STOP:
        return;
    }

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
                case MTCP:
                    promote_pkt_to_layer4(node, interface, 
								(char *)eth_hdr, pkt_size, ip_hdr->protocol);
                    break;
                case ICMP_PRO:
                    //printf("\nIP Address : %s, ping success\n", dest_ip_addr);
                    break;
                case IP_IN_IP:
                    /*Packet has reached ERO, now set the packet onto its new 
                      Journey from ERO to final destination*/
                    layer3_ip_pkt_recv_from_layer2(node,
									interface, 
		                            (char *)INCREMENT_IPHDR(ip_hdr),
        		                    IP_HDR_PAYLOAD_SIZE(ip_hdr));
                    return;
                default:
                    ;
            }
			promote_pkt_from_layer3_to_layer5(node, interface,
											  (char *)eth_hdr,
											   pkt_size, ETH_HDR);
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
	if(!nexthop) return;

    nf_result = nf_invoke_netfilter_hook(
                    NF_IP_FORWARD,
		            (char *)ip_hdr,
                    pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD,
		            node, nexthop->oif,
                    IP_HDR);

    switch (nf_result) {
    case NF_ACCEPT:
        break;
    case NF_DROP:
    case NF_STOLEN:
    case NF_STOP:
        return;
    }

    inet_pton(AF_INET, nexthop->gw_ip, &next_hop_ip);
    next_hop_ip = htonl(next_hop_ip);
   
    tcp_dump_l3_fwding_logger(node, 
        nexthop->oif->if_name, nexthop->gw_ip);

    nf_result = nf_invoke_netfilter_hook(
                    NF_IP_POST_ROUTING,
		            (char *)ip_hdr,
                    pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD,
		            node, nexthop->oif,
                    IP_HDR);

    switch (nf_result) {
    case NF_ACCEPT:
        break;
    case NF_DROP:
    case NF_STOLEN:
    case NF_STOP:
        return;
    }

    demote_pkt_to_layer2(node, 
            next_hop_ip,
            nexthop->oif->if_name,
            (char *)ip_hdr, pkt_size,
            ETH_IP); /*Network Layer need to tell Data link layer, 
                       what type of payload it is passing down*/
            nexthop->hit_count++;
}


/*Implementing Routing Table APIs*/
void
init_rt_table(node_t *node, rt_table_t **rt_table){

    *rt_table = XCALLOC(0, 1, rt_table_t);
    init_glthread(&((*rt_table)->route_list));
	(*rt_table)->is_active = true;
    strncpy( (*rt_table)->nfc_rt_updates.nfc_name, 
                 "NFC for IPV4 RT UPDATES",
                 sizeof((*rt_table)->nfc_rt_updates.nfc_name));
    init_glthread(&((*rt_table)->nfc_rt_updates.notif_chain_head));
    (*rt_table)->node = node;
}

void
rt_table_set_active_status(rt_table_t *rt_table, bool active){
	rt_table->is_active = active;
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
l3_route_free(l3_route_t *l3_route){

    assert(IS_GLTHREAD_LIST_EMPTY(&l3_route->rt_glue));
    assert(IS_GLTHREAD_LIST_EMPTY(&l3_route->notif_glue));
    assert(IS_GLTHREAD_LIST_EMPTY(&l3_route->flash_glue));
    spf_flush_nexthops(l3_route->nexthops);
    XFREE(l3_route);
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
        rt_table_add_route_to_notify_list(rt_table, l3_route, RT_DEL_F);
    } ITERATE_GLTHREAD_END(&rt_table->route_list, curr);
     rt_table_kick_start_notif_job(rt_table);
}

nexthop_t *
l3_route_get_active_nexthop(l3_route_t *l3_route){

    if(l3_is_direct_route(l3_route))
        return NULL;
    
    nexthop_t *nexthop = l3_route->nexthops[l3_route->nxthop_idx];

	if(!nexthop) return NULL;

    l3_route->nxthop_idx++;

    if(l3_route->nxthop_idx == MAX_NXT_HOPS || 
        !l3_route->nexthops[l3_route->nxthop_idx]){
        l3_route->nxthop_idx = 0;
    }
    return nexthop;
}


void
rt_table_delete_route(rt_table_t *rt_table, 
        char *ip_addr, char mask){

    char dst_str_with_mask[16];
    
    apply_mask(ip_addr, mask, dst_str_with_mask); 
    l3_route_t *l3_route = rt_table_lookup(rt_table, dst_str_with_mask, mask);

    if(!l3_route)
        return;

    remove_glthread(&l3_route->rt_glue);
    rt_table_add_route_to_notify_list (rt_table, l3_route, RT_DEL_F);
    rt_table_kick_start_notif_job(rt_table);
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
    int count = 0;
    glthread_t *curr = NULL;
    l3_route_t *l3_route = NULL;
    
    printf("L3 Routing Table:\n");

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, curr){

        l3_route = rt_glue_to_l3_route(curr);
        count++;
		
		if(count != 0 && (count % 20) == 0) {
			printf("continue ?\n");
			getchar();			
		}

        if(l3_route->is_direct){
            if(count != 1){
                printf("\t|===================|=======|====================|==============|==========|============|==============|\n");
            }
            else{
                printf("\t|======= IP ========|== M ==|======== Gw ========|===== Oif ====|== Cost ==|== uptime ==|=== hits =====|\n");
            }
            printf("\t|%-18s |  %-4d | %-18s | %-12s |          |  %-10s| 0            |\n", 
                    l3_route->dest, l3_route->mask, "NA", "NA",
					RT_UP_TIME(l3_route));
            continue;
        }

        for( i = 0; i < MAX_NXT_HOPS; i++){
            if(l3_route->nexthops[i]) {
                if(i == 0){
                    if(count != 1){
                        printf("\t|===================|=======|====================|==============|==========|============|==============|\n");
                    }
                    else{
                        printf("\t|======= IP ========|== M ==|======== Gw ========|===== Oif ====|== Cost ==|== uptime ==|=== hits =====|\n");
                    }
                    printf("\t|%-18s |  %-4d | %-18s | %-12s |  %-4u    |  %-10s| %-8llu     |\n", 
                            l3_route->dest, l3_route->mask,
                            l3_route->nexthops[i]->gw_ip, 
                            l3_route->nexthops[i]->oif->if_name, l3_route->spf_metric,
							RT_UP_TIME(l3_route),
                             l3_route->nexthops[i]->hit_count);
                }
                else{
                    printf("\t|                   |       | %-18s | %-12s |          |  %-10s| %-8llu     |\n", 
                            l3_route->nexthops[i]->gw_ip, 
                            l3_route->nexthops[i]->oif->if_name, "",
                            l3_route->nexthops[i]->hit_count);
                }
            }
        }
    } ITERATE_GLTHREAD_END(&rt_table->route_list, curr); 
    printf("\t|===================|=======|====================|==============|==========|============|==============|\n");
}

static bool
_rt_table_entry_add(rt_table_t *rt_table, l3_route_t *l3_route){

    init_glthread(&l3_route->rt_glue);
    glthread_add_next(&rt_table->route_list, &l3_route->rt_glue);
	l3_route->install_time = time(NULL);
    rt_table_add_route_to_notify_list (rt_table, l3_route, RT_ADD_F);
    rt_table_kick_start_notif_job(rt_table);
    return true;
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

/* 
 * Insert nexthop using insertion sort on ifindex
 * */
static bool
l3_route_insert_nexthop(l3_route_t *l3_route,
						 nexthop_t *nexthop) {

	int i;
	
	nexthop_t *temp;
	nexthop_t **nexthop_arr;

	nexthop_arr = l3_route->nexthops;

	if (nexthop_arr[MAX_NXT_HOPS - 1]) {
		
		return false;
	}	

	nexthop_arr[MAX_NXT_HOPS - 1] = nexthop;
	nexthop->ref_count++;

	i = MAX_NXT_HOPS - 1;

	while(i > 0 &&
		 (!nexthop_arr[i-1] ||
		    (nexthop_arr[i-1]->ifindex > 
		     nexthop_arr[i]->ifindex))) {
	
		temp = nexthop_arr[i-1];
		nexthop_arr[i-1] = nexthop_arr[i];
		nexthop_arr[i] = temp; 
		i--;
	}
	l3_route->install_time = time(NULL);
	return true;
}


void
rt_table_add_route(rt_table_t *rt_table,
                   char *dst, char mask,
                   char *gw, interface_t *oif,
                   uint32_t spf_metric){

   uint32_t dst_int;
   char dst_str_with_mask[16];
   bool new_route = false;

    apply_mask(dst, mask, dst_str_with_mask); 
    dst_int = tcp_ip_covert_ip_p_to_n(dst_str_with_mask);
   
   l3_route_t *l3_route = l3rib_lookup(rt_table, dst_int, mask);

   if(!l3_route){
       l3_route = XCALLOC(0, 1, l3_route_t);
       strncpy(l3_route->dest, dst_str_with_mask, 16);
       l3_route->dest[15] = '\0';
       l3_route->mask = mask;
       new_route = true;
       l3_route->is_direct = true;
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
        nexthop_t *nexthop = XCALLOC(0, 1, nexthop_t);
        l3_route->is_direct = false;
        l3_route->spf_metric = spf_metric;
        strncpy(nexthop->gw_ip, gw, 16);
        nexthop->gw_ip[15] = '\0';
        nexthop->oif = oif;
		l3_route_insert_nexthop(l3_route, nexthop);
        if (!new_route) {
            rt_table_add_route_to_notify_list (rt_table, l3_route, RT_UPDATE_F);
            rt_table_kick_start_notif_job(rt_table);
        }
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
                            int L3_protocol_type) {

    switch(L3_protocol_type){
        
        case ETH_IP:
        case IP_IN_IP:
            layer3_ip_pkt_recv_from_layer2(node, interface, pkt, pkt_size);
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
                      int L3_protocol_number) {  /*obtained from eth_hdr->type field*/
	
	_layer3_pkt_recv_from_layer2(node, interface,
				pkt, pkt_size,
				L3_protocol_number);
}

/* An API to be used by L4 or L5 to push the pkt down the TCP/IP
 * stack to layer 3*/
void
demote_packet_to_layer3(node_t *node, 
                                           char *pkt,
                                           uint32_t size,
                                           int protocol_number, /*L4 or L5 protocol type*/
                                           uint32_t dest_ip_address){

    ip_hdr_t iphdr;
    initialize_ip_hdr(&iphdr);  
      
    /*Now fill the non-default fields*/
    iphdr.protocol = protocol_number;

    uint32_t addr_int =  tcp_ip_covert_ip_p_to_n(NODE_LO_ADDR(node));
    iphdr.src_ip = addr_int;
    iphdr.dst_ip = dest_ip_address;

    iphdr.total_length = IP_HDR_COMPUTE_DEFAULT_TOTAL_LEN(size);

    char *new_pkt = NULL;
    uint32_t new_pkt_size = 0 ;

    new_pkt_size = IP_HDR_TOTAL_LEN_IN_BYTES((&iphdr));
    new_pkt = tcp_ip_get_new_pkt_buffer (new_pkt_size);

    memcpy(new_pkt, (char *)&iphdr, IP_HDR_LEN_IN_BYTES((&iphdr)));

    if(pkt && size) {
        memcpy(new_pkt + IP_HDR_LEN_IN_BYTES((&iphdr)), pkt, size);
    }

    /*Now Resolve Next hop*/
    l3_route_t *l3_route = l3rib_lookup_lpm(NODE_RT_TABLE(node), 
                                          iphdr.dst_ip);
    
    if(!l3_route){
        printf("Node : %s : No L3 route %s\n",
			node->node_name, tcp_ip_covert_ip_n_to_p(iphdr.dst_ip, 0));   
		tcp_ip_free_pkt_buffer(new_pkt, new_pkt_size);
        return;
    }

    bool is_direct_route = l3_is_direct_route(l3_route);
    
    if(is_direct_route){

        int8_t nf_result = nf_invoke_netfilter_hook(
                NF_IP_LOCAL_OUT,
				new_pkt,
                new_pkt_size,
				node, NULL,
                IP_HDR);

        switch (nf_result) {
        case NF_ACCEPT:
            break;
        case NF_DROP:
        case NF_STOLEN:
        case NF_STOP:
            return;
        }

        demote_pkt_to_layer2(node,
                         dest_ip_address,
                         0,
                         new_pkt, new_pkt_size,
                         ETH_IP);
        return;
    }

    /* If route is non direct, then ask LAyer 2 to send the pkt
     * out of all ecmp nexthops of the route*/
    uint32_t next_hop_ip;
    nexthop_t *nexthop = NULL;

    nexthop = l3_route_get_active_nexthop(l3_route);
    
    if(!nexthop){
        tcp_ip_free_pkt_buffer(new_pkt, new_pkt_size);
        return;
    }
    
    inet_pton(AF_INET, nexthop->gw_ip, &next_hop_ip);
    next_hop_ip = htonl(next_hop_ip);

    tcp_dump_l3_fwding_logger(node,
        nexthop->oif->if_name, nexthop->gw_ip);

    int8_t nf_result = nf_invoke_netfilter_hook(
            NF_IP_LOCAL_OUT,
			new_pkt,
            new_pkt_size,
			node, nexthop->oif,
            IP_HDR);

    switch (nf_result) {
    case NF_ACCEPT:
        break;
    case NF_DROP:
    case NF_STOLEN:
    case NF_STOP:
        tcp_ip_free_pkt_buffer(new_pkt, new_pkt_size);
        return;
    }

    demote_pkt_to_layer2(node,
            next_hop_ip,
            nexthop->oif->if_name,
            new_pkt, new_pkt_size,
            ETH_IP);

    nexthop->hit_count++;

    tcp_ip_free_pkt_buffer(new_pkt, new_pkt_size);
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
    ip_hdr_t *inner_ip_hdr = XCALLOC(0, 1, ip_hdr_t);
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
    XFREE(inner_ip_hdr);
}

/*Wrapper fn to be used by Applications*/
void
tcp_ip_send_ip_data(node_t *node, char *app_data, uint32_t data_size,
                    int L5_protocol_id, uint32_t dest_ip_address){

    demote_packet_to_layer3(node, app_data, data_size,
            L5_protocol_id, dest_ip_address);
}

void
interface_set_ip_addr(node_t *node, interface_t *intf, 
                                    char *intf_ip_addr, uint8_t mask) {

    uint32_t ip_addr_int;
    uint32_t if_change_flags = 0;
    intf_prop_changed_t intf_prop_changed;

    if (IS_INTF_L2_MODE(intf)) {
        printf("Error : Remove L2 config from interface first\n");
        return;
    }

    /* new config */
    if ( !IF_IP_EXIST(intf)) {
        strncpy(IF_IP(intf), intf_ip_addr, 16);
        IF_MASK(intf) = mask;
        IF_IP_EXIST(intf) = true;

        SET_BIT(if_change_flags, IF_IP_ADDR_CHANGE_F);
        ip_addr_int = tcp_ip_covert_ip_p_to_n(intf_ip_addr);
        intf_prop_changed.ip_addr.ip_addr = 0;
        intf_prop_changed.ip_addr.mask = 0;
        rt_table_add_direct_route(NODE_RT_TABLE(node), intf_ip_addr, mask);

        nfc_intf_invoke_notification_to_sbscribers(intf,  
                &intf_prop_changed, if_change_flags);
        return;
    }

    /* Existing config changed */
    if (strncmp(IF_IP(intf), intf_ip_addr, 16) || 
            IF_MASK(intf) != mask ) {

        ip_addr_int = tcp_ip_covert_ip_p_to_n(IF_IP(intf));
        intf_prop_changed.ip_addr.ip_addr = ip_addr_int;
        intf_prop_changed.ip_addr.mask = IF_MASK(intf);
        SET_BIT(if_change_flags, IF_IP_ADDR_CHANGE_F);
        rt_table_delete_route(NODE_RT_TABLE(node),  IF_IP(intf), IF_MASK(intf));
        strncpy(IF_IP(intf), intf_ip_addr, 16);
        IF_MASK(intf) = mask;
        rt_table_add_direct_route(NODE_RT_TABLE(node), IF_IP(intf), IF_MASK(intf));

         nfc_intf_invoke_notification_to_sbscribers(intf,  
                &intf_prop_changed, if_change_flags);
    }
}

void
interface_unset_ip_addr(node_t *node, interface_t *intf, 
                                        char *new_intf_ip_addr, uint8_t new_mask) {

    uint8_t mask;
    uint32_t ip_addr_int;
    uint32_t if_change_flags = 0;
    intf_prop_changed_t intf_prop_changed;

    if ( !IF_IP_EXIST(intf)) {
        return;
    }

    if (strncmp(IF_IP(intf), new_intf_ip_addr, 16)  ||
            IF_MASK(intf) != new_mask) {

        printf("Error : Non Existing IP address Specified \n");
        return;
    }

    ip_addr_int = tcp_ip_covert_ip_p_to_n(IF_IP(intf));
    mask = IF_MASK(intf);
    intf_prop_changed.ip_addr.ip_addr = ip_addr_int;
    intf_prop_changed.ip_addr.mask = mask;

    IF_IP_EXIST(intf) = false;
    SET_BIT(if_change_flags, IF_IP_ADDR_CHANGE_F);

    rt_table_delete_route(NODE_RT_TABLE(node),  new_intf_ip_addr, new_mask);

    nfc_intf_invoke_notification_to_sbscribers(intf,  
                &intf_prop_changed, if_change_flags);
}

void
layer3_mem_init() {

    MM_REG_STRUCT(0, ip_hdr_t);
    MM_REG_STRUCT(0, rt_table_t);
    MM_REG_STRUCT(0, nexthop_t);
    MM_REG_STRUCT(0, l3_route_t);
}
