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
#include <pthread.h>
#include "../common/l3_hdrs.h"
#include "../graph.h"
#include "../Layer2/layer2.h"
#include "../Layer5/layer5.h"
#include "rt_table/nexthop.h"
#include "../Threads/refcount.h"
#include "layer3.h"
#include "../tcpconst.h"
#include "../comm.h"
#include "netfilter.h"
#include "../notif.h"
#include "rt_notif.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../FireWall/acl/acldb.h"
#include "../mtrie/mtrie.h"
#include "../pkt_block.h"
#include "../prefix-list/prefixlst.h"
#include "../FireWall/Connection/conn.h"
#include "../Interface/InterfaceUApi.h"
#include "../common/cp2dp.h"
#include "../Tracer/tracer.h"

extern int
nh_flush_nexthops(nexthop_t **nexthop);

extern void
rt_table_kick_start_notif_job(rt_table_t *rt_table) ;

extern void
rt_table_add_route_to_notify_list (
                rt_table_t *rt_table, 
                l3_route_t *l3route,
                uint8_t flag);

/*L3 layer recv pkt from below Layer 2. Layer 2 hdr has been
 * chopped off already.*/
bool
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
    uint32_t intf_addr ;

    tcp_ip_covert_ip_n_to_p(dst_ip, dest_ip_str);

    /*checking with node's loopback address*/
    if(string_compare(NODE_LO_ADDR(node), dest_ip_str, 16) == 0)
        return true;

    /*checking with interface IP Addresses*/
    uint32_t i = 0;
    Interface *intf;

    for( ; i < MAX_INTF_PER_NODE; i++){
        
        intf = node->intf[i];
        if(!intf) return false;

        if (!intf->IsIpConfigured()) continue;

        intf_addr = IF_IP(intf);

        if  (intf_addr == dst_ip)  return true;
    }
    return false;
}

extern void
promote_pkt_to_layer4(node_t *node, Interface *recv_intf, 
                      pkt_block_t *pkt_block,
                      int L4_protocol_number);

/*import function from layer 2*/
extern void
demote_pkt_to_layer2(node_t *node,
                     uint32_t next_hop_ip,
                     c_string outgoing_intf, 
                     pkt_block_t *pkt_block,
                     hdr_type_t hdr_type);

void
layer3_ip_route_pkt(node_t *node,
							   Interface *interface,
					           pkt_block_t *pkt_block) {

    int8_t nf_result;
    char *l4_hdr, *l5_hdr;
    char dest_ip_addr[16];
    ip_hdr_t *ip_hdr = NULL;
    uint32_t next_hop_ip= 0;
    nexthop_t *nexthop = NULL;

    /* We are in L3 IP land, so starting hdr type must be IP_HDR */
    assert (pkt_block_get_starting_hdr(pkt_block) == IP_HDR ||
                pkt_block_get_starting_hdr(pkt_block) == IP_IN_IP_HDR);

    ip_hdr = (ip_hdr_t *)pkt_block_get_ip_hdr(pkt_block);

    tcp_ip_covert_ip_n_to_p(ip_hdr->dst_ip, (c_string)dest_ip_addr);

    tracer (node->dptr, DL3FWD, "Dest : %s : Trying to route ... \n", dest_ip_addr);

        nf_result = nf_invoke_netfilter_hook(
            NF_IP_PRE_ROUTING,
            pkt_block, 
            node,
            interface,
            IP_HDR);

    switch(nf_result) {
        case NF_ACCEPT:
        break;
        case NF_DROP:
        case NF_STOLEN:
        case NF_STOP:
        return;
    }

    if (!connection_exist (node, pkt_block)) {
        /* Access List Evaluation at Layer 3 Entry point*/
        if (interface && /* For local ping, interface will be NULL */
            access_list_evaluate_ip_packet(node, interface,
                                           ip_hdr, true) == ACL_DENY) {

            tracer (node->dptr, DL3FWD, "Pkt : %s : Pkt Dropped :  L3 ACL Denied on ingress interface %s\n",
            pkt_block_str(pkt_block), interface->if_name.c_str());
            return;
        }
    }

    tracer (node->dptr, DL3FWD_DET, "Dest : %s : Pkt Qualified L3 ACL Test\n", dest_ip_addr);

    l3_route_t *l3_route = l3rib_lookup_lpm(
                                        NODE_RT_TABLE(node), ip_hdr->dst_ip);

    if(!l3_route){
        /*Router do not know what to do with the pkt. drop it*/
        //cprintf("Router %s : Cannot Route IP : %s\n", 
        //         node->node_name, dest_ip_addr);
        tracer (node->dptr, DL3FWD | DERR, "Pkt : %s :  Pkt Dropped :  No L3 Route\n", pkt_block_str(pkt_block));
        return;
    }

    tracer (node->dptr, DL3FWD, "Pkt : %s : L3 Route Found\n", 
    pkt_block_str(pkt_block));

    /*L3 route exist, 3 cases now : 
     * case 1 : pkt is destined to self(this router only)
     * case 2 : pkt is destined for host machine connected to directly attached subnet
     * case 3 : pkt is to be forwarded to next router*/

    if (l3_is_direct_route(l3_route)){

        /* case 1 and case 2 are possible here*/

        /* case 1 : local delivery:  dst ip address in pkt must exact match with
         * ip of any local interface of the router, including loopback*/

        tracer (node->dptr, DL3FWD, "Pkt : %s : L3 Route found is local route\n", pkt_block_str(pkt_block));

        if (is_layer3_local_delivery(node, ip_hdr->dst_ip)) {

            tracer (node->dptr, DL3FWD, "Pkt : %s : Pkt is for Local Delivery, IP protocol = %s\n",   
                 pkt_block_str(pkt_block), proto_name_str(ip_hdr->protocol));

            l4_hdr = (char *)INCREMENT_IPHDR(ip_hdr);
            l5_hdr = l4_hdr;

            switch(ip_hdr->protocol) {

                case MTCP:
                    promote_pkt_to_layer4(node, interface, 
								pkt_block, ip_hdr->protocol);
                    return;

                case ICMP_PROTO:
                    cprintf("IP Address : %s, ping success\n", dest_ip_addr);
                    return;

                case UDP_PROTO:
                        promote_pkt_to_layer4 (
                                              node, interface,
											  pkt_block,
                                              UDP_HDR);
                    return;

                case PROTO_IP_IN_IP:
                    /*Packet has reached ERO, now set the packet onto its new 
                      Journey from ERO to final destination*/
                    pkt_block_set_new_pkt(pkt_block, 
                                                            (uint8_t *)INCREMENT_IPHDR(ip_hdr),
                                                            pkt_block->pkt_size - IP_HDR_LEN_IN_BYTES(ip_hdr));

                    pkt_block_set_starting_hdr_type (pkt_block, IP_IN_IP_HDR);
                     
                     tracer (node->dptr, DL3FWD, "Pkt : %s : Pkt is being subjected to L3 Routing again a per Inner Header\n", pkt_block_str (pkt_block));

                    layer3_ip_route_pkt(node,
                                                      interface, 
                                                      pkt_block);
                    return;

                case GRE_PROTO:
                    pkt_block_set_new_pkt (pkt_block, 
                                                            (uint8_t *)INCREMENT_IPHDR(ip_hdr),
                                                            pkt_block->pkt_size - IP_HDR_LEN_IN_BYTES(ip_hdr));
                    pkt_block_set_starting_hdr_type (pkt_block, GRE_HDR);
                    tracer (node->dptr, DL3FWD, "Pkt : %s : Pkt is being subjected to GRE Decapsulation\n", pkt_block_str (pkt_block));
                    gre_decapsulate (node, pkt_block, 
                        gre_lookup_tunnel_intf (node, ip_hdr->dst_ip, ip_hdr->src_ip));
                    return;

                default: ;
            }

            tracer (node->dptr, DL3FWD, "Pkt : %s : Pkt is being subjected to Layer 5\n",  pkt_block_str (pkt_block));

            promote_pkt_from_layer3_to_layer5(
                                                node, interface,
                                                pkt_block,
                                                IP_HDR);
        }
         
        /* case 2 : It means, the dst ip address lies in direct connected
         * subnet of this router, time for l2 routing*/
        nexthop = l3_route_get_active_nexthop(l3_route, pkt_block->exclude_oif);

        tracer (node->dptr, DL3FWD, "Pkt : %s :  Nexthop found OIF %s, Gw : %s\n", pkt_block_str (pkt_block), nexthop->oif->if_name.c_str(), nexthop->gw_ip);

        /* If src ip address is not feeded by application, then take the OIF IP address*/
        if (ip_hdr->src_ip == 0) {
            
            char ip_addr_str[16];
            ip_hdr->src_ip = IF_IP(nexthop->oif);
            tracer (node->dptr, DL3FWD, "Pkt: %s : Using OIF IP as Src IP : %s\n", pkt_block_str (pkt_block), tcp_ip_covert_ip_n_to_p(ip_hdr->src_ip, ip_addr_str)); 
        }

        tracer (node->dptr, DL3FWD, "Pkt : %s :  Demoting Pkt to Layer 2 for L2 Forwarding\n", pkt_block_str (pkt_block));

        demote_pkt_to_layer2 (
                node,           /*Current processing node*/
                ip_hdr->dst_ip,     /*next hop IP is dest itself as dest is present in local subnet*/
                nexthop->oif->if_name.c_str(),           /*No oif as dest is present in local subnet*/
                pkt_block,  /*Network Layer payload and size*/
                IP_HDR);        /*Network Layer need to tell Data link layer, what type of payload it is passing down*/

        nexthop->hit_count++;
        return;
    }

    /*case 3 : L3 forwarding case*/

    ip_hdr->ttl--;

    if (ip_hdr->ttl == 0) {

        tracer (node->dptr, DL3FWD, "Dest : %s :  Pkt Dropped : TTL Expired\n", dest_ip_addr);
        return;
    }

    tracer (node->dptr, DL3FWD_DET, "Dest : %s :  TTL Reduced to %d\n", dest_ip_addr, ip_hdr->ttl);

    /* If route is non direct, then ask LAyer 2 to send the pkt
     * out of all ecmp nexthops of the route*/
    nexthop = l3_route_get_active_nexthop(l3_route, pkt_block->exclude_oif);

    tracer (node->dptr, DL3FWD, "Dest : %s :  Nexthop found OIF %s, Gw : %s\n", dest_ip_addr, 
            nexthop->oif->if_name.c_str(), nexthop->gw_ip);

    nf_result = nf_invoke_netfilter_hook(
                        NF_IP_FORWARD,
                        pkt_block,
                        node, 
                        nexthop->oif,
                        IP_HDR);

    switch (nf_result) {
        case NF_ACCEPT:
            break;
        case NF_DROP:
        case NF_STOLEN:
        case NF_STOP:
        default: ;
    }

    next_hop_ip = tcp_ip_convert_ip_p_to_n(nexthop->gw_ip);
   
    tcp_dump_l3_fwding_logger(node, 
        nexthop->oif->if_name.c_str(), nexthop->gw_ip);

    nf_result = nf_invoke_netfilter_hook(
                    NF_IP_POST_ROUTING,
		            pkt_block,
		            node, nexthop->oif,
                    IP_HDR);

    switch (nf_result) {
        case NF_ACCEPT:
            break;
        case NF_DROP:
        case NF_STOLEN:
        case NF_STOP:
        break;
    }

    tracer (node->dptr, DL3FWD, "Dest : %s :  Demoting Pkt to Layer 2 for L2 Forwarding\n", dest_ip_addr);

    demote_pkt_to_layer2(node, 
            next_hop_ip,
            nexthop->oif->if_name.c_str(),
            pkt_block,
            IP_HDR); /*Network Layer need to tell Data link layer, 
                                what type of payload it is passing down*/
    nexthop->hit_count++;
}


/*Implementing Routing Table APIs*/
void
init_rt_table(node_t *node, rt_table_t **rt_table){

    *rt_table = (rt_table_t *)XCALLOC(0, 1, rt_table_t);
    
    init_mtrie (&(*rt_table)->route_list, 32, NULL);

    string_copy((char *) (*rt_table)->nfc_rt_updates.nfc_name, 
                 "NFC for IPV4 RT UPDATES",
                 sizeof((*rt_table)->nfc_rt_updates.nfc_name));

    init_glthread(&((*rt_table)->nfc_rt_updates.notif_chain_head));
    
    (*rt_table)->node = node;
}

/* MP Unsafe */
l3_route_t *
rt_table_lookup_exact_match(rt_table_t *rt_table, c_string ip_addr, char mask){
    
    uint32_t bin_ip, bin_mask;
    bitmap_t prefix_bm, mask_bm;

    bin_ip = tcp_ip_convert_ip_p_to_n(ip_addr);
    bin_ip = htonl(bin_ip);

    bin_mask = tcp_ip_convert_dmask_to_bin_mask(mask);
    bin_mask = ~bin_mask;
    bin_mask = htonl(bin_mask);

    bitmap_init(&prefix_bm, 32);
    bitmap_init(&mask_bm, 32);

    prefix_bm.bits[0] = bin_ip;
    mask_bm.bits[0] = bin_mask;

    mtrie_node_t *node = mtrie_exact_prefix_match_search(
                            &rt_table->route_list,
                            &prefix_bm,
                            &mask_bm);

    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);
    
    if (!node) {
        return NULL;
    }

    return  (l3_route_t *)node->data;
}

void
rt_table_perform_app_operation_on_routes (
                            rt_table_t *rt_table, 
                            void (*app_cbk) (mtrie_t *, mtrie_node_t *, void *)) {

    mtrie_longest_prefix_first_traverse (&rt_table->route_list, app_cbk,  NULL);
}

void
clear_rt_table (rt_table_t *rt_table, uint16_t proto_id){

    int count;
    glthread_t *curr;
    l3_route_t *l3_route;
    mtrie_node_t *mnode;

    nxthop_proto_id_t nh_proto = l3_rt_map_proto_id_to_nxthop_index(proto_id);

    curr = glthread_get_next(&rt_table->route_list.list_head);

    while(curr) {

        mnode = list_glue_to_mtrie_node(curr);

        l3_route = (l3_route_t *)mnode->data;
       assert(l3_route);

        if (l3_is_direct_route(l3_route)) {
            curr = glthread_get_next(curr);
            continue;
        }

        count = nh_flush_nexthops(l3_route->nexthops[nh_proto]);
        l3_route->nh_count -= count;
        if (l3_route->nh_count) {
            curr = glthread_get_next(curr);
            continue;
        }

       l3_route->spf_metric[nh_proto] = 0;
       curr = mtrie_node_delete_while_traversal (&rt_table->route_list, mnode);
       rt_table_add_route_to_notify_list(rt_table, l3_route, RT_DEL_F);
       l3_route_dec_ref_count(l3_route);
    }
     
     rt_table_kick_start_notif_job(rt_table);
}

nexthop_t *
l3_route_get_active_nexthop (l3_route_t *l3_route, Interface *exclude_oif) {

    int nh_index_old;
    nexthop_t *nexthop;
    nxthop_proto_id_t nh_proto;

    nh_index_old = l3_route->nxthop_idx;

    FOR_ALL_NXTHOP_PROTO(nh_proto) {

        do {

            nexthop = l3_route->nexthops[nh_proto][l3_route->nxthop_idx];

            if (!nexthop) { 

                l3_route->nxthop_idx++;

                if (l3_route->nxthop_idx == MAX_NXT_HOPS) {
                    l3_route->nxthop_idx = 0;
                }

                if (l3_route->nxthop_idx == nh_index_old) {
                    break;
                }

                continue;
            }

            if (nexthop->oif == exclude_oif && exclude_oif) {

                l3_route->nxthop_idx++;

                if (l3_route->nxthop_idx == MAX_NXT_HOPS) {
                    l3_route->nxthop_idx = 0;
                }

                if (l3_route->nxthop_idx == nh_index_old) {
                    break;
                }

                continue;
            }

            l3_route->nxthop_idx++;

            if (l3_route->nxthop_idx == MAX_NXT_HOPS) {
                l3_route->nxthop_idx = 0;
            }

            return nexthop;

        } while (1);

    }

    return NULL;
}


void
rt_table_delete_route(
        rt_table_t *rt_table, 
        c_string ip_addr,
        char mask,
        uint16_t proto_id) {

    int count;
    l3_route_t *l3_route = NULL;
    uint32_t bin_ip, bin_mask;
    bitmap_t prefix_bm, mask_bm;
    
    l3_route = rt_table_lookup_exact_match(rt_table, ip_addr, mask);

    if (!l3_route) {
        return;
    }
    
    bin_ip = tcp_ip_convert_ip_p_to_n(ip_addr);
    bin_ip = htonl(bin_ip);
    bin_mask = tcp_ip_convert_dmask_to_bin_mask((uint8_t)mask);
    bin_mask = ~bin_mask;
    bin_mask = htonl(bin_mask);

    nxthop_proto_id_t nh_proto = l3_rt_map_proto_id_to_nxthop_index(proto_id);
    count = nh_flush_nexthops(l3_route->nexthops[nh_proto]);
    l3_route->spf_metric[nh_proto] = 0;
    l3_route->nh_count -= count;

    if (l3_route->nh_count) {
        tracer(rt_table->node->dptr, DRTM, 
            "Route %s/%d : Nexthop of type %s deleted successfully from Rib\n", 
            l3_route->dest, l3_route->mask, proto_index_to_str(nh_proto));
        return;
    }

    bitmap_init(&prefix_bm, 32);
    bitmap_init(&mask_bm, 32);

    prefix_bm.bits[0] = bin_ip;
    mask_bm.bits[0] = bin_mask;

    assert (mtrie_delete_prefix(&rt_table->route_list, 
                                            &prefix_bm,
                                            &mask_bm,
                                            (void **)&l3_route) == MTRIE_DELETE_SUCCESS);

    tracer(rt_table->node->dptr, DRTM, 
        "Route %s/%d : deleted successfully from Rib\n",  l3_route->dest, l3_route->mask);

    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);
    rt_table_add_route_to_notify_list (rt_table, l3_route, RT_DEL_F);
    l3_route_dec_ref_count(l3_route);
    rt_table_kick_start_notif_job(rt_table);
}

/*Look up L3 routing table using longest prefix match
    MP Unsafe */
l3_route_t *
l3rib_lookup_lpm(rt_table_t *rt_table, 
                               uint32_t dest_ip){

    bitmap_t prefix;
    uint32_t bin_ip;
    mtrie_node_t *mnode ;

   bin_ip = htonl(dest_ip);
   bitmap_init(&prefix, 32);

   prefix.bits[0] = bin_ip;
   
   mnode = mtrie_longest_prefix_match_search(
                            &rt_table->route_list, &prefix);

    bitmap_free_internal(&prefix);

    if (!mnode) return NULL;
    assert(mnode->data);
    return (l3_route_t *)mnode->data;
}

void
dump_rt_table(rt_table_t *rt_table){

    int i = 0, nxthop_cnt = 0;
    int count = 0;
    glthread_t *curr = NULL;
    l3_route_t *l3_route = NULL;
    mtrie_node_t *mnode;
    byte time_str[HRS_MIN_SEC_FMT_TIME_LEN];

    cprintf("L3 Routing Table:\n");

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list.list_head, curr){

        mnode = list_glue_to_mtrie_node(curr);
        l3_route = (l3_route_t *)mnode->data;
        count++;
        nxthop_cnt = 0;
		
		if(count != 0 && (count % 20) == 0) {
			cprintf("continue ?\n");
			getchar();			
		}

        nxthop_proto_id_t nxthop_proto;

        FOR_ALL_NXTHOP_PROTO(nxthop_proto) {

            for( i = 0; i < MAX_NXT_HOPS; i++ ){
                if(l3_route->nexthops[nxthop_proto][i]) {
                    if(nxthop_cnt == 0){
                        if(count != 1){
                            cprintf("\t|===================|=======|============|====================|==============|==========|============|==============|\n");
                        }
                        else{
                            cprintf("\t|======= IP ========|== M ==|== proto ===|======== Gw ========|===== Oif ====|== Cost ==|== uptime ==|=== hits =====|\n");
                        }
                        cprintf("\t|%-18s |  %-4d | %-10s | %-18s | %-12s |  %-4d    |  %-10s| %-8llu     |\n", 
                                l3_route->dest, 
                                l3_route->mask,
                                proto_name_str(l3_route->nexthops[nxthop_proto][i]->proto),
                                l3_route->nexthops[nxthop_proto][i]->gw_ip, 
                                l3_route->nexthops[nxthop_proto][i]->oif->if_name.c_str(), 
                                l3_route->spf_metric[nxthop_proto],
                                RT_UP_TIME(l3_route, time_str, HRS_MIN_SEC_FMT_TIME_LEN),
                                l3_route->nexthops[nxthop_proto][i]->hit_count);
                    }
                    else if ( i == 0) {
                        /* Fst next hop of a given protocol */
                        cprintf("\t|                   |       | %-10s | %-18s | %-12s |  %-4d   |  %-10s| %-8llu     |\n", 
                                proto_name_str(l3_route->nexthops[nxthop_proto][i]->proto),
                                l3_route->nexthops[nxthop_proto][i]->gw_ip, 
                                l3_route->nexthops[nxthop_proto][i]->oif->if_name.c_str(),
                                l3_route->spf_metric[nxthop_proto],
                                "",
                                l3_route->nexthops[nxthop_proto][i]->hit_count);
                    }
                    else{
                        cprintf("\t|                   |       | %-10s | %-18s | %-12s |          |  %-10s| %-8llu     |\n", 
                                proto_name_str(l3_route->nexthops[nxthop_proto][i]->proto),
                                l3_route->nexthops[nxthop_proto][i]->gw_ip, 
                                l3_route->nexthops[nxthop_proto][i]->oif->if_name.c_str(), "",
                                l3_route->nexthops[nxthop_proto][i]->hit_count);
                    }
                    nxthop_cnt++;
                }
            }
        }
    } ITERATE_GLTHREAD_END(&rt_table->route_list, curr); 
    cprintf("\t|===================|=======|============|====================|==============|==========|============|==============|\n");
}

/* 
 * Insert nexthop using insertion sort on ifindex
 * */
static bool
l3_route_insert_nexthop(l3_route_t *l3_route,
						 nexthop_t *nexthop,
                         nxthop_proto_id_t nxthop_proto) {

	int i;
	
	nexthop_t *temp;
	nexthop_t **nexthop_arr;

	nexthop_arr = l3_route->nexthops[nxthop_proto];

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
    l3_route->nh_count++;
	return true;
}

/* Return true if policy is passed, else false */

static bool
rt_table_evaluate_import_policy(rt_table_t *rt_table, l3_route_t *l3_route) {

    uint32_t prefix;

    if (!rt_table->import_policy) return true;

    prefix = tcp_ip_convert_ip_p_to_n(l3_route->dest);

    pfx_lst_result_t policy_res = prefix_list_evaluate (
                                                    prefix,
                                                    l3_route->mask,
                                                    rt_table->import_policy) ;

    switch (policy_res) {
        case PFX_LST_DENY:
            return false;
        case PFX_LST_PERMIT:
            return true;
        case PFX_LST_SKIP:
            return true;
        case PFX_LST_UNKNOWN:
            assert(0);
    }
    return false;
}

static bool
_rt_table_entry_add(rt_table_t *rt_table, l3_route_t *l3_route){

    mtrie_node_t *mnode;
    uint32_t bin_ip, bin_mask;
    bitmap_t prefix_bm, mask_bm;
    mtrie_ops_result_code_t rc;

    if (!rt_table_evaluate_import_policy(rt_table, l3_route)) {
        tracer(rt_table->node->dptr, DRTM , "Route %s/%d : Installation Rejected due to Import policy\n",  l3_route->dest, l3_route->mask );
        return false;
    }

   bin_ip = tcp_ip_convert_ip_p_to_n(l3_route->dest);
   bin_ip = htonl(bin_ip);
   bin_mask = tcp_ip_convert_dmask_to_bin_mask(l3_route->mask);
   bin_mask = ~bin_mask;
   bin_mask = htonl(bin_mask);

   bitmap_init(&prefix_bm, 32);
   bitmap_init(&mask_bm, 32);

   prefix_bm.bits[0] = bin_ip;
   mask_bm.bits[0] = bin_mask;

   rc = mtrie_insert_prefix(&rt_table->route_list,
                            &prefix_bm,
                            &mask_bm,
                            32,
                            &mnode);

   bitmap_free_internal(&prefix_bm);
   bitmap_free_internal(&mask_bm);

   if (rc != MTRIE_INSERT_SUCCESS) 
       return false;

   mnode->data = (void *)l3_route;
   l3_route_inc_ref_count (l3_route);
   l3_route->install_time = time(NULL);
    tracer(rt_table->node->dptr, DRTM , "Route %s/%d : Successfully added to Rib\n", 
            l3_route->dest, l3_route->mask);
   rt_table_add_route_to_notify_list(rt_table, l3_route, RT_ADD_F);
   rt_table_kick_start_notif_job(rt_table);
   return true;
}

void
rt_table_add_route (rt_table_t *rt_table,
                                const char *dst, 
                                char mask,
                                const char *gw, 
                                Interface *oif,
                                uint32_t spf_metric,
                                uint16_t proto_id) {

   bool new_route = false;
    node_t *node = rt_table->node;

    nxthop_proto_id_t nxthop_proto = 
        l3_rt_map_proto_id_to_nxthop_index(proto_id);
    
   l3_route_t *l3_route = rt_table_lookup_exact_match(
                                            rt_table, dst, mask);

   if(!l3_route){
       l3_route = l3_route_get_new_route();
       string_copy((char *)l3_route->dest, dst, 16);
       l3_route->dest[15] = '\0';
       l3_route->mask = mask;
       new_route = true;
       l3_route->is_direct = true;
       l3_route->nh_count = 0;
   }

   int i = 0;

   /*Get the index into nexthop array to fill the new nexthop*/
   if(!new_route){

       for( ; i < MAX_NXT_HOPS; i++){

           if (l3_route->nexthops[nxthop_proto][i]){

                if (gw && string_compare(l3_route->nexthops[nxthop_proto][i]->gw_ip, gw, 16) == 0 && 
                    l3_route->nexthops[nxthop_proto][i]->oif == oif) { 

                    tracer(node->dptr, DRTM | DERR, 
                        "Error : Route %s/%d : Attempt to Add Duplicate \n", dst, mask);
                    return;
                }
           }
           else break;
       }
   }

   if( i == MAX_NXT_HOPS){
        tracer(node->dptr, DRTM | DERR,  "Error : Route %s/%d : No Space left for Nexthop \n", dst, mask);
        return;
   }

   if(oif){

        nexthop_t *nexthop = (nexthop_t *)XCALLOC(0, 1, nexthop_t);
        if (gw) l3_route->is_direct = false;
        l3_route->spf_metric[nxthop_proto] = spf_metric;
        if (gw) {
            string_copy((char *)nexthop->gw_ip, gw, 16);
        }
        else {
            nexthop->gw_ip[0] = '\0';
        }
        nexthop->gw_ip[15] = '\0';
        nexthop->proto = proto_id;
        nexthop->oif = oif;
        nexthop->ifindex = oif->ifindex;

        switch (proto_id) {
            case PROTO_STATIC:
                oif->InterfaceLockStatic();
            break;
            case PROTO_ISIS:
                oif->InterfaceLockDynamic();
            break;
            default:
                assert (0);
        }
        
		l3_route_insert_nexthop(l3_route, nexthop, nxthop_proto);
        if (!new_route) {
            tracer(node->dptr, DRTM, "Route %s/%d : Nexthop %s %s added to Rib\n", 
                dst, mask, nexthop->gw_ip, nexthop->oif ? nexthop->oif->if_name.c_str() : "None");
            rt_table_add_route_to_notify_list (rt_table, l3_route, RT_UPDATE_F);
            rt_table_kick_start_notif_job(rt_table);
        }
   }

   if (new_route){
       if (!_rt_table_entry_add(rt_table, l3_route)){
           tracer(node->dptr, DRTM | DERR, "Error : Route %s/%d : Installation Failed in Rib\n",  dst, mask);
       }
   }
}

/* Wrapper fn to add route to Routing table Asynchronously*/
void
rt_ipv4_route_add (node_t *node, 
                                uint32_t prefix, 
                                uint8_t mask, 
                                uint32_t gw_ip,
                                Interface *oif,
                                uint32_t metric,
                                uint16_t proto_id,
                                bool async) {

    dp_msg_t *dp_msg;
    rt_update_msg_t *rt_update_msg;
    rt_table_t *rt_table = NODE_RT_TABLE(node);

    dp_msg = cp2dp_msg_alloc (node, sizeof (rt_update_msg_t));
    dp_msg->component_type = RT_TABLE_IPV4;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(rt_update_msg_t);
    rt_update_msg = (rt_update_msg_t *)dp_msg->data;
    rt_update_msg->prefix = prefix;
    rt_update_msg->mask = mask;
    rt_update_msg->gateway = gw_ip;
    rt_update_msg->oif = oif;
    if (oif) oif->InterfaceLockDynamic();
    rt_update_msg->metric = metric;
    rt_update_msg->proto_id = proto_id;
    cp2dp_submit(node, dp_msg, async);
}

void
rt_ipv4_route_del (node_t *node, 
                                uint32_t prefix, 
                                uint8_t mask, 
                                uint16_t proto_id,
                                bool async) {

    dp_msg_t *dp_msg;
    rt_update_msg_t *rt_update_msg;
    rt_table_t *rt_table = NODE_RT_TABLE(node);

    dp_msg = cp2dp_msg_alloc (node, sizeof (rt_update_msg_t));
    dp_msg->component_type = RT_TABLE_IPV4;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(rt_update_msg_t);
    rt_update_msg = (rt_update_msg_t *)dp_msg->data;
    rt_update_msg->prefix = prefix;
    rt_update_msg->mask = mask;
    rt_update_msg->proto_id = proto_id;
    cp2dp_submit(node, dp_msg, async);
}

static void
_layer3_pkt_recv_from_layer2(node_t *node, 
                            Interface *interface,
                           pkt_block_t *pkt_block,
                            int L3_protocol_type) {

    pkt_size_t pkt_size;
    char ip_addr_str[16];

    assert(pkt_block_verify_pkt (pkt_block, ETH_HDR));

    pkt_block_get_pkt(pkt_block, &pkt_size);

    switch(L3_protocol_type){
        
        case ETH_IP:
        case PROTO_IP_IN_IP:

            /* Remove the Data link Hdr from the pkt */
            pkt_block_set_new_pkt( pkt_block,
                    (uint8_t *)pkt_block_get_ip_hdr(pkt_block),
                    pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD + ETH_FCS_SIZE);
            pkt_block_set_starting_hdr_type(pkt_block, 
                L3_protocol_type == ETH_IP ? IP_HDR : IP_IN_IP_HDR);

            tracer (node->dptr, DL3FWD, "Dest : %s :  Pkt Arrived in L3-land from Layer 2\n",
                pkt_ip(pkt_block, ip_addr_str));

            layer3_ip_route_pkt(node, interface, pkt_block);
            break;
        default:
            ;
    }
}

/* A public API to be used by L2 or other lower Layers to promote
 * pkts to Layer 3 in TCP IP Stack*/
void
promote_pkt_to_layer3(node_t *node,            /*Current node on which the pkt is received*/
                      Interface *interface,  /*ingress interface*/
                      pkt_block_t *pkt_block, /*L3 payload*/
                      int L3_protocol_number) {  /*obtained from eth_hdr->type field*/
	
	_layer3_pkt_recv_from_layer2(node, interface,
				pkt_block,
				L3_protocol_number);
}

/* An API to be used by L4 or L5 to push the pkt down the TCP/IP
 * stack to layer 3*/
void
demote_packet_to_layer3 (node_t *node, 
                                           pkt_block_t *pkt_block,
                                           hdr_type_t protocol_number, /*L4 or L5 protocol type*/
                                           uint32_t dest_ip_address){

    byte *pkt;
    ip_hdr_t iphdr;
    byte dst_ip_addr_str[16];
    pkt_size_t pkt_size;

    tracer (node->dptr, DL3FWD, "Dest : %s :  Pkt Arrived in L3-land from Top\n", 
        tcp_ip_covert_ip_n_to_p(dest_ip_address, dst_ip_addr_str));

    initialize_ip_hdr(&iphdr);  
      
    pkt = pkt_block_get_pkt(pkt_block,  &pkt_size);

    /*Now fill the non-default fields*/
    iphdr.protocol = tcp_ip_convert_internal_proto_to_std_proto(protocol_number);

    uint32_t addr_int =  tcp_ip_convert_ip_p_to_n(NODE_LO_ADDR(node));
    iphdr.src_ip = addr_int;
    iphdr.dst_ip = dest_ip_address;

    iphdr.total_length = IP_HDR_COMPUTE_DEFAULT_TOTAL_LEN(pkt_size);

    uint8_t *new_pkt = NULL;
    pkt_size_t new_pkt_size = 0 ;

    /* Make a room in pkt to accomodate IP Hdr */
    if (!pkt_block_expand_buffer_left (pkt_block, IP_HDR_LEN_IN_BYTES((&iphdr)))) {
        return;
    }

    new_pkt = pkt_block_get_pkt (pkt_block,  &new_pkt_size);
    pkt_block_set_starting_hdr_type(pkt_block, IP_HDR);

    memcpy((char *)new_pkt, (char *)&iphdr, IP_HDR_LEN_IN_BYTES((&iphdr)));


    l3_route_t *l3_route = l3rib_lookup_lpm(NODE_RT_TABLE(node), 
                                          iphdr.dst_ip);
    
    if(!l3_route){
        tracer (node->dptr, DL3FWD | DERR, "Dest : %s :  Pkt Dropped : No L3 route\n", dst_ip_addr_str);   
        return;
    }

    bool is_direct_route = l3_is_direct_route(l3_route);
    
    if(is_direct_route){

        int8_t nf_result = nf_invoke_netfilter_hook(
                NF_IP_LOCAL_OUT,
				pkt_block,
				node, NULL,
                IP_HDR);

        switch (nf_result)
        {
            case NF_ACCEPT:
                break;
            case NF_DROP:
            case NF_STOLEN:
            case NF_STOP:
                return;
        }

        tracer (node->dptr, DL3FWD, "Dest : %s :  Direct Route found, Pkt is being demoted to L2 Layer\n", dst_ip_addr_str);

        demote_pkt_to_layer2(node,
                         dest_ip_address,
                         0,
                         pkt_block,
                         IP_HDR);
        return;
    }

    /* If route is non direct, then ask LAyer 2 to send the pkt
     * out of all ecmp nexthops of the route*/
    uint32_t next_hop_ip;
    nexthop_t *nexthop = NULL;

    nexthop = l3_route_get_active_nexthop(l3_route, pkt_block->exclude_oif);
    
    if(!nexthop){
        tracer (node->dptr, DL3FWD | DERR, "Dest : %s :  Pkt Dropped : No nexthop found\n", dst_ip_addr_str);
        return;
    }

    tracer (node->dptr, DL3FWD, "Dest : %s :  Nexthop found OIF %s, Gw : %s\n", dst_ip_addr_str, 
            nexthop->oif->if_name.c_str(), nexthop->gw_ip);

    if (pkt_block->exclude_oif &&
            pkt_block->exclude_oif == nexthop->oif) assert(0);

#if 0
    if (access_list_evaluate_ip_packet(node, 
                nexthop->oif, 
                (ip_hdr_t *)pkt_block_get_ip_hdr(pkt_block),
                false) == ACL_DENY) {

        pkt_block_dereference (pkt_block);
        l3_route_unlock(l3_route);
        thread_using_route_done(l3_route);
        return;
    }
#endif 
    next_hop_ip = tcp_ip_convert_ip_p_to_n(nexthop->gw_ip);

    tcp_dump_l3_fwding_logger(node,
                                                    nexthop->oif->if_name.c_str(), 
                                                    nexthop->gw_ip);

    int8_t nf_result = nf_invoke_netfilter_hook(
            NF_IP_LOCAL_OUT,
			pkt_block,
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

    tracer (node->dptr, DL3FWD, "Dest : %s :  Pkt is being demoted to L2 Layer\n", dst_ip_addr_str);
    demote_pkt_to_layer2(node,
            next_hop_ip,
            nexthop->oif->if_name.c_str(),
            pkt_block,
            IP_HDR);

    nexthop->hit_count++;
}

/* This fn sends a dummy packet to test L3 and L2 routing
 * in the project. We send dummy Packet starting from Network
 * Layer on node 'node' to destination address 'dst_ip_addr'
 * using below fn*/
void
layer3_ping_fn(node_t *node, c_string dst_ip_addr, uint32_t count){

    uint32_t i;
    uint32_t addr_int;

    addr_int = tcp_ip_convert_ip_p_to_n(dst_ip_addr);
    cprintf("\nSrc node : %s, Ping ip : %s", node->node_name, dst_ip_addr);

    for (i = 0; i < count ; i ++) {
        cp2dp_send_ip_data (node, NULL, addr_int, ICMP_PROTO);
    }
}

void
layer3_ero_ping_fn(node_t *node, 
                    c_string dst_ip_addr, 
                    c_string ero_ip_address){

    pkt_block_t *pkt_block = pkt_block_get_new_pkt_buffer (sizeof (ip_hdr_t));
    pkt_block_set_starting_hdr_type (pkt_block, IP_HDR);
    ip_hdr_t *inner_ip_hdr = (ip_hdr_t *)pkt_block_get_ip_hdr (pkt_block);
    initialize_ip_hdr(inner_ip_hdr);
    inner_ip_hdr->total_length = sizeof(ip_hdr_t)/4;
    inner_ip_hdr->protocol = ICMP_PROTO;
    uint32_t addr_int = tcp_ip_convert_ip_p_to_n(NODE_LO_ADDR(node));
    inner_ip_hdr->src_ip = addr_int;
    addr_int =  tcp_ip_convert_ip_p_to_n(dst_ip_addr);
    inner_ip_hdr->dst_ip = addr_int;
    addr_int = tcp_ip_convert_ip_p_to_n(ero_ip_address);
    cp2dp_send_ip_data (node, pkt_block, addr_int, PROTO_IP_IN_IP);
    pkt_block_dereference(pkt_block);
}

l3_route_t *
l3_route_get_new_route () {

    l3_route_t *l3route = (l3_route_t *)XCALLOC(0, 1, l3_route_t);
    init_glthread(&l3route->notif_glue);
    init_glthread(&l3route->flash_glue);
    return l3route;
}

static void
l3_route_free (l3_route_t *l3_route){

    /* Assume the route has already been removed from main routing table */
    nxthop_proto_id_t nxthop_proto_id;
    assert (!l3_route->rt_ref_count);
    assert (IS_GLTHREAD_LIST_EMPTY(&l3_route->notif_glue));
    assert (IS_GLTHREAD_LIST_EMPTY(&l3_route->flash_glue));
    FOR_ALL_NXTHOP_PROTO(nxthop_proto_id) {
        nh_flush_nexthops (l3_route->nexthops[nxthop_proto_id]);
    }
    XFREE(l3_route);
}

uint32_t
l3_route_dec_ref_count (l3_route_t *l3_route) {

    assert (l3_route->rt_ref_count);
    l3_route->rt_ref_count--;
    if ( l3_route->rt_ref_count ) return l3_route->rt_ref_count;
    l3_route_free (l3_route);
    return 0;
}

void 
l3_route_inc_ref_count (l3_route_t *l3_route) {

    l3_route->rt_ref_count++;
}

void
np_tcp_ip_send_ip_data (node_t *node, pkt_block_t *pkt_block) {

    char ip_addr_str[16];

    assert (pkt_block_verify_pkt (pkt_block, IP_HDR));

    ip_hdr_t *ip_hdr = (ip_hdr_t *)pkt_block_get_ip_hdr(pkt_block);

    /* This API expects that IP-HDR must have following fields set */
    assert (ip_hdr->protocol);

    // Src IP may or may not be set already. If not set, we will determine it
    //assert (ip_hdr->src_ip);

    assert (ip_hdr->dst_ip);
    assert (ip_hdr->total_length);

    tracer (node->dptr, DL3FWD, "Dest : %s : NP Recvd Routing Request\n", pkt_ip(pkt_block, ip_addr_str));

    layer3_ip_route_pkt (node, NULL, pkt_block); 
}

void
layer3_mem_init() {

    MM_REG_STRUCT(0, ip_hdr_t);
    MM_REG_STRUCT(0, rt_table_t);
    MM_REG_STRUCT(0, nexthop_t);
    MM_REG_STRUCT(0, l3_route_t);
}
