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
#include "../router_init.h"
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
#include "../lmm_enums.h"
#include "../FireWall/acl/acldb.h"
#include "../mtrie/mtrie.h"
#include "../pkt_block.h"
#include "../prefix-list/prefixlst.h"
#include "../FireWall/Connection/conn.h"
#include "../Interface/InterfaceUApi.h"
#include "../common/cp2dp.h"
#include "../Tracer/tracer.h"
#include "ipv6/ipv6_route.h"

extern graph_t *topo;

extern int
nh_flush_nexthops(nexthop_t **nexthop);

extern void
rt_table_kick_start_notif_job(rt_table_t *rt_table) ;

extern void
rt_table_add_route_to_notify_list (
                rt_table_t *rt_table, 
                l3_route_t *l3route,
                uint8_t flag);

extern  void
layer3_ipv6_route_pkt (node_t *node,
							          Interface *interface,
					                  pkt_block_t *pkt_block) ;
                                      
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

    uint32_t intf_addr ;
    char dest_ip_str[IPV4_ADDR_LEN_STR];

    tcp_ip_covert_ip_n_to_p(dst_ip, dest_ip_str);

    /*checking with node's loopback address*/
    if(string_compare(NODE_LO_ADDR(node), dest_ip_str, 16) == 0) {
        tracer (node->dptr, DL3FWD, "Pkt : %s : Local interface IP Address match : Lo\n", dest_ip_str);
        return true;
    }

    /*checking with interface IP Addresses*/
    Interface *intf;

     ITERATE_NODE_INTERFACES_BEGIN(node, intf) {
        
        if(!intf) return false;

        if (!intf->IsIpConfigured()) continue;

        intf_addr = IF_IP(intf);

        if  (intf_addr == dst_ip)  {
             tracer (node->dptr, DL3FWD, "Pkt : %s : Local interface IP Address match : %s\n", dest_ip_str, intf->if_name.c_str());
            return true;
        }

    } ITERATE_NODE_INTERFACES_END(node, intf);

    /* Checking with vlan interface addresses */
    if (node->vlan_intf_db) {

        for (auto it = node->vlan_intf_db->begin(); it != node->vlan_intf_db->end(); it++) {

            intf = it->second.get();

            if (!intf->IsIpConfigured()) continue;

            intf_addr = IF_IP(intf);

            if  (intf_addr == dst_ip)  {
                tracer (node->dptr, DL3FWD, "Pkt : %s : Local interface IP Address match : %s\n", dest_ip_str, intf->if_name.c_str());
                return true;
            }
        }
    }

    tracer (node->dptr, DL3FWD, "Pkt : %s : No Matching Local interface\n", dest_ip_str);
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
    ip_hdr_t *ip_hdr = NULL;
    uint32_t next_hop_ip= 0;
    nexthop_t *nexthop = NULL;
    char dest_ip_addr[IPV4_ADDR_LEN_STR];

    /* We are in L3 IP land, so starting hdr type must be IP_HDR */
    assert (pkt_block_get_starting_hdr(pkt_block) == IP_HDR ||
                pkt_block_get_starting_hdr(pkt_block) == IP_IN_IP_HDR);

    ip_hdr = (ip_hdr_t *)pkt_block_get_ip_hdr(pkt_block);

    tcp_ip_covert_ip_n_to_p(htonl(ip_hdr->dst_ip), (c_string)dest_ip_addr);

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
                           NODE_RT_TABLE(node), htonl(ip_hdr->dst_ip));

    if(!l3_route){
        tracer (node->dptr, DL3FWD | DERR, "Pkt : %s :  Pkt Dropped :  No L3 Route\n", pkt_block_str(pkt_block));
        return;
    }

    tracer (node->dptr, DL3FWD, "Pkt : %s : L3 Route Found\n", dest_ip_addr);

    /*L3 route exist, 3 cases now : 
     * case 1 : pkt is destined to self(this router only)
     * case 2 : pkt is destined for host machine connected to directly attached subnet
     * case 3 : pkt is to be forwarded to next router*/

    if (l3_is_direct_route(l3_route)){

        /* case 1 and case 2 are possible here*/

        /* case 1 : local delivery:  dst ip address in pkt must exact match with
         * ip of any local interface of the router, including loopback*/

        tracer (node->dptr, DL3FWD, "Pkt : %s : L3 Route found is local route\n", dest_ip_addr);

        if (is_layer3_local_delivery(node, htonl(ip_hdr->dst_ip))) {

            tracer (node->dptr, DL3FWD, "Pkt : %s : Pkt is for Local Delivery, IP protocol = %s\n",   
                 dest_ip_addr, proto_name_str(ip_hdr->protocol));

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
                                              UDP_PROTO);
                    return;

                case PROTO_IP_IN_IP:
                    /*Packet has reached ERO, now set the packet onto its new 
                      Journey from ERO to final destination*/
                    pkt_block_set_new_pkt(pkt_block, 
                                                            (uint8_t *)INCREMENT_IPHDR(ip_hdr),
                                                            pkt_block->pkt_size - IP_HDR_LEN_IN_BYTES(ip_hdr));

                    pkt_block_set_starting_hdr_type (pkt_block, IP_IN_IP_HDR);
                     
                    tracer (node->dptr, DL3FWD, "Pkt : %s : Pkt is being subjected to L3 Routing again a per Inner Header\n", dest_ip_addr);

                    layer3_ip_route_pkt(node,
                                                      interface, 
                                                      pkt_block);
                    return;

                case GRE_PROTO:
                {
                    char gre_t_src_addr[IPV4_ADDR_LEN_STR];
                    char gre_t_dst_addr[IPV4_ADDR_LEN_STR];

                    pkt_block_set_new_pkt (pkt_block, 
                                           (uint8_t *)INCREMENT_IPHDR(ip_hdr),
                                           pkt_block->pkt_size - IP_HDR_LEN_IN_BYTES(ip_hdr));

                    pkt_block_set_starting_hdr_type (pkt_block, GRE_HDR);
                    tcp_ip_covert_ip_n_to_p ( htonl (ip_hdr->dst_ip), gre_t_src_addr);
                    tcp_ip_covert_ip_n_to_p ( htonl (ip_hdr->src_ip), gre_t_dst_addr);

                    tracer (node->dptr, DL3FWD, 
                           "Pkt : %s : Pkt is being subjected to GRE Decapsulation, Tunnel key : [%s, %s]\n", 
                           dest_ip_addr, gre_t_src_addr, gre_t_dst_addr);

                    gre_decapsulate (node, pkt_block, 
                            gre_lookup_tunnel_intf (node, 
			                htonl(ip_hdr->dst_ip), htonl(ip_hdr->src_ip)));
                    return;
                }
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
        nexthop = l3_route_get_active_nexthop(l3_route, pkt_block->exclude_oif.get());

        tracer (node->dptr, DL3FWD, "Pkt : %s :  Nexthop found OIF %s, Gw : %s\n", 
            pkt_block_str (pkt_block), nexthop->oif->if_name.c_str(), nexthop->gw_ip);

        /* If nexthop do not have any OIF attached to it, it could be loose next hope. Perform 
        loose nexthop resolution */
        while (nexthop->ifindex == 0) {

            tracer (node->dptr, DL3FWD, "Pkt : %s :  Loose Nexthop found, Nexthop addr : %s\n", 
                    pkt_block_str (pkt_block), nexthop->gw_ip);

            nexthop->hit_count++;

            /* Recusrive look up */
            next_hop_ip = tcp_ip_convert_ip_p_to_n(nexthop->gw_ip);

            l3_route_t *recursive_l3_route = l3rib_lookup_lpm(
                                NODE_RT_TABLE(node), next_hop_ip);

            if (!recursive_l3_route) {

                    tracer (node->dptr, DL3FWD | DERR, "Pkt : %s :  Pkt Dropped :  No L3 Route for Loose Nexthop %s\n",
                        pkt_block_str (pkt_block), nexthop->gw_ip);
                    return;
            }

            nexthop = l3_route_get_active_nexthop(recursive_l3_route, pkt_block->exclude_oif.get());

            tracer (node->dptr, DL3FWD, "Pkt : %s :  Recursive Nexthop found OIF %s, Gw : %s\n", 
                pkt_block_str (pkt_block), nexthop->oif->if_name.c_str(), nexthop->gw_ip);
        }

        /* If src ip address is not feeded by application, then take the OIF IP address*/
        if (ip_hdr->src_ip == 0) {
            
            char ip_addr_str[IPV4_ADDR_LEN_STR];
            ip_hdr->src_ip = htonl(IF_IP(nexthop->oif.get()));
            tracer (node->dptr, DL3FWD, "Pkt: %s : Using OIF IP as Src IP : %s\n", 
                pkt_block_str (pkt_block), 
                tcp_ip_covert_ip_n_to_p(htonl(ip_hdr->src_ip), ip_addr_str)); 
        }

        tracer (node->dptr, DL3FWD, "Pkt : %s :  Demoting Pkt to Layer 2 for L2 Forwarding\n", pkt_block_str (pkt_block));

        demote_pkt_to_layer2 (
                node,           /*Current processing node*/
                htonl(ip_hdr->dst_ip),     /*next hop IP is dest itself as dest is present in local subnet*/
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
    nexthop = l3_route_get_active_nexthop(l3_route, pkt_block->exclude_oif.get());

    tracer (node->dptr, DL3FWD, "Dest : %s :  Nexthop found OIF %s, Gw : %s\n", 
            dest_ip_addr, 
            nexthop->oif->if_name.c_str(), 
            nexthop->gw_ip);

    nf_result = nf_invoke_netfilter_hook(
                        NF_IP_FORWARD,
                        pkt_block,
                        node, 
                        nexthop->oif.get(),
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
		            node, nexthop->oif.get(),
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

    *rt_table = (rt_table_t *)XCALLOC2(0, 1, rt_table_t);
    
    init_mtrie (&(*rt_table)->route_list, 32, NULL);

    string_copy((char *) (*rt_table)->nfc_rt_updates.nfc_name, 
                 "NFC for IPV4 RT UPDATES",
                 sizeof((*rt_table)->nfc_rt_updates.nfc_name));

    init_glthread(&((*rt_table)->nfc_rt_updates.notif_chain_head));
    
    (*rt_table)->node = node;
}

void
init_rtv6_table(node_t *node, rt_table_t **rt_table){

    *rt_table = (rt_table_t *)XCALLOC2(0, 1, rt_table_t);
    
    init_mtrie (&(*rt_table)->route_list, 128, NULL);

    string_copy((char *) (*rt_table)->nfc_rt_updates.nfc_name, 
                 "NFC for IPV6 RT UPDATES",
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

            if (nexthop->oif.get() == exclude_oif && exclude_oif) {

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

    if (IS_GLTHREAD_LIST_EMPTY (&rt_table->route_list.list_head)) {
        return;
    }

    cprintf("L3 Routing Table:\n");

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list.list_head, curr){

        mnode = list_glue_to_mtrie_node(curr);
        l3_route = (l3_route_t *)mnode->data;
        count++;
        nxthop_cnt = 0;
		
		if(count != 0 && (count % 20) == 0) {
			//cprintf("continue ?\n");
			//getchar();			
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

/* Return true if policy is passed, else false */

static void
_layer3_pkt_recv_from_layer2(node_t *node, 
                            Interface *interface,
                            pkt_block_t *pkt_block,
                            int L3_protocol_type) {

    pkt_size_t pkt_size;
    char ip_addr_str[IPV4_ADDR_LEN_STR];

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

        case ETH_IP6:
            pkt_block_set_new_pkt( pkt_block,
                    (uint8_t *)pkt_block_get_ip6_hdr(pkt_block),
                    pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD + ETH_FCS_SIZE);
            pkt_block_set_starting_hdr_type(pkt_block, IP6_HDR);
            layer3_ipv6_route_pkt(node, interface, pkt_block);            
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
    byte dst_ip_addr_str[IPV4_ADDR_LEN_STR];
    pkt_size_t pkt_size;

    tracer (node->dptr, DL3FWD, "Dest : %s :  Pkt Arrived in L3-land from Top\n", 
        tcp_ip_covert_ip_n_to_p(dest_ip_address, dst_ip_addr_str));

    initialize_ip_hdr(&iphdr);  
      
    pkt = pkt_block_get_pkt(pkt_block,  &pkt_size);

    /*Now fill the non-default fields*/
    iphdr.protocol = tcp_ip_convert_internal_proto_to_std_proto(protocol_number);

    uint32_t addr_int =  tcp_ip_convert_ip_p_to_n(NODE_LO_ADDR(node));
    iphdr.src_ip = htonl(addr_int);
    iphdr.dst_ip = htonl(dest_ip_address);

    iphdr.total_length = htons(IP_HDR_DEFAULT_SIZE + pkt_size);

    uint8_t *new_pkt = NULL;
    pkt_size_t new_pkt_size = 0 ;

    /* Make a room in pkt to accomodate IP Hdr */
    if (!pkt_block_expand_buffer_left (pkt_block, IP_HDR_LEN_IN_BYTES((&iphdr)))) {
        return;
    }

    new_pkt = pkt_block_get_pkt (pkt_block,  &new_pkt_size);
    pkt_block_set_starting_hdr_type(pkt_block, IP_HDR);

    memcpy((char *)new_pkt, (char *)&iphdr, IP_HDR_LEN_IN_BYTES((&iphdr)));


    l3_route_t *l3_route = l3rib_lookup_lpm(
                                          NODE_RT_TABLE(node), 
                                          htonl(iphdr.dst_ip));

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

    nexthop = l3_route_get_active_nexthop(l3_route, pkt_block->exclude_oif.get());
    
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
			node, nexthop->oif.get(),
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
    inner_ip_hdr->total_length = htons(IP_HDR_DEFAULT_SIZE);
    inner_ip_hdr->protocol = ICMP_PROTO;
    uint32_t addr_int = tcp_ip_convert_ip_p_to_n(NODE_LO_ADDR(node));
    inner_ip_hdr->src_ip = htonl(addr_int);
    addr_int =  tcp_ip_convert_ip_p_to_n(dst_ip_addr);
    inner_ip_hdr->dst_ip = htonl(addr_int);
    addr_int = tcp_ip_convert_ip_p_to_n(ero_ip_address);
    cp2dp_send_ip_data (node, pkt_block, addr_int, PROTO_IP_IN_IP);
    pkt_block_dereference(pkt_block);
}

l3_route_t *
l3_route_get_new_route () {

    l3_route_t *l3route = (l3_route_t *)XCALLOC2(0, 1, l3_route_t);
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

    char ip_addr_str[IPV4_ADDR_LEN_STR];

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

extern int 
ip_traffic_generate_handler(int cmdcode,
    Stack_t *tlv_stack,
    op_mode enable_or_disable) {

    int i;
    uint32_t count = 1;
    uint8_t protocol;
    uint32_t addr_int;
    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    char *src_addr_str = NULL;
    char *dst_addr_str = NULL;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if  (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "src-addr"))
            src_addr_str = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "dst-addr"))
            dst_addr_str = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "count"))
            count = atoi(tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "protocol"))
            protocol = atoi(tlv->value);

   } TLV_LOOP_END;
   
   node = node_get_node_by_name(topo, node_name);

   addr_int = tcp_ip_convert_ip_p_to_n(dst_addr_str );

   for (i = 0; i < count ; i ++) {
        cp2dp_send_ip_data (node, NULL, addr_int, protocol);
    }
    
    return 0;
}


void
layer3_mem_init() {

    MM_REG_STRUCT(0, ip_hdr_t);
    MM_REG_STRUCT(0, rt_table_t);
    //MM_REG_STRUCT(0, nexthop_t);
    MM_REG_STRUCT(0, l3_route_t);
    //MM_REG_STRUCT(0, v6nexthop_t);
    MM_REG_STRUCT(0, ipv6_route_t);
    MM_REG_STRUCT(0, ipv6_addr_t);
    MM_REG_STRUCT(0, ipv6_hdr_t);
    MM_REG_STRUCT(0, srh_hdr_t);
}
