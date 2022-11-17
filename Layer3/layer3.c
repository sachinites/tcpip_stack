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
#include "../graph.h"
#include "../Layer2/layer2.h"
#include "../Layer5/layer5.h"
#include "rt_table/nexthop.h"
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
#include "FireWall/Connection/conn.h"

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
    c_string intf_addr = NULL;

    dst_ip = htonl(dst_ip);
    inet_ntop(AF_INET, &dst_ip, dest_ip_str, 16);

    /*checking with node's loopback address*/
    if(string_compare(NODE_LO_ADDR(node), dest_ip_str, 16) == 0)
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

        if(string_compare(intf_addr, dest_ip_str, 16) == 0)
            return true;
    }
    return false;
}

extern void
promote_pkt_to_layer4(node_t *node, interface_t *recv_intf, 
                      pkt_block_t *pkt_block,
                      int L4_protocol_number);

/*import function from layer 2*/
extern void
demote_pkt_to_layer2(node_t *node,
                     uint32_t next_hop_ip,
                     char *outgoing_intf, 
                     pkt_block_t *pkt_block,
                     hdr_type_t hdr_type);


static void
layer3_ip_route_pkt(node_t *node,
							   interface_t *interface,
					           pkt_block_t *pkt_block) {

    int8_t nf_result;
    char *l4_hdr, *l5_hdr;
    char dest_ip_addr[16];
    ip_hdr_t *ip_hdr = NULL;
    
    /* We are in L3 IP land, so starting hdr type must be IP_HDR */
    assert (pkt_block_get_starting_hdr(pkt_block) == IP_HDR ||
                pkt_block_get_starting_hdr(pkt_block) == IP_IN_IP_HDR);

    ip_hdr = (ip_hdr_t *)pkt_block_get_ip_hdr(pkt_block);

    tcp_ip_covert_ip_n_to_p(ip_hdr->dst_ip, (c_string)dest_ip_addr);

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
            pkt_block_dereference(pkt_block);
        return;
    }

    if (!connection_exist (node, pkt_block)) {
        /* Access List Evaluation at Layer 3 Entry point*/
        if (interface && /* For local ping, interface will be NULL */
            access_list_evaluate_ip_packet(node, interface,
                                           ip_hdr, true) == ACL_DENY) {

            pkt_block_dereference(pkt_block);
            return;
        }
    }

    /*Implement Layer 3 forwarding functionality*/
    pthread_rwlock_rdlock(&(NODE_RT_TABLE(node)->rwlock));

    l3_route_t *l3_route = l3rib_lookup_lpm(
                                        NODE_RT_TABLE(node), ip_hdr->dst_ip);

    if(!l3_route){
        /*Router do not know what to do with the pkt. drop it*/
        printf("Router %s : Cannot Route IP : %s\n", 
                    node->node_name, dest_ip_addr);

        pthread_rwlock_unlock(&NODE_RT_TABLE(node)->rwlock);
        pkt_block_dereference(pkt_block);
        return;
    }

    l3_route_lock (l3_route);

    /* Done with the RT table, release the lock */
    pthread_rwlock_unlock(&NODE_RT_TABLE(node)->rwlock);

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
								pkt_block, ip_hdr->protocol);
                    return;
                case ICMP_PROTO:
                    printf("\nIP Address : %s, ping success\n", dest_ip_addr);
                    //pkt_block_dereference(pkt_block);
                    break;
                case UDP_PROTO:
                        promote_pkt_to_layer4 (
                                              node, interface,
											  pkt_block,
                                              UDP_HDR);
                        return;
                case IP_IN_IP:
                    /*Packet has reached ERO, now set the packet onto its new 
                      Journey from ERO to final destination*/
                    pkt_block_set_new_pkt(pkt_block, 
                                                            (uint8_t *)INCREMENT_IPHDR(ip_hdr),
                                                            IP_HDR_PAYLOAD_SIZE(ip_hdr));
                    layer3_ip_route_pkt(node,
									interface, 
                                    pkt_block);
                    goto done;
                default:
                    ;
            }

			promote_pkt_from_layer3_to_layer5(
                                              node, interface,
											  pkt_block,
                                              IP_HDR);
            pkt_block_dereference(pkt_block);
           goto done;
        }
         
        /* case 2 : It means, the dst ip address lies in direct connected
         * subnet of this router, time for l2 routing*/

        demote_pkt_to_layer2(
                node,           /*Current processing node*/
                0,              /*Dont know next hop IP as dest is present in local subnet*/
                NULL,           /*No oif as dest is present in local subnet*/
                pkt_block,  /*Network Layer payload and size*/
                IP_HDR);        /*Network Layer need to tell Data link layer, what type of payload it is passing down*/

        goto done;
    }

    /*case 3 : L3 forwarding case*/

    ip_hdr->ttl--;

    if(ip_hdr->ttl == 0){
        pkt_block_dereference(pkt_block);
       goto done;
    }

    /* If route is non direct, then ask LAyer 2 to send the pkt
     * out of all ecmp nexthops of the route*/
    uint32_t next_hop_ip;
    nexthop_t *nexthop = NULL;

    nexthop = l3_route_get_active_nexthop(l3_route);
	if(!nexthop) {
        pkt_block_dereference(pkt_block);
        goto done;
    }

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
        pkt_block_dereference(pkt_block);
         goto done;
    }

    inet_pton(AF_INET, nexthop->gw_ip, &next_hop_ip);
    next_hop_ip = htonl(next_hop_ip);
   
    tcp_dump_l3_fwding_logger(node, 
        nexthop->oif->if_name, nexthop->gw_ip);

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
        pkt_block_dereference(pkt_block);   
        goto done;
    }

    /* Access List Evaluation at Layer 3 Exit point*/
    if (access_list_evaluate_ip_packet(
            node, nexthop->oif, 
            ip_hdr,
            false) == ACL_DENY) {

        pkt_block_dereference(pkt_block);
        goto done;
    }

    demote_pkt_to_layer2(node, 
            next_hop_ip,
            nexthop->oif->if_name,
            pkt_block,
            IP_HDR); /*Network Layer need to tell Data link layer, 
                                what type of payload it is passing down*/
    nexthop->hit_count++;

     done:
         l3_route_unlock (l3_route);
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

    pthread_rwlock_init(&(*rt_table)->rwlock, NULL);
}

/* MP Unsafe */
l3_route_t *
rt_table_lookup_exact_match(rt_table_t *rt_table, c_string ip_addr, char mask){
    
    uint32_t bin_ip, bin_mask;
    bitmap_t prefix_bm, mask_bm;

    bin_ip = tcp_ip_covert_ip_p_to_n(ip_addr);
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
clear_rt_table (rt_table_t *rt_table, uint16_t proto_id){

    int count;
    glthread_t *curr;
    l3_route_t *l3_route;
    mtrie_node_t *mnode;

    nxthop_proto_id_t nh_proto = l3_rt_map_proto_id_to_nxthop_index(proto_id);

    pthread_rwlock_wrlock(&rt_table->rwlock);

    curr = glthread_get_next(&rt_table->route_list.list_head);

    while(curr) {

        mnode = list_glue_to_mtrie_node(curr);

        l3_route = (l3_route_t *)mnode->data;
       assert(l3_route);

        if(l3_is_direct_route(l3_route)) {
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
       l3_route_unlock(l3_route);
    }
     
     pthread_rwlock_unlock(&rt_table->rwlock);
     rt_table_kick_start_notif_job(rt_table);
}


nexthop_t *
l3_route_get_active_nexthop(l3_route_t *l3_route){

    nexthop_t *nexthop;
    nxthop_proto_id_t nh_proto;

    if(l3_is_direct_route(l3_route))
        return NULL;
    
    FOR_ALL_NXTHOP_PROTO(nh_proto) {
        nexthop = l3_route->nexthops[nh_proto][l3_route->nxthop_idx];
        if (nexthop) {
            l3_route->nxthop_idx++;
            if (l3_route->nxthop_idx == MAX_NXT_HOPS || 
                 !l3_route->nexthops[nh_proto][l3_route->nxthop_idx]){
                l3_route->nxthop_idx = 0;
            }
            break;
        }
        else {
            l3_route->nxthop_idx = 0;
        }
    }
    return nexthop;
}

void
rt_table_delete_route(
        rt_table_t *rt_table, 
        c_string ip_addr,
        char mask,
        uint16_t proto_id){

    int count;
    l3_route_t *l3_route = NULL;
    uint32_t bin_ip, bin_mask;
    bitmap_t prefix_bm, mask_bm;
    char dst_str_with_mask[16];
    
    pthread_rwlock_wrlock(&rt_table->rwlock);

    l3_route = rt_table_lookup_exact_match(rt_table, ip_addr, mask);

    if (!l3_route) {
        pthread_rwlock_unlock(&rt_table->rwlock);
        return;
    }

    apply_mask(ip_addr, mask, dst_str_with_mask); 

    bin_ip = tcp_ip_covert_ip_p_to_n(dst_str_with_mask);
    bin_ip = htonl(bin_ip);
    bin_mask = tcp_ip_convert_dmask_to_bin_mask((uint8_t)mask);
    bin_mask = ~bin_mask;
    bin_mask = htonl(bin_mask);

    nxthop_proto_id_t nh_proto = l3_rt_map_proto_id_to_nxthop_index(proto_id);
    count = nh_flush_nexthops(l3_route->nexthops[nh_proto]);
    l3_route->spf_metric[nh_proto] = 0;
    l3_route->nh_count -= count;

    if (l3_route->nh_count) {
        pthread_rwlock_unlock(&rt_table->rwlock);
        return;
    }

    bitmap_init(&prefix_bm, 32);
    bitmap_init(&mask_bm, 32);

    prefix_bm.bits[0] = bin_ip;
    mask_bm.bits[0] = bin_mask;

    assert(mtrie_delete_prefix(&rt_table->route_list, 
                                            &prefix_bm,
                                            &mask_bm,
                                            (void **)&l3_route) == MTRIE_DELETE_SUCCESS);

    pthread_rwlock_unlock(&rt_table->rwlock);
    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);
    assert(l3_route);
    rt_table_add_route_to_notify_list (rt_table, l3_route, RT_DEL_F);
    rt_table_kick_start_notif_job(rt_table);
    l3_route_unlock(l3_route);
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

    printf("L3 Routing Table:\n");

    pthread_rwlock_rdlock(&rt_table->rwlock);

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list.list_head, curr){

        mnode = list_glue_to_mtrie_node(curr);
        l3_route = (l3_route_t *)mnode->data;
        count++;
        nxthop_cnt = 0;
		
		if(count != 0 && (count % 20) == 0) {
			printf("continue ?\n");
			getchar();			
		}

        if(l3_route->is_direct){
            if(count != 1){
                printf("\t|===================|=======|============|====================|==============|==========|============|==============|\n");
            }
            else{
                printf("\t|======= IP ========|== M ==|===proto====|======== Gw ========|===== Oif ====|== Cost ==|== uptime ==|=== hits =====|\n");
            }
            printf("\t|%-18s |  %-4d | %-10s | %-18s | %-10s   |          |  %-10s| 0            |\n", 
                    l3_route->dest,
                    l3_route->mask, 
                    "",
                    "NA", "NA",
					RT_UP_TIME(l3_route, time_str, HRS_MIN_SEC_FMT_TIME_LEN));
            continue;
        }

        nxthop_proto_id_t nxthop_proto;

        FOR_ALL_NXTHOP_PROTO(nxthop_proto) {
            for( i = 0; i < MAX_NXT_HOPS; i++ ){
                if(l3_route->nexthops[nxthop_proto][i]) {
                    if(nxthop_cnt == 0){
                        if(count != 1){
                            printf("\t|===================|=======|============|====================|==============|==========|============|==============|\n");
                        }
                        else{
                            printf("\t|======= IP ========|== M ==|===proto====|======== Gw ========|===== Oif ====|== Cost ==|== uptime ==|=== hits =====|\n");
                        }
                        printf("\t|%-18s |  %-4d | %-10s | %-18s | %-12s |  %-4d    |  %-10s| %-8llu     |\n", 
                                l3_route->dest, 
                                l3_route->mask,
                                proto_name_str(l3_route->nexthops[nxthop_proto][i]->proto),
                                l3_route->nexthops[nxthop_proto][i]->gw_ip, 
                                l3_route->nexthops[nxthop_proto][i]->oif->if_name, 
                                l3_route->spf_metric[nxthop_proto],
                                RT_UP_TIME(l3_route, time_str, HRS_MIN_SEC_FMT_TIME_LEN),
                                l3_route->nexthops[nxthop_proto][i]->hit_count);
                    }
                    else if ( i == 0) {
                        /* Fst next hop of a given protocol */
                        printf("\t|                   |       | %-10s | %-18s | %-12s |  %-4d   |  %-10s| %-8llu     |\n", 
                                proto_name_str(l3_route->nexthops[nxthop_proto][i]->proto),
                                l3_route->nexthops[nxthop_proto][i]->gw_ip, 
                                l3_route->nexthops[nxthop_proto][i]->oif->if_name,
                                l3_route->spf_metric[nxthop_proto],
                                "",
                                l3_route->nexthops[nxthop_proto][i]->hit_count);
                    }
                    else{
                        printf("\t|                   |       | %-10s | %-18s | %-12s |          |  %-10s| %-8llu     |\n", 
                                proto_name_str(l3_route->nexthops[nxthop_proto][i]->proto),
                                l3_route->nexthops[nxthop_proto][i]->gw_ip, 
                                l3_route->nexthops[nxthop_proto][i]->oif->if_name, "",
                                l3_route->nexthops[nxthop_proto][i]->hit_count);
                    }
                    nxthop_cnt++;
                }
            }
        }
    } ITERATE_GLTHREAD_END(&rt_table->route_list, curr); 
    printf("\t|===================|=======|============|====================|==============|==========|============|==============|\n");
    pthread_rwlock_unlock(&rt_table->rwlock);
}

void
rt_table_add_direct_route(rt_table_t *rt_table,
                                          const char *dst, 
                                          char mask){

    rt_table_add_route(rt_table, dst, mask, 0, 0, 0, PROTO_STATIC);
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

    prefix = tcp_ip_covert_ip_p_to_n(l3_route->dest);

    pfx_lst_result_t policy_res = prefix_list_evaluate (prefix, l3_route->mask, rt_table->import_policy) ;

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
        printf ("Info : Route Installation Rejected due to Import policy\n");
        return false;
    }

   bin_ip = tcp_ip_covert_ip_p_to_n(l3_route->dest);
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

    if (rc != MTRIE_INSERT_SUCCESS) return false;

    mnode->data = (void *)l3_route;
	l3_route->install_time = time(NULL);
    rt_table_add_route_to_notify_list (rt_table, l3_route, RT_ADD_F);
    rt_table_kick_start_notif_job(rt_table);
    return true;
}

void
rt_table_add_route (rt_table_t *rt_table,
                                const char *dst, 
                                char mask,
                                const char *gw, 
                                interface_t *oif,
                                uint32_t spf_metric,
                                uint8_t proto_id){

   bool new_route = false;
   char dst_str_with_mask[16];

    apply_mask(dst, mask, dst_str_with_mask); 

    nxthop_proto_id_t nxthop_proto = 
        l3_rt_map_proto_id_to_nxthop_index(proto_id);
    
    /* Taking Write lock because we need to add a route eventually to
    RT table */
    pthread_rwlock_wrlock(&rt_table->rwlock);

   l3_route_t *l3_route = rt_table_lookup_exact_match(
                                            rt_table, dst_str_with_mask, mask);

   if(!l3_route){
       l3_route = XCALLOC(0, 1, l3_route_t);
       string_copy((char *)l3_route->dest, dst_str_with_mask, 16);
       l3_route->dest[15] = '\0';
       l3_route->mask = mask;
       new_route = true;
       l3_route->is_direct = true;
       l3_route->nh_count = 0;
       l3_route->ref_count = 0;
   }
   
   int i = 0;

   /*Get the index into nexthop array to fill the new nexthop*/
   if(!new_route){
       for( ; i < MAX_NXT_HOPS; i++){

           if(l3_route->nexthops[nxthop_proto][i]){
                if(string_compare(l3_route->nexthops[nxthop_proto][i]->gw_ip, gw, 16) == 0 && 
                    l3_route->nexthops[nxthop_proto][i]->oif == oif){ 
                    printf("%s Error : Attempt to Add Duplicate Route %s/%d\n",
                            rt_table->node->node_name, dst_str_with_mask, mask);
                    pthread_rwlock_unlock(&rt_table->rwlock);
                    return;
                }
           }
           else break;
       }
   }

   if( i == MAX_NXT_HOPS){
        printf("%s Error : No Nexthop space left for route %s/%u\n", 
            rt_table->node->node_name, dst_str_with_mask, mask);
        
        pthread_rwlock_unlock(&rt_table->rwlock);
        return;
   }

   if(gw && oif){
        nexthop_t *nexthop = XCALLOC(0, 1, nexthop_t);
        l3_route->is_direct = false;
        l3_route->spf_metric[nxthop_proto] = spf_metric;
        string_copy((char *)nexthop->gw_ip, gw, 16);
        nexthop->gw_ip[15] = '\0';
        nexthop->oif = oif;
        nexthop->ifindex = IF_INDEX(oif);
        nexthop->proto = proto_id;
		l3_route_insert_nexthop(l3_route, nexthop, nxthop_proto);
        if (!new_route) {
            rt_table_add_route_to_notify_list (rt_table, l3_route, RT_UPDATE_F);
            rt_table_kick_start_notif_job(rt_table);
        }
   }

   if(new_route){
       if(!_rt_table_entry_add(rt_table, l3_route)){
           printf("%s Error : Route %s/%d Installation Failed\n", 
                     rt_table->node->node_name,
                   dst_str_with_mask, mask);
           l3_route_unlock (l3_route);   
       }
       else {
           l3_route_lock (l3_route);   
       }
   }
   pthread_rwlock_unlock(&rt_table->rwlock);
}

static void
_layer3_pkt_recv_from_layer2(node_t *node, 
                            interface_t *interface,
                           pkt_block_t *pkt_block,
                            int L3_protocol_type) {

    uint8_t *pkt;
    pkt_size_t pkt_size;

    assert(pkt_block_verify_pkt (pkt_block, ETH_HDR));

    pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    switch(L3_protocol_type){
        
        case ETH_IP:
        case IP_IN_IP:

            /* Remove the Data link Hdr from the pkt */
            pkt_block_set_new_pkt( pkt_block,
                    (uint8_t *)pkt_block_get_ip_hdr(pkt_block),
                    pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD + ETH_FCS_SIZE);
            pkt_block_set_starting_hdr_type(pkt_block, 
                L3_protocol_type == ETH_IP ? IP_HDR : IP_IN_IP_HDR);

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
                      interface_t *interface,  /*ingress interface*/
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

    ip_hdr_t iphdr;
    char ip_addr[16];
    pkt_size_t pkt_size;

    initialize_ip_hdr(&iphdr);  
      
    uint8_t *pkt = pkt_block_get_pkt(pkt_block,  &pkt_size);

    /*Now fill the non-default fields*/
    iphdr.protocol = tcp_ip_convert_internal_proto_to_std_proto(protocol_number);

    uint32_t addr_int =  tcp_ip_covert_ip_p_to_n(NODE_LO_ADDR(node));
    iphdr.src_ip = addr_int;
    iphdr.dst_ip = dest_ip_address;

    iphdr.total_length = IP_HDR_COMPUTE_DEFAULT_TOTAL_LEN(pkt_size);

    uint8_t *new_pkt = NULL;
    pkt_size_t new_pkt_size = 0 ;

    /* Make a room in pkt to accomodate IP Hdr */
    if (!pkt_block_expand_buffer_left (pkt_block, IP_HDR_LEN_IN_BYTES((&iphdr)))) {
        pkt_block_dereference(pkt_block);
        return;
    }

    new_pkt = pkt_block_get_pkt (pkt_block,  &new_pkt_size);
    pkt_block_set_starting_hdr_type(pkt_block, IP_HDR);

    memcpy((char *)new_pkt, (char *)&iphdr, IP_HDR_LEN_IN_BYTES((&iphdr)));

    /*Now Resolve Next hop*/
    l3_route_t *l3_route = l3rib_lookup_lpm(NODE_RT_TABLE(node), 
                                          iphdr.dst_ip);
    
    if(!l3_route){
        printf("Node : %s : No L3 route %s\n",
			node->node_name, tcp_ip_covert_ip_n_to_p(iphdr.dst_ip, ip_addr));   
		pkt_block_dereference(pkt_block);
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
            pkt_block_dereference(pkt_block);
            return;
        }

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

    nexthop = l3_route_get_active_nexthop(l3_route);
    
    if(!nexthop){
        pkt_block_dereference(pkt_block);
        return;
    }
    
    if (access_list_evaluate_ip_packet(node, 
                nexthop->oif, 
                (ip_hdr_t *)pkt_block_get_ip_hdr(pkt_block),
                false) == ACL_DENY) {

        pkt_block_dereference (pkt_block);
        return;
    }

    inet_pton(AF_INET, nexthop->gw_ip, &next_hop_ip);
    next_hop_ip = htonl(next_hop_ip);

    tcp_dump_l3_fwding_logger(node,
                                                    nexthop->oif->if_name, 
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
        pkt_block_dereference(pkt_block);
        return;
    }

    demote_pkt_to_layer2(node,
            next_hop_ip,
            nexthop->oif->if_name,
            pkt_block,
            IP_HDR);

    nexthop->hit_count++;
}

/* This fn sends a dummy packet to test L3 and L2 routing
 * in the project. We send dummy Packet starting from Network
 * Layer on node 'node' to destination address 'dst_ip_addr'
 * using below fn*/
void
layer3_ping_fn(node_t *node, char *dst_ip_addr){

    uint32_t addr_int;
    pkt_block_t *pkt_block;

    printf("Src node : %s, Ping ip : %s\n", node->node_name, dst_ip_addr);
    
    addr_int = tcp_ip_covert_ip_p_to_n(dst_ip_addr);

    /* We dont have any application or transport layer paylod, so, directly prepare
     * L3 hdr*/
    pkt_block = pkt_block_get_new(NULL, 0);
    pkt_block_reference(pkt_block);

    demote_packet_to_layer3(node, pkt_block,  ICMP_HDR, addr_int);
}

void
layer3_ero_ping_fn(node_t *node, char *dst_ip_addr, 
                    char *ero_ip_address){

    /*Prepare the payload and push it down to the network layer.
     The payload shall be inner ip hdr*/
    ip_hdr_t *inner_ip_hdr = XCALLOC(0, 1, ip_hdr_t);
    initialize_ip_hdr(inner_ip_hdr);
    inner_ip_hdr->total_length = sizeof(ip_hdr_t)/4;
    inner_ip_hdr->protocol = ICMP_PROTO;
    
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

    pkt_block_t *pkt_block = pkt_block_get_new(
                            (uint8_t *)inner_ip_hdr,
                            IP_HDR_TOTAL_LEN_IN_BYTES(inner_ip_hdr));

    pkt_block_set_starting_hdr_type(pkt_block, IP_HDR);
    pkt_block_reference(pkt_block);

    demote_packet_to_layer3(node, 
                            pkt_block,
                            IP_IN_IP, 
                            addr_int);
}

/*Wrapper fn to be used by Applications*/
void
tcp_ip_send_ip_data(node_t *node, char *app_data, uint32_t data_size,
                    int L5_protocol_id, uint32_t dest_ip_address){

    pkt_block_t *pkt_block = pkt_block_get_new(
        (uint8_t *)app_data, (pkt_size_t)data_size);

    pkt_block_set_starting_hdr_type(pkt_block, MISC_APP_HDR);

    pkt_block_reference(pkt_block);

    demote_packet_to_layer3(node, pkt_block,
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
        string_copy((char *)IF_IP(intf), intf_ip_addr, 16);
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
    if (string_compare(IF_IP(intf), intf_ip_addr, 16) || 
            IF_MASK(intf) != mask ) {

        ip_addr_int = tcp_ip_covert_ip_p_to_n(IF_IP(intf));
        intf_prop_changed.ip_addr.ip_addr = ip_addr_int;
        intf_prop_changed.ip_addr.mask = IF_MASK(intf);
        SET_BIT(if_change_flags, IF_IP_ADDR_CHANGE_F);
        rt_table_delete_route(NODE_RT_TABLE(node),  IF_IP(intf), IF_MASK(intf), PROTO_STATIC);
        string_copy((char *)IF_IP(intf), intf_ip_addr, 16);
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

    if (string_compare(IF_IP(intf), new_intf_ip_addr, 16)  ||
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

    rt_table_delete_route(NODE_RT_TABLE(node),  new_intf_ip_addr, new_mask, PROTO_STATIC);

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
