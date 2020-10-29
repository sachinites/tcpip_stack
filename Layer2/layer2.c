/*
 * =====================================================================================
 *
 *       Filename:  layer2.c
 *
 *    Description:  This file implements all the Data link Layer functionality
 *
 *        Version:  1.0
 *        Created:  Friday 20 September 2019 05:15:51  IST
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

#include "graph.h"
#include <stdio.h>
#include "layer2.h"
#include <stdlib.h>
#include <sys/socket.h>
#include "comm.h"
#include <arpa/inet.h> /*for inet_ntop & inet_pton*/
#include <unistd.h>
#include "../tcp_ip_trace.h"
#include "../WheelTimer/WheelTimer.h"

#define ARP_ENTRY_EXP_TIME	30

/*Layer 2 Globals : */
/* to decide that whenever layer 2 promote pkt to upper layer of
 * TCP/IP stack, should layer 2 chop-off data link hdr or handover the pkt
 * to upper layer along with data link hdr intact*/
static unsigned short 
l2_proto_include_l2_hdr[MAX_L2_PROTO_INCLUSION_SUPPORTED];

static bool_t 
should_include_l2_hdr(uint32_t L2_protocol_no){

    int i = 0;
    for( ; i < MAX_L2_PROTO_INCLUSION_SUPPORTED; i++){
        if(l2_proto_include_l2_hdr[i] == L2_protocol_no)
            return TRUE;
    }
    return FALSE;
}

void
tcp_ip_stack_register_l2_proto_for_l2_hdr_inclusion(
        uint32_t L2_protocol_no){

    int i = 0, j = 0;
    for( ; i < MAX_L2_PROTO_INCLUSION_SUPPORTED; i++){
        if(l2_proto_include_l2_hdr[i] == L2_protocol_no)
            return;
        if(l2_proto_include_l2_hdr[i] == 0){
            j = i;
        }
    }
    if(j){
        l2_proto_include_l2_hdr[j] = L2_protocol_no;
        return;
    }
    printf("Error : Could not register L2 protocol %u for l2 Hdr inclusion", 
        L2_protocol_no);
}

void
tcp_ip_stack_unregister_l2_proto_for_l2_hdr_inclusion(
        uint32_t L2_protocol_no){

    int i = 0;
    for( ; i < MAX_L2_PROTO_INCLUSION_SUPPORTED; i++){
        if(l2_proto_include_l2_hdr[i] == L2_protocol_no){
            l2_proto_include_l2_hdr[i] = 0;
            return;
        }
    }
}

/*A Routine to resolve ARP out of oif*/
void
send_arp_broadcast_request(node_t *node,
                           interface_t *oif,
                           char *ip_addr){

    /*Take memory which can accomodate Ethernet hdr + ARP hdr*/
    uint32_t payload_size = sizeof(arp_hdr_t);

    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)calloc(1, 
                ETH_HDR_SIZE_EXCL_PAYLOAD + payload_size);

    if(!oif){
        oif = node_get_matching_subnet_interface(node, ip_addr);
        if(!oif){
            printf("Error : %s : No eligible subnet for ARP resolution for Ip-address : %s",
                    node->node_name, ip_addr);
            return;
        }
        if(strncmp(IF_IP(oif), ip_addr, 16) == 0){
            printf("Error : %s : Attemp to resolve ARP for local Ip-address : %s",
                    node->node_name, ip_addr);
            return;
        }
    }
    /*STEP 1 : Prepare ethernet hdr*/
    layer2_fill_with_broadcast_mac(ethernet_hdr->dst_mac.mac);
    memcpy(ethernet_hdr->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
    ethernet_hdr->type = ARP_MSG;

    /*Step 2 : Prepare ARP Broadcast Request Msg out of oif*/
    arp_hdr_t *arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr));
    arp_hdr->hw_type = 1;
    arp_hdr->proto_type = 0x0800;
    arp_hdr->hw_addr_len = sizeof(mac_add_t);
    arp_hdr->proto_addr_len = 4;

    arp_hdr->op_code = ARP_BROAD_REQ;

    memcpy(arp_hdr->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));

    inet_pton(AF_INET, IF_IP(oif), &arp_hdr->src_ip);
    arp_hdr->src_ip = htonl(arp_hdr->src_ip);

    memset(arp_hdr->dst_mac.mac, 0,  sizeof(mac_add_t));

    inet_pton(AF_INET, ip_addr, &arp_hdr->dst_ip);
    arp_hdr->dst_ip = htonl(arp_hdr->dst_ip);

    SET_COMMON_ETH_FCS(ethernet_hdr, sizeof(arp_hdr_t), 0); /*Not used*/

    /*STEP 3 : Now dispatch the ARP Broadcast Request Packet out of interface*/
    send_pkt_out((char *)ethernet_hdr, 
            ETH_HDR_SIZE_EXCL_PAYLOAD + payload_size, oif);

    free(ethernet_hdr);
}

static void
send_arp_reply_msg(ethernet_hdr_t *ethernet_hdr_in, interface_t *oif){

    arp_hdr_t *arp_hdr_in = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr_in));

    ethernet_hdr_t *ethernet_hdr_reply = (ethernet_hdr_t *)calloc(1, MAX_PACKET_BUFFER_SIZE);

    memcpy(ethernet_hdr_reply->dst_mac.mac, arp_hdr_in->src_mac.mac, sizeof(mac_add_t));
    memcpy(ethernet_hdr_reply->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
    
    ethernet_hdr_reply->type = ARP_MSG;
    
    arp_hdr_t *arp_hdr_reply = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr_reply));
    
    arp_hdr_reply->hw_type = 1;
    arp_hdr_reply->proto_type = 0x0800;
    arp_hdr_reply->hw_addr_len = sizeof(mac_add_t);
    arp_hdr_reply->proto_addr_len = 4;
    
    arp_hdr_reply->op_code = ARP_REPLY;
    memcpy(arp_hdr_reply->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));

    inet_pton(AF_INET, IF_IP(oif), &arp_hdr_reply->src_ip);
    arp_hdr_reply->src_ip =  htonl(arp_hdr_reply->src_ip);

    memcpy(arp_hdr_reply->dst_mac.mac, arp_hdr_in->src_mac.mac, sizeof(mac_add_t));
    arp_hdr_reply->dst_ip = arp_hdr_in->src_ip;
  
    SET_COMMON_ETH_FCS(ethernet_hdr_reply, sizeof(arp_hdr_t), 0); /*Not used*/

    uint32_t total_pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(arp_hdr_t);

    char *shifted_pkt_buffer = pkt_buffer_shift_right((char *)ethernet_hdr_reply, 
                               total_pkt_size, MAX_PACKET_BUFFER_SIZE);

    send_pkt_out(shifted_pkt_buffer, total_pkt_size, oif);

    free(ethernet_hdr_reply);  
}

static void
process_arp_reply_msg(node_t *node, interface_t *iif,
                        ethernet_hdr_t *ethernet_hdr){

    arp_table_update_from_arp_reply( NODE_ARP_TABLE(node), 
                    (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr), iif);    
}


static void
process_arp_broadcast_request(node_t *node, interface_t *iif, 
                              ethernet_hdr_t *ethernet_hdr){

   /* ARP broadcast request msg has passed MAC Address check*/
   /* Now, this node need to reply to this ARP Broadcast req
    * msg if Dst ip address in ARP req msg matches iif's ip address*/

    char ip_addr[16];
    arp_hdr_t *arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr));

    uint32_t arp_dst_ip = htonl(arp_hdr->dst_ip);

    inet_ntop(AF_INET, &arp_dst_ip, ip_addr, 16);
    ip_addr[15] = '\0';
    
    if(strncmp(IF_IP(iif), ip_addr, 16)){
        #if 0
        printf("%s : Error : ARP Broadcast req msg dropped, "
                "Dst IP address %s did not match with interface ip : %s\n", 
                node->node_name, ip_addr , IF_IP(iif));
        #endif
        return;
    }

   send_arp_reply_msg(ethernet_hdr, iif);
}

extern void
l2_switch_recv_frame(interface_t *interface,
                     char *pkt, uint32_t pkt_size);

extern void
promote_pkt_to_layer3(node_t *node, interface_t *interface,
                         char *pkt, uint32_t pkt_size,
                         int L3_protocol_type,
                         uint32_t flags);

extern void
promote_pkt_to_layer5(node_t *node, interface_t *interface,
                         char *pkt, uint32_t pkt_size,
                         int L5_protocol_type,
                         uint32_t flags);

void
init_arp_table(arp_table_t **arp_table){

    *arp_table = calloc(1, sizeof(arp_table_t));
    init_glthread(&((*arp_table)->arp_entries));
}

arp_entry_t *
arp_table_lookup(arp_table_t *arp_table, char *ip_addr){

    glthread_t *curr;
    arp_entry_t *arp_entry;
    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, curr){
    
        arp_entry = arp_glue_to_arp_entry(curr);
        if(strncmp(arp_entry->ip_addr.ip_addr, ip_addr, 16) == 0){
            return arp_entry;
        }
    } ITERATE_GLTHREAD_END(&arp_table->arp_entries, curr);
    return NULL;
}

void
clear_arp_table(arp_table_t *arp_table){

    glthread_t *curr;
    arp_entry_t *arp_entry;

    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, curr){
        
        arp_entry = arp_glue_to_arp_entry(curr);
        delete_arp_entry(arp_entry);
    } ITERATE_GLTHREAD_END(&arp_table->arp_entries, curr);
}

void
delete_arp_table_entry(arp_table_t *arp_table, char *ip_addr){

    arp_entry_t *arp_entry = arp_table_lookup(arp_table, ip_addr);
    
    if(!arp_entry)
        return;

    delete_arp_entry(arp_entry);
}

bool_t
arp_table_entry_add(node_t *node,
					arp_table_t *arp_table, arp_entry_t *arp_entry,
                    glthread_t **arp_pending_list){

    if(arp_pending_list){
        assert(*arp_pending_list == NULL);   
    }

    arp_entry_t *arp_entry_old = arp_table_lookup(arp_table, 
            arp_entry->ip_addr.ip_addr);

    /* Case 0 : if ARP table do not exist already, then add it
     * and return TRUE*/
    if(!arp_entry_old){
        glthread_add_next(&arp_table->arp_entries, &arp_entry->arp_glue);
		assert(arp_entry->exp_timer_wt_elem == NULL);
		arp_entry->exp_timer_wt_elem =
			arp_entry_create_expiration_timer(
				node,
				arp_entry, ARP_ENTRY_EXP_TIME); 
        return TRUE;
    }
    

    /*Case 1 : If existing and new ARP entries are full and equal, then
     * do nothing*/
    if(arp_entry_old &&
            IS_ARP_ENTRIES_EQUAL(arp_entry_old, arp_entry)){

        return FALSE;
    }

    /*Case 2 : If there already exists full ARP table entry, then replace it*/
    if(arp_entry_old && !arp_entry_sane(arp_entry_old)){
        delete_arp_entry(arp_entry_old);
        init_glthread(&arp_entry->arp_glue);
        glthread_add_next(&arp_table->arp_entries, &arp_entry->arp_glue);
		assert(arp_entry->exp_timer_wt_elem == NULL);
		arp_entry->exp_timer_wt_elem =
			arp_entry_create_expiration_timer(
				node, arp_entry, ARP_ENTRY_EXP_TIME); 	
        return TRUE;
    }

    /*Case 3 : if existing ARP table entry is sane, and new one is also
     * sane, then move the pending arp list from new to old one and return FALSE*/
    if(arp_entry_old &&
        arp_entry_sane(arp_entry_old) &&
        arp_entry_sane(arp_entry)){
    
        if(!IS_GLTHREAD_LIST_EMPTY(&arp_entry->arp_pending_list)){
            glthread_add_next(&arp_entry_old->arp_pending_list,
                    arp_entry->arp_pending_list.right);
        }
        if(arp_pending_list)
            *arp_pending_list = &arp_entry_old->arp_pending_list;

		arp_entry_refresh_expiration_timer(arp_entry_old);
        return FALSE;
    }

    /*Case 4 : If existing ARP table entry is sane, but new one if full,
     * then copy contents of new ARP entry to old one, return FALSE*/
    if(arp_entry_old && 
        arp_entry_sane(arp_entry_old) && 
        !arp_entry_sane(arp_entry)){

        strncpy(arp_entry_old->mac_addr.mac,
				arp_entry->mac_addr.mac, sizeof(mac_add_t));
        strncpy(arp_entry_old->oif_name, arp_entry->oif_name, IF_NAME_SIZE);
        arp_entry_old->oif_name[IF_NAME_SIZE -1] = '\0';

        if(arp_pending_list)
            *arp_pending_list = &arp_entry_old->arp_pending_list;

		arp_entry_refresh_expiration_timer(arp_entry_old);
        return FALSE;
    }

    return FALSE;
}

static void 
pending_arp_processing_callback_function(node_t *node,
                                         interface_t *oif,
                                         arp_entry_t *arp_entry,
                                         arp_pending_entry_t *arp_pending_entry){

    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)arp_pending_entry->pkt;
    uint32_t pkt_size = arp_pending_entry->pkt_size;
    memcpy(ethernet_hdr->dst_mac.mac, arp_entry->mac_addr.mac, sizeof(mac_add_t));
    memcpy(ethernet_hdr->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
    SET_COMMON_ETH_FCS(ethernet_hdr, 
        pkt_size - GET_ETH_HDR_SIZE_EXCL_PAYLOAD(ethernet_hdr), 0);
    send_pkt_out((char *)ethernet_hdr, pkt_size, oif);
}


static void
process_arp_pending_entry(node_t *node, interface_t *oif, 
                          arp_entry_t *arp_entry, 
                          arp_pending_entry_t *arp_pending_entry){

    arp_pending_entry->cb(node, oif, arp_entry, arp_pending_entry);  
}

static void
delete_arp_pending_entry(arp_pending_entry_t *arp_pending_entry){

    remove_glthread(&arp_pending_entry->arp_pending_entry_glue);
    free(arp_pending_entry);
}

void
arp_table_update_from_arp_reply(arp_table_t *arp_table, 
                                arp_hdr_t *arp_hdr, interface_t *iif){

    uint32_t src_ip = 0;
    glthread_t *arp_pending_list = NULL;

    assert(arp_hdr->op_code == ARP_REPLY);

    arp_entry_t *arp_entry = calloc(1, sizeof(arp_entry_t));

    src_ip = htonl(arp_hdr->src_ip);

    inet_ntop(AF_INET, &src_ip, arp_entry->ip_addr.ip_addr, 16);

    arp_entry->ip_addr.ip_addr[15] = '\0';

    memcpy(arp_entry->mac_addr.mac, arp_hdr->src_mac.mac, sizeof(mac_add_t));

    strncpy(arp_entry->oif_name, iif->if_name, IF_NAME_SIZE);

    arp_entry->is_sane = FALSE;

    bool_t rc = arp_table_entry_add(iif->att_node, 
				arp_table, arp_entry, &arp_pending_list);

    glthread_t *curr;
    arp_pending_entry_t *arp_pending_entry;

    if(arp_pending_list){
        
        ITERATE_GLTHREAD_BEGIN(arp_pending_list, curr){
        
            arp_pending_entry = arp_pending_entry_glue_to_arp_pending_entry(curr);

            remove_glthread(&arp_pending_entry->arp_pending_entry_glue);

            process_arp_pending_entry(iif->att_node, iif, arp_entry, arp_pending_entry);
            
            delete_arp_pending_entry(arp_pending_entry);

        } ITERATE_GLTHREAD_END(arp_pending_list, curr);

		assert(IS_GLTHREAD_LIST_EMPTY(arp_pending_list));
        (arp_pending_list_to_arp_entry(arp_pending_list))->is_sane = FALSE;
    }

    if(rc == FALSE){
        delete_arp_entry(arp_entry);
    }
}


void
dump_arp_table(arp_table_t *arp_table){

    glthread_t *curr;
    arp_entry_t *arp_entry;
    int count = 0 ;

    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, curr){
        count++;
        arp_entry = arp_glue_to_arp_entry(curr);
        if(count == 1){
            printf("\t|========IP==========|========MAC========|=====OIF======|===Resolved==|=Exp-Time(sec)==|\n");
        }
        else{
            printf("\t|====================|===================|==============|=============|================|\n");
        }
        printf("\t| %-18s | %02x:%02x:%02x:%02x:%02x:%02x |  %-12s|   %-3s      |  %-4d          |\n", 
            arp_entry->ip_addr.ip_addr, 
            arp_entry->mac_addr.mac[0], 
            arp_entry->mac_addr.mac[1], 
            arp_entry->mac_addr.mac[2], 
            arp_entry->mac_addr.mac[3], 
            arp_entry->mac_addr.mac[4], 
            arp_entry->mac_addr.mac[5], 
            arp_entry->oif_name,
            arp_entry_sane(arp_entry) ? "FALSE" : "TRUE",
			arp_entry_get_exp_time_left(arp_entry));
    } ITERATE_GLTHREAD_END(&arp_table->arp_entries, curr);
    if(count){
        printf("\t|====================|===================|==============|=============|================|\n");
    }
}

/*Interface config APIs for L2 mode configuration*/

void
interface_set_l2_mode(node_t *node, 
                      interface_t *interface, 
                      char *l2_mode_option){

    intf_l2_mode_t intf_l2_mode;

    if(strncmp(l2_mode_option, "access", strlen("access")) == 0){
        intf_l2_mode = ACCESS;    
    }
    else if(strncmp(l2_mode_option, "trunk", strlen("trunk")) ==0){
        intf_l2_mode = TRUNK;
    }
    else{
        assert(0);
    }

    /*Case 1 : if interface is working in L3 mode, i.e. IP address is configured.
     * then disable ip address, and set interface in L2 mode*/
    if(IS_INTF_L3_MODE(interface)){
        interface->intf_nw_props.is_ipadd_config_backup = TRUE;
        interface->intf_nw_props.is_ipadd_config = FALSE;

        IF_L2_MODE(interface) = intf_l2_mode;
        return;
    }

    /*Case 2 : if interface is working neither in L2 mode or L3 mode, then
     * apply L2 config*/
    if(IF_L2_MODE(interface) == L2_MODE_UNKNOWN){
        IF_L2_MODE(interface) = intf_l2_mode;
        return;
    }

    /*case 3 : if interface is operating in same mode, and user config same mode
     * again, then do nothing*/
    if(IF_L2_MODE(interface) == intf_l2_mode){
        return;
    }

    /*case 4 : if interface is operating in access mode, and user config trunk mode,
     * then overwrite*/
    if(IF_L2_MODE(interface) == ACCESS &&
            intf_l2_mode == TRUNK){
        IF_L2_MODE(interface) = intf_l2_mode;
        return;
    }

    /* case 5 : if interface is operating in trunk mode, and user config access mode,
     * then overwrite, remove all vlans from interface, user must enable vlan again 
     * on interface*/
    if(IF_L2_MODE(interface) == TRUNK &&
           intf_l2_mode == ACCESS){

        IF_L2_MODE(interface) = intf_l2_mode;

        uint32_t i = 0;

        for ( ; i < MAX_VLAN_MEMBERSHIP; i++){
            interface->intf_nw_props.vlans[i] = 0;
        }
    }
}

void
interface_unset_l2_mode(node_t *node, 
                      interface_t *interface, 
                      char *l2_mode_option){

    
}

void
interface_set_vlan(node_t *node,
                   interface_t *interface,
                   uint32_t vlan_id){

    /* Case 1 : Cant set vlans on interface configured with ip
     * address*/
    if(IS_INTF_L3_MODE(interface)){
        printf("Error : Interface %s : L3 mode enabled\n", interface->if_name);
        return;
    }

    /*Case 2 : Cant set vlan on interface not operating in L2 mode*/
    if(IF_L2_MODE(interface) != ACCESS &&
        IF_L2_MODE(interface) != TRUNK){
        printf("Error : Interface %s : L2 mode not Enabled\n", interface->if_name);
        return;
    }

    /*case 3 : Can set only one vlan on interface operating in ACCESS mode*/
    if(interface->intf_nw_props.intf_l2_mode == ACCESS){
        
        uint32_t i = 0, *vlan = NULL;    
        for( ; i < MAX_VLAN_MEMBERSHIP; i++){
            if(interface->intf_nw_props.vlans[i]){
                vlan = &interface->intf_nw_props.vlans[i];
            }
        }
        if(vlan){
            *vlan = vlan_id;
            return;
        }
        interface->intf_nw_props.vlans[0] = vlan_id;
    }
    /*case 4 : Add vlan membership on interface operating in TRUNK mode*/
    if(interface->intf_nw_props.intf_l2_mode == TRUNK){

        uint32_t i = 0, *vlan = NULL;

        for( ; i < MAX_VLAN_MEMBERSHIP; i++){

            if(!vlan && interface->intf_nw_props.vlans[i] == 0){
                vlan = &interface->intf_nw_props.vlans[i];
            }
            else if(interface->intf_nw_props.vlans[i] == vlan_id){
                return;
            }
        }
        if(vlan){
            *vlan = vlan_id;
            return;
        }
        printf("Error : Interface %s : Max Vlan membership limit reached", interface->if_name);
    }
}

void
interface_unset_vlan(node_t *node,
                   interface_t *interface,
                   uint32_t vlan){

}

/*APIs to be used to create topologies*/
void
node_set_intf_l2_mode(node_t *node, char *intf_name, 
                        intf_l2_mode_t intf_l2_mode){

    interface_t *interface = get_node_if_by_name(node, intf_name);
    assert(interface);

    interface_set_l2_mode(node, interface, intf_l2_mode_str(intf_l2_mode));
}

void
node_set_intf_vlan_membsership(node_t *node, char *intf_name, 
                                uint32_t vlan_id){

    interface_t *interface = get_node_if_by_name(node, intf_name);
    assert(interface);

    interface_set_vlan(node, interface, vlan_id);
}

static void
l2_forward_ip_packet(node_t *node, uint32_t next_hop_ip,
                    char *outgoing_intf, ethernet_hdr_t *pkt, 
                    uint32_t pkt_size){

    interface_t *oif = NULL;
    char next_hop_ip_str[16];
    arp_entry_t * arp_entry = NULL;
    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)pkt;
    
    uint32_t ethernet_payload_size = 
        pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD;

    next_hop_ip = htonl(next_hop_ip);
    inet_ntop(AF_INET, &next_hop_ip, next_hop_ip_str, 16);

    if(outgoing_intf) {

        /* It means, L3 has resolved the nexthop, So its time to L2 forward the pkt
         * out of this interface*/
        oif = get_node_if_by_name(node, outgoing_intf);
        assert(oif);

        arp_entry = arp_table_lookup(NODE_ARP_TABLE(node), next_hop_ip_str);

        if (!arp_entry){

            /*Time for ARP resolution*/
            create_arp_sane_entry(node, NODE_ARP_TABLE(node), 
                    next_hop_ip_str, 
                    (char *)pkt, 
                    pkt_size);

            send_arp_broadcast_request(node, oif, next_hop_ip_str);
            return;
        }
        goto l2_frame_prepare ;
    }
   
    /* if outgoing_intf is NULL, then two cases possible : 
       1. L2 has to forward the frame to self(destination is local interface ip address
        including loopback address)
       2. L2 has to forward the frame to machine on local connected subnet*/

    /*case 1 */
    
    oif = node_get_matching_subnet_interface(node, next_hop_ip_str);
   
    /*If the destination IP address do not match any local subnet Nor
     * is it a self loopback address*/
    if(!oif && strncmp(next_hop_ip_str, NODE_LO_ADDR(node), 16)){
        printf("%s : Error : Local matching subnet for IP : %s could not be found\n",
                    node->node_name, next_hop_ip_str);
        return;
    }

    /*if the destination ip address is exact match to local interface
     * ip address*/
    if((oif && strncmp(IF_IP(oif), next_hop_ip_str, 16) == 0)){
        /*send to self*/
        memset(ethernet_hdr->dst_mac.mac, 0, sizeof(mac_add_t));
        memset(ethernet_hdr->src_mac.mac, 0, sizeof(mac_add_t));
        SET_COMMON_ETH_FCS(ethernet_hdr, ethernet_payload_size, 0);
        send_pkt_to_self((char *)ethernet_hdr, pkt_size, oif);
        return;
    }

    /*If the destination ip address is exact match to self loopback address, 
     * rebounce the pkt to Network Layer again*/
    bool_t include_data_link_hdr = should_include_l2_hdr(ethernet_hdr->type);

    if(strncmp(next_hop_ip_str, NODE_LO_ADDR(node), 16) == 0){
       promote_pkt_to_layer3(node, 0, 
        !include_data_link_hdr ? GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr) : \
         (char *)ethernet_hdr,
         !include_data_link_hdr ? 
         pkt_size - GET_ETH_HDR_SIZE_EXCL_PAYLOAD(ethernet_hdr): \
         pkt_size,
         ethernet_hdr->type, include_data_link_hdr ? DATA_LINK_HDR_INCLUDED : 0);
         return;
    }

    arp_entry = arp_table_lookup(NODE_ARP_TABLE(node), next_hop_ip_str);

    if (!arp_entry || (arp_entry && arp_entry_sane(arp_entry))){
        
        /*Time for ARP resolution*/
        create_arp_sane_entry(node, NODE_ARP_TABLE(node), 
                next_hop_ip_str, 
                (char *)pkt, 
                pkt_size);
        send_arp_broadcast_request(node, oif, next_hop_ip_str);
        return;
    }

    l2_frame_prepare:
        memcpy(ethernet_hdr->dst_mac.mac, arp_entry->mac_addr.mac, sizeof(mac_add_t));
        memcpy(ethernet_hdr->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
        SET_COMMON_ETH_FCS(ethernet_hdr, ethernet_payload_size, 0);
        send_pkt_out((char *)ethernet_hdr, pkt_size, oif);
		arp_entry_refresh_expiration_timer(arp_entry);
}


/* An API to be used by Layer 3 or higher to push the pkt
 * down the TCP IP Stack to L2. Note that, though most of the time
 * this API shall be used by L3, but any Higher Layer API can use
 * this API. For example, An application can run directly on L2 bypassing
 * L3 altogether.*/
void
demote_pkt_to_layer2(node_t *node, /*Current node*/ 
        uint32_t next_hop_ip,  /*If pkt is forwarded to next router, 
                                 then this is Nexthop IP address (gateway) 
                                 provided by L3 layer. L2 need to resolve ARP for this IP address*/
        char *outgoing_intf,   /*The oif obtained from L3 lookup if L3 
                                 has decided to forward the pkt. If NULL, 
                                 then L2 will find the appropriate interface*/
        char *pkt, uint32_t pkt_size,   /*Higher Layers payload*/
        int protocol_number){           /*Higher Layer need to tell L2 
                                          what value need to be feed in eth_hdr->type field*/

    assert(pkt_size < sizeof(((ethernet_hdr_t *)0)->payload));

    switch(protocol_number){
        case ETH_IP:
            {
                ethernet_hdr_t *empty_ethernet_hdr = 
                    ALLOC_ETH_HDR_WITH_PAYLOAD(pkt, pkt_size); 

                empty_ethernet_hdr->type = ETH_IP;

                l2_forward_ip_packet(node, next_hop_ip, 
                        outgoing_intf, empty_ethernet_hdr, 
                        pkt_size + ETH_HDR_SIZE_EXCL_PAYLOAD); 
            }
        break;
        default:
            ;
    }
}

void
delete_arp_entry(arp_entry_t *arp_entry){
    
    glthread_t *curr;
    arp_pending_entry_t *arp_pending_entry;

    remove_glthread(&arp_entry->arp_glue);

    ITERATE_GLTHREAD_BEGIN(&arp_entry->arp_pending_list, curr){

        arp_pending_entry = arp_pending_entry_glue_to_arp_pending_entry(curr);
        delete_arp_pending_entry(arp_pending_entry);
    } ITERATE_GLTHREAD_END(&arp_entry->arp_pending_list, curr);

	arp_entry_delete_expiration_timer(arp_entry);
    free(arp_entry);
}

void
add_arp_pending_entry(arp_entry_t *arp_entry,
        arp_processing_fn cb,
        char *pkt,
        uint32_t pkt_size){

    arp_pending_entry_t *arp_pending_entry = 
        calloc(1, sizeof(arp_pending_entry_t) + pkt_size);

    init_glthread(&arp_pending_entry->arp_pending_entry_glue);
    arp_pending_entry->cb = cb;
    arp_pending_entry->pkt_size = pkt_size;
    memcpy(arp_pending_entry->pkt, pkt, pkt_size);

    glthread_add_next(&arp_entry->arp_pending_list, 
                    &arp_pending_entry->arp_pending_entry_glue);
}

void
create_arp_sane_entry(node_t *node,
					  arp_table_t *arp_table, char *ip_addr, 
                      char *pkt, uint32_t pkt_size){

    /*case 1 : If full entry already exist - assert. The L2 must have
     * not create ARP sane entry if the already was already existing*/

    arp_entry_t *arp_entry = arp_table_lookup(arp_table, ip_addr);
    
    if(arp_entry){
    
        if(!arp_entry_sane(arp_entry)){
            assert(0);
        }

        /*ARP sane entry already exists, append the arp pending entry to it*/
        add_arp_pending_entry(arp_entry, 
                              pending_arp_processing_callback_function, 
                              pkt, pkt_size);
	    arp_entry_refresh_expiration_timer(arp_entry);	
        return;
    }

    /*if ARP entry do not exist, create a new sane entry*/
    arp_entry = calloc(1, sizeof(arp_entry_t));
    strncpy(arp_entry->ip_addr.ip_addr, ip_addr, 16);
    arp_entry->ip_addr.ip_addr[15] = '\0';
    init_glthread(&arp_entry->arp_pending_list);
    arp_entry->is_sane = TRUE;
    add_arp_pending_entry(arp_entry, 
                          pending_arp_processing_callback_function, 
                          pkt, pkt_size);
    bool_t rc = arp_table_entry_add(node, arp_table, arp_entry, 0);
    if(rc == FALSE){
        assert(0);
    }
}

static void
arp_entry_timer_delete_cbk(void *arg,
						   uint32_t arg_size){

	arp_entry_t *arp_entry = (arp_entry_t *)arg;
	delete_arp_entry(arp_entry);	
}

/* ARP entry Timer management functions */
wheel_timer_elem_t *
arp_entry_create_expiration_timer(
	node_t *node,
	arp_entry_t *arp_entry,
	uint16_t exp_time) {

	assert(arp_entry->exp_timer_wt_elem == NULL);
	
	arp_entry->exp_timer_wt_elem = register_app_event(
					 node_get_timer_instance(node),
					 arp_entry_timer_delete_cbk,
					 (void *)arp_entry,
					 sizeof(arp_entry),
					 ARP_ENTRY_EXP_TIME,
					 0); 				 
}

void
arp_entry_delete_expiration_timer(
	arp_entry_t *arp_entry) {

	if(!arp_entry->exp_timer_wt_elem) 
		return;
	de_register_app_event(arp_entry->exp_timer_wt_elem);
	arp_entry->exp_timer_wt_elem = NULL;
}

void
arp_entry_refresh_expiration_timer(
	arp_entry_t *arp_entry) {

	wt_elem_reschedule(arp_entry->exp_timer_wt_elem,
		ARP_ENTRY_EXP_TIME);
}

uint16_t
arp_entry_get_exp_time_left(
	arp_entry_t *arp_entry){

	assert(arp_entry->exp_timer_wt_elem);
	return wt_get_remaining_time(arp_entry->exp_timer_wt_elem);
}

/*Vlan Management Routines*/

/* Return new packet size if pkt is tagged with new vlan id*/

ethernet_hdr_t * 
tag_pkt_with_vlan_id(ethernet_hdr_t *ethernet_hdr, 
                     uint32_t total_pkt_size,
                     int vlan_id, 
                     uint32_t *new_pkt_size){

    *new_pkt_size = 0;
    uint32_t payload_size  = 0 ;

    /*If the pkt is already tagged, replace it*/
    vlan_8021q_hdr_t *vlan_8021q_hdr = 
        is_pkt_vlan_tagged(ethernet_hdr);

    
    if(vlan_8021q_hdr){
        payload_size = total_pkt_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;
        vlan_8021q_hdr->tci_vid = (short)vlan_id;
        
        /*Update checksum, however not used*/
        SET_COMMON_ETH_FCS(ethernet_hdr, payload_size, 0);

        *new_pkt_size = total_pkt_size;
        return ethernet_hdr;
    }

    /*If the pkt is not already tagged, tag it*/
    /*Fix me : Avoid declaring local variables of type 
     ethernet_hdr_t or vlan_ethernet_hdr_t as the size of these
     variables are too large and is not healthy for program stack
     memory*/
    ethernet_hdr_t ethernet_hdr_old;
    memcpy((char *)&ethernet_hdr_old, (char *)ethernet_hdr, 
                ETH_HDR_SIZE_EXCL_PAYLOAD - ETH_FCS_SIZE);

    payload_size = total_pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD; 
    vlan_ethernet_hdr_t *vlan_ethernet_hdr = 
            (vlan_ethernet_hdr_t *)((char *)ethernet_hdr - sizeof(vlan_8021q_hdr_t));

    memset((char *)vlan_ethernet_hdr, 0, 
                VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD - ETH_FCS_SIZE);
    memcpy(vlan_ethernet_hdr->dst_mac.mac, 
        ethernet_hdr_old.dst_mac.mac, sizeof(mac_add_t));
    memcpy(vlan_ethernet_hdr->src_mac.mac, 
        ethernet_hdr_old.src_mac.mac, sizeof(mac_add_t));

    /*Come to 802.1Q vlan hdr*/
    vlan_ethernet_hdr->vlan_8021q_hdr.tpid = VLAN_8021Q_PROTO;
    vlan_ethernet_hdr->vlan_8021q_hdr.tci_pcp = 0;
    vlan_ethernet_hdr->vlan_8021q_hdr.tci_dei = 0;
    vlan_ethernet_hdr->vlan_8021q_hdr.tci_vid = (short)vlan_id;

    /*Type field*/
    vlan_ethernet_hdr->type = ethernet_hdr_old.type;

    /*No need to copy data*/

    /*Update checksum, however not used*/
    SET_COMMON_ETH_FCS((ethernet_hdr_t *)vlan_ethernet_hdr, payload_size, 0 );
    *new_pkt_size = total_pkt_size  + sizeof(vlan_8021q_hdr_t);
    return (ethernet_hdr_t *)vlan_ethernet_hdr;
}

/* Return new packet size if pkt is untagged with the existing
 * vlan 801.1q hdr*/
ethernet_hdr_t *
untag_pkt_with_vlan_id(ethernet_hdr_t *ethernet_hdr, 
                     uint32_t total_pkt_size,
                     uint32_t *new_pkt_size){

    *new_pkt_size = 0;

    vlan_8021q_hdr_t *vlan_8021q_hdr =
        is_pkt_vlan_tagged(ethernet_hdr);
    
    /*NOt tagged already, do nothing*/    
    if(!vlan_8021q_hdr){
        *new_pkt_size = total_pkt_size;
        return ethernet_hdr;
    }

    /*Fix me : Avoid declaring local variables of type 
      ethernet_hdr_t or vlan_ethernet_hdr_t as the size of these
      variables are too large and is not healthy for program stack
      memory*/
    vlan_ethernet_hdr_t vlan_ethernet_hdr_old;
    memcpy((char *)&vlan_ethernet_hdr_old, (char *)ethernet_hdr, 
                VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD - ETH_FCS_SIZE);

    ethernet_hdr = (ethernet_hdr_t *)((char *)ethernet_hdr + sizeof(vlan_8021q_hdr_t));
   
    memcpy(ethernet_hdr->dst_mac.mac, vlan_ethernet_hdr_old.dst_mac.mac, sizeof(mac_add_t));
    memcpy(ethernet_hdr->src_mac.mac, vlan_ethernet_hdr_old.src_mac.mac, sizeof(mac_add_t));

    ethernet_hdr->type = vlan_ethernet_hdr_old.type;
    
    /*No need to copy data*/
    uint32_t payload_size = total_pkt_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;

    /*Update checksum, however not used*/
    SET_COMMON_ETH_FCS(ethernet_hdr, payload_size, 0);
    
    *new_pkt_size = total_pkt_size - sizeof(vlan_8021q_hdr_t);
    return ethernet_hdr;
}

static void
promote_pkt_to_layer2(node_t *node, interface_t *iif, 
                      ethernet_hdr_t *ethernet_hdr, 
                      uint32_t pkt_size){

    bool_t include_data_link_hdr;

    switch(ethernet_hdr->type){
        case ARP_MSG:
            {
                /*Can be ARP Broadcast or ARP reply*/
                arp_hdr_t *arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr));
                switch(arp_hdr->op_code){
                    case ARP_BROAD_REQ:
                        process_arp_broadcast_request(node, iif, ethernet_hdr);
                        break;
                    case ARP_REPLY:
                        process_arp_reply_msg(node, iif, ethernet_hdr);
                        break;
                    default:
                        break;
                }
            }
            break;
#if 0
        case DDCP_MSG_TYPE_FLOOD_QUERY:
            /* Promote the pkt to application layer. Application Layer doesnt necessarily
             * means the application is running on top of Transport/Network Layer. Since
             * we are promoting the pkt from Data link layer to Application layer directly,
             * It means this application is running directly on top of data link layer.*/
            promote_pkt_to_layer5(node, iif, 
                (char *)ethernet_hdr, /*No need to chop off ethernet hdr in this case*/
                pkt_size, ethernet_hdr->type);
            break;
#endif
        case ETH_IP:
        case IP_IN_IP:
#if 0
        case DDCP_MSG_TYPE_UCAST_REPLY:
#endif
            include_data_link_hdr = should_include_l2_hdr(ethernet_hdr->type);
            promote_pkt_to_layer3(node, iif, 
                    !include_data_link_hdr ? GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr) : \
                    (char *)ethernet_hdr,
                    !include_data_link_hdr ? 
                    pkt_size - GET_ETH_HDR_SIZE_EXCL_PAYLOAD(ethernet_hdr) : \
                    pkt_size,
                    ethernet_hdr->type,
                    include_data_link_hdr ? DATA_LINK_HDR_INCLUDED : 0);
            break;
        default:
            include_data_link_hdr = should_include_l2_hdr(ethernet_hdr->type);
            promote_pkt_to_layer5(node, iif, 
                    !include_data_link_hdr ? GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr) : \
                    (char *)ethernet_hdr,
                    !include_data_link_hdr ? 
                    pkt_size - GET_ETH_HDR_SIZE_EXCL_PAYLOAD(ethernet_hdr) : \
                    pkt_size,
                    ethernet_hdr->type,
                    include_data_link_hdr ? DATA_LINK_HDR_INCLUDED : 0);
            ;
    }
}

void
layer2_frame_recv(node_t *node, interface_t *interface,
                     char *pkt, uint32_t pkt_size){

    uint32_t vlan_id_to_tag = 0;

    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)pkt;

    if(l2_frame_recv_qualify_on_interface(interface, 
                                          ethernet_hdr, 
                                          &vlan_id_to_tag) == FALSE){
        
        printf("L2 Frame Rejected on node %s(%s)\n", 
            node->node_name, interface->if_name);
        return;
    }

    if(IS_INTF_L3_MODE(interface)){

        promote_pkt_to_layer2(node, interface, ethernet_hdr, pkt_size);
    }
    else if(IF_L2_MODE(interface) == ACCESS ||
                IF_L2_MODE(interface) == TRUNK){

        uint32_t new_pkt_size = 0;

        if(vlan_id_to_tag){
            pkt = (char *)tag_pkt_with_vlan_id((ethernet_hdr_t *)pkt,
                                                pkt_size, vlan_id_to_tag,
                                                &new_pkt_size);
            assert(new_pkt_size != pkt_size);
        }
        l2_switch_recv_frame(interface, pkt, 
            vlan_id_to_tag ? new_pkt_size : pkt_size);
    }
    else
        return; /*Do nothing, drop the packet*/
}
