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

/*A Routine to resolve ARP out of oif*/
void
send_arp_broadcast_request(node_t *node,
                           interface_t *oif,
                           char *ip_addr){

    /*Take memory which can accomodate Ethernet hdr + ARP hdr*/
    unsigned int payload_size = sizeof(arp_hdr_t);
    ethernet_hdr_t *ethernet_hdr = ALLOC_ETH_HDR_WITH_PAYLOAD(payload_size);

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
    arp_hdr_t *arp_hdr = (arp_hdr_t *)(ethernet_hdr->payload);
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

    ETH_FCS(ethernet_hdr, sizeof(arp_hdr_t)) = 0; /*Not used*/

    /*STEP 3 : Now dispatch the ARP Broadcast Request Packet out of interface*/
    send_pkt_out((char *)ethernet_hdr, ETH_HDR_SIZE_EXCL_PAYLOAD + payload_size,
                    oif);

    free(ethernet_hdr);
}

static void
send_arp_reply_msg(ethernet_hdr_t *ethernet_hdr_in, interface_t *oif){

    arp_hdr_t *arp_hdr_in = (arp_hdr_t *)(ethernet_hdr_in->payload);

    ethernet_hdr_t *ethernet_hdr_reply = ALLOC_ETH_HDR_WITH_PAYLOAD(sizeof(arp_hdr_t));

    memcpy(ethernet_hdr_reply->dst_mac.mac, arp_hdr_in->src_mac.mac, sizeof(mac_add_t));
    memcpy(ethernet_hdr_reply->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
    
    ethernet_hdr_reply->type = ARP_MSG;
    
    arp_hdr_t *arp_hdr_reply = (arp_hdr_t *)(ethernet_hdr_reply->payload);
    
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
  
    send_pkt_out((char *)ethernet_hdr_reply, sizeof(ethernet_hdr_t) + sizeof(arp_hdr_t),
                    oif);

    ETH_FCS(ethernet_hdr_reply, sizeof(arp_hdr_t)) = 0; /*Not used*/
    free(ethernet_hdr_reply);  
}

static void
process_arp_reply_msg(node_t *node, interface_t *iif,
                        ethernet_hdr_t *ethernet_hdr){

    printf("%s : ARP reply msg recvd on interface %s of node %s\n",
             __FUNCTION__, iif->if_name , iif->att_node->node_name);

    arp_table_update_from_arp_reply( NODE_ARP_TABLE(node), 
                    (arp_hdr_t *)(ethernet_hdr->payload), iif);    
}


static void
process_arp_broadcast_request(node_t *node, interface_t *iif, 
                              ethernet_hdr_t *ethernet_hdr){

   printf("%s : ARP Broadcast msg recvd on interface %s of node %s\n", 
                __FUNCTION__, iif->if_name , iif->att_node->node_name); 

   /* ARP broadcast request msg has passed MAC Address check*/
   /* Now, this node need to reply to this ARP Broadcast req
    * msg if Dst ip address in ARP req msg matches iif's ip address*/

    char ip_addr[16];
    arp_hdr_t *arp_hdr = (arp_hdr_t *)(ethernet_hdr->payload);

    unsigned int arp_dst_ip = htonl(arp_hdr->dst_ip);

    inet_ntop(AF_INET, &arp_dst_ip, ip_addr, 16);
    ip_addr[15] = '\0';
    
    if(strncmp(IF_IP(iif), ip_addr, 16)){
        
        printf("%s : ARP Broadcast req msg dropped, Dst IP address %s did not match with interface ip : %s\n", 
                node->node_name, ip_addr , IF_IP(iif));
        return;
    }

   send_arp_reply_msg(ethernet_hdr, iif);
}

extern void
l2_switch_recv_frame(interface_t *interface,
                     char *pkt, unsigned int pkt_size);

extern void
promote_pkt_to_layer3(node_t *node, interface_t *interface,
                         char *pkt, unsigned int pkt_size,
                         int L3_protocol_type);

void
layer2_frame_recv(node_t *node, interface_t *interface,
                     char *pkt, unsigned int pkt_size){

    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)pkt;
    
    if(l2_frame_recv_qualify_on_interface(interface, ethernet_hdr) == FALSE){
        
        printf("L2 Frame Rejected on node %s\n", node->node_name);
        return;
    }

    printf("L2 Frame Accepted on node %s\n", node->node_name);

    /*Handle Reception of a L2 Frame on L3 Interface*/
    if(IS_INTF_L3_MODE(interface)){

        switch(ethernet_hdr->type){
            /*When L2 Frame is ARP MSG - could be request or reply*/   
            case ARP_MSG:
                {
                    /*Can be ARP Broadcast or ARP reply*/
                    arp_hdr_t *arp_hdr = (arp_hdr_t *)(ethernet_hdr->payload);
                    switch(arp_hdr->op_code){
                        case ARP_BROAD_REQ:
                            process_arp_broadcast_request(node, interface, ethernet_hdr);
                            break;
                        case ARP_REPLY:
                            process_arp_reply_msg(node, interface, ethernet_hdr);
                            break;
                        default:
                            break;
                    }
                }
                break;
            case ETH_IP:
                promote_pkt_to_layer3(node, interface, (char *)(ethernet_hdr->payload), 
                    pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD, ETH_IP);
            default:
                break;
        }
    }
    else if(IF_L2_MODE(interface) == ACCESS ||
                IF_L2_MODE(interface) == TRUNK){

        l2_switch_recv_frame(interface, pkt, pkt_size);
    }
    else
        return; /*Do nothing, drop the packet*/
}

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
arp_table_entry_add(arp_table_t *arp_table, arp_entry_t *arp_entry,
                    glthread_t **arp_pending_list){

    if(arp_pending_list){
        assert(*arp_pending_list == NULL);   
    }

    arp_entry_t *arp_entry_old = arp_table_lookup(arp_table, 
            arp_entry->ip_addr.ip_addr);

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
        return FALSE;
    }

    /*Case 4 : If existing ARP table entry is sane, but new one if full,
     * then copy contents of new ARP entry to old one, return FALSE*/
    if(arp_entry_old && 
        arp_entry_sane(arp_entry_old) && 
        !arp_entry_sane(arp_entry)){

        strncpy(arp_entry_old->mac_addr.mac, arp_entry->mac_addr.mac, sizeof(mac_add_t));
        strncpy(arp_entry_old->oif_name, arp_entry->oif_name, IF_NAME_SIZE);
        arp_entry_old->oif_name[IF_NAME_SIZE -1] = '\0';

        if(arp_pending_list)
            *arp_pending_list = &arp_entry_old->arp_pending_list;
        return FALSE;
    }
}

static void 
pending_arp_processing_callback_function(node_t *node,
                                         interface_t *oif,
                                         arp_entry_t *arp_entry,
                                         arp_pending_entry_t *arp_pending_entry){

    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)arp_pending_entry->pkt;
    unsigned int pkt_size = arp_pending_entry->pkt_size;
    memcpy(ethernet_hdr->dst_mac.mac, arp_entry->mac_addr.mac, sizeof(mac_add_t));
    memcpy(ethernet_hdr->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
    // This is pending
    //ETH_FCS(ethernet_hdr, pkt_size - ) = 0;
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

    unsigned int src_ip = 0;
    glthread_t *arp_pending_list = NULL;

    assert(arp_hdr->op_code == ARP_REPLY);

    arp_entry_t *arp_entry = calloc(1, sizeof(arp_entry_t));

    src_ip = htonl(arp_hdr->src_ip);

    inet_ntop(AF_INET, &src_ip, &arp_entry->ip_addr.ip_addr, 16);

    arp_entry->ip_addr.ip_addr[15] = '\0';

    memcpy(arp_entry->mac_addr.mac, arp_hdr->src_mac.mac, sizeof(mac_add_t));

    strncpy(arp_entry->oif_name, iif->if_name, IF_NAME_SIZE);

    arp_entry->is_sane = FALSE;

    bool_t rc = arp_table_entry_add(arp_table, arp_entry, &arp_pending_list);

    glthread_t *curr;
    arp_pending_entry_t *arp_pending_entry;

    if(arp_pending_list){
        
        ITERATE_GLTHREAD_BEGIN(arp_pending_list, curr){
        
            arp_pending_entry = arp_pending_entry_glue_to_arp_pending_entry(curr);

            remove_glthread(&arp_pending_entry->arp_pending_entry_glue);

            process_arp_pending_entry(iif->att_node, iif, arp_entry, arp_pending_entry);
            
            delete_arp_pending_entry(arp_pending_entry);

        } ITERATE_GLTHREAD_END(arp_pending_list, curr);

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

    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, curr){

        arp_entry = arp_glue_to_arp_entry(curr);
        printf("IP : %s, MAC : %u:%u:%u:%u:%u:%u, OIF = %s\n", 
            arp_entry->ip_addr.ip_addr, 
            arp_entry->mac_addr.mac[0], 
            arp_entry->mac_addr.mac[1], 
            arp_entry->mac_addr.mac[2], 
            arp_entry->mac_addr.mac[3], 
            arp_entry->mac_addr.mac[4], 
            arp_entry->mac_addr.mac[5], 
            arp_entry->oif_name);
    } ITERATE_GLTHREAD_END(&arp_table->arp_entries, curr);
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

        unsigned int i = 0;

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
                   unsigned int vlan_id){

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
        
        unsigned int i = 0, *vlan = NULL;    
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

        unsigned int i = 0, *vlan = NULL;

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
                   unsigned int vlan){

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
                                unsigned int vlan_id){

    interface_t *interface = get_node_if_by_name(node, intf_name);
    assert(interface);

    interface_set_vlan(node, interface, vlan_id);
}

static void
l2_forward_ip_packet(node_t *node, unsigned int next_hop_ip,
                    char *outgoing_intf, ethernet_hdr_t *pkt, 
                    unsigned int pkt_size){

    interface_t *oif = NULL;
    char next_hop_ip_str[16];
    arp_entry_t * arp_entry = NULL;
    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)pkt;
    unsigned int ethernet_payload_size = pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD;

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
            create_arp_sane_entry(NODE_ARP_TABLE(node), 
                    next_hop_ip_str, 
                    (char *)pkt, 
                    pkt_size);

            send_arp_broadcast_request(node, oif, next_hop_ip_str);
            return;
        }
        goto l2_frame_prepare ;
    }
   
    /* if outgoing_intf is NULL, then two cases possible : 
       1. L2 has to forward the frame to self
       2. L2 has to forward the frame to machine on local connected subnet*/

    /*case 1 */
    
    oif = node_get_matching_subnet_interface(node, next_hop_ip_str);
    if(!oif){
        printf("%s : Error : Local matching subnet for IP : %s could not be found\n",
                    node->node_name, next_hop_ip_str);
        return;
    }

    if(strncmp(IF_IP(oif), next_hop_ip_str, 16) == 0){
        /*send to self*/
        memcpy(ethernet_hdr->dst_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
        memcpy(ethernet_hdr->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
        ETH_FCS(ethernet_hdr, ethernet_payload_size) = 0;
        send_pkt_to_self((char *)ethernet_hdr, pkt_size, oif);
        return;
    }

    arp_entry = arp_table_lookup(NODE_ARP_TABLE(node), next_hop_ip_str);

    if (!arp_entry){
        
        /*Time for ARP resolution*/
        create_arp_sane_entry(NODE_ARP_TABLE(node), 
                next_hop_ip_str, 
                (char *)pkt, 
                pkt_size);
        send_arp_broadcast_request(node, oif, next_hop_ip_str);
        return;
    }

    l2_frame_prepare:
        memcpy(ethernet_hdr->dst_mac.mac, arp_entry->mac_addr.mac, sizeof(mac_add_t));
        memcpy(ethernet_hdr->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
        ETH_FCS(ethernet_hdr, ethernet_payload_size) = 0;
        send_pkt_out((char *)ethernet_hdr, pkt_size, oif);
}


/* An API to be used by Layer 3 or higher to push the pkt
 * down the TCP IP Stack to L2. Note that, though most of the time
 * this API shall be used by L3, but any Higher Layer API can use
 * this API. For example, An application can run directly on L2 bypassing
 * L3 altogether.*/
void
demote_pkt_to_layer2(node_t *node, /*Currenot node*/ 
        unsigned int next_hop_ip,  /*If pkt is forwarded to next router, then this is Nexthop IP address (gateway) provided by L3 layer. L2 need to resolve ARP for this IP address*/
        char *outgoing_intf,       /*The oif obtained from L3 lookup if L3 has decided to forward the pkt. If NULL, then L2 will find the appropriate interface*/
        char *pkt, unsigned int pkt_size,   /*Higher Layers payload*/
        int protocol_number){               /*Higher Layer need to tell L2 what value need to be feed in eth_hdr->type field*/

    assert(pkt_size < sizeof(((ethernet_hdr_t *)0)->payload));

    if(protocol_number == ETH_IP){
   
        ethernet_hdr_t *empty_ethernet_hdr = ALLOC_ETH_HDR_WITH_PAYLOAD(pkt_size); 
        empty_ethernet_hdr->type = ETH_IP;
        memcpy(empty_ethernet_hdr->payload, pkt, pkt_size);

        l2_forward_ip_packet(node, next_hop_ip, 
            outgoing_intf, empty_ethernet_hdr, pkt_size + ETH_HDR_SIZE_EXCL_PAYLOAD);

        free(empty_ethernet_hdr);
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

    free(arp_entry);
}

void
add_arp_pending_entry(arp_entry_t *arp_entry,
        arp_processing_fn cb,
        char *pkt,
        unsigned int pkt_size){

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
create_arp_sane_entry(arp_table_t *arp_table, char *ip_addr, 
                       char *pkt, unsigned int pkt_size){

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
    bool_t rc = arp_table_entry_add(arp_table, arp_entry, 0);
    if(rc == FALSE){
        assert(0);
    }
}
