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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h> /*for inet_ntop & inet_pton*/
#include "../graph.h"
#include "layer2.h"
#include "arp.h"
#include "../comm.h"
#include "../Layer5/layer5.h"
#include "../tcp_ip_trace.h"
#include "../libtimer/WheelTimer.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../pkt_block.h"

#define ARP_ENTRY_EXP_TIME	30


extern void layer2_mem_init(); 

extern void
l2_switch_recv_frame(interface_t *interface,
                     char *pkt, uint32_t pkt_size);

extern void
promote_pkt_to_layer3(node_t *node, interface_t *interface,
                         pkt_block_t *pkt_block,
                         int L3_protocol_type);

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
        interface->intf_nw_props.is_ipadd_config_backup = true;
        interface->intf_nw_props.is_ipadd_config = false;

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
node_set_intf_l2_mode(node_t *node,
                                      const char *intf_name, 
                                      intf_l2_mode_t intf_l2_mode){

    interface_t *interface = node_get_intf_by_name(node, intf_name);
    assert(interface);

    interface_set_l2_mode(node, interface, intf_l2_mode_str(intf_l2_mode));
}

void
node_set_intf_vlan_membership(node_t *node, 
                                                     const char *intf_name, 
                                                     uint32_t vlan_id){

    interface_t *interface = node_get_intf_by_name(node, intf_name);
    assert(interface);

    interface_set_vlan(node, interface, vlan_id);
}

static void
l2_forward_ip_packet(node_t *node,
                                    uint32_t next_hop_ip,
                                    char *outgoing_intf,
                                    pkt_block_t *pkt_block){



    pkt_size_t pkt_size;
    interface_t *oif = NULL;
    char next_hop_ip_str[16];
     ethernet_hdr_t *ethernet_hdr;
    arp_entry_t * arp_entry = NULL;

     ethernet_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);
    
    pkt_size_t ethernet_payload_size = 
        pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD;

    tcp_ip_covert_ip_n_to_p(next_hop_ip, next_hop_ip_str);

    if(outgoing_intf) {

        /* It means, L3 has resolved the nexthop, So its time to L2 forward the pkt
         * out of this interface*/
        oif = node_get_intf_by_name(node, outgoing_intf);
        assert(oif);

        arp_entry = arp_table_lookup(NODE_ARP_TABLE(node), next_hop_ip_str);

        if (!arp_entry){

            /*Time for ARP resolution*/
            create_arp_sane_entry(node, NODE_ARP_TABLE(node), 
                    next_hop_ip_str, 
                    pkt_block);

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
        pkt_block_dereference(pkt_block);
        return;
    }

    /*if the destination ip address is exact match to local interface
     * ip address*/
    if((oif && strncmp(IF_IP(oif), next_hop_ip_str, 16) == 0)){
        /*send to self*/
        memset(ethernet_hdr->dst_mac.mac, 0, sizeof(mac_add_t));
        memset(ethernet_hdr->src_mac.mac, 0, sizeof(mac_add_t));
        SET_COMMON_ETH_FCS(ethernet_hdr, ethernet_payload_size, 0);
        send_pkt_to_self(pkt_block, oif);
        pkt_block_dereference(pkt_block);
        return;
    }

    /*If the destination ip address is exact match to self loopback address, 
     * rebounce the pkt to Network Layer again*/
    if(strncmp(next_hop_ip_str, NODE_LO_ADDR(node), 16) == 0){
         promote_pkt_to_layer3(node, 0, pkt_block, ethernet_hdr->type);
         return;
    }

    arp_entry = arp_table_lookup(NODE_ARP_TABLE(node), next_hop_ip_str);

    if (!arp_entry || (arp_entry && arp_entry_sane(arp_entry))){
        
        /*Time for ARP resolution*/
        create_arp_sane_entry(node, NODE_ARP_TABLE(node), 
                next_hop_ip_str, 
                pkt_block);
        send_arp_broadcast_request(node, oif, next_hop_ip_str);
        return;
    }

    l2_frame_prepare:
        memcpy(ethernet_hdr->dst_mac.mac, arp_entry->mac_addr.mac, sizeof(mac_add_t));
        memcpy(ethernet_hdr->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
        SET_COMMON_ETH_FCS(ethernet_hdr, ethernet_payload_size, 0);
        send_pkt_out(pkt_block, oif);
        pkt_block_dereference(pkt_block);
		arp_entry_refresh_expiration_timer(arp_entry);
        arp_entry->hit_count++;
}


/* An API to be used by Layer 3 or higher to push the pkt
 * down the TCP IP Stack to L2. Note that, though most of the time
 * this API shall be used by L3, but any Higher Layer API can use
 * this API. For example, An application can run directly on L2 bypassing
 * L3 altogether.*/
void
demote_pkt_to_layer2 (node_t *node, /*Current node*/ 
                                       uint32_t next_hop_ip,   /*If pkt is forwarded to next router, 
                                                                                then this is Nexthop IP address (gateway) 
                                                                                provided by L3 layer. L2 need to resolve ARP for this IP address*/
                                       char *outgoing_intf,    /* The oif obtained from L3 lookup if L3 
                                                                                has decided to forward the pkt. If NULL, 
                                                                                then L2 will find the appropriate interface*/
                                      pkt_block_t *pkt_block, /*Higher Layers payload*/
                                      hdr_type_t hdr_type) {   /*Higher Layer need to tell L2 
                                                                                what value need to be feed in eth_hdr->type field*/

    pkt_size_t pkt_size;

    uint8_t *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    assert (pkt_size < sizeof(((ethernet_hdr_t *)0)->payload));

    switch(hdr_type){

        case ETH_IP:
            {
                tcp_ip_expand_buffer_ethernet_hdr(pkt_block); 
                ethernet_hdr_t *empty_ethernet_hdr = 
                        (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);
                empty_ethernet_hdr->type = ETH_IP;

                l2_forward_ip_packet(node, 
                                                    next_hop_ip, 
                                                    outgoing_intf,
                                                    pkt_block); 
            }
        break;
        default:
                pkt_block_dereference(pkt_block);
            ;
    }
}

/*Vlan Management Routines*/

/* Return new packet size if pkt is tagged with new vlan id*/

void
tag_pkt_with_vlan_id (
                     pkt_block_t *pkt_block,
                     int vlan_id ) {

    pkt_size_t total_pkt_size;

    ethernet_hdr_t *ethernet_hdr = 
        ( ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &total_pkt_size);

    uint32_t payload_size  = 0 ;

    /*If the pkt is already tagged, replace it*/
    vlan_8021q_hdr_t *vlan_8021q_hdr = 
        is_pkt_vlan_tagged(ethernet_hdr);
    
    if(vlan_8021q_hdr){
        payload_size = total_pkt_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;
        vlan_8021q_hdr->tci_vid = (short)vlan_id;
        
        /*Update checksum, however not used*/
        SET_COMMON_ETH_FCS(ethernet_hdr, payload_size, 0);

        return;
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

    pkt_block_set_new_pkt(
                pkt_block,
                (uint8_t *)vlan_ethernet_hdr,
                total_pkt_size  + (pkt_size_t)sizeof(vlan_8021q_hdr_t));
}

/* Return new packet size if pkt is untagged with the existing
 * vlan 801.1q hdr*/
void
untag_pkt_with_vlan_id(pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;

    ethernet_hdr_t *ethernet_hdr = 
        (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr =
        is_pkt_vlan_tagged(ethernet_hdr);
    
    /*Not tagged already, do nothing*/    
    if(!vlan_8021q_hdr){
        return;
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
    uint32_t payload_size = pkt_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;

    /*Update checksum, however not used*/
    SET_COMMON_ETH_FCS(ethernet_hdr, payload_size, 0);
    
    pkt_block_set_new_pkt(pkt_block, (uint8_t *)ethernet_hdr,  
                                            pkt_size - (pkt_size_t )sizeof(vlan_8021q_hdr_t));
}

void
promote_pkt_to_layer2(
                    node_t *node,
                    interface_t *iif, 
                    pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;

    assert(pkt_block_verify_pkt(pkt_block, ETH_HDR));

    /* Unconditionally distribute pkt-copy to interested applications */
    cp_punt_promote_pkt_from_layer2_to_layer5(
                    node, iif, 
                    pkt_block,
                    ETH_HDR);

    ethernet_hdr_t *ethernet_hdr = 
        (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    switch(ethernet_hdr->type){
        case PROTO_ARP:
            {
                /*Can be ARP Broadcast or ARP reply*/
                arp_hdr_t *arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr));
                switch(arp_hdr->op_code){
                    case ARP_BROAD_REQ:
                        process_arp_broadcast_request(node, iif, ethernet_hdr);
                        assert(!pkt_block_dereference(pkt_block));
                        return;
                    case ARP_REPLY:
                        process_arp_reply_msg(node, iif, ethernet_hdr);
                        assert(!pkt_block_dereference(pkt_block));
                        return;
                    default:
                        assert(0);
                }
            }
            break;
        case ETH_IP:
        case IP_IN_IP:
            promote_pkt_to_layer3(node, iif, 
                    pkt_block,
                    ethernet_hdr->type);
            break;
        default:
            assert(!pkt_block_dereference(pkt_block));
    }
}

bool 
l2_frame_recv_qualify_on_interface(
                                    node_t *node,
                                    interface_t *interface, 
                                    pkt_block_t *pkt_block,
                                    uint32_t *output_vlan_id){

    pkt_size_t pkt_size;
    ethernet_hdr_t *ethernet_hdr;

    *output_vlan_id = 0;

    ethernet_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr = 
                        is_pkt_vlan_tagged(ethernet_hdr);

    /* Presence of IP address on interface makes it work in L3 mode,
     * while absence of IP-address automatically make it work in
     * L2 mode provided that it is operational either in ACCESS mode or TRUNK mode.*/

    /* case 10 : If receiving interface is neither working in L3 mode
     * nor in L2 mode, then reject the packet*/
    if(!IS_INTF_L3_MODE(interface) &&
        IF_L2_MODE(interface) == L2_MODE_UNKNOWN){

        return false;
    }

    /* If interface is working in ACCESS mode but at the
     * same time not operating within a vlan, then it must
     * accept untagged packet only*/

    if(IF_L2_MODE(interface) == ACCESS &&
        get_access_intf_operating_vlan_id(interface) == 0){

        if(!vlan_8021q_hdr)
            return true;    /*case 3*/
        else
            return false;   /*case 4*/
    }

    /* if interface is working in ACCESS mode and operating with in
     * vlan, then :
     * 1. it must accept untagged frame and tag it with a vlan-id of an interface
     * 2. Or  it must accept tagged frame but tagged with same vlan-id as interface's vlan operation*/

    uint32_t intf_vlan_id = 0,
                 pkt_vlan_id = 0;

    if(IF_L2_MODE(interface) == ACCESS){
        
        intf_vlan_id = get_access_intf_operating_vlan_id(interface);
            
        if(!vlan_8021q_hdr && intf_vlan_id){
            *output_vlan_id = intf_vlan_id;
            return true; /*case 6*/
        }

        if(!vlan_8021q_hdr && !intf_vlan_id){
            /*case 3*/
            return true;
        }

        pkt_vlan_id = GET_802_1Q_VLAN_ID(vlan_8021q_hdr);
        if(pkt_vlan_id == intf_vlan_id){
            return true;    /*case 5*/
        }
        else{
            return false;   /*case 5*/
        }
    }

    /* if interface is operating in a TRUNK mode, then it must discard all untagged
     * frames*/
    
    if(IF_L2_MODE(interface) == TRUNK){
       
        if(!vlan_8021q_hdr){
            /*case 7 & 8*/
            return false;
        }
    }

    /* if interface is operating in a TRUNK mode, then it must accept the frame
     * which are tagged with any vlan-id in which interface is operating.*/

    if(IF_L2_MODE(interface) == TRUNK && 
            vlan_8021q_hdr){
        
        pkt_vlan_id = GET_802_1Q_VLAN_ID(vlan_8021q_hdr);
        if(is_trunk_interface_vlan_enabled(interface, pkt_vlan_id)){
            return true;    /*case 9*/
        }
        else{
            return false;   /*case 9*/
        }
    }
    
    /*If the interface is operating in L3 mode, and recv vlan tagged frame, drop it*/
    if(IS_INTF_L3_MODE(interface) && vlan_8021q_hdr){
        /*case 2*/
        return false;
    }

    /* If interface is working in L3 mode, then accept the frame only when
     * its dst mac matches with receiving interface MAC*/
    if(IS_INTF_L3_MODE(interface) &&
        memcmp(IF_MAC(interface), 
        ethernet_hdr->dst_mac.mac, 
        sizeof(mac_add_t)) == 0){
        /*case 1*/
        return true;
    }

    /*If interface is working in L3 mode, then accept the frame with
     * broadcast MAC*/
    if(IS_INTF_L3_MODE(interface) &&
        IS_MAC_BROADCAST_ADDR(ethernet_hdr->dst_mac.mac)){
        /*case 1*/
        return true;
    }

    return false;
}

void
layer2_mem_init() {

    MM_REG_STRUCT(0, arp_hdr_t);
    MM_REG_STRUCT(0, ethernet_hdr_t);
    MM_REG_STRUCT(0, arp_table_t);
    MM_REG_STRUCT(0,  arp_pending_entry_t);
    MM_REG_STRUCT(0,  arp_entry_t);
    MM_REG_STRUCT(0,  vlan_8021q_hdr_t);
    MM_REG_STRUCT(0,  vlan_ethernet_hdr_t);
    MM_REG_STRUCT(0,  mac_table_t);
    MM_REG_STRUCT(0,  mac_table_entry_t);
}