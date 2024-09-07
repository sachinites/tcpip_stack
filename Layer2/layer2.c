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
#include <string>
#include "../common/l2_hdrs.h"
#include "../graph.h"
#include "layer2.h"
#include "arp.h"
#include "../comm.h"
#include "../Layer5/layer5.h"
#include "../tcp_ip_trace.h"
#include "../libtimer/WheelTimer.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../pkt_block.h"
#include "../Interface/InterfaceUApi.h"
#include "transport_svc.h"
#include "../Tracer/tracer.h"

#define ARP_ENTRY_EXP_TIME	30


extern void layer2_mem_init(); 

extern void
l2_switch_recv_frame(Interface *interface,
                     char *pkt, uint32_t pkt_size);

extern void
promote_pkt_to_layer3(node_t *node, Interface *interface,
                         pkt_block_t *pkt_block,
                         int L3_protocol_type);

/*Interface config APIs for L2 mode configuration*/

/*APIs to be used to create topologies*/
void
node_set_intf_l2_mode(node_t *node,
                                      const char *intf_name, 
                                      IntfL2Mode intf_l2_mode){

    Interface *interface = node_get_intf_by_name(node, intf_name);
    assert(interface);
    interface->SetL2Mode(intf_l2_mode);
}

void
node_set_intf_switchport(node_t *node,
                                         const char *intf_name) {

    Interface *interface = node_get_intf_by_name(node, intf_name);
    assert(interface);
    interface->SetSwitchport(true);
}

void
node_set_intf_vlan_membership(node_t *node, 
                                                     const char *intf_name, 
                                                     vlan_id_t vlan_id,
                                                     bool Trunk){

    Interface *interface = node_get_intf_by_name(node, intf_name);
    assert(interface);

    if (interface->GetL2Mode() == LAN_ACCESS_MODE &&
            Trunk == true) {
         cprintf ("Error : Interface %s already in Access mode, cannot be trunked\n", intf_name);
        return;
    }

    if (interface->GetL2Mode() == LAN_TRUNK_MODE &&
            Trunk == false) {
         cprintf ("Error : Interface %s already in Trunk mode, cannot be accessed\n", intf_name);
        return;
    }

    if (interface->GetSwitchport() == false) {
         cprintf ("Error : Interface %s is not switchport enabled\n", intf_name);
        return;
    }

    /* Create VLAN also*/
    VlanInterface *vlan_intf =
                    static_cast<VlanInterface *>(VlanInterface::VlanInterfaceLookUp(node, vlan_id));

    if(!vlan_intf) {

        vlan_intf = new VlanInterface(vlan_id);
        vlan_intf->att_node = node;
        if (!node->vlan_intf_db) {
            node->vlan_intf_db = new std::unordered_map<uint16_t, VlanInterface *>;
        }
        node->vlan_intf_db->insert(std::make_pair(vlan_id, vlan_intf));
        vlan_intf->InterfaceLockStatic();
    }

    if (Trunk) {
        std::string def_tsp_name(std::string(reinterpret_cast<const char *>(DEFAULT_TSP)));
        TransportService *tsp = TransportServiceCreate(node, def_tsp_name);
        tsp->AddVlan(vlan_id);
        tsp->AttachInterface(interface);
    }
    else {
        interface->IntfConfigVlan (vlan_id, true);
    }

}

static void
l2_forward_ip_packet(node_t *node,
                                    uint32_t next_hop_ip,
                                    c_string outgoing_intf,
                                    pkt_block_t *pkt_block){

    pkt_size_t pkt_size;
    Interface *oif = NULL;
    byte next_hop_ip_str[16];
    ethernet_hdr_t *ethernet_hdr;
    arp_entry_t * arp_entry = NULL;

    ethernet_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);
    
    pkt_size_t ethernet_payload_size = 
        pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD;

    tcp_ip_covert_ip_n_to_p(next_hop_ip, (c_string)next_hop_ip_str);

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
    if(!oif && string_compare((const char *)next_hop_ip_str, (const char *)NODE_LO_ADDR(node), 16)){
        cprintf("%s : Error : Local matching subnet for IP : %s could not be found\n",
                    node->node_name, next_hop_ip_str);
        return;
    }

    /*if the destination ip address is exact match to local interface
     * ip address*/
    if (oif && (next_hop_ip == IF_IP(oif))) {
        /*send to self*/

        memset(ethernet_hdr->src_mac.mac, 0, MAC_ADDR_SIZE);
        memcpy(ethernet_hdr->dst_mac.mac, IF_MAC(oif), MAC_ADDR_SIZE);
        SET_COMMON_ETH_FCS(ethernet_hdr, ethernet_payload_size, 0);
        send_pkt_to_self(pkt_block, oif);
        return;
    }

    /*If the destination ip address is exact match to self loopback address, 
     * rebounce the pkt to Network Layer again*/
    if(string_compare((const char *)next_hop_ip_str, (const char *)NODE_LO_ADDR(node), 16) == 0){
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
        memcpy(ethernet_hdr->dst_mac.mac, arp_entry->mac_addr.mac, MAC_ADDR_SIZE);
        memcpy(ethernet_hdr->src_mac.mac, IF_MAC(oif), MAC_ADDR_SIZE);
        SET_COMMON_ETH_FCS(ethernet_hdr, ethernet_payload_size, 0);
        oif->SendPacketOut(pkt_block);
		arp_entry_refresh_expiration_timer(node, arp_entry);
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
                                      c_string outgoing_intf,    /* The oif obtained from L3 lookup if L3 
                                                                                has decided to forward the pkt. If NULL, 
                                                                                then L2 will find the appropriate interface*/
                                      pkt_block_t *pkt_block, /*Higher Layers payload*/
                                      hdr_type_t hdr_type) {   /*Higher Layer need to tell L2 
                                                                                what value need to be feed in eth_hdr->type field*/

     pkt_size_t pkt_size;
     
    switch (hdr_type){

        case IP_HDR:
        case IP_IN_IP_HDR:
            {
                tcp_ip_expand_buffer_ethernet_hdr(pkt_block);

                ethernet_hdr_t *empty_ethernet_hdr = 
                        (ethernet_hdr_t *) pkt_block_get_pkt (pkt_block, &pkt_size);
                empty_ethernet_hdr->type = ETH_IP;

                l2_forward_ip_packet(node, 
                                                    next_hop_ip, 
                                                    outgoing_intf,
                                                    pkt_block); 
            }
        break;
        default:
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
        ethernet_hdr_old.dst_mac.mac, MAC_ADDR_SIZE);
    memcpy(vlan_ethernet_hdr->src_mac.mac, 
        ethernet_hdr_old.src_mac.mac, MAC_ADDR_SIZE);

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
   
    memcpy(ethernet_hdr->dst_mac.mac, vlan_ethernet_hdr_old.dst_mac.mac, MAC_ADDR_SIZE);
    memcpy(ethernet_hdr->src_mac.mac, vlan_ethernet_hdr_old.src_mac.mac, MAC_ADDR_SIZE);

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
                    Interface *iif, 
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
                        return;
                    case ARP_REPLY:
                        process_arp_reply_msg(node, iif, ethernet_hdr);
                        return;
                    default:
                        assert(0);
                }
            }
            break;

        case ETH_IP:
        case PROTO_IP_IN_IP:
            promote_pkt_to_layer3(node, iif, 
                    pkt_block,
                    ethernet_hdr->type);
            break;
        default: ;
    }
}

bool 
l2_frame_recv_qualify_on_interface(
                                    node_t *node,
                                    Interface *interface, 
                                    pkt_block_t *pkt_block,
                                    vlan_id_t *output_vlan_id){

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

    tracer (node->dptr, DL2FWD | DFLOW, "Pkt : %s received on interface %s being tested for "
        "RECV-Qualification test\n", pkt_block_str(pkt_block), interface->if_name.c_str());

    if (!interface->IsIpConfigured() &&
            !interface->GetSwitchport()) {

        tracer (node->dptr, DL2FWD | DFLOW | DERR, "Pkt : %s received on interface %s "
            "failed RECV-Qualification test : Interface is neither L3 interface or L2 switchport\n",
            pkt_block_str(pkt_block), interface->if_name.c_str());

        return false;
    }

    /* If interface is working in ACCESS mode but at the
     * same time not operating within a vlan, then it must
     * accept untagged packet only*/

    if (interface->GetL2Mode() == LAN_ACCESS_MODE &&
            interface->GetVlanId() == 0) {

        if(!vlan_8021q_hdr)
            return true;    /*case 3*/
        
        else {
            tracer (node->dptr, DL2FWD | DFLOW | DERR, "Pkt : %s received on interface %s "
                "failed RECV-Qualification test : Tagged pkt recvd on Access interface not operating in any vlan\n",
                pkt_block_str(pkt_block), interface->if_name.c_str());
            return false;   /*case 4*/
        }
    }

    /* if interface is working in ACCESS mode and operating with in
     * vlan, then :
     * 1. it must accept untagged frame and tag it with a vlan-id of an interface
     * 2. Or  it must accept tagged frame but tagged with same vlan-id as interface's vlan operation*/

    vlan_id_t intf_vlan_id = 0,
                 pkt_vlan_id = 0;

    if(interface->GetL2Mode() == LAN_ACCESS_MODE){
        
        intf_vlan_id = interface->GetVlanId();
            
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
            tracer (node->dptr, DL2FWD | DFLOW | DERR, "Pkt : %s received on interface %s "
                "failed RECV-Qualification test : Vlan Mismatch, 802.1Q vlan  %d != Interface vlan %d\n", 
                pkt_block_str(pkt_block), interface->if_name.c_str(),  pkt_vlan_id, intf_vlan_id);
            return false;   /*case 5*/
        }
    }

    /* if interface is operating in a TRUNK mode, then it must discard all untagged
     * frames*/
    
    if(interface->GetL2Mode() == LAN_TRUNK_MODE){
       
        if(!vlan_8021q_hdr){
            /*case 7 & 8*/
            tracer (node->dptr, DL2FWD | DFLOW | DERR, "Pkt : %s received on interface %s "
                "failed RECV-Qualification test : Untagged pkt recvd on Trunk Interface", 
                pkt_block_str(pkt_block), interface->if_name.c_str());
            return false;
        }
    }

    /* if interface is operating in a TRUNK mode, then it must accept the frame
     * which are tagged with any vlan-id in which interface is operating.*/

    if((interface->GetL2Mode() == LAN_TRUNK_MODE) && 
            vlan_8021q_hdr){
        
        pkt_vlan_id = GET_802_1Q_VLAN_ID(vlan_8021q_hdr);
        if (interface->IsVlanTrunked(pkt_vlan_id)) {
            return true;    /*case 9*/
        }
        else{
            tracer (node->dptr, DL2FWD | DFLOW | DERR, "Pkt : %s received on interface %s "
                "failed RECV-Qualification test : Trunk Interface is not configured with Pkt vlan %d\n", 
                pkt_block_str(pkt_block), interface->if_name.c_str(),  pkt_vlan_id);
            return false;   /*case 9*/
        }
    }

    /* Tagged Ethernet pkt is allowed on GRE interface due to Vlan
    Extension*/
    if (interface->iftype == INTF_TYPE_GRE_TUNNEL &&
            vlan_8021q_hdr) {
                
        *output_vlan_id = GET_802_1Q_VLAN_ID(vlan_8021q_hdr);
        return true;
    }


    /*If the interface is operating in L3 mode, and recv vlan tagged frame, drop it*/
    if(interface->IsIpConfigured() && vlan_8021q_hdr){
        /*case 2*/
        tracer (node->dptr, DL2FWD | DFLOW | DERR, "Pkt : %s received on interface %s "
            "failed RECV-Qualification test : Vlan tagged pkt recvd on L3 interface\n", 
            pkt_block_str(pkt_block), interface->if_name.c_str());
        return false;
    }

    /* If interface is working in L3 mode, then accept the frame only when
     * its dst mac matches with receiving interface MAC*/
    if(interface->IsIpConfigured()  && 
            memcmp(IF_MAC(interface), 
            ethernet_hdr->dst_mac.mac, 
            MAC_ADDR_SIZE) == 0){
            /*case 1*/
            return true;
    }

    /*If interface is working in L3 mode, then accept the frame with
     * broadcast MAC*/
    if(interface->IsIpConfigured()  &&
        IS_MAC_BROADCAST_ADDR(ethernet_hdr->dst_mac.mac)){
        /*case 1*/
        return true;
    }

    tracer (node->dptr, DL2FWD | DFLOW | DERR, "Pkt : %s received on interface %s "
        "failed RECV-Qualification test : Unknown Reason\n", 
        pkt_block_str(pkt_block), interface->if_name.c_str());    

    interface->recvd_pkt_dropped++;
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
