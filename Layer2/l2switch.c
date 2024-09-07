/*
 * =====================================================================================
 *
 *       Filename:  l2switch.c
 *
 *    Description:  This file defines routines and structues to implement L2 Switch Functionality
 *
 *        Version:  1.0
 *        Created:  Sunday 22 September 2019 05:31:06  IST
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

#include <stdlib.h>
#include <stdio.h>
#include "../graph.h"
#include "layer2.h"
#include "../gluethread/glthread.h"
#include "../comm.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../pkt_block.h"
#include "../tcpconst.h"
#include "../Interface/InterfaceUApi.h"
#include "../Tracer/tracer.h"

void
init_mac_table(mac_table_t **mac_table){

    *mac_table = (mac_table_t *)XCALLOC(0, 1, mac_table_t);
    init_glthread(&((*mac_table)->mac_entries));
}

mac_table_entry_t *
mac_table_lookup(mac_table_t *mac_table, vlan_id_t vlan, c_string mac){

    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;

    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, curr){

        mac_table_entry = mac_entry_glue_to_mac_entry(curr);
        if (mac_address_compare(mac_table_entry->mac.mac, mac) &&
                mac_table_entry->vlan_id == vlan) {

            return mac_table_entry;
        }
    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
    return NULL;
}

void
clear_mac_table(mac_table_t *mac_table){

    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;

    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, curr){
        
        mac_table_entry = mac_entry_glue_to_mac_entry(curr);
        mac_table_entry->oif->InterfaceUnLockDynamic();
        remove_glthread(curr);
        XFREE(mac_table_entry);
    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
}

void
delete_mac_table_entry(mac_table_t *mac_table, vlan_id_t vlan_id, c_string mac){

    mac_table_entry_t *mac_table_entry;
    mac_table_entry = mac_table_lookup(mac_table, vlan_id, mac);
    if(!mac_table_entry)
        return;
    remove_glthread(&mac_table_entry->mac_entry_glue);
    mac_table_entry->oif->InterfaceUnLockDynamic();
    tracer (mac_table_entry->oif->att_node->dptr, DL2SW, 
            "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x %s ] Deleted\n", 
            mac_table_entry->vlan_id, 
            mac_table_entry->mac.mac[0],
            mac_table_entry->mac.mac[1],
            mac_table_entry->mac.mac[2],
            mac_table_entry->mac.mac[3],
            mac_table_entry->mac.mac[4],
            mac_table_entry->mac.mac[5],
            mac_table_entry->oif_name     );
    XFREE(mac_table_entry);
}

#define IS_MAC_TABLE_ENTRY_EQUAL(mac_entry_1, mac_entry_2)   \
    (mac_address_compare  (mac_entry_1->mac.mac, mac_entry_2->mac.mac) && \
    (string_compare(mac_entry_1->mac.mac, mac_entry_2->mac.mac, sizeof(mac_addr_t)) == 0 && \
            string_compare(mac_entry_1->oif_name, mac_entry_2->oif_name, IF_NAME_SIZE) == 0 && \
            mac_entry_1->oif == mac_entry_2->oif && \
            mac_entry_1->vlan_id == mac_entry_2->vlan_id))


bool
mac_table_entry_add(mac_table_t *mac_table, mac_table_entry_t *mac_table_entry){

    assert (mac_table_entry->vlan_id >= 1 && mac_table_entry->vlan_id <= 4095);
    
    mac_table_entry_t *mac_table_entry_old = mac_table_lookup(
                                                mac_table,
                                                mac_table_entry->vlan_id, 
                                                mac_table_entry->mac.mac);

    if(mac_table_entry_old &&
            IS_MAC_TABLE_ENTRY_EQUAL(mac_table_entry_old, mac_table_entry)){

        return false;
    }

    if(mac_table_entry_old){
        delete_mac_table_entry(mac_table, mac_table_entry_old->vlan_id, mac_table_entry_old->mac.mac);
    }

    init_glthread(&mac_table_entry->mac_entry_glue);
    glthread_add_next(&mac_table->mac_entries, &mac_table_entry->mac_entry_glue);
    tracer (mac_table_entry->oif->att_node->dptr, DL2SW, 
        "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x %s ] Added\n", 
            mac_table_entry->vlan_id, 
            mac_table_entry->mac.mac[0],
            mac_table_entry->mac.mac[1],
            mac_table_entry->mac.mac[2],
            mac_table_entry->mac.mac[3],
            mac_table_entry->mac.mac[4],
            mac_table_entry->mac.mac[5],
            mac_table_entry->oif_name     );
    return true;
}

void
dump_mac_table(mac_table_t *mac_table){

    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;
    int count = 0;

    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, curr){

        count++;
        mac_table_entry = mac_entry_glue_to_mac_entry(curr);
        if(count == 1){
            cprintf("\t|==Vlan====|========= MAC =========|==== Ports ===|\n");
        }
        else {
            cprintf("\t|==========|=======================|==============|\n");
        }
        cprintf("\t|  %-6d  | %02x:%02x:%02x:%02x:%02x:%02x     | %-12s |\n", 
            mac_table_entry->vlan_id,
            mac_table_entry->mac.mac[0], 
            mac_table_entry->mac.mac[1],
            mac_table_entry->mac.mac[2],
            mac_table_entry->mac.mac[3], 
            mac_table_entry->mac.mac[4],
            mac_table_entry->mac.mac[5],
            mac_table_entry->oif_name);

    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
    if(count){
        cprintf("\t|==========|=======================|==============|\n");
    }
}

static void
l2_switch_perform_mac_learning (node_t *node, vlan_id_t vlan_id, c_string src_mac, Interface *oif){

    bool rc;

    if (vlan_id == 0 || vlan_id > 4095){
        return;
    }

    if (memcmp (src_mac, "\x00\x00\x00\x00\x00\x00", sizeof(mac_addr_t)) == 0){
        return;
    }

    mac_table_entry_t *mac_table_entry = ( mac_table_entry_t *)XCALLOC(0, 1, mac_table_entry_t);
    mac_table_entry->vlan_id = vlan_id;
    memcpy(mac_table_entry->mac.mac, src_mac, sizeof(mac_addr_t));
    string_copy((char *)mac_table_entry->oif_name, oif->if_name.c_str(), IF_NAME_SIZE);
    mac_table_entry->oif_name[IF_NAME_SIZE - 1] = '\0';
    mac_table_entry->oif = oif;
    oif->InterfaceLockDynamic();
    rc = mac_table_entry_add(NODE_MAC_TABLE(node), mac_table_entry);
    if(rc == false){
        XFREE(mac_table_entry);
    }
}

static void
l2_switch_flood_pkt_out (node_t *node, 
                                          Interface *exempted_intf,
                                          pkt_block_t *pkt_block) {


    Interface *oif;
    pkt_block_t *pkt_block2;
   
    tracer (node->dptr, DL2SW, "Pkt : %s : Layer 2 Flooding\n",  pkt_block_str (pkt_block));

    ITERATE_NODE_INTERFACES_BEGIN(node, oif){
        
        if(oif == exempted_intf) continue;

        if (!oif->GetSwitchport()) continue;

        pkt_block2 = pkt_block_dup(pkt_block);
        oif->SendPacketOut(pkt_block2);
        pkt_block_dereference(pkt_block2);

    } ITERATE_NODE_INTERFACES_END(node, oif);
}

static void
l2_switch_forward_frame(
                        node_t *node,
                        Interface *recv_intf, 
                        pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    ethernet_hdr_t *ethernet_hdr;
    vlan_8021q_hdr_t *vlan_8021q_hdr = NULL;

    ethernet_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    assert ((vlan_8021q_hdr = is_pkt_vlan_tagged (ethernet_hdr))) ;  

    tracer (node->dptr, DL2SW, "Pkt : %s : Layer 2 Forwarding in vlan %d\n",  
        pkt_block_str (pkt_block), GET_802_1Q_VLAN_ID(vlan_8021q_hdr));

    /*If dst mac is broadcast mac, then flood the frame*/
    if (IS_MAC_BROADCAST_ADDR(ethernet_hdr->dst_mac.mac)){
        l2_switch_flood_pkt_out(node, recv_intf, pkt_block);
        return;
    }

    /*Check the mac table to forward the frame*/
    mac_table_entry_t *mac_table_entry = 
        mac_table_lookup(NODE_MAC_TABLE(node), 
                                      GET_802_1Q_VLAN_ID(vlan_8021q_hdr),
                                      ethernet_hdr->dst_mac.mac);

    if(!mac_table_entry){

        tracer (node->dptr, DL2SW, 
            "Mac Table Lookup Failed for vlan = %d, "
            "Mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
            GET_802_1Q_VLAN_ID(vlan_8021q_hdr),
            ethernet_hdr->dst_mac.mac[0],
            ethernet_hdr->dst_mac.mac[1],
            ethernet_hdr->dst_mac.mac[2],
            ethernet_hdr->dst_mac.mac[3],
            ethernet_hdr->dst_mac.mac[4],
            ethernet_hdr->dst_mac.mac[5]);

        l2_switch_flood_pkt_out(node, recv_intf, pkt_block);
        return;
    }

    mac_table_entry->oif->SendPacketOut(pkt_block);
}

void
l2_switch_recv_frame(node_t *node,
                                     vlan_id_t vlan_id,
                                     Interface *interface, 
                                     pkt_block_t *pkt_block) { 

    pkt_size_t pkt_size;

    if (pkt_block_get_starting_hdr (pkt_block) != ETH_HDR){
        return;
    }

    vlan_ethernet_hdr_t *vlan_ethernet_hdr = 
        (vlan_ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    c_string src_mac = (c_string)vlan_ethernet_hdr->src_mac.mac;

    tracer (node->dptr, DL2SW, "Pkt : %s : Layer 2 Frame Received on Interface %s in vlan %d\n", 
        pkt_block_str (pkt_block), interface->if_name.c_str(), vlan_id);

    l2_switch_perform_mac_learning(node, vlan_id, src_mac, interface);
    l2_switch_forward_frame(node, interface, pkt_block);
}

