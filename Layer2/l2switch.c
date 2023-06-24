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

void
init_mac_table(mac_table_t **mac_table){

    *mac_table = (mac_table_t *)XCALLOC(0, 1, mac_table_t);
    init_glthread(&((*mac_table)->mac_entries));
}

mac_table_entry_t *
mac_table_lookup(mac_table_t *mac_table, c_string mac){

    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;

    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, curr){

        mac_table_entry = mac_entry_glue_to_mac_entry(curr);
        if(string_compare(mac_table_entry->mac.mac, mac, sizeof(mac_addr_t)) == 0){
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
        remove_glthread(curr);
        XFREE(mac_table_entry);
    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
}

void
delete_mac_table_entry(mac_table_t *mac_table, c_string mac){

    mac_table_entry_t *mac_table_entry;
    mac_table_entry = mac_table_lookup(mac_table, mac);
    if(!mac_table_entry)
        return;
    remove_glthread(&mac_table_entry->mac_entry_glue);
    XFREE(mac_table_entry);
}

#define IS_MAC_TABLE_ENTRY_EQUAL(mac_entry_1, mac_entry_2)   \
    (string_compare(mac_entry_1->mac.mac, mac_entry_2->mac.mac, sizeof(mac_addr_t)) == 0 && \
            string_compare(mac_entry_1->oif_name, mac_entry_2->oif_name, IF_NAME_SIZE) == 0)


bool
mac_table_entry_add(mac_table_t *mac_table, mac_table_entry_t *mac_table_entry){

    mac_table_entry_t *mac_table_entry_old = mac_table_lookup(mac_table,
            mac_table_entry->mac.mac);

    if(mac_table_entry_old &&
            IS_MAC_TABLE_ENTRY_EQUAL(mac_table_entry_old, mac_table_entry)){

        return false;
    }

    if(mac_table_entry_old){
        delete_mac_table_entry(mac_table, mac_table_entry_old->mac.mac);
    }

    init_glthread(&mac_table_entry->mac_entry_glue);
    glthread_add_next(&mac_table->mac_entries, &mac_table_entry->mac_entry_glue);
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
            cprintf("\t|========= MAC =========|==== Ports ===|\n");
        }
        else {
            cprintf("\t|=======================|==============|\n");
        }
        cprintf("\t| %02x:%02x:%02x:%02x:%02x:%02x     | %-12s |\n", 
            mac_table_entry->mac.mac[0], 
            mac_table_entry->mac.mac[1],
            mac_table_entry->mac.mac[2],
            mac_table_entry->mac.mac[3], 
            mac_table_entry->mac.mac[4],
            mac_table_entry->mac.mac[5],
            mac_table_entry->oif_name);
    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
    if(count){
        cprintf("\t|=======================|==============|\n");
    }
}

static void
l2_switch_perform_mac_learning(node_t *node, c_string src_mac, c_string if_name){

    bool rc;
    mac_table_entry_t *mac_table_entry = ( mac_table_entry_t *)XCALLOC(0, 1, mac_table_entry_t);
    memcpy(mac_table_entry->mac.mac, src_mac, sizeof(mac_addr_t));
    string_copy((char *)mac_table_entry->oif_name, if_name, IF_NAME_SIZE);
    mac_table_entry->oif_name[IF_NAME_SIZE - 1] = '\0';
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

    ethernet_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    /*If dst mac is broadcast mac, then flood the frame*/
    if (IS_MAC_BROADCAST_ADDR(ethernet_hdr->dst_mac.mac)){
        l2_switch_flood_pkt_out(node, recv_intf, pkt_block);
        return;
    }

    /*Check the mac table to forward the frame*/
    mac_table_entry_t *mac_table_entry = 
        mac_table_lookup(NODE_MAC_TABLE(node), ethernet_hdr->dst_mac.mac);

    if(!mac_table_entry){
        l2_switch_flood_pkt_out(node, recv_intf, pkt_block);
        return;
    }

    c_string oif_name = mac_table_entry->oif_name;
    Interface *oif = node_get_intf_by_name(node, (const char *)oif_name);

    if(!oif){
        return;
    }

    oif->SendPacketOut(pkt_block);
}

void
l2_switch_recv_frame(node_t *node,
                                     Interface *interface, 
                                     pkt_block_t *pkt_block) { 

    pkt_size_t pkt_size;

    ethernet_hdr_t *ethernet_hdr = 
        (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    c_string dst_mac = (c_string)ethernet_hdr->dst_mac.mac;
    c_string src_mac = (c_string)ethernet_hdr->src_mac.mac;

    l2_switch_perform_mac_learning(node, src_mac, interface->if_name.c_str());
    l2_switch_forward_frame(node, interface, pkt_block);
}

