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
#include "transport_svc.h"
#include "../Interface/InterfaceUApi.h"
#include "../Tracer/tracer.h"
#include "mac_table.h"
#include "vxlan/dp/vlan_vni_ht.h"
#include "../lmm_enums.h"
#include "vxlan/dp/vxlan_dp.h"

extern void
promote_pkt_to_layer3(node_t *node,           
                      Interface *interface,  
                      pkt_block_t *pkt_block, 
                      int L3_protocol_number) ; 

void
l2_switch_perform_mac_learning (node_t *node, vlan_id_t vlan_id, 
                                                    c_string src_mac, Interface *oif, uint32_t src_ip) {

    int i;
    uint16_t flags;
    mac_table_entry_t *mac_table_entry;

    if (memcmp (src_mac, "\x00\x00\x00\x00\x00\x00", sizeof(mac_addr_t)) == 0){
        return;
    }

    /* If existing mac table entry */
    mac_table_entry = mac_table_lookup(NODE_MAC_TABLE(node), vlan_id, src_mac);

    if (mac_table_entry) {

        /* If existing entry is dynamic and OIF is same, then refresh the timer */
        mac_oif_entry_t *existing = mac_table_entry_find_oif(mac_table_entry, oif->ifindex, src_ip);
        if (existing) {
            return;  /* Interface already exists, nothing to do */
        }

        /* Add new OIF to the existing entry */
        mac_table_entry_add_oif(mac_table_entry, oif->GetSharedPtr(), src_ip);
        return;
    }

    /* Determine MAC entry flags */
    if (oif == NODE_RMAC_INTF(node).get() || 
            oif == NODE_VLAN_FLOOD_INTF(node).get()) {

        flags = MAC_STATIC;
        
    } else {
        
        flags = MAC_DYNAMIC;
    }
    
    /* Use sync API to add MAC entry since called is in DP itself */
    mac_table_entry_add (node, NODE_MAC_TABLE(node), 
        (uint8_t*)src_mac, vlan_id, oif->ifindex, flags, src_ip);
}

static void 
mac_table_entry_xmit_frame (node_t *node, 
                            mac_table_entry_t *mac_entry, 
                            pkt_block_t *pkt_block, 
                            Interface *recv_intf) 
{
    glthread_t *curr;
    mac_oif_entry_t *oif_entry;
    Interface *oif; 
    uint32_t vni_id = 0;
    vlan_id_t vlan_id = 0;
    pkt_block_t *pkt_block2;
    encap_meta_data_t *encap_data = NULL;

    ITERATE_GLTHREAD_BEGIN(&mac_entry->oif_list, curr) {
        oif_entry = mac_oif_glue_to_entry(curr);
        oif = oif_entry->oif.get();
        
        if (!oif) continue;
        
        if (oif == recv_intf) {
            continue;
        }

        if (oif->iftype== INTF_TYPE_NVE) {
            
            encap_data = (encap_meta_data_t *) XCALLOC2 (0, 1, encap_meta_data_t);

            vlan_id = mac_entry->vlan_id;

            /* Get VNI id using DP hashtable*/
            vni_id = vlan_vni_ht_vlan_to_vni_lookup (node, vlan_id);

            if (vni_id == 0) {

                tracer (node->dptr, DL2SW | DERR,
                        "VLAN to VNI mapping not found for vlan %d, Dropping the frame on NVE interface\n", vlan_id);

                XFREE(encap_data);
                return;
            }

            encap_data->u.vxlan.vni = vni_id;
            encap_data->u.vxlan.remote_vtep_ip = oif_entry->remote_dst_ip;

            if (pkt_block->encap_data) {

                XFREE(pkt_block->encap_data);
            }

            pkt_block->encap_data = encap_data;
        }

        pkt_block2 = pkt_block_dup(pkt_block);
        pkt_block->encap_data = NULL;
        oif->SendPacketOut(pkt_block2);
        pkt_block_dereference(pkt_block2);
        
    } ITERATE_GLTHREAD_END(&mac_entry->oif_list, curr);
}

static void
l2_switch_flood_unknown_unicast (node_t *node, 
                                          Interface *exempted_intf,
                                          pkt_block_t *pkt_block) {


    Interface *oif;
    pkt_block_t *dup_pkt_block;
    vlan_8021q_hdr_t *vlan_8021q_hdr;
    mac_table_entry_t *mac_flood_entry = NULL;

    mac_flood_entry = 
                        mac_table_lookup(NODE_MAC_TABLE(node), 
                        1,
                        BROADCAST_MAC);    

    if (!mac_flood_entry) {
         tracer (node->dptr, DL2SW, "Mac Table : Flooding Disabled ");
        return;
    }

    assert ((vlan_8021q_hdr = 
            is_pkt_vlan_tagged ((ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, NULL))));

    tracer (node->dptr, DL2SW, "Pkt : %s : Layer 2 Flooding in vlan %d\n",  
            pkt_block_str (pkt_block), vlan_8021q_hdr->tci_vid);

    mac_table_entry_xmit_frame (node, mac_flood_entry, pkt_block, exempted_intf);
}

void
l2_switch_forward_frame(
                        node_t *node,
                        Interface *recv_intf, 
                        pkt_block_t *pkt_block) {

    vlan_id_t vlan_id;
    pkt_size_t pkt_size;
    ethernet_hdr_t *ethernet_hdr;
    mac_table_entry_t *mac_table_entry = NULL;
    vlan_8021q_hdr_t *vlan_8021q_hdr = NULL;

    ethernet_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    assert ((vlan_8021q_hdr = is_pkt_vlan_tagged (ethernet_hdr))) ;  

    tracer (node->dptr, DL2SW, "Pkt : %s : Layer 2 Forwarding in vlan %d\n",  
        pkt_block_str (pkt_block), GET_802_1Q_VLAN_ID(vlan_8021q_hdr));

     pkt_block->switchport_ingress_intf = recv_intf->GetSharedPtr();
     vlan_id = GET_802_1Q_VLAN_ID(vlan_8021q_hdr);

    mac_table_entry = mac_table_lookup(NODE_MAC_TABLE(node), 
                                      vlan_id,
                                      ethernet_hdr->dst_mac.mac);

    if (mac_table_entry) {
        mac_table_entry_xmit_frame (node, mac_table_entry, pkt_block, recv_intf);
        mac_table_entry_cancel_expiry_timer(mac_table_entry);
        mac_table_entry_init_timer(node, mac_table_entry);
        return;
    }

    if (IS_MAC_BROADCAST_ADDR(ethernet_hdr->dst_mac.mac)) {

            /* Handle BUM traffic for EVPN case */
            mac_table_entry = mac_table_lookup(NODE_MAC_TABLE(node), 
                                        vlan_id,
                                        BROADCAST_MAC);

            if (mac_table_entry) {
                mac_table_entry_xmit_frame (node, mac_table_entry, pkt_block, recv_intf);
                return;
            }        

            mac_table_entry = mac_table_lookup(NODE_MAC_TABLE(node), 
                                        DEFAULT_VLAN_ID,
                                        BROADCAST_MAC);

            if (!mac_table_entry) {
                tracer (node->dptr, DL2SW, "Mac Table : Flooding Disabled for Broadcast MAC");
                return;
            }
       
            mac_table_entry_xmit_frame (node, mac_table_entry, pkt_block, recv_intf);
            return;
    }

    /* Check if the pkt matches the router mac , vlan id dont matter here */
    if (mac_address_compare (NODE_RMAC(node)->mac, ethernet_hdr->dst_mac.mac)) {

        mac_table_entry = 
            mac_table_lookup(NODE_MAC_TABLE(node), 
                                      DEFAULT_VLAN_ID,
                                      ethernet_hdr->dst_mac.mac);    

        if (!mac_table_entry) {
                tracer (node->dptr, DL2SW, "Mac Table : Router MAC not programmed, Dropping the frame");
                return;
        }

        mac_table_entry_xmit_frame (node, mac_table_entry, pkt_block, recv_intf);
        return;
    }

    /* Handle Unknown Unicast */
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

        l2_switch_flood_unknown_unicast(node, recv_intf, pkt_block);
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

    l2_switch_perform_mac_learning(node, vlan_id, src_mac, interface, 0);
    l2_switch_forward_frame(node, interface, pkt_block);
}