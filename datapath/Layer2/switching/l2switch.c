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
#include <arpa/inet.h>
#include "../../../libs/common/l2_hdrs.h"
#include "../../../libs/gluethread/glthread.h"
#include "../../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../../../libs/pkt-block/pkt_mbuf.h"
#include "../../../tcpconst.h"
#include "../../../libs/Tracer/tracer.h"
#include "mac_table.h"
#include "../../Layer2/vxlan/vlan_vni_ht.h"
#include "../../../lmm_enums.h"
#include "../../Layer2/vxlan/vxlan_dp.h"
#include "../../dp_ctx.h"
#include "../../Interface/dp_intf.h"
#include "../../dp_uapi.h"
#include "../../classifier/pkt_classifier.h"
#include "../MacNexthop/L2FwdObject.h"

extern void
dp_promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      dp_intf_t *interface, 
                      struct rte_mbuf *mbuf);

void
l2_switch_perform_mac_learning(dp_ctx_t *dp_ctx,
                               vlan_id_t vlan_id,
                               c_string src_mac,
                               dp_intf_t *oif, 
                               uint32_t src_ip)
{
    if (memcmp(src_mac, "\x00\x00\x00\x00\x00\x00", sizeof(mac_addr_t)) == 0)
        return;

    /*
     * Fast-path pre-check (lock-free rte_hash lookup, safe from any thread):
     * if an entry already exists for this MAC+VLAN, skip posting a job.
     * New OIF additions for the same MAC are handled via the CP path or will
     * be re-triggered on the next packet for an unknown OIF.
     * The dp_ev_dis handler deduplicates concurrent learn posts.
     */
    mac_table_entry_t *existing =
        mac_table_lookup(dp_ctx->mac_table, vlan_id, (uint8_t *)src_mac);
    if (existing) {
        /* Refresh aging on source-MAC activity (standard switch behavior):
         * seeing a frame *from* this MAC keeps its entry alive, independent
         * of whether it is ever a forwarding destination. */
        if (!(existing->flags & MAC_STATIC))
            mac_table_entry_touch(existing);
        return;
    }

    /* Post MAC learn job to dp_ev_dis (single-writer thread). */
    dp_post_mac_learn_job(dp_ctx, (uint8_t *)src_mac, vlan_id,
                          oif->port_id, src_ip);
}

static void 
mac_table_entry_xmit_frame (dp_ctx_t *dp_ctx,
                            dp_intf_t *vlan_bd_intf,
                            mac_table_entry_t *mac_entry, 
                            struct rte_mbuf *mbuf, 
                            dp_intf_t *recv_intf) 
{
    struct rte_mbuf *mbuf2;
    mac_fwd_object_t *fwd_obj;
    uint16_t i;

    for (i = 0; i < mac_entry->oif_count; i++) {

        fwd_obj = mac_entry->oifs[i];
        if (!fwd_obj) continue;
        mbuf2 = PKT_MBUF_DUP(mbuf);
        dp_l2fwd(dp_ctx, fwd_obj, mbuf2);
        pkt_mbuf_dereference(mbuf2);
    }

}

static void
l2_switch_flood_unknown_unicast(dp_ctx_t *dp_ctx,
                                dp_intf_t *vlan_bd_intf,
                                mac_table_t *mac_table,
                                dp_intf_t *exempted_intf,
                                struct rte_mbuf *mbuf)
                                
{

    vlan_8021q_hdr_t *vlan_8021q_hdr;
    mac_table_entry_t *mac_flood_entry = NULL;

    bool bd_processing = (vlan_bd_intf && (vlan_bd_intf->if_type == DP_INTF_TYPE_BD)) ;

    mac_flood_entry =
        mac_table_lookup(mac_table,
                         DEFAULT_VLAN_ID,
                         BROADCAST_MAC);

    if (!mac_flood_entry) {
         tracer (dp_ctx->dptr, DL2SW, "Mac Table : Flooding Disabled ");
        return;
    }

    if (!bd_processing ) {

        assert ((vlan_8021q_hdr = 
            is_pkt_vlan_tagged ((ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, NULL))));

        tracer (dp_ctx->dptr, DL2SW, "Pkt : %s : Layer 2 Flooding in vlan %d\n",  
            pkt_mbuf_str (mbuf), 
            TCI_VID(vlan_8021q_hdr->tci));
    }
    else {
        tracer (dp_ctx->dptr, DL2SW, "Pkt : %s : Layer 2 Flooding in BD %d\n",  
            pkt_mbuf_str (mbuf), 
            vlan_bd_intf->if_name);
    }

    mac_table_entry_xmit_frame (dp_ctx, vlan_bd_intf, mac_flood_entry, mbuf, exempted_intf);
}

void
l2_switch_forward_frame(
                        dp_ctx_t *dp_ctx,
                        mac_table_t *mac_table,
                        /* This is either vlan or BD interface, for vlans it is NULL*/
                        dp_intf_t *vlan_bd_intf,
                        /* Underlying Vlan physical interface or AC . For locally generated 
                            this interface would be RMAC interface */
                        dp_intf_t *recv_intf,  
                        /* Pkt , which */
                        struct rte_mbuf *mbuf) {

    uint16_t vlan_id;
    pkt_size_t pkt_size;
    dp_intf_t *bd_intf = NULL;
    ethernet_hdr_t *ethernet_hdr;
    mac_table_entry_t *mac_table_entry = NULL;
    vlan_8021q_hdr_t *vlan_8021q_hdr = NULL;
    
    /* For BD, recv_intf is BD intf, while AC is hidden in pkt pvt data*/
    bool bd_processing = (vlan_bd_intf && (vlan_bd_intf->if_type == DP_INTF_TYPE_BD)) ;

    ethernet_hdr = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    if (!bd_processing) {

        assert ((vlan_8021q_hdr = is_pkt_vlan_tagged (ethernet_hdr))) ;  

        tracer (dp_ctx->dptr, DL2SW, "Pkt : %s : Layer 2 Forwarding in vlan %d\n",  
            pkt_mbuf_str (mbuf), 
            GET_802_1Q_VLAN_ID(vlan_8021q_hdr));
    }
    else {

        tracer (dp_ctx->dptr, DL2SW, "Pkt : %s : Layer 2 Forwarding in BD %s\n",  
            pkt_mbuf_str (mbuf), vlan_bd_intf->if_name);
    }

     vlan_id = (!bd_processing) ? (uint16_t)GET_802_1Q_VLAN_ID(vlan_8021q_hdr) : DEFAULT_VLAN_ID;

     mac_table_entry = mac_table_lookup(mac_table, 
                                      vlan_id,
                                      ethernet_hdr->dst_mac.mac);

    if (mac_table_entry) {

        mac_table_entry_xmit_frame (dp_ctx, vlan_bd_intf, mac_table_entry, mbuf, recv_intf);

        if (!(mac_table_entry->flags & MAC_STATIC))
            mac_table_entry_touch(mac_table_entry); /* cheap timestamp store */

        return;
    }

    if (IS_MAC_BROADCAST_ADDR(ethernet_hdr->dst_mac.mac)) {

            /* Handle BUM traffic for EVPN case */
            mac_table_entry = mac_table_lookup(mac_table,
                                        vlan_id,
                                        BROADCAST_MAC);

            if (mac_table_entry) {
                mac_table_entry_xmit_frame (dp_ctx, vlan_bd_intf, mac_table_entry, mbuf, recv_intf);
                return;
            }        

            mac_table_entry = mac_table_lookup(mac_table, 
                                        DEFAULT_VLAN_ID,
                                        BROADCAST_MAC);

            if (!mac_table_entry) {
                tracer (dp_ctx->dptr, DL2SW, "Mac Table : Flooding Disabled for Broadcast MAC");
                return;
            }
       
            mac_table_entry_xmit_frame (dp_ctx, vlan_bd_intf, mac_table_entry, mbuf, recv_intf);
            return;
    }

    /* Check if the pkt matches the router mac , vlan id dont matter here */
    if (mac_address_compare (dp_ctx->rmac.mac, ethernet_hdr->dst_mac.mac)) {

        mac_table_entry = 
            mac_table_lookup(mac_table, 
                                      DEFAULT_VLAN_ID,
                                      ethernet_hdr->dst_mac.mac);    

        if (!mac_table_entry) {
            tracer (dp_ctx->dptr, DL2SW, "Mac Table : Router MAC not programmed, Dropping the frame\n");
            return;
        }

        mac_table_entry_xmit_frame (dp_ctx, vlan_bd_intf, mac_table_entry, mbuf, recv_intf);
        return;
    }

    /* Handle Unknown Unicast */
    tracer (dp_ctx->dptr, DL2SW, 
            "Mac Table Lookup Failed for vlan = %d, "
            "Mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
            (!bd_processing) ? GET_802_1Q_VLAN_ID(vlan_8021q_hdr) : DEFAULT_VLAN_ID,
            ethernet_hdr->dst_mac.mac[0],
            ethernet_hdr->dst_mac.mac[1],
            ethernet_hdr->dst_mac.mac[2],
            ethernet_hdr->dst_mac.mac[3],
            ethernet_hdr->dst_mac.mac[4],
            ethernet_hdr->dst_mac.mac[5]);

        l2_switch_flood_unknown_unicast(dp_ctx, vlan_bd_intf, mac_table, recv_intf, mbuf);
}

void l2_switch_recv_frame(dp_ctx_t *dp_ctx,
                          uint16_t vlan_id,
                          dp_intf_t *interface,
                          struct rte_mbuf *mbuf)
{
    pkt_size_t pkt_size;

    if (pkt_mbuf_get_starting_hdr (mbuf) != ETHERNET_HEADER){
        return;
    }

    dp_pkt_trap_l2(dp_ctx, &interface->trap_rule_table, mbuf);

    vlan_ethernet_hdr_t *vlan_ethernet_hdr = 
        (vlan_ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    c_string src_mac = (c_string)vlan_ethernet_hdr->src_mac.mac;

    tracer (dp_ctx->dptr, DL2SW, "Pkt : %s : Layer 2 Frame Received on Interface %s in vlan %d\n", 
        pkt_mbuf_str (mbuf), interface->if_name, vlan_id);

    l2_switch_perform_mac_learning(dp_ctx, vlan_id, src_mac, interface, 0);
    l2_switch_forward_frame(dp_ctx, dp_ctx->mac_table, NULL, interface, mbuf);
}
