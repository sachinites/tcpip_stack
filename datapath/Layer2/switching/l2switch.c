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

extern void
dp_promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
                      dp_intf_t *interface, 
                      struct rte_mbuf *mbuf);

void
l2_switch_perform_mac_learning(dp_ctx_t *dp_ctx,
                               vlan_id_t vlan_id,
                               c_string src_mac,
                               dp_intf_t *oif, uint32_t src_ip)
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
    if (mac_table_lookup(dp_ctx->mac_table, vlan_id, (uint8_t *)src_mac))
        return;

    /* Post MAC learn job to dp_ev_dis (single-writer thread). */
    dp_post_mac_learn_job(dp_ctx, (uint8_t *)src_mac, vlan_id,
                          oif->port_id, src_ip);
}

static void 
mac_table_entry_xmit_frame (dp_ctx_t *dp_ctx,
                            mac_table_entry_t *mac_entry, 
                            struct rte_mbuf *mbuf, 
                            dp_intf_t *recv_intf) 
{
    dp_intf_t *oif; 
    glthread_t *curr;
    uint32_t vni_id = 0;
    uint16_t vlan_id = 0;
    struct rte_mbuf *mbuf2;
    mac_oif_entry_t *oif_entry;
    pkt_mbuf_pvt_data_t *pvt_data;
    pkt_mbuf_encap_meta_data_t *encap_data = NULL;

    ITERATE_GLTHREAD_BEGIN(&mac_entry->oif_list, curr) {
        
        oif_entry = mac_oif_glue_to_entry(curr);
        oif = oif_entry->oif;
        
        if (!oif || (oif == recv_intf )) continue;

        if (oif->if_type == DP_INTF_TYPE_NVE) {
            
            encap_data = (pkt_mbuf_encap_meta_data_t *) XCALLOC2 (0, 1, pkt_mbuf_encap_meta_data_t);
            vlan_id = mac_entry->vlan_id;

            /* Get VNI id using DP hashtable*/
            vni_id = vlan_vni_ht_vlan_to_vni_lookup (dp_ctx, vlan_id);

            if (vni_id == 0) {

                tracer (dp_ctx->dptr, DL2SW | DERR,
                    "VLAN to VNI mapping not found for vlan %d, Dropping the frame on NVE interface\n", vlan_id);
                XFREE(encap_data);
                continue;
            }

            encap_data->u.vxlan.vni = vni_id;
            encap_data->u.vxlan.remote_vtep_ip = oif_entry->remote_dst_ip;
        }

        /* Create a copy of pkt blocks, and xmit them because they can be modified*/
        /* Flush old encap data if any*/
        pvt_data = pkt_mbuf_get_pvt_data(mbuf);

        if (pvt_data && pvt_data->encap_data) {
            XFREE(pvt_data->encap_data);
            pvt_data->encap_data = NULL;
        }

        mbuf2 = PKT_MBUF_DUP(mbuf);
        pvt_data = pkt_mbuf_get_pvt_data(mbuf2);
        pvt_data->encap_data = encap_data;
        encap_data = NULL;
        dp_send_pkt_out(dp_ctx, oif, mbuf2);
        pkt_mbuf_dereference(mbuf2);

    } ITERATE_GLTHREAD_END(&mac_entry->oif_list, curr);

}

static void
l2_switch_flood_unknown_unicast(dp_ctx_t *dp_ctx,
                                dp_intf_t *exempted_intf,
                                struct rte_mbuf *mbuf)
{

    dp_intf_t *oif;
    struct rte_mbuf *dup_mbuf;
    vlan_8021q_hdr_t *vlan_8021q_hdr;
    mac_table_entry_t *mac_flood_entry = NULL;

    mac_flood_entry =
        mac_table_lookup(dp_ctx->mac_table,
                         1,
                         BROADCAST_MAC);

    if (!mac_flood_entry) {
         tracer (dp_ctx->dptr, DL2SW, "Mac Table : Flooding Disabled ");
        return;
    }

    assert ((vlan_8021q_hdr = 
            is_pkt_vlan_tagged ((ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, NULL))));

    tracer (dp_ctx->dptr, DL2SW, "Pkt : %s : Layer 2 Flooding in vlan %d\n",  
            pkt_mbuf_str (mbuf), 
            TCI_VID(vlan_8021q_hdr->tci));

    mac_table_entry_xmit_frame (dp_ctx, mac_flood_entry, mbuf, exempted_intf);
}

void
l2_switch_forward_frame(
                        dp_ctx_t *dp_ctx,
                        dp_intf_t *recv_intf, 
                        struct rte_mbuf *mbuf) {

    uint16_t vlan_id;
    pkt_size_t pkt_size;
    ethernet_hdr_t *ethernet_hdr;
    mac_table_entry_t *mac_table_entry = NULL;
    vlan_8021q_hdr_t *vlan_8021q_hdr = NULL;

    ethernet_hdr = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    assert ((vlan_8021q_hdr = is_pkt_vlan_tagged (ethernet_hdr))) ;  

    tracer (dp_ctx->dptr, DL2SW, "Pkt : %s : Layer 2 Forwarding in vlan %d\n",  
        pkt_mbuf_str (mbuf), 
        GET_802_1Q_VLAN_ID(vlan_8021q_hdr));

     pkt_mbuf_set_ingress_intf (mbuf, recv_intf);
     vlan_id = (uint16_t)GET_802_1Q_VLAN_ID(vlan_8021q_hdr);

    mac_table_entry = mac_table_lookup(dp_ctx->mac_table, 
                                      vlan_id,
                                      ethernet_hdr->dst_mac.mac);

    if (mac_table_entry) {
        mac_table_entry_xmit_frame (dp_ctx, mac_table_entry, mbuf, recv_intf);
        if (!(mac_table_entry->flags & MAC_STATIC)) {
            mac_table_entry_cancel_expiry_timer(mac_table_entry);
            mac_table_entry_init_timer(dp_ctx, mac_table_entry);
        }
        return;
    }

    if (IS_MAC_BROADCAST_ADDR(ethernet_hdr->dst_mac.mac)) {

            /* Handle BUM traffic for EVPN case */
            mac_table_entry = mac_table_lookup(dp_ctx->mac_table,
                                        vlan_id,
                                        BROADCAST_MAC);

            if (mac_table_entry) {
                mac_table_entry_xmit_frame (dp_ctx, mac_table_entry, mbuf, recv_intf);
                return;
            }        

            mac_table_entry = mac_table_lookup(dp_ctx->mac_table, 
                                        DEFAULT_VLAN_ID,
                                        BROADCAST_MAC);

            if (!mac_table_entry) {
                tracer (dp_ctx->dptr, DL2SW, "Mac Table : Flooding Disabled for Broadcast MAC");
                return;
            }
       
            mac_table_entry_xmit_frame (dp_ctx, mac_table_entry, mbuf, recv_intf);
            return;
    }

    /* Check if the pkt matches the router mac , vlan id dont matter here */
    if (mac_address_compare (dp_ctx->rmac.mac, ethernet_hdr->dst_mac.mac)) {

        mac_table_entry = 
            mac_table_lookup(dp_ctx->mac_table, 
                                      DEFAULT_VLAN_ID,
                                      ethernet_hdr->dst_mac.mac);    

        if (!mac_table_entry) {
            tracer (dp_ctx->dptr, DL2SW, "Mac Table : Router MAC not programmed, Dropping the frame\n");
            return;
        }

        mac_table_entry_xmit_frame (dp_ctx, mac_table_entry, mbuf, recv_intf);
        return;
    }

    /* Handle Unknown Unicast */
    tracer (dp_ctx->dptr, DL2SW, 
            "Mac Table Lookup Failed for vlan = %d, "
            "Mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
            GET_802_1Q_VLAN_ID(vlan_8021q_hdr),
            ethernet_hdr->dst_mac.mac[0],
            ethernet_hdr->dst_mac.mac[1],
            ethernet_hdr->dst_mac.mac[2],
            ethernet_hdr->dst_mac.mac[3],
            ethernet_hdr->dst_mac.mac[4],
            ethernet_hdr->dst_mac.mac[5]);

        l2_switch_flood_unknown_unicast(dp_ctx, recv_intf, mbuf);
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

    vlan_ethernet_hdr_t *vlan_ethernet_hdr = 
        (vlan_ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    c_string src_mac = (c_string)vlan_ethernet_hdr->src_mac.mac;

    tracer (dp_ctx->dptr, DL2SW, "Pkt : %s : Layer 2 Frame Received on Interface %s in vlan %d\n", 
        pkt_mbuf_str (mbuf), interface->if_name, vlan_id);

    l2_switch_perform_mac_learning(dp_ctx, vlan_id, src_mac, interface, 0);
    l2_switch_forward_frame(dp_ctx, interface, mbuf);
}
