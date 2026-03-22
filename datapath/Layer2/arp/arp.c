#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ncurses.h>
#include "../../../LinuxMemoryManager/uapi_mm.h"
#include "../../../common/l2_hdrs.h"
#include "arp.h"
#include "../l2fwd/ipv4-l2fwd.h"
#include "../../../tcp_ip_trace.h"
#include "../../../libtimer/WheelTimer.h"
#include "../../../pkt_block.h"
#include "../../../utils.h"
#include "../../../Tracer/tracer.h"
#include "../../../lmm_enums.h"
#include "../../Vrfs/dp_vrf.h"
#include "../../dp_ctx.h"
#include "../../Interface/dp_intf.h"
#include "../../dp_utils.h"
#include "../../dp_uapi.h"
#include "../../../common/cmn_api.h"
#include "../../../CLIBuilder/cmdtlv.h"
#include "../../../CLIBuilder/libcli.h"
#include "../../../cmdcodes.h"


#define ARP_ENTRY_EXP_TIME	30

/*A Routine to resolve ARP out of oif*/
void
send_arp_broadcast_request(dp_ctx_t *dp_ctx,
                           dp_vrf_t *vrf,
                           dp_intf_t *oif,
                           uint32_t ip_addr){

    pkt_size_t pkt_size;
    uint16_t vlan_id = 0;
    char ip_addr_str[16];

    uint32_t payload_size = sizeof (arp_hdr_t);

    tcp_ip_covert_ip_n_to_p(ip_addr, ip_addr_str);

    if (oif && oif->if_type == DP_INTF_TYPE_VLAN) {
        vlan_id = oif->vlan_id;
    }

    pkt_block_t *pkt_block = pkt_block_get_new_pkt_buffer(
                                (vlan_id ? VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD : \
                                ETH_HDR_SIZE_EXCL_PAYLOAD) + payload_size);

    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *) 
        pkt_block_get_pkt(pkt_block, &pkt_size);

    /* Tag the pkt with Vlan id if not already tagged */
    if (vlan_id) {
        tag_pkt_with_vlan_id (pkt_block, vlan_id);
        ethernet_hdr = (ethernet_hdr_t *) pkt_block_get_pkt(pkt_block, &pkt_size);
    }
    
    if (!oif) {

        oif = dp_intf_get_matching_subnet_interface(dp_ctx, vrf, ip_addr);

        if (!oif) {

            tracer(dp_ctx->dptr, DARP | DERR, 
                "VRF:%s: Error : No eligible subnet for ARP resolution for IP-Address : %s\n",
                 vrf->vrf_name, ip_addr_str);
            pkt_block_dereference(pkt_block);
            return;
        }

        if (oif->ip_addr == ip_addr) {

             tracer(dp_ctx->dptr, DARP | DERR,  
                "VRF:%s: Error : Attempt to resolve ARP for local IP-Address : %s\n", 
                vrf->vrf_name, ip_addr_str);
             pkt_block_dereference(pkt_block);
            return;
        }
    }

    /*STEP 1 : Prepare ethernet hdr*/
    layer2_fill_with_broadcast_mac(ethernet_hdr->dst_mac.mac);
    memcpy(ethernet_hdr->src_mac.mac, oif->mac_add.mac, MAC_ADDR_SIZE);
    SET_COMMON_ETH_HDR_TYPE(ethernet_hdr, PROTO_ARP);

    /*Step 2 : Prepare ARP Broadcast Request Msg out of oif*/
    arp_hdr_t *arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr));
    arp_hdr->hw_type = htons(0x1);
    arp_hdr->proto_type = htons(ETH_IP);
    arp_hdr->hw_addr_len = MAC_ADDR_SIZE;
    arp_hdr->proto_addr_len = 4;

    arp_hdr->op_code = htons(ARP_BROAD_REQ);

    memcpy(arp_hdr->src_mac.mac, oif->mac_add.mac, MAC_ADDR_SIZE);
    arp_hdr->src_ip = htonl(oif->ip_addr);
    memset(arp_hdr->dst_mac.mac, 0,  MAC_ADDR_SIZE);
    arp_hdr->dst_ip = htonl(ip_addr);
    SET_COMMON_ETH_FCS(ethernet_hdr, sizeof(arp_hdr_t), 0); /*Not used*/

    /*STEP 3 : Now dispatch the ARP Broadcast Request Packet out of interface*/
    pkt_block_set_starting_hdr_type(pkt_block, ETH_HDR);
    tracer(dp_ctx->dptr, DARP, 
        "VRF:%s: Sending ARP Broadcast Request for IP : %s out of interface %s\n",
        vrf->vrf_name, ip_addr_str, oif->if_name);
    dp_send_pkt_out (dp_ctx, oif, pkt_block);
    pkt_block_dereference(pkt_block);
}

void 
l2_prepare_arp_reply_msg(
                    ethernet_hdr_t *ethernet_hdr_reply, 
                    mac_addr_t *dst_mac, uint32_t dst_ip,
                    mac_addr_t *src_mac, uint32_t src_ip ) {

    memcpy(ethernet_hdr_reply->dst_mac.mac, dst_mac->mac, sizeof(mac_addr_t));
    memcpy(ethernet_hdr_reply->src_mac.mac, src_mac->mac, sizeof(mac_addr_t));
    SET_COMMON_ETH_HDR_TYPE(ethernet_hdr_reply, PROTO_ARP);
    arp_hdr_t *arp_hdr_reply = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr_reply));
    arp_hdr_reply->hw_type = htons(0x1);
    arp_hdr_reply->proto_type = htons(ETH_IP);
    arp_hdr_reply->hw_addr_len = sizeof(mac_addr_t);
    arp_hdr_reply->proto_addr_len = 4;
    arp_hdr_reply->op_code = htons(ARP_REPLY);
    memcpy(arp_hdr_reply->src_mac.mac, src_mac->mac, MAC_ADDR_SIZE);
    arp_hdr_reply->src_ip = htonl(src_ip);
    memcpy(arp_hdr_reply->dst_mac.mac, dst_mac->mac, MAC_ADDR_SIZE);
    arp_hdr_reply->dst_ip = htonl(dst_ip);
    SET_COMMON_ETH_FCS(ethernet_hdr_reply, sizeof(arp_hdr_t), 0);
}

/* Fn is not suppose to modify the input pkt */
static void
send_arp_reply_msg(dp_ctx_t *dp_ctx, ethernet_hdr_t *ethernet_hdr_in, dp_intf_t *oif){

    pkt_block_t *pkt_block;
    char ip_addr_str[IPV4_ADDR_LEN_STR];

    arp_hdr_t *arp_hdr_in = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr_in));
    pkt_size_t total_pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + (pkt_size_t )sizeof(arp_hdr_t);
    ethernet_hdr_t *ethernet_hdr_reply = (ethernet_hdr_t *)tcp_ip_get_new_pkt_buffer(total_pkt_size);

    l2_prepare_arp_reply_msg(ethernet_hdr_reply, 
            &arp_hdr_in->src_mac, 
            htonl(arp_hdr_in->src_ip),
            &oif->mac_add, 
            oif->ip_addr);

    pkt_block = pkt_block_get_new((uint8_t *)ethernet_hdr_reply, total_pkt_size);

    arp_hdr_t *arp_hdr_reply = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr_reply));

    tracer(dp_ctx->dptr, DARP, "Sending ARP Reply [%s : %02x:%02x:%02x:%02x:%02x:%02x] out of interface %s\n",
            tcp_ip_covert_ip_n_to_p (htonl(arp_hdr_reply->dst_ip), (unsigned char*)ip_addr_str), 
            arp_hdr_reply->dst_mac.mac[0],
            arp_hdr_reply->dst_mac.mac[1],
            arp_hdr_reply->dst_mac.mac[2],
            arp_hdr_reply->dst_mac.mac[3],
            arp_hdr_reply->dst_mac.mac[4],
            arp_hdr_reply->dst_mac.mac[5],
            oif->if_name);

    dp_send_pkt_out(dp_ctx, oif, pkt_block);
    pkt_block_dereference(pkt_block);
}

void
process_arp_reply_msg(dp_ctx_t *dp_ctx, 
                        dp_vrf_t *vrf, dp_intf_t *iif,
                        ethernet_hdr_t *ethernet_hdr){

    tracer(dp_ctx->dptr, DARP, "VRF:%s: Recvd ARP Reply [ %02x:%02x:%02x:%02x:%02x:%02x -> "
            "%02x:%02x:%02x:%02x:%02x:%02x] on interface %s\n",
            vrf->vrf_name,
            ethernet_hdr->src_mac.mac[0], 
            ethernet_hdr->src_mac.mac[1],
            ethernet_hdr->src_mac.mac[2],
            ethernet_hdr->src_mac.mac[3],
            ethernet_hdr->src_mac.mac[4],
            ethernet_hdr->src_mac.mac[5],
            ethernet_hdr->dst_mac.mac[0], 
            ethernet_hdr->dst_mac.mac[1],
            ethernet_hdr->dst_mac.mac[2],
            ethernet_hdr->dst_mac.mac[3],
            ethernet_hdr->dst_mac.mac[4],
            ethernet_hdr->dst_mac.mac[5],            
            iif->if_name);

    arp_table_update_from_arp_reply(dp_ctx, vrf,
                    vrf->arp_table, 
                    (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr), iif);    
}

/* Fn is not suppose to modify the input pkt */
void
process_arp_broadcast_request(dp_ctx_t *dp_ctx, 
                              dp_vrf_t *vrf,
                              dp_intf_t *iif, 
                              ethernet_hdr_t *ethernet_hdr){

    byte ip_addr_str[IPV4_ADDR_LEN_STR];

    arp_hdr_t *arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr));

    tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-Broadcast Req Recvd  from %02x:%02x:%02x:%02x:%02x:%02x  "
            "for resolution of %s on interface %s\n",
            vrf->vrf_name,
            ethernet_hdr->src_mac.mac[0], 
            ethernet_hdr->src_mac.mac[1],
            ethernet_hdr->src_mac.mac[2],
            ethernet_hdr->src_mac.mac[3],
            ethernet_hdr->src_mac.mac[4],
            ethernet_hdr->src_mac.mac[5],
            tcp_ip_covert_ip_n_to_p(htonl(arp_hdr->dst_ip), ip_addr_str),
            iif->if_name);  

   /* ARP broadcast request msg has passed MAC Address check*/

    /* Now populate ARP cache using ARP's src mac and src IP address. Here
        We are overhearing ARP-B request msg to populate our ARP cache */
    arp_table_update_from_arp_reply(dp_ctx, vrf,
                    vrf->arp_table,
                    (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr), iif);    

   /* Now, this node need to reply to this ARP Broadcast req
    * msg if Dst ip address in ARP req msg matches iif's ip address*/

     if (htonl(arp_hdr->dst_ip) != iif->ip_addr) {
         tracer(dp_ctx->dptr, DARP | DERR, "VRF:%s: Error : Mismatched ARP Broadcast Req "
            "Recvd for IP %s on interface %s\n",
            vrf->vrf_name,
            tcp_ip_covert_ip_n_to_p(htonl(arp_hdr->dst_ip), ip_addr_str), 
            iif->if_name);
        return;
     }

   send_arp_reply_msg(dp_ctx, ethernet_hdr, iif);
}

void
init_arp_table(arp_table_t **arp_table){

    *arp_table = (arp_table_t *)XCALLOC2(0, 1, arp_table_t);
    init_glthread(&((*arp_table)->arp_entries));
}

arp_entry_t *
arp_table_lookup(arp_table_t *arp_table, uint32_t ip_addr){

    glthread_t *curr;
    arp_entry_t *arp_entry;

    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, curr){
    
        arp_entry = arp_glue_to_arp_entry(curr);
        if (arp_entry->ip_addr == ip_addr) {
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
arp_entry_delete(dp_ctx_t *dp_ctx, dp_vrf_t *vrf, uint32_t ip_addr, uint16_t proto){

    arp_table_t *arp_table = vrf->arp_table;
    arp_entry_t *arp_entry = arp_table_lookup(arp_table, ip_addr);
    
    if(!arp_entry || arp_entry->proto != proto)
        return;

    delete_arp_entry(arp_entry);
    char ip_addr_str[IPV4_ADDR_LEN_STR];
    tcp_ip_covert_ip_n_to_p(ip_addr, ip_addr_str);
    tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-entry %s : Deleted\n",
        vrf->vrf_name, ip_addr_str);
}

bool arp_table_entry_add(dp_ctx_t *dp_ctx,
                         dp_vrf_t *vrf,
                         arp_table_t *arp_table,
                         arp_entry_t *arp_entry,
                         glthread_t **arp_pending_list)
{
    char ip_addr_str[IPV4_ADDR_LEN_STR];
    tcp_ip_covert_ip_n_to_p(arp_entry->ip_addr, ip_addr_str);
    tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-entry %s : called ...\n",
        vrf->vrf_name, ip_addr_str);

    if(arp_pending_list){
        assert(*arp_pending_list == NULL);   
    }

    arp_entry_t *arp_entry_old = arp_table_lookup(arp_table, 
                                    arp_entry->ip_addr);

    /* Case 0 : if ARP table entry do not exist already, then add it
     * and return true*/
    if(!arp_entry_old){
        glthread_add_next(&arp_table->arp_entries, &arp_entry->arp_glue);
		assert(arp_entry->exp_timer_wt_elem == NULL);

		if (arp_entry->proto == PROTO_ARP) {
            arp_entry->exp_timer_wt_elem =
			    arp_entry_create_expiration_timer(
				       dp_ctx, arp_entry, ARP_ENTRY_EXP_TIME); 
        }
        tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-entry %s : Added to ARP Table\n",
            vrf->vrf_name, ip_addr_str);
        tracer_disable_hdr_print (dp_ctx->dptr);
        tracer(dp_ctx->dptr, DARP_DET, "VRF:%s:     ARP Mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
            vrf->vrf_name,
            arp_entry->mac_addr.mac[0], 
            arp_entry->mac_addr.mac[1],
            arp_entry->mac_addr.mac[2],
            arp_entry->mac_addr.mac[3],
            arp_entry->mac_addr.mac[4],
            arp_entry->mac_addr.mac[5]);
        tracer_disable_hdr_print (dp_ctx->dptr);
        tracer(dp_ctx->dptr, DARP_DET, "VRF:%s:     OIF = %s, is_sane = %s\n", 
            vrf->vrf_name,
            arp_entry->oif_name, arp_entry_sane(arp_entry) ? "true" : "false");
        return true;
    }
    

    /*Case 1 : If existing and new ARP entries are full and equal, then
     * do nothing*/
    if(arp_entry_old &&
            IS_ARP_ENTRIES_EQUAL(arp_entry_old, arp_entry)){

        tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-entry %s : Already Exist\n",
            vrf->vrf_name, ip_addr_str);
        return false;
    }

    /*Case 2 : If there already exists full ARP table entry, then replace it*/
    if(arp_entry_old && !arp_entry_sane(arp_entry_old) &&
        ( (arp_entry_old->proto == arp_entry->proto) ||  /* Proto can update its own entry */
           (arp_entry_old->proto == PROTO_ARP &&   /* Proto overwrites ARP's entry */
           arp_entry->proto != PROTO_ARP))) {

        delete_arp_entry(arp_entry_old);
        init_glthread(&arp_entry->arp_glue);
        glthread_add_next(&arp_table->arp_entries, &arp_entry->arp_glue);
		assert(arp_entry->exp_timer_wt_elem == NULL);

        if (arp_entry->proto == PROTO_ARP) {
		    arp_entry->exp_timer_wt_elem =
			    arp_entry_create_expiration_timer(
				    dp_ctx, arp_entry, ARP_ENTRY_EXP_TIME); 	
        }

        tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-entry %s : Updated\n", 
            vrf->vrf_name, ip_addr_str);
        return true;
    }

    /*Case 3 : if existing ARP table entry is sane, and new one is also
     * sane, then move the pending arp list from new to old one and return false*/
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
        return false;
    }

    /*Case 4 : If existing ARP table entry is sane, but new one is full,
     * then copy contents of new ARP entry to old one, return false*/
    if (arp_entry_old && 
        arp_entry_sane(arp_entry_old) && 
        !arp_entry_sane(arp_entry)){

        memcpy( (char *)arp_entry_old->mac_addr.mac,
				(char *)arp_entry->mac_addr.mac, sizeof(mac_addr_t));
        memcpy( (char *)arp_entry_old->oif_name, 
                 ( char *)arp_entry->oif_name, IF_NAME_SIZE);
        arp_entry_old->oif_name[IF_NAME_SIZE -1] = '\0';

        if(arp_pending_list)
            *arp_pending_list = &arp_entry_old->arp_pending_list;

        arp_entry_old->proto = arp_entry->proto;
		arp_entry_refresh_expiration_timer(arp_entry_old);
        tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-entry %s : Updated\n",
            vrf->vrf_name, ip_addr_str);
        return false;
    }

    tcp_ip_covert_ip_n_to_p(arp_entry->ip_addr, ip_addr_str);
    tracer(dp_ctx->dptr, DARP | DERR, 
        "VRF:%s: ARP-entry %s : Failed to Add/Update\n",
        vrf->vrf_name, ip_addr_str);
    return false;
}

static void 
pending_arp_processing_callback_function(dp_ctx_t *dp_ctx,
                                         dp_intf_t *oif,
                                         arp_entry_t *arp_entry,
                                         arp_pending_entry_t *arp_pending_entry){

    pkt_size_t pkt_size;
    ethernet_hdr_t *ethernet_hdr = NULL;
    pkt_block_t *pkt_block = arp_pending_entry->pkt_block;
    ethernet_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);
    memcpy(ethernet_hdr->dst_mac.mac, arp_entry->mac_addr.mac, MAC_ADDR_SIZE);
    memcpy(ethernet_hdr->src_mac.mac, oif->mac_add.mac, MAC_ADDR_SIZE);
    SET_COMMON_ETH_FCS(ethernet_hdr, 
        pkt_size - GET_ETH_HDR_SIZE_EXCL_PAYLOAD(ethernet_hdr), 0);
    dp_send_pkt_out (dp_ctx, oif, pkt_block);
    arp_entry->hit_count++;
}

static void
process_arp_pending_entry(dp_ctx_t *dp_ctx, dp_intf_t *oif, 
                          arp_entry_t *arp_entry, 
                          arp_pending_entry_t *arp_pending_entry){

    arp_pending_entry->cb(dp_ctx, oif, arp_entry, arp_pending_entry);  
}

static void
delete_arp_pending_entry (arp_pending_entry_t *arp_pending_entry){

    remove_glthread(&arp_pending_entry->arp_pending_entry_glue);
    pkt_block_dereference(arp_pending_entry->pkt_block);
    XFREE(arp_pending_entry);
}

void arp_table_update_from_arp_reply(dp_ctx_t *dp_ctx,
                                     dp_vrf_t *vrf,
                                     arp_table_t *arp_table,
                                     arp_hdr_t *arp_hdr,
                                     dp_intf_t *iif)
{

    uint32_t src_ip = 0;
    glthread_t *arp_pending_list = NULL;

    arp_entry_t *arp_entry = ( arp_entry_t *)XCALLOC2(0, 1, arp_entry_t);

    arp_entry->ip_addr = htonl(arp_hdr->src_ip);
    memcpy(arp_entry->mac_addr.mac, arp_hdr->src_mac.mac, MAC_ADDR_SIZE);
    string_copy(arp_entry->oif_name, iif->if_name, IF_NAME_SIZE);
    arp_entry->is_sane = false;
    arp_entry->proto = PROTO_ARP;

    char ip_addr_str[IPV4_ADDR_LEN_STR];
    tcp_ip_covert_ip_n_to_p(arp_entry->ip_addr, ip_addr_str);
    tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-Reply from %s : Updating ARP Table\n", 
        vrf->vrf_name, ip_addr_str);

    bool rc = arp_table_entry_add(dp_ctx, 
                iif->vrf, 
				arp_table, arp_entry, &arp_pending_list);

    glthread_t *curr;
    arp_pending_entry_t *arp_pending_entry;

    if(arp_pending_list){
        
        tcp_ip_covert_ip_n_to_p(arp_entry->ip_addr, ip_addr_str);
        tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-Entry %s : processing ARP Pending List\n", 
            vrf->vrf_name, ip_addr_str);

        ITERATE_GLTHREAD_BEGIN(arp_pending_list, curr){
        
            arp_pending_entry = arp_pending_entry_glue_to_arp_pending_entry(curr);
            remove_glthread(&arp_pending_entry->arp_pending_entry_glue);
            process_arp_pending_entry(dp_ctx, iif, arp_entry, arp_pending_entry);
            delete_arp_pending_entry(arp_pending_entry);

        } ITERATE_GLTHREAD_END(arp_pending_list, curr);

        tracer(dp_ctx->dptr, DARP_DET, 
            "VRF:%s: ARP-Entry %s : Number of ARP Pending List processed %d\n", 
            vrf->vrf_name, ip_addr_str, arp_entry->hit_count);

		assert(IS_GLTHREAD_LIST_EMPTY(arp_pending_list));
        (arp_pending_list_to_arp_entry(arp_pending_list))->is_sane = false;

        tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-Entry %s :  Marked Resolved\n",
            vrf->vrf_name, ip_addr_str);
        tracer_disable_hdr_print (dp_ctx->dptr);
        tracer(dp_ctx->dptr, DARP_DET, "VRF:%s:     Mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
            vrf->vrf_name,
            arp_entry->mac_addr.mac[0], 
            arp_entry->mac_addr.mac[1],
            arp_entry->mac_addr.mac[2],
            arp_entry->mac_addr.mac[3],
            arp_entry->mac_addr.mac[4],
            arp_entry->mac_addr.mac[5]);
        tracer_disable_hdr_print (dp_ctx->dptr);
        tracer(dp_ctx->dptr, DARP_DET, "VRF:%s:     OIF = %s, is_sane = %s\n", 
            vrf->vrf_name,
            arp_entry->oif_name, arp_entry_sane(arp_entry) ? "true" : "false");        
    }

    if(rc == false){
        delete_arp_entry(arp_entry);
    }
}

void
show_arp_table(arp_table_t *arp_table){

    glthread_t *curr;
    arp_entry_t *arp_entry;
    int count = 0 ;

    printw ("\n\r");
    
    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, curr){
        count++;
        arp_entry = arp_glue_to_arp_entry(curr);
        if(count == 1){
            cprintf("\t|========IP==========|========MAC========|=====OIF======|===Resolved==|=Exp-Time(msec)==|===Proto==|== hits ===|\n");
        }
        else{
            cprintf("\t|====================|===================|==============|=============|=================|==========|===========|\n");
        }
        {
            char ip_addr_str[IPV4_ADDR_LEN_STR];
            tcp_ip_covert_ip_n_to_p(arp_entry->ip_addr, ip_addr_str);
        cprintf("\t| %-18s | %02x:%02x:%02x:%02x:%02x:%02x |  %-12s|   %-6s    |  %-5d          |  %-6s  | %-6llu    |\n", 
            ip_addr_str, 
            arp_entry->mac_addr.mac[0], 
            arp_entry->mac_addr.mac[1], 
            arp_entry->mac_addr.mac[2], 
            arp_entry->mac_addr.mac[3], 
            arp_entry->mac_addr.mac[4], 
            arp_entry->mac_addr.mac[5], 
            arp_entry->oif_name,
            arp_entry_sane(arp_entry) ? "false" : "true",
			arp_entry_get_exp_time_left(arp_entry),
            proto_name_str(arp_entry->proto),
            arp_entry->hit_count);
        }
    } ITERATE_GLTHREAD_END(&arp_table->arp_entries, curr);
    if(count){
        cprintf("\t|====================|===================|==============|=============|=================|==========|===========|\n");
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
    XFREE(arp_entry);
}

void
add_arp_pending_entry (dp_ctx_t *dp_ctx,
        arp_entry_t *arp_entry,
        arp_processing_fn cb,
        pkt_block_t *pkt_block){
    
    arp_pending_entry_t *arp_pending_entry = 
        (arp_pending_entry_t *)XCALLOC2(0, 1, arp_pending_entry_t);

    init_glthread(&arp_pending_entry->arp_pending_entry_glue);
    arp_pending_entry->cb = cb;
    arp_pending_entry->pkt_block = pkt_block;
    pkt_block_reference(pkt_block);

    glthread_add_next(&arp_entry->arp_pending_list, 
                    &arp_pending_entry->arp_pending_entry_glue);
    {
        char ip_addr_str[IPV4_ADDR_LEN_STR];
        tcp_ip_covert_ip_n_to_p(arp_entry->ip_addr, ip_addr_str);
        tracer(dp_ctx->dptr, DARP_DET, 
            "ARP-entry %s : Added ARP-Pending entry\n", 
            ip_addr_str);
    }
}

void create_update_arp_sane_entry(dp_ctx_t *dp_ctx,
                           dp_vrf_t *vrf,
                           arp_table_t *arp_table,
                           uint32_t ip_addr,
                           pkt_block_t *pkt_block)
{

    /*case 1 : If full entry already exist - assert. The L2 must have
     * not create ARP sane entry if the already was already existing*/
    arp_entry_t *arp_entry = arp_table_lookup(arp_table, ip_addr);
    
    if(arp_entry){
    
        if(!arp_entry_sane(arp_entry)){
            assert(0);
        }

        /*ARP sane entry already exists, append the arp pending entry to it*/
        add_arp_pending_entry(dp_ctx, arp_entry, 
                              pending_arp_processing_callback_function, 
                              pkt_block);
	    arp_entry_refresh_expiration_timer(arp_entry);	
        return;
    }
    
    {
        char ip_addr_str[IPV4_ADDR_LEN_STR];
        tcp_ip_covert_ip_n_to_p(ip_addr, ip_addr_str);
        tracer(dp_ctx->dptr, DARP, 
            "VRF:%s: ARP-entry %s : Creating ARP Sane Entry\n",
            vrf->vrf_name, ip_addr_str);
    }

    /*if ARP entry do not exist, create a new sane entry*/
    arp_entry = (arp_entry_t *)XCALLOC2(0, 1,arp_entry_t);
    arp_entry->ip_addr = ip_addr;
    init_glthread(&arp_entry->arp_pending_list);
    arp_entry->is_sane = true;
    arp_entry->proto = PROTO_ARP;
    add_arp_pending_entry(dp_ctx, arp_entry, 
                          pending_arp_processing_callback_function, 
                          pkt_block);
    assert (arp_table_entry_add(dp_ctx, vrf, arp_table, arp_entry, 0));
}

static void
arp_entry_timer_delete_cbk(event_dispatcher_t *ev_dis,
                           void *arg,
						   uint32_t arg_size){
            
    UNUSED(arg_size);

    if(!arg) return;
	arp_entry_t *arp_entry = (arp_entry_t *)arg;
    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;
    char ip_addr_str[IPV4_ADDR_LEN_STR];
    tcp_ip_covert_ip_n_to_p(arp_entry->ip_addr, ip_addr_str);
    tracer(dp_ctx->dptr, DARP | DTIMER, "ARP-entry %s : Expired\n", 
        ip_addr_str);
	delete_arp_entry(arp_entry);	
}

/* ARP entry Timer management functions */
wheel_timer_elem_t *
arp_entry_create_expiration_timer(
                                    dp_ctx_t *dp_ctx,
                                    arp_entry_t *arp_entry,
                                    uint16_t exp_time) {

    UNUSED(exp_time);

	assert(arp_entry->exp_timer_wt_elem == NULL);
	
	arp_entry->exp_timer_wt_elem = timer_register_app_event(
					 DP_TIMER(dp_ctx),
					 arp_entry_timer_delete_cbk,
					 (void *)arp_entry,
					 sizeof(*arp_entry),
					 ARP_ENTRY_EXP_TIME * 1000,
					 0); 				 

    {
        char ip_addr_str[IPV4_ADDR_LEN_STR];
        tcp_ip_covert_ip_n_to_p(arp_entry->ip_addr, ip_addr_str);
    tracer(dp_ctx->dptr, DARP_DET | DTIMER, 
        "ARP-entry %s :  Expiration Timer Created\n", ip_addr_str);
    }

    return arp_entry->exp_timer_wt_elem;
}

void
arp_entry_delete_expiration_timer(
	arp_entry_t *arp_entry) {

	if(!arp_entry->exp_timer_wt_elem)  return;
	timer_de_register_app_event(arp_entry->exp_timer_wt_elem);
	arp_entry->exp_timer_wt_elem = NULL;
}

void
arp_entry_refresh_expiration_timer(arp_entry_t *arp_entry) {

    if (arp_entry->exp_timer_wt_elem) {
	    timer_reschedule(arp_entry->exp_timer_wt_elem,
		    ARP_ENTRY_EXP_TIME * 1000);
    }
}

uint16_t
arp_entry_get_exp_time_left(arp_entry_t *arp_entry){

	if (arp_entry->exp_timer_wt_elem) {
	    return wt_get_remaining_time(arp_entry->exp_timer_wt_elem);
    }
    return 0;
}

bool
arp_entry_add(dp_ctx_t *dp_ctx,
             dp_vrf_t *vrf, 
             unsigned char *ip_addr, 
             mac_addr_t mac, 
             dp_intf_t *oif, 
             uint16_t proto) {

    arp_entry_t *arp_entry = ( arp_entry_t *)XCALLOC2 (0 , 1, arp_entry_t );
    arp_entry->ip_addr = tcp_ip_convert_ip_p_to_n((char *)ip_addr);
    memcpy(arp_entry->mac_addr.mac, mac.mac, MAC_ADDR_SIZE);
    arp_entry->proto = proto;
    string_copy(arp_entry->oif_name, oif->if_name, IF_NAME_SIZE);
    if (!arp_table_entry_add (dp_ctx, vrf, vrf->arp_table, arp_entry, 0)) {
        XFREE(arp_entry);
        return false;
    }
    return true;
}

#if 0
static int
show_arp_handler(int cmdcode, Stack_t *tlv_stack, 
                    op_mode enable_or_disable){

    node_t *node;
    c_string node_name;
    c_string vrf_name = NULL;
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "vrf-name"))
            vrf_name = tlv->value;

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    dp_vrf_t *vrf = dp_look_up_vrf(node->dp_ctx, vrf_name);

    show_arp_table(vrf->arp_table);

    return 0;
}
#endif

static int
show_arp_handler(int cmdcode, Stack_t *tlv_stack, 
                    op_mode enable_or_disable) {return 0;}

int show_arp_cli_tree(param_t *param)
{
    {
        /*show node <node-name> protocol arp*/
        static param_t arp;
        init_param(&arp, CMD, "arp", show_arp_handler, 0, INVALID, 0, "Dump Arp Table");
        libcli_register_param(param, &arp);
        libcli_set_param_cmd_code(&arp, CMDCODE_SHOW_NODE_ARP_TABLE);
    }

    return 0;
}