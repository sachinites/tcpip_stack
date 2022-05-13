#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h> /*for inet_ntop & inet_pton*/
#include "graph.h"
#include "layer2.h"
#include "arp.h"
#include "comm.h"
#include "../Layer5/layer5.h"
#include "../tcp_ip_trace.h"
#include "../libtimer/WheelTimer.h"
#include "../LinuxMemoryManager/uapi_mm.h"

#define ARP_ENTRY_EXP_TIME	30

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
    ethernet_hdr->type = PROTO_ARP;

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
    
    ethernet_hdr_reply->type = PROTO_ARP;
    
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

void
process_arp_reply_msg(node_t *node, interface_t *iif,
                        ethernet_hdr_t *ethernet_hdr){

    arp_table_update_from_arp_reply( NODE_ARP_TABLE(node), 
                    (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr), iif);    
}


void
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

void
init_arp_table(arp_table_t **arp_table){

    *arp_table = XCALLOC(0, 1, arp_table_t);
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
arp_entry_delete(node_t *node, char *ip_addr, uint16_t proto){

    arp_table_t *arp_table = NODE_ARP_TABLE(node);
    arp_entry_t *arp_entry = arp_table_lookup(arp_table, ip_addr);
    
    if(!arp_entry || arp_entry->proto != proto)
        return;

    delete_arp_entry(arp_entry);
}

bool
arp_table_entry_add(node_t *node,
					              arp_table_t *arp_table,
                                  arp_entry_t *arp_entry,
                                  glthread_t **arp_pending_list){

    if(arp_pending_list){
        assert(*arp_pending_list == NULL);   
    }

    arp_entry_t *arp_entry_old = arp_table_lookup(arp_table, 
            arp_entry->ip_addr.ip_addr);

    /* Case 0 : if ARP table entry do not exist already, then add it
     * and return true*/
    if(!arp_entry_old){
        glthread_add_next(&arp_table->arp_entries, &arp_entry->arp_glue);
		assert(arp_entry->exp_timer_wt_elem == NULL);

		if (arp_entry->proto == PROTO_ARP) {
            arp_entry->exp_timer_wt_elem =
			    arp_entry_create_expiration_timer(
				         node,
				        arp_entry, ARP_ENTRY_EXP_TIME); 
        }
        return true;
    }
    

    /*Case 1 : If existing and new ARP entries are full and equal, then
     * do nothing*/
    if(arp_entry_old &&
            IS_ARP_ENTRIES_EQUAL(arp_entry_old, arp_entry)){

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
				    node, arp_entry, ARP_ENTRY_EXP_TIME); 	
        }
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
    if(arp_entry_old && 
        arp_entry_sane(arp_entry_old) && 
        !arp_entry_sane(arp_entry)){

        strncpy(arp_entry_old->mac_addr.mac,
				arp_entry->mac_addr.mac, sizeof(mac_add_t));
        strncpy(arp_entry_old->oif_name, arp_entry->oif_name, IF_NAME_SIZE);
        arp_entry_old->oif_name[IF_NAME_SIZE -1] = '\0';

        if(arp_pending_list)
            *arp_pending_list = &arp_entry_old->arp_pending_list;

        arp_entry_old->proto = arp_entry->proto;
		arp_entry_refresh_expiration_timer(arp_entry_old);
        return false;
    }

    return false;
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
    arp_entry->hit_count++;
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
    arp_entry_t *arp_entry = XCALLOC(0, 1, arp_entry_t);
    src_ip = htonl(arp_hdr->src_ip);
    inet_ntop(AF_INET, &src_ip, arp_entry->ip_addr.ip_addr, 16);
    arp_entry->ip_addr.ip_addr[15] = '\0';
    memcpy(arp_entry->mac_addr.mac, arp_hdr->src_mac.mac, sizeof(mac_add_t));
    strncpy(arp_entry->oif_name, iif->if_name, IF_NAME_SIZE);
    arp_entry->is_sane = false;
    arp_entry->proto = PROTO_ARP;

    bool rc = arp_table_entry_add(iif->att_node, 
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
        (arp_pending_list_to_arp_entry(arp_pending_list))->is_sane = false;
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

    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, curr){
        count++;
        arp_entry = arp_glue_to_arp_entry(curr);
        if(count == 1){
            printf("\t|========IP==========|========MAC========|=====OIF======|===Resolved==|=Exp-Time(msec)==|===Proto==|== hits ===|\n");
        }
        else{
            printf("\t|====================|===================|==============|=============|=================|==========|===========|\n");
        }
        printf("\t| %-18s | %02x:%02x:%02x:%02x:%02x:%02x |  %-12s|   %-6s    |  %-5d          |  %-6s  | %-6llu    |\n", 
            arp_entry->ip_addr.ip_addr, 
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
    } ITERATE_GLTHREAD_END(&arp_table->arp_entries, curr);
    if(count){
        printf("\t|====================|===================|==============|=============|=================|==========|===========|\n");
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
					                 arp_table_t *arp_table,
                                     char *ip_addr, 
                                     char *pkt,
                                     uint32_t pkt_size){

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
    arp_entry = XCALLOC(0, 1,arp_entry_t);
    strncpy(arp_entry->ip_addr.ip_addr, ip_addr, 16);
    arp_entry->ip_addr.ip_addr[15] = '\0';
    init_glthread(&arp_entry->arp_pending_list);
    arp_entry->is_sane = true;
    arp_entry->proto = PROTO_ARP;
    add_arp_pending_entry(arp_entry, 
                          pending_arp_processing_callback_function, 
                          pkt, pkt_size);
    assert(arp_table_entry_add(node, arp_table, arp_entry, 0));
}

static void
arp_entry_timer_delete_cbk(void *arg,
						   uint32_t arg_size){

    if(!arg) return;
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
	
	arp_entry->exp_timer_wt_elem = timer_register_app_event(
					 node_get_timer_instance(node),
					 arp_entry_timer_delete_cbk,
					 (void *)arp_entry,
					 sizeof(*arp_entry),
					 ARP_ENTRY_EXP_TIME * 1000,
					 0); 				 
}

void
arp_entry_delete_expiration_timer(
	arp_entry_t *arp_entry) {

	if(!arp_entry->exp_timer_wt_elem) 
		return;
	timer_de_register_app_event(arp_entry->exp_timer_wt_elem);
	arp_entry->exp_timer_wt_elem = NULL;
}

void
arp_entry_refresh_expiration_timer(
	arp_entry_t *arp_entry) {

    if (arp_entry->exp_timer_wt_elem) {
	    timer_reschedule(arp_entry->exp_timer_wt_elem,
		    ARP_ENTRY_EXP_TIME * 1000);
    }
}

uint16_t
arp_entry_get_exp_time_left(
	arp_entry_t *arp_entry){

	if (arp_entry->exp_timer_wt_elem) {
	    return wt_get_remaining_time(arp_entry->exp_timer_wt_elem);
    }
    return 0;
}

bool
arp_entry_add(node_t *node, char *ip_addr, mac_add_t mac, interface_t *oif, uint16_t proto) {

    arp_entry_t *arp_entry = XCALLOC (0 , 1, arp_entry_t );
    strncpy(arp_entry->ip_addr.ip_addr, ip_addr, 16);
    memcpy(arp_entry->mac_addr.mac, mac.mac, sizeof(mac.mac));
    arp_entry->proto = proto;
    strncpy(arp_entry->oif_name, oif->if_name, IF_NAME_SIZE);
    if (!arp_table_entry_add (node, NODE_ARP_TABLE(node), arp_entry, 0)) {
        XFREE(arp_entry);
        printf("Error : Failed to Add ARP Entry\n");
        return false;
    }
    return true;
}
