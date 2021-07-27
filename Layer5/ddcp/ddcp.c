/*
 * =====================================================================================
 *
 *       Filename:  ddcp.c
 *
 *    Description:  This file implements the definition of APIs related to DDCP (Distributed Data Collection Protocol)
 *
 *        Version:  1.0
 *        Created:  11/09/2019 02:56:06 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Juniper Networks (www.csepracticals.com), sachinites@gmail.com
 *        Company:  Juniper Networks
 *
 *        This file is part of the DDCP distribution (https://github.com/sachinites) 
 *        Copyright (c) 2019 Abhishek Sagar.
 *        This program is free software: you can redistribute it and/or modify it under the terms of the GNU General 
 *        Public License as published by the Free Software Foundation, version 3.
 *        
 *        This program is distributed in the hope that it will be useful, but
 *        WITHOUT ANY WARRANTY; without even the implied warranty of
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *        General Public License for more details.
 *
 *        visit website : www.csepracticals.com for more courses and projects
 *                                  
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "../../tcp_public.h"
#include "ddcp.h"
#include "ddcp_cmd_codes.h"
#include "serialize.h"

void
init_ddcp(node_t *node);

#define GET_DDCP_INTF_PROP(intf_ptr)    \
    (intf_ptr->intf_nw_props.ddcp_interface_prop)

void
init_ddcp_interface_props(ddcp_interface_prop_t **ddcp_interface_prop){

    *ddcp_interface_prop = calloc(1, sizeof(ddcp_interface_prop_t));
    (*ddcp_interface_prop)->is_enabled = true;
}

static bool
ddcp_is_enabled_on_node(node_t *node) {

    if (node->node_nw_prop.ddcp_db ) {

        return true;
    }

    return false;
}

void
ddcp_send_ddcp_query_out(char *pkt,
                         uint32_t pkt_size,
                         interface_t *oif){

    if(ddcp_is_enabled_on_interface(GET_DDCP_INTF_PROP(oif)) == false) return;
    if(!IS_INTF_L3_MODE(oif)) return;
    send_pkt_out(pkt, pkt_size, oif);
}


void
ddcp_flood_ddcp_query_out(node_t *node, char *pkt,
                          uint32_t pkt_size,
                          interface_t *exempted_intf){

    interface_t *intf = NULL;

    if(!node){
        return;
    }
    uint32_t i = 0 ;
    for(; i < MAX_INTF_PER_NODE; i++){
        intf = node->intf[i];
        if(!intf) return;
        if(intf == exempted_intf) continue;
        ddcp_send_ddcp_query_out(pkt, pkt_size, intf);
    }
}

static uint32_t
ddcp_get_rtr_name(node_t *node, ser_buff_t *data_out){

    serialize_uint8(data_out, DDCP_TLV_RTR_NAME);
    serialize_uint8(data_out, NODE_NAME_SIZE);
    serialize_string(data_out, node->node_name, NODE_NAME_SIZE);
    return NODE_NAME_SIZE + TLV_OVERHEAD_SIZE;
}

static uint32_t
ddcp_get_lo_addr(node_t *node, ser_buff_t *data_out){

    serialize_uint8(data_out, DDCP_TLV_RTR_LO_ADDR);
    serialize_uint8(data_out, sizeof(ip_add_t));
    serialize_string(data_out, NODE_LO_ADDR(node), sizeof(ip_add_t));
    return  sizeof(ip_add_t) + TLV_OVERHEAD_SIZE;
}

static uint32_t
ddcp_get_ram_size(node_t *node, ser_buff_t *data_out){

    uint32_t node_ram = 2;
    serialize_uint8(data_out, DDCP_TLV_RAM_SIZE);
    serialize_uint8(data_out, sizeof(uint32_t));
    serialize_uint32(data_out, node_ram);
    return sizeof(uint32_t) + TLV_OVERHEAD_SIZE;
}

static uint32_t
ddcp_get_os_version(node_t *node, ser_buff_t *data_out){

    char *OS = "Linux";
    serialize_uint8(data_out, DDCP_TLV_OS_VERSION);
    serialize_uint8(data_out, (char)strlen(OS));
    serialize_string(data_out, OS, strlen(OS)); 
    return strlen(OS) + TLV_OVERHEAD_SIZE;
}

static uint32_t
ddcp_get_unknown_data(node_t *node, ser_buff_t *data_out, 
        char unknown_tlv_code_point){

    serialize_uint8(data_out, unknown_tlv_code_point);
    serialize_uint8(data_out, 0);
    return TLV_OVERHEAD_SIZE;
}

static uint32_t
ddcp_get_ip_reach_data(node_t *node, ser_buff_t *data_out){

    /* Iterate over all L3 enabled interfaces of a node, and
     * place Network ID of each interface in TLV Buffer. Size
     * of 1 unit of TLV shall be 5B (= 4B (address) + 1B mask)*/

     int i = 0;
     char mask;
     int chekpoint;
     interface_t *intf;
     char intf_subnet[16];
     uint32_t ip_addr;
     char tlv_size = 0;
     
     serialize_uint8(data_out, DDCP_TLV_IP_REACH);
     
     /*Dont use checkpoint again as it is already being in use*/
     //mark_checkpoint_serialize_buffer(data_out);
     chekpoint = get_serialize_buffer_current_ptr_offset(data_out);
     
     serialize_buffer_skip(data_out, sizeof(char));

     for( ; i < MAX_INTF_PER_NODE; i++){
        
        intf = node->intf[i];
        if(!intf) break;
        if(!IS_INTF_L3_MODE(intf)) continue;
        memset(intf_subnet, 0, sizeof(intf_subnet));
        mask = intf->intf_nw_props.mask;
        apply_mask(IF_IP(intf), mask, intf_subnet);
        inet_pton(AF_INET, intf_subnet, &ip_addr);
        ip_addr = htonl(ip_addr);
        serialize_uint32(data_out, ip_addr);
        serialize_uint8(data_out, mask);
        tlv_size += sizeof(uint32_t) + sizeof(char);
     }

     copy_in_serialized_buffer_by_offset(data_out, 
                                        sizeof(char), 
                                        &tlv_size,
                                        chekpoint);

        
     return tlv_size + TLV_OVERHEAD_SIZE;
}


static void
ddcp_print_ddcp_reply_msg(char *pkt){ 

     char *tlv_ptr;
     char type, length;
    
     char *start_ptr = GET_TLV_START_PTR(pkt);
     char *ddcp_tlv_str = NULL;

     printf("Seq No : %u, pkt size = %u, tlv size = %u\n", 
            GET_SEQ_NO(pkt), GET_PKT_TLEN(pkt), TLV_SIZE(pkt));
     
     ITERATE_TLV_BEGIN(start_ptr, type, length, tlv_ptr, TLV_SIZE(pkt)){
        
        ddcp_tlv_str = ddcp_tlv_id_str((DDCP_TLV_ID)type);

        switch(type){
            case DDCP_TLV_RTR_NAME:
                printf("T : %-22s L : %-6d V : %s\n", 
                        ddcp_tlv_str, length, tlv_ptr);
                break;
            case DDCP_TLV_RTR_LO_ADDR:
                printf("T : %-22s L : %-6d V : %s\n",
                        ddcp_tlv_str, length, tlv_ptr);
                break;
            case DDCP_TLV_RAM_SIZE:
            {
                uint32_t ram_size = *((uint32_t *)tlv_ptr);
                printf("T : %-22s L : %-6d V : %u\n",
                        ddcp_tlv_str, length, ram_size);
            }
            break;
            case DDCP_TLV_OS_VERSION:
                printf("T : %-22s L : %-6d V : %s\n",
                        ddcp_tlv_str, length, tlv_ptr);
                break;
            case DDCP_TLV_IP_REACH:
                printf("T : %-22s L : %-6d V : \n", ddcp_tlv_str, length);
                {
                    char mask;
                    char ip_str[16];
                    uint32_t ip_addr, i;

                    int prefix_mask_len = sizeof(uint32_t) + sizeof(char);
                    
                    uint32_t no_of_prefixes =  length/prefix_mask_len;
                    
                    printf("    No of Prefixes : %u\n", no_of_prefixes);

                    for( i = 0; i < no_of_prefixes; i++){
                        ip_addr = *(uint32_t *)(tlv_ptr + (i * prefix_mask_len));
                        mask = *(tlv_ptr + ((i+1) * prefix_mask_len) - 1);
                        ip_addr = htonl(ip_addr);
                        memset(ip_str, 0, 16);
                        inet_ntop(AF_INET, &ip_addr, ip_str, 16);
                        ip_str[15] = '\0';
                        printf("    %u. %s/%d\n", i, ip_str, mask);
                    }
                }
                break;
            case DDCP_TLV_MAX:
                assert(0);
            default:
                ;
        }
    } ITERATE_TLV_END(start_ptr, type, length, tlv_ptr, TLV_SIZE(pkt));
}


static char *
ddcp_process_ddcp_query(node_t *node, 
                        ddcp_query_hdr_t *ddcp_query_hdr,
                        uint32_t *output_buff_len){

    uint32_t i = 0;
    *output_buff_len = 0;
    DDCP_TLV_ID ddcp_tlv_id;
    char *copy_buffer = NULL;
    ser_buff_t *ser_buff = NULL;

    init_serialized_buffer(&ser_buff);
    serialize_uint32(ser_buff, ddcp_query_hdr->seq_no);
    mark_checkpoint_serialize_buffer(ser_buff);
    serialize_buffer_skip(ser_buff, sizeof(uint32_t));

    for(; i < ddcp_query_hdr->no_of_tlvs; i++){
        ddcp_tlv_id = ddcp_query_hdr->tlv_code_points[i];
        switch(ddcp_tlv_id){
            case DDCP_TLV_RTR_NAME:
                ddcp_get_rtr_name(node, ser_buff);
            break;
            case DDCP_TLV_RTR_LO_ADDR:
                ddcp_get_lo_addr(node, ser_buff);
            break;
            case DDCP_TLV_RAM_SIZE:
               ddcp_get_ram_size(node, ser_buff); 
            break;
            case DDCP_TLV_OS_VERSION:
                ddcp_get_os_version(node, ser_buff);
            break;
            case DDCP_TLV_IP_REACH:
                ddcp_get_ip_reach_data(node, ser_buff);
            break;
            case DDCP_TLV_MAX:
            break;
            default:
                ddcp_get_unknown_data(node, ser_buff, (char)ddcp_tlv_id);                
            ;
        }
    }

    if(is_serialized_buffer_empty(ser_buff)){
        free_serialize_buffer(ser_buff);
        ser_buff = NULL;
        return NULL;
    }

    *output_buff_len = (uint32_t)get_serialize_buffer_size(ser_buff);

    int size_offset = get_serialize_buffer_checkpoint_offset(ser_buff);

    copy_in_serialized_buffer_by_offset(ser_buff, 
                    sizeof(uint32_t), 
                    (char *)output_buff_len, 
                    size_offset);

    copy_buffer = tcp_ip_get_new_pkt_buffer (get_serialize_buffer_size(ser_buff));

    if(!copy_buffer){
        printf("Error : Memory alloc failed\n");
        free_serialize_buffer(ser_buff);
        return NULL;
    }
    memcpy(copy_buffer, ser_buff->b, get_serialize_buffer_size(ser_buff));
    free_serialize_buffer(ser_buff);
    ser_buff = NULL;
    return copy_buffer;
}

void
ddcp_process_ddcp_query_msg(void *arg, size_t arg_size){

    char *pkt;
    node_t *node;
    interface_t *iif;
    uint32_t pkt_size;
	hdr_type_t hdr_code;

    pkt_notif_data_t *pkt_notif_data;

    pkt_notif_data = (pkt_notif_data_t *)arg;

    node        = pkt_notif_data->recv_node;
    iif         = pkt_notif_data->recv_interface;
    pkt         = pkt_notif_data->pkt;
    pkt_size    = pkt_notif_data->pkt_size;
	hdr_code    = pkt_notif_data->hdr_code;	

    char l5_protocol;
    char *ddcp_reply_msg = NULL;
    uint32_t output_buff_len = 0;

	assert(hdr_code == ETH_HDR);
 
    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)pkt;
    
    assert(ethernet_hdr->type == DDCP_MSG_TYPE_FLOOD_QUERY);

    ddcp_query_hdr_t *ddcp_query_msg = (ddcp_query_hdr_t *)
            GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr);

    if(!ddcp_db_should_process_ddcp_query(node, iif, 
                ddcp_query_msg->originator_ip, 
                ddcp_query_msg->seq_no)){

        return;
    }

    ddcp_reply_msg = ddcp_process_ddcp_query(
                      node, 
                      ddcp_query_msg, 
                      &output_buff_len);

    if(!ddcp_reply_msg || !output_buff_len){
        printf("DDCP Reply msg Could not be prepared\n");
        return;
    }
    ddcp_flood_ddcp_query_out(node, (char *)ethernet_hdr, pkt_size, iif);

    l5_protocol = DDCP_MSG_TYPE_UCAST_REPLY;
    tcp_ip_send_ip_data(node, ddcp_reply_msg, 
            output_buff_len, l5_protocol,
            ddcp_query_msg->originator_ip);
    tcp_ip_free_pkt_buffer (ddcp_reply_msg, output_buff_len);
    ddcp_reply_msg = NULL;
}

static void
ddcp_update_ddcp_reply_from_ddcp_tlv(node_t *node, 
                                     ddcp_reply_msg_t *ddcp_reply_msg,
                                     char *ddcp_tlv_msg){

    uint32_t ddcp_reply_msg_size = 
        ddcp_reply_msg ? GET_PKT_TLEN(ddcp_reply_msg->reply_msg) : 0;
    uint32_t tlv_msg_size = 
        GET_PKT_TLEN(ddcp_tlv_msg);

    if(ddcp_reply_msg){
        if(ddcp_reply_msg_size != tlv_msg_size){
            remove_glthread(&ddcp_reply_msg->glue);
            tcp_ip_free_pkt_buffer((char *)ddcp_reply_msg, ddcp_reply_msg_size);
            ddcp_reply_msg = NULL;
        }
    }
    if(!ddcp_reply_msg){

        ddcp_reply_msg = (ddcp_reply_msg_t *)tcp_ip_get_new_pkt_buffer( 
                sizeof(ddcp_reply_msg_t) + tlv_msg_size);

        init_glthread(&ddcp_reply_msg->glue);
        glthread_add_next(GET_NODE_DDCP_DB_REPLY_HEAD(node), 
            &ddcp_reply_msg->glue); 
    }
    memcpy(ddcp_reply_msg->reply_msg, ddcp_tlv_msg, tlv_msg_size);
}

static void
ddcp_add_or_update_ddcp_reply_msg(node_t *node, 
                                 char *ddcp_tlv_msg){


    glthread_t *curr;
    char type, length;
    ddcp_reply_msg_t *ddcp_reply_msg;

    if(!ddcp_tlv_msg) return;

    char *start_ptr = GET_TLV_START_PTR(ddcp_tlv_msg);
    seq_t new_seq_no = GET_SEQ_NO(ddcp_tlv_msg);
    seq_t old_seq_no = 0;

    char *lo_addr = NULL, *tlv_ptr = NULL;
    
    ITERATE_TLV_BEGIN(start_ptr, type, length, tlv_ptr, 
                TLV_SIZE(ddcp_tlv_msg)){

        if((DDCP_TLV_ID)type != DDCP_TLV_RTR_LO_ADDR) continue;
        lo_addr = tlv_ptr;
        break;
    } ITERATE_TLV_END(start_ptr, type, length, tlv_ptr, 
                TLV_SIZE(ddcp_tlv_msg));

    if(!lo_addr){
        printf("Error : Could not find lo-addr in ddcp reply tlv\n");
        return;
    }

    ITERATE_GLTHREAD_BEGIN(GET_NODE_DDCP_DB_REPLY_HEAD(node), curr){

        ddcp_reply_msg = ddcp_db_reply_node_glue_to_ddcp_reply_msg(curr);
        
        old_seq_no = GET_SEQ_NO(ddcp_reply_msg->reply_msg);

        start_ptr = GET_TLV_START_PTR(ddcp_reply_msg->reply_msg);

        ITERATE_TLV_BEGIN(start_ptr, type, length, tlv_ptr,
                    TLV_SIZE(ddcp_reply_msg->reply_msg)){

            if((DDCP_TLV_ID)type != DDCP_TLV_RTR_LO_ADDR)
                continue;
            
            if(strncmp(tlv_ptr, lo_addr, sizeof(ip_add_t)) == 0){
                if(old_seq_no < new_seq_no){
                    ddcp_update_ddcp_reply_from_ddcp_tlv(
                        node, ddcp_reply_msg, ddcp_tlv_msg);
                }
                return;
            }
         }ITERATE_TLV_END(start_ptr, type, length, tlv_ptr,
                    TLV_SIZE(ddcp_reply_msg->reply_msg));

    } ITERATE_GLTHREAD_END(GET_NODE_DDCP_DB_REPLY_HEAD(node), curr);

    ddcp_update_ddcp_reply_from_ddcp_tlv(node,
                        NULL, ddcp_tlv_msg);
}


void
ddcp_process_ddcp_reply_msg(void *arg, size_t arg_size){

    char *pkt;
    node_t *node;
    interface_t *recv_intf;
    uint32_t pkt_size;
	hdr_type_t hdr_code;

    pkt_notif_data_t *pkt_notif_data;

    pkt_notif_data = (pkt_notif_data_t *)arg;

    node        = pkt_notif_data->recv_node;
    recv_intf   = pkt_notif_data->recv_interface;
    pkt         = pkt_notif_data->pkt;
    pkt_size    = pkt_notif_data->pkt_size;
	hdr_code    = pkt_notif_data->hdr_code;

	assert(hdr_code == ETH_HDR);
	ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt;
	ip_hdr_t *ip_hdr = (ip_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr);
    ddcp_add_or_update_ddcp_reply_msg(node, INCREMENT_IPHDR(ip_hdr));
}

/*DDCP Query Database*/

void
init_ddcp_query_db(ddcp_db_t **ddcp_db){

    assert(*ddcp_db == NULL);
    *ddcp_db = calloc(1, sizeof(ddcp_db_t));
    init_glthread(&((*ddcp_db)->ddcp_query_head));
    init_glthread(&((*ddcp_db)->ddcp_reply_head));
    (*ddcp_db)->periodic_ddcp_query_wt_elem = NULL;
}

static ddcp_db_query_node_t *
ddcp_get_ddcp_db_query_info(ddcp_db_t *ddcp_db, 
                             uint32_t originator_ip){

    glthread_t *curr;
    ddcp_db_query_node_t *ddcp_db_query_node;

    ITERATE_GLTHREAD_BEGIN(&ddcp_db->ddcp_query_head, curr){

        ddcp_db_query_node = 
            ddcp_db_query_node_glue_to_ddcp_db_query_node(curr);
        if(ddcp_db_query_node->originator_ip == originator_ip)
            return ddcp_db_query_node;
    } ITERATE_GLTHREAD_END(&ddcp_db->ddcp_head, curr);
    return NULL;
}

seq_t
ddcp_update_ddcp_db_self_query_info(node_t *node){

    uint32_t addr_int = 0;
    inet_pton(AF_INET, NODE_LO_ADDR(node), &addr_int);
    addr_int = htonl(addr_int);

    ddcp_db_query_node_t *ddcp_db_query_node =
        ddcp_get_ddcp_db_query_info(GET_NODE_DDCP_DB(node), addr_int);

    if(!ddcp_db_query_node){
        ddcp_db_query_node = calloc(1, sizeof(ddcp_db_query_node_t));
        ddcp_db_query_node->originator_ip = addr_int;
        ddcp_db_query_node->seq_no = 0;
        init_glthread(&ddcp_db_query_node->ddcp_db_query_node_glue);
        glthread_add_next(GET_NODE_DDCP_DB_HEAD(node),
                &ddcp_db_query_node->ddcp_db_query_node_glue);
        return ddcp_db_query_node->seq_no;
    }

    ddcp_db_query_node->seq_no++;
    return ddcp_db_query_node->seq_no;
}

bool
ddcp_db_should_process_ddcp_query(node_t *node, 
                                  interface_t *iif,
                                  uint32_t originator_ip,
                                  seq_t seq_no){

    uint32_t addr_int = 0;
    inet_pton(AF_INET, NODE_LO_ADDR(node), &addr_int);
    addr_int = htonl(addr_int);
   
    if(ddcp_is_enabled_on_interface(GET_DDCP_INTF_PROP(iif)) == false){
        return false;
    }

    ddcp_db_query_node_t *ddcp_db_query_node = 
        ddcp_get_ddcp_db_query_info(GET_NODE_DDCP_DB(node), 
                                 originator_ip);

    if(originator_ip == addr_int && 
        !ddcp_db_query_node){
        assert(0);
    }

    if(!ddcp_db_query_node){
        ddcp_db_query_node = calloc(1, sizeof(ddcp_db_query_node_t));
        ddcp_db_query_node->originator_ip = originator_ip;
        ddcp_db_query_node->seq_no = seq_no;
        init_glthread(&ddcp_db_query_node->ddcp_db_query_node_glue);
        glthread_add_next(GET_NODE_DDCP_DB_HEAD(node),
                &ddcp_db_query_node->ddcp_db_query_node_glue);
        return true;
    }

    if(ddcp_db_query_node->seq_no < seq_no){
        ddcp_db_query_node->seq_no = seq_no;
        return true;
    }

    if(ddcp_db_query_node->seq_no >= seq_no){
        return false;
    }

    return false;
}

void
ddcp_print_ddcp_reply_msgs_db(node_t *node){

    glthread_t *curr;
    ddcp_reply_msg_t *ddcp_reply_msg = NULL;
   
    if (!ddcp_is_enabled_on_node(node)) return;

    ITERATE_GLTHREAD_BEGIN(GET_NODE_DDCP_DB_REPLY_HEAD(node), curr){

        ddcp_reply_msg = ddcp_db_reply_node_glue_to_ddcp_reply_msg(curr);
        ddcp_print_ddcp_reply_msg(ddcp_reply_msg->reply_msg);
        printf("\n");
    } ITERATE_GLTHREAD_END(GET_NODE_DDCP_DB_REPLY_HEAD(node), curr); 
}

typedef struct ddcp_pkt_meta_data_{

    node_t *node;
    char *pkt;
    uint32_t pkt_size;
} ddcp_pkt_meta_data_t;

static void
wrapper_ddcp_flood_ddcp_query_out(void *arg , 
                                  uint32_t arg_size){

    ddcp_pkt_meta_data_t *ddcp_pkt_meta_data = 
            (ddcp_pkt_meta_data_t *)arg;

    node_t *node = ddcp_pkt_meta_data->node;

    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)ddcp_pkt_meta_data->pkt;
    
    uint32_t pkt_size = ddcp_pkt_meta_data->pkt_size;

    ddcp_query_hdr_t *ddcp_query_hdr = 
            (ddcp_query_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr);

    ddcp_query_hdr->seq_no = ddcp_update_ddcp_db_self_query_info(node);
    SET_COMMON_ETH_FCS(ethernet_hdr, 
        pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD, 0);

    ddcp_flood_ddcp_query_out(node, (char *)ethernet_hdr,
                                      pkt_size, NULL);
}

#define DEFAULT_DDCP_TLVS   5
void
ddcp_trigger_default_ddcp_query(node_t *node, int ddcp_q_interval){

    uint32_t addr_int = 0;
    ddcp_query_hdr_t *ddcp_query_hdr;

    uint32_t payload_size = sizeof(ddcp_query_hdr_t) + 
                (DEFAULT_DDCP_TLVS * sizeof(DDCP_TLV_ID));

    uint32_t ethernet_hdr_size = ETH_HDR_SIZE_EXCL_PAYLOAD +
                                 payload_size;

    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)tcp_ip_get_new_pkt_buffer (
            ethernet_hdr_size);

    ddcp_query_hdr = (ddcp_query_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr);

    inet_pton(AF_INET, NODE_LO_ADDR(node), &addr_int);
    addr_int = htonl(addr_int);

    ddcp_query_hdr->originator_ip = addr_int;
    ddcp_query_hdr->seq_no = ddcp_update_ddcp_db_self_query_info(node);
    ddcp_query_hdr->no_of_tlvs = DEFAULT_DDCP_TLVS;
    ddcp_query_hdr->tlv_code_points[0] = DDCP_TLV_RTR_NAME;
    ddcp_query_hdr->tlv_code_points[1] = DDCP_TLV_RTR_LO_ADDR;
    ddcp_query_hdr->tlv_code_points[2] = DDCP_TLV_RAM_SIZE;
    ddcp_query_hdr->tlv_code_points[3] = DDCP_TLV_OS_VERSION;
    ddcp_query_hdr->tlv_code_points[4] = DDCP_TLV_IP_REACH;

    /*Let src mac be zero*/

    /*Fill Dst mac with Broadcast address*/
    layer2_fill_with_broadcast_mac(ethernet_hdr->dst_mac.mac);
    ethernet_hdr->type = DDCP_MSG_TYPE_FLOOD_QUERY;
    SET_COMMON_ETH_FCS(ethernet_hdr, payload_size, 0);
    if(ddcp_q_interval == 0){
        ddcp_flood_ddcp_query_out(node, (char *)ethernet_hdr, 
                ETH_HDR_SIZE_EXCL_PAYLOAD + payload_size, NULL);
        tcp_ip_free_pkt_buffer ((char *)ethernet_hdr, ethernet_hdr_size);
    }
    else{
        /*Schedule periodic ddcp query firing*/
        wheel_timer_t *wt = node->node_nw_prop.wt;
        assert(wt);

        if((GET_NODE_DDCP_DB(node))->periodic_ddcp_query_wt_elem){
            tcp_ip_free_pkt_buffer((char *)ethernet_hdr, ethernet_hdr_size);
            printf("Config Aborted : Info : Already Firing ddcp Queries !!\n");
            return;
        }
        ddcp_pkt_meta_data_t *ddcp_pkt_meta_data =
			calloc(1, sizeof(ddcp_pkt_meta_data_t));
        ddcp_pkt_meta_data->node = node;
        ddcp_pkt_meta_data->pkt = (char *)ethernet_hdr;
        ddcp_pkt_meta_data->pkt_size = ethernet_hdr_size;
        
        (GET_NODE_DDCP_DB(node))->periodic_ddcp_query_wt_elem = 
                timer_register_app_event(wt,
                wrapper_ddcp_flood_ddcp_query_out,
                (void *)ddcp_pkt_meta_data,
                sizeof(ddcp_pkt_meta_data_t),
                ddcp_q_interval * 1000,
                1);
    }
}

/* DDCP pkt Trap functions */
bool
ddcp_trap_l2_pkt_rule(char *pkt, size_t pkt_size) {

	ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt;
	/* DDCP is an application, hence, it is guaranteed that
	 * pkt is vlan untagged, because hosts are vlan unaware.
	 * DDCP as an application runs only on hosts/L3 routers*/
	assert (!is_pkt_vlan_tagged(eth_hdr));

	if (eth_hdr->type == DDCP_MSG_TYPE_FLOOD_QUERY) {
		return true;
	}
	return false;
}

bool
ddcp_trap_l3_pkt_rule(char *pkt, size_t pkt_size) {

	ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt;

    /* DDCP is an application, hence, it is guaranteed that
	 * pkt is vlan untagged, because hosts are vlan unaware.
 	 * DDCP as an application runs only on hosts/L3 routers*/
	assert (!is_pkt_vlan_tagged(eth_hdr));

	if (eth_hdr->type != ETH_IP) {
		return false;
	}

	ip_hdr_t *ip_hdr = (ip_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr);

	if (ip_hdr->protocol == DDCP_MSG_TYPE_UCAST_REPLY) {
		return true;
	}
	return false;
}

static void
ddcp_cleanup_interface_state(interface_t *intf) {


}

static void
ddcp_cleanup_node_state(node_t *node) {


}

static void
ddcp_init(node_t *node){

    if (!node->node_nw_prop.ddcp_db) {
#if 0 
        tcp_stack_register_l2_pkt_trap_rule(
			node, ddcp_trap_l2_pkt_rule, ddcp_process_ddcp_query_msg);

		nf_register_netfilter_hook(node, NF_IP_LOCAL_IN,
			ddcp_trap_l3_pkt_rule, ddcp_process_ddcp_reply_msg);
#endif
        init_ddcp_query_db(&node->node_nw_prop.ddcp_db);
	}
}

static void
ddcp_de_init(node_t *node){

    if (node->node_nw_prop.ddcp_db) {
#if 0
        tcp_stack_de_register_l2_pkt_trap_rule(
                node, ddcp_trap_l2_pkt_rule, ddcp_process_ddcp_query_msg);

        nf_de_register_netfilter_hook(node, NF_IP_LOCAL_IN,
                ddcp_trap_l3_pkt_rule, ddcp_process_ddcp_reply_msg);
#endif
        ddcp_cleanup_node_state(node);
    }
}

/* CLIs */

int
ddcp_validate_query_interval(char *ddcp_q_interval){

    int ddcp_q_intvl = atoi(ddcp_q_interval);
    if(ddcp_q_intvl < 1){
        printf("Error : Invalid Value, expected > 1\n");
        return VALIDATION_FAILED;
    }
    return VALIDATION_SUCCESS;
}

int
ddcp_handler(param_t *param, ser_buff_t *tlv_buf,
             op_mode enable_or_disable){

   int CMDCODE = -1;
   node_t *node = NULL;
   char *node_name = NULL;
   char *intf_name = NULL;
   int ddcp_q_interval = 0 ;
   interface_t *intf = NULL;

   CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

   tlv_struct_t *tlv = NULL;

   TLV_LOOP_BEGIN(tlv_buf, tlv){

        if  (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else if(strncmp(tlv->leaf_id, "ddcp-q-interval", strlen("ddcp-q-interval")) == 0)
            ddcp_q_interval = atoi(tlv->value);
        else if(strncmp(tlv->leaf_id, "if-name", strlen("if-name")) == 0)
            intf_name = tlv->value;
        else
            assert(0);
   } TLV_LOOP_END;


   node = node_get_node_by_name(topo, node_name);

    switch(CMDCODE){
		case CMDCODE_CONF_NODE_DDCP_PROTO:
		switch(enable_or_disable) {

			case CONFIG_ENABLE:
				ddcp_init(node);
				break;
			case CONFIG_DISABLE:
				ddcp_de_init(node);
				break;
			default: ;
		}
		break;
        case CMDCODE_RUN_DDCP_QUERY:
        case CMDCODE_RUN_DDCP_QUERY_PERIODIC:
            if(!ddcp_is_enabled_on_node(node)) {
                printf("Node %s : DDCP protocol not operational\n",
                        node->node_name);
                break;
            }
            ddcp_trigger_default_ddcp_query(node, ddcp_q_interval);
            break;
        case CMDCODE_SHOW_DDCP_DB:
            ddcp_print_ddcp_reply_msgs_db(node);
            break;
        case CMDCODE_CONF_NODE_DDCP_PROTO_INTF_ENABLE:
            switch(enable_or_disable) {
			case CONFIG_ENABLE:
                if(!ddcp_is_enabled_on_node(node)) {
                    printf("Node %s : DDCP protocol not operational\n",
                            node->node_name);
                    break;
                }
                intf = node_get_intf_by_name(node, intf_name);
                if(!intf) {
                    printf("Error : Non Existing interface\n");
                    return -1;
                }
                if (!GET_DDCP_INTF_PROP(intf)) {
                    init_ddcp_interface_props(&(GET_DDCP_INTF_PROP(intf)));
                }
                else if(GET_DDCP_INTF_PROP(intf)->is_enabled == false) {
                    GET_DDCP_INTF_PROP(intf)->is_enabled = true;
                }
				break;
			case CONFIG_DISABLE:
                intf = node_get_intf_by_name(node, intf_name);
                if(!intf) {
                    printf("Error : Non Existing interface\n");
                    return -1;
                }
                if(GET_DDCP_INTF_PROP(intf)) {
                    free(GET_DDCP_INTF_PROP(intf));
                    GET_DDCP_INTF_PROP(intf) = NULL;
                }
				break;
			default: ;		
            }
            break;
        case CMDCODE_CONF_NODE_DDCP_PROTO_INTF_ALL_ENABLE:
            break;
        default:
            ;
    }
    return 0;
}

extern void
display_node_interfaces(param_t *param, ser_buff_t *tlv_buf);

/* conf node <node-name> protocol ... */
int
ddcp_config_cli_tree(param_t *param) {

	{
		static param_t ddcp_proto;
		init_param(&ddcp_proto, CMD, "ddcp", ddcp_handler, 0, INVALID, 0, "ddcp protocol");
		libcli_register_param(param, &ddcp_proto);
		set_param_cmd_code(&ddcp_proto, CMDCODE_CONF_NODE_DDCP_PROTO);
        {
            /* conf node <node-name> [no] protocol ddcp interface ... */
            static param_t interface;
            init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "interface");
            libcli_register_display_callback(&interface, display_node_interfaces);
            libcli_register_param(&ddcp_proto, &interface);
            {
                /*  conf node <node-name> [no] protocol ddcp interface <intf-name> */
                static param_t if_name;
                init_param(&if_name, LEAF, 0, ddcp_handler, 0, STRING, "if-name",
                        ("Interface Name"));
                libcli_register_param(&interface, &if_name);
                set_param_cmd_code(&if_name, CMDCODE_CONF_NODE_DDCP_PROTO_INTF_ENABLE);
            }
            {
                /*  conf node <node-name> [no] protocol ddcp interface all */
                static param_t all;
                init_param(&all, CMD, "all", ddcp_handler, 0, INVALID, 0,
                        ("All Interfaces"));
                libcli_register_param(&interface, &all);
                set_param_cmd_code(&all, CMDCODE_CONF_NODE_DDCP_PROTO_INTF_ALL_ENABLE);
            }
        }
	}
	return 0;
}

/* show node <node-name> protocol ... */
int
ddcp_show_cli_tree(param_t *param) {

    {
        /* show node <node-name> protocol ddcp ... */
        static param_t ddcp_proto;
        init_param(&ddcp_proto, CMD, "ddcp", 0, 0, INVALID, 0, "ddcp protocol");
        libcli_register_param(param, &ddcp_proto);
        {
            /*  show node <node-name> protocol ddcp ddcp-db */
            static param_t ddcp_db;
            init_param(&ddcp_db, CMD, "ddcp-db", ddcp_handler, 0, INVALID, 0, "Dump DDCP database");
            libcli_register_param(&ddcp_proto, &ddcp_db);
            set_param_cmd_code(&ddcp_db, CMDCODE_SHOW_DDCP_DB);
        }
    }
}

/* run node  <node-name> protocol ... */
int
ddcp_run_cli_tree(param_t *param) {

    {
        /* run node <node-name> protocol ddcp ... */
        static param_t ddcp_proto;
        init_param(&ddcp_proto, CMD, "ddcp", 0, 0, INVALID, 0, "ddcp protocol");
        libcli_register_param(param, &ddcp_proto);
        {
            /* run node <node-name> protocol ddcp ddcp-query*/
            static param_t ddcp_query;
            init_param(&ddcp_query, CMD, "ddcp-query", ddcp_handler, 0, INVALID, 0, "Trigger DDCP Query Flood");
            libcli_register_param(&ddcp_proto, &ddcp_query);
            set_param_cmd_code(&ddcp_query, CMDCODE_RUN_DDCP_QUERY);
            {
                static param_t periodic;
                init_param(&periodic, CMD, "periodic", 0, 0, INVALID, 0, "Periodic ddcp Query");
                libcli_register_param(&ddcp_query, &periodic);
                {
                    static param_t ddcp_q_interval;
                    init_param(&ddcp_q_interval, LEAF, 0, ddcp_handler, ddcp_validate_query_interval,
                            INT, "ddcp-q-interval", "ddcp query interval(min 1 sec)");
                    libcli_register_param(&periodic, &ddcp_q_interval);
                    set_param_cmd_code(&ddcp_q_interval, CMDCODE_RUN_DDCP_QUERY_PERIODIC);
                }
            }
        } 
    }
}
