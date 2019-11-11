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
 *         Author:  Er. Abhishek Sagar, Juniper Networks (https://csepracticals.wixsite.com/csepracticals), sachinites@gmail.com
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
 *        visit website : https://csepracticals.wixsite.com/csepracticals for more courses and projects
 *                                  
 * =====================================================================================
 */

#include <stdlib.h>
#include "ddcp.h"
#include "stdio.h"
#include "serialize.h"
#include <assert.h>
#include "../../tcpconst.h"
#include <arpa/inet.h> /*for inet_ntop & inet_pton*/
#include "../../WheelTimer/WheelTimer.h"

#define GET_DDCP_INTF_PROP(intf_ptr)    \
    (intf_ptr->intf_nw_props.ddcp_interface_prop)

extern void
demote_packet_to_layer3(node_t *node,
        char *pkt, unsigned int size,
        int protocol_number, /*L4 or L5 protocol type*/
        unsigned int dest_ip_address);

void
init_ddcp_interface_props(ddcp_interface_prop_t **ddcp_interface_prop){

    *ddcp_interface_prop = calloc(1, sizeof(ddcp_interface_prop_t));
    (*ddcp_interface_prop)->is_enabled = TRUE;
}

void
ddcp_send_ddcp_query_out(char *pkt,
                         unsigned int pkt_size,
                         interface_t *oif){

    if(is_interface_ddcp_enabled(GET_DDCP_INTF_PROP(oif)) == FALSE) return;
    if(!IS_INTF_L3_MODE(oif)) return;
    send_pkt_out(pkt, pkt_size, oif);
}


void
ddcp_flood_ddcp_query_out(node_t *node, char *pkt,
                          unsigned int pkt_size,
                          interface_t *exempted_intf){

    interface_t *intf = NULL;

    if(!node){
        return;
    }
    unsigned int i = 0 ;
    for(; i < MAX_INTF_PER_NODE; i++){
        intf = node->intf[i];
        if(!intf) return;
        if(intf == exempted_intf) continue;
        ddcp_send_ddcp_query_out(pkt, pkt_size, intf);
    }
}

static unsigned int
ddcp_get_rtr_name(node_t *node, ser_buff_t *data_out){

    serialize_uint8(data_out, DDCP_TLV_RTR_NAME);
    serialize_uint8(data_out, NODE_NAME_SIZE);
    serialize_string(data_out, node->node_name, NODE_NAME_SIZE);
    return NODE_NAME_SIZE + TLV_OVERHEAD_SIZE;
}

static unsigned int
ddcp_get_lo_addr(node_t *node, ser_buff_t *data_out){

    serialize_uint8(data_out, DDCP_TLV_RTR_LO_ADDR);
    serialize_uint8(data_out, sizeof(ip_add_t));
    serialize_string(data_out, NODE_LO_ADDR(node), sizeof(ip_add_t));
    return  sizeof(ip_add_t) + TLV_OVERHEAD_SIZE;
}

static unsigned int
ddcp_get_ram_size(node_t *node, ser_buff_t *data_out){

    unsigned int node_ram = 2;
    serialize_uint8(data_out, DDCP_TLV_RAM_SIZE);
    serialize_uint8(data_out, sizeof(unsigned int));
    serialize_uint32(data_out, node_ram);
    return sizeof(unsigned int) + TLV_OVERHEAD_SIZE;
}

static unsigned int
ddcp_get_os_version(node_t *node, ser_buff_t *data_out){

    char *OS = "Linux";
    serialize_uint8(data_out, DDCP_TLV_OS_VERSION);
    serialize_uint8(data_out, (char)strlen(OS));
    serialize_string(data_out, OS, strlen(OS)); 
    return strlen(OS) + TLV_OVERHEAD_SIZE;
}

static unsigned int
ddcp_get_unknown_data(node_t *node, ser_buff_t *data_out, 
        char unknown_tlv_code_point){

    serialize_uint8(data_out, unknown_tlv_code_point);
    serialize_uint8(data_out, 0);
    return TLV_OVERHEAD_SIZE;
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
                unsigned int ram_size = *((unsigned int *)tlv_ptr);
                printf("T : %-22s L : %-6d V : %u\n",
                        ddcp_tlv_str, length, ram_size);
            }
            break;
            case DDCP_TLV_OS_VERSION:
                printf("T : %-22s L : %-6d V : %s\n",
                        ddcp_tlv_str, length, tlv_ptr);
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
                        unsigned int *output_buff_len){

    unsigned int i = 0;
    *output_buff_len = 0;
    DDCP_TLV_ID ddcp_tlv_id;
    char *copy_buffer = NULL;
    ser_buff_t *ser_buff = NULL;

    init_serialized_buffer(&ser_buff);
    serialize_uint32(ser_buff, ddcp_query_hdr->seq_no);
    mark_checkpoint_serialize_buffer(ser_buff);
    serialize_buffer_skip(ser_buff, sizeof(unsigned int));

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

    *output_buff_len = (unsigned int)get_serialize_buffer_size(ser_buff);

    int size_offset = get_serialize_buffer_checkpoint_offset(ser_buff);

    copy_in_serialized_buffer_by_offset(ser_buff, 
                    sizeof(unsigned int), 
                    (char *)output_buff_len, 
                    size_offset);

    copy_buffer = calloc(1, get_serialize_buffer_size(ser_buff));

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
ddcp_process_ddcp_query_msg(node_t *node, interface_t *iif, 
                            ethernet_hdr_t *ethernet_hdr, 
                            unsigned int pkt_size){

    char l5_protocol;
    char *ddcp_reply_msg = NULL;
    unsigned int output_buff_len = 0;

    assert(ethernet_hdr->type == DDCP_MSG_TYPE_FLOOD_QUERY);

    ddcp_query_hdr_t *ddcp_query_msg = (ddcp_query_hdr_t *)
            GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr);

    if(!ddcp_db_should_process_ddcp_query(node, 
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
    demote_packet_to_layer3(node, ddcp_reply_msg, 
            output_buff_len, l5_protocol,
            ddcp_query_msg->originator_ip);
    free(ddcp_reply_msg);
    ddcp_reply_msg = NULL;
}

static void
ddcp_update_ddcp_reply_from_ddcp_tlv(node_t *node, 
                                     ddcp_reply_msg_t *ddcp_reply_msg,
                                     char *ddcp_tlv_msg){

    unsigned int ddcp_reply_msg_size = 
        ddcp_reply_msg ? GET_PKT_TLEN(ddcp_reply_msg->reply_msg) : 0;
    unsigned int tlv_msg_size = 
        GET_PKT_TLEN(ddcp_tlv_msg);

    if(ddcp_reply_msg){
        if(ddcp_reply_msg_size != tlv_msg_size){
            remove_glthread(&ddcp_reply_msg->glue);
            free(ddcp_reply_msg);
            ddcp_reply_msg = NULL;
        }
    }
    if(!ddcp_reply_msg){
        ddcp_reply_msg = calloc(1, 
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
ddcp_process_ddcp_reply_msg(node_t *node, char *pkt){

    ddcp_add_or_update_ddcp_reply_msg(node, pkt);
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
                             unsigned int originator_ip){

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

    unsigned int addr_int = 0;
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

bool_t
ddcp_db_should_process_ddcp_query(node_t *node, 
                                  unsigned int originator_ip,
                                  seq_t seq_no){

    unsigned int addr_int = 0;
    inet_pton(AF_INET, NODE_LO_ADDR(node), &addr_int);
    addr_int = htonl(addr_int);
    
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
        return TRUE;
    }

    if(ddcp_db_query_node->seq_no < seq_no){
        ddcp_db_query_node->seq_no = seq_no;
        return TRUE;
    }

    if(ddcp_db_query_node->seq_no >= seq_no){
        return FALSE;
    }

    return FALSE;
}

void
ddcp_print_ddcp_reply_msgs_db(node_t *node){

    glthread_t *curr;
    ddcp_reply_msg_t *ddcp_reply_msg = NULL;
    
    ITERATE_GLTHREAD_BEGIN(GET_NODE_DDCP_DB_REPLY_HEAD(node), curr){

        ddcp_reply_msg = ddcp_db_reply_node_glue_to_ddcp_reply_msg(curr);
        ddcp_print_ddcp_reply_msg(ddcp_reply_msg->reply_msg);
        printf("\n");
    } ITERATE_GLTHREAD_END(GET_NODE_DDCP_DB_REPLY_HEAD(node), curr); 
}

typedef struct ddcp_pkt_meta_data_{

    node_t *node;
    char *pkt;
    unsigned int pkt_size;
} ddcp_pkt_meta_data_t;

static void
wrapper_ddcp_flood_ddcp_query_out(void *arg , 
                                  int arg_size){

    ddcp_pkt_meta_data_t *ddcp_pkt_meta_data = 
            (ddcp_pkt_meta_data_t *)arg;

    node_t *node = ddcp_pkt_meta_data->node;

    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)ddcp_pkt_meta_data->pkt;
    
    unsigned int pkt_size = ddcp_pkt_meta_data->pkt_size;

    ddcp_query_hdr_t *ddcp_query_hdr = 
            (ddcp_query_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr);

    ddcp_query_hdr->seq_no = ddcp_update_ddcp_db_self_query_info(node);
    SET_COMMON_ETH_FCS(ethernet_hdr, pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD, 0);

    ddcp_flood_ddcp_query_out(node, (char *)ethernet_hdr,
                                      pkt_size, NULL);
}

void
ddcp_trigger_default_ddcp_query(node_t *node, int ddcp_q_interval){

    unsigned int addr_int = 0;
    ddcp_query_hdr_t *ddcp_query_hdr;

    unsigned int payload_size = sizeof(ddcp_query_hdr_t) + 
                (4 * sizeof(DDCP_TLV_ID));

    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)calloc(
                1, ETH_HDR_SIZE_EXCL_PAYLOAD + payload_size);

    ddcp_query_hdr = (ddcp_query_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr);

    inet_pton(AF_INET, NODE_LO_ADDR(node), &addr_int);
    addr_int = htonl(addr_int);

    ddcp_query_hdr->originator_ip = addr_int;
    ddcp_query_hdr->seq_no = ddcp_update_ddcp_db_self_query_info(node);
    ddcp_query_hdr->no_of_tlvs = 4;
    ddcp_query_hdr->tlv_code_points[0] = DDCP_TLV_RTR_NAME;
    ddcp_query_hdr->tlv_code_points[1] = DDCP_TLV_RTR_LO_ADDR;
    ddcp_query_hdr->tlv_code_points[2] = DDCP_TLV_RAM_SIZE;
    ddcp_query_hdr->tlv_code_points[3] = DDCP_TLV_OS_VERSION;

    /*Let src mac be zero*/

    /*Fill Dst mac with Broadcast address*/
    layer2_fill_with_broadcast_mac(ethernet_hdr->dst_mac.mac);
    ethernet_hdr->type = DDCP_MSG_TYPE_FLOOD_QUERY;
    SET_COMMON_ETH_FCS(ethernet_hdr, payload_size, 0);
    if(ddcp_q_interval == 0){
        ddcp_flood_ddcp_query_out(node, (char *)ethernet_hdr, 
                ETH_HDR_SIZE_EXCL_PAYLOAD + payload_size, NULL);
        free(ethernet_hdr);
    }
    else{
        /*Schedule periodic ddcp query firing*/
        wheel_timer_t *wt = node->node_nw_prop.wt;
        assert(wt);

        if((GET_NODE_DDCP_DB(node))->periodic_ddcp_query_wt_elem){
            free(ethernet_hdr);
            printf("Config Aborted : Info : Already Firing ddcp Queries !!\n");
            return;
        }
        ddcp_pkt_meta_data_t ddcp_pkt_meta_data;
        ddcp_pkt_meta_data.node = node;
        ddcp_pkt_meta_data.pkt = (char *)ethernet_hdr;
        ddcp_pkt_meta_data.pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + payload_size;
        
        (GET_NODE_DDCP_DB(node))->periodic_ddcp_query_wt_elem = 
                register_app_event(wt,
                wrapper_ddcp_flood_ddcp_query_out,
                (char *)&ddcp_pkt_meta_data,
                sizeof(ddcp_pkt_meta_data_t),
                ddcp_q_interval,
                1);
    }
}
