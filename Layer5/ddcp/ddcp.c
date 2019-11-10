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
ddcp_flood_ddcp_query_out(char *pkt,
        unsigned int pkt_size,
        interface_t *exempted_intf){

    interface_t *intf = NULL;
    node_t *node = exempted_intf->att_node;

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
    serialize_uint8(ser_buff, DDCP_MSG_TYPE_UCAST_REPLY);

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
                ;
        }
    }

    if(is_serialized_buffer_empty(ser_buff))
        return NULL;

    copy_buffer = calloc(1, get_serialize_buffer_size(ser_buff));
    if(!copy_buffer){
        printf("Error : Memory alloc failed\n");
        free_serialize_buffer(ser_buff);
        return NULL;
    }
    memcpy(copy_buffer, ser_buff->b, get_serialize_buffer_size(ser_buff));
    *output_buff_len = (unsigned int)get_serialize_buffer_size(ser_buff);
    free_serialize_buffer(ser_buff);
    ser_buff = NULL;
    return copy_buffer;
}

static void
ddcp_print_ddcp_reply_msg(char *pkt, 
                          unsigned int pkt_size){

     char *tlv_ptr;
     char type, length;
     char ddcp_msg_type = pkt[0];
     
     char *start_ptr = pkt + 1;
     
     assert(ddcp_msg_type == DDCP_MSG_TYPE_UCAST_REPLY);

     ITERATE_TLV_BEGIN(start_ptr, type, length, tlv_ptr, 
                (pkt_size - sizeof(char))){

        switch(type){
            case DDCP_TLV_RTR_NAME:
                printf("T : DDCP_TLV_RTR_NAME, L : %d, V : %s\n", 
                    length, tlv_ptr);
                break;
            case DDCP_TLV_RTR_LO_ADDR:
                printf("T : DDCP_TLV_RTR_LO_ADDR, L : %d, V : %s\n",
                    length, tlv_ptr);
                break;
            case DDCP_TLV_RAM_SIZE:
            {
                unsigned int ram_size = *((unsigned int *)tlv_ptr);
                printf("T : DDCP_TLV_RAM_SIZE, L : %d, V : %u\n",
                    length, ram_size);
            }
            break;
            case DDCP_TLV_OS_VERSION:
                printf("T : DDCP_TLV_OS_VERSION, L : %d, V : %s\n",
                    length, tlv_ptr);
                break;
            case DDCP_TLV_MAX:
                assert(0);
            default:
                ;
        }
    } ITERATE_TLV_END(start_ptr, type, length, tlv_ptr,
                (pkt_size - sizeof(char)));

}


void
ddcp_process_ddcp_hdr(node_t *node, interface_t *iif, 
                      ethernet_hdr_t *ethernet_hdr, 
                      unsigned int pkt_size){

    char protocol;
    char ddcp_msg_type;
    char *ddcp_reply_msg = NULL;
    unsigned int output_buff_len = 0;
   
    char *ddcp_msg = GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr);
    ddcp_msg_type = ddcp_msg[0];

    unsigned int ddcp_msg_len = pkt_size - \
        GET_ETH_HDR_SIZE_EXCL_PAYLOAD(ethernet_hdr);

    switch(ddcp_msg_type){
        case DDCP_MSG_TYPE_FLOOD_QUERY:
            ddcp_reply_msg = ddcp_process_ddcp_query(
                                node, 
                                (ddcp_query_hdr_t *)ddcp_msg, 
                                &output_buff_len);

            if(!ddcp_reply_msg || !output_buff_len){
                printf("DDCP Reply msg Could not be prepared\n");
                return;
            }
            ddcp_flood_ddcp_query_out((char *)ethernet_hdr, pkt_size, iif);
            protocol = DDCP_MSG;
            demote_packet_to_layer3(node, ddcp_reply_msg, 
                                    output_buff_len, protocol,
                                    ((ddcp_query_hdr_t *)ddcp_msg)->originator_ip);
            break;
        case DDCP_MSG_TYPE_UCAST_REPLY:
            ddcp_print_ddcp_reply_msg(ddcp_msg, ddcp_msg_len);
            break;
        default:
            ;
    }
}
