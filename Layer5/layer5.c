/*
 * =====================================================================================
 *
 *       Filename:  Layer5.c
 *
 *    Description:  This file represents the application making use of our virtual TCP/IP stack
 *
 *        Version:  1.0
 *        Created:  Thursday 26 September 2019 07:48:10  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *        
 *        This file is part of the TCP/IP Stack distribution (https://github.com/sachinites).
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

#include <stdio.h>
#include <stdint.h>
#include "graph.h"
#include "../tcpconst.h"
#include "../gluethread/glthread.h"
#include "layer5.h"
#include "ddcp/ddcp.h"

static notif_chain_t layer2_proto_reg_db2 = {
	"L2 proto registration db",
	{0, 0}
};

static notif_chain_t layer3_proto_reg_db2 = {
	"L3 proto registration db",
	{0, 0}
};

static void
layer5_invoke_app_cb(node_t *node,
					 interface_t *recv_intf, 
                     char *l5_hdr, /*Application Data*/
                     uint32_t pkt_size, 
                     uint32_t L5_protocol,
                     uint32_t flags){

	pkt_notif_data_t pkt_notif_data;

	pkt_notif_data.recv_node = node;
	pkt_notif_data.recv_interface = recv_intf;
	pkt_notif_data.pkt = l5_hdr;
	pkt_notif_data.pkt_size = pkt_size;
	pkt_notif_data.flags = flags;	
	pkt_notif_data.protocol_no = L5_protocol;

	nfc_invoke_notif_chain(&layer2_proto_reg_db2,
			(void *)&pkt_notif_data,
			sizeof(pkt_notif_data_t),
			(char *)&L5_protocol, 
			sizeof(L5_protocol));
	nfc_invoke_notif_chain(&layer3_proto_reg_db2,
			(void *)&pkt_notif_data,
			sizeof(pkt_notif_data_t),
			(char *)&L5_protocol, 
			sizeof(L5_protocol));
}

void
promote_pkt_to_layer5(node_t *node, interface_t *recv_intf,
        char *l5_hdr, uint32_t pkt_size,
        uint32_t L5_protocol, uint32_t flags){

    switch(L5_protocol){
        case USERAPP1:
            break;
#if 0
        case DDCP_MSG_TYPE_UCAST_REPLY:
           ddcp_process_ddcp_reply_msg(node, l5_hdr);
            break;
        case DDCP_MSG_TYPE_FLOOD_QUERY:
           ddcp_process_ddcp_query_msg(node, recv_intf, (ethernet_hdr_t *)l5_hdr, pkt_size);
           break;
#endif
        default:
            layer5_invoke_app_cb(node, recv_intf, 
                l5_hdr, pkt_size, L5_protocol, flags);
            ;
    }
}

void
tcp_app_register_l2_protocol_interest(uint32_t L5_protocol, 
                                nfc_app_cb app_layer_cb){

	notif_chain_elem_t nfce_template;
	
	memset(&nfce_template, 0, sizeof(notif_chain_elem_t));

	memcpy(&nfce_template.key, (char *)&L5_protocol, sizeof(L5_protocol));

	nfce_template.key_size = sizeof(L5_protocol);
	nfce_template.is_key_set = TRUE;
	nfce_template.app_cb = app_layer_cb;
	init_glthread(&nfce_template.glue);

	nfc_register_notif_chain(&layer2_proto_reg_db2,
		&nfce_template);
}

void
tcp_app_register_l3_protocol_interest(uint32_t L5_protocol, 
                                nfc_app_cb app_layer_cb){

	notif_chain_elem_t nfce_template;
	
	memset(&nfce_template, 0, sizeof(notif_chain_elem_t));

	memcpy(&nfce_template.key, (char *)&L5_protocol, sizeof(L5_protocol));

	nfce_template.key_size = sizeof(L5_protocol);

	nfce_template.is_key_set = TRUE;
	nfce_template.app_cb = app_layer_cb;
	init_glthread(&nfce_template.glue);

	nfc_register_notif_chain(&layer3_proto_reg_db2,
		&nfce_template);
}

