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
#include "../router_init.h"
#include "../tcpconst.h"
#include "../gluethread/glthread.h"
#include "layer5.h"
#include "../Layer3/netfilter.h"
#include "../pkt_block.h"
#include "../LinuxMemoryManager/uapi_mm.h"

void
dp2cp_punt_pkt_to_layer5(void *_node,
					uint32_t recv_intf_ifindex, 
					pkt_block_t *pkt_block,
					 hdr_type_t hdr_code) {

	//nf_invoke_netfilter_hook(NF_IP_LOCAL_IN,
	//				pkt_block, node, recv_intf, hdr_code);
}

void
cp_punt_pkt_from_layer2_to_layer5 (
					 void *_node,
					 uint32_t recv_intf_ifindex, 
                     pkt_block_t *pkt_block,
					 hdr_type_t hdr_code) { 

	char *pkt;
	pkt_size_t pkt_size;
	pkt_notif_data_t pkt_notif_data;
	node_t *node = (node_t *)_node;
	pkt_notif_data.recv_node = node;
	pkt_notif_data.recv_intf_index = recv_intf_ifindex;
	pkt_notif_data.pkt_block = pkt_block;
	pkt_notif_data.hdr_code = hdr_code;

	pkt = (char *)pkt_block_get_pkt(pkt_notif_data.pkt_block, &pkt_size);

	nfc_invoke_notif_chain(
			EV(node),
			&node->dp_ctx->layer2_proto_reg_db,
			(void *)&pkt_notif_data,
			sizeof(pkt_notif_data_t),
			pkt, pkt_size,
            TASK_PRIORITY_PKT_PROCESSING);
}

void
tcp_stack_register_l2_pkt_trap_rule(
		notif_chain_t *nfc,
		nfc_pkt_trap pkt_trap_cb,
		nfc_app_cb app_cb) {

	notif_chain_elem_t nfce_template;

	memset(&nfce_template, 0, sizeof(notif_chain_elem_t));
	nfce_template.is_key_set = false;
	nfce_template.app_cb = app_cb;
	nfce_template.pkt_trap_cb = pkt_trap_cb;	
	init_glthread(&nfce_template.glue);

	nfc_register_notif_chain(nfc, &nfce_template);	
}


void
tcp_stack_de_register_l2_pkt_trap_rule(
		notif_chain_t *nfc,
		nfc_pkt_trap pkt_trap_cb,
		nfc_app_cb app_cb) {

	notif_chain_elem_t nfce_template;

	memset(&nfce_template, 0, sizeof(notif_chain_elem_t));
	nfce_template.is_key_set = false;
	nfce_template.app_cb = app_cb;
	nfce_template.pkt_trap_cb = pkt_trap_cb;	
	init_glthread(&nfce_template.glue);

	nfc_de_register_notif_chain(nfc, &nfce_template);	
}

extern void *
netfilter_pkt_notif_data_dup_fn (void *arg);
extern void
tcp_ip_register_default_l2_pkt_trap_rules(notif_chain_t *nfc);

void
init_nfc_layer2_proto_reg_db2(notif_chain_t *nfc) {

		string_copy((char *)nfc->nfc_name,
			"L2 proto registration db",
			strlen("L2 proto registration db") + 1);

		nfc->preprocessing_fn_ptr = NULL;
		nfc->copy_arg_fn_ptr = netfilter_pkt_notif_data_dup_fn;
		tcp_ip_register_default_l2_pkt_trap_rules(nfc);
}

