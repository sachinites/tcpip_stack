/*
 * =====================================================================================
 *
 *       Filename:  layer5.h
 *
 *    Description:  This file decines the structures and routines for Application LAyer
 *
 *        Version:  1.0
 *        Created:  05/30/2020 11:09:53 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Juniper Networks (www.csepracticals.com), sachinites@gmail.com
 *        Company:  Juniper Networks
 *
 *        This file is part of the TCP/IP Stack distribution (https://github.com/sachinites) 
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

#ifndef __LAYER5__
#define __LAYER5__

#include "../tcpconst.h"
#include "../tcpip_notif.h"

typedef struct node_ node_t;
class Interface;
typedef struct pkt_block_ pkt_block_t;

typedef struct pkt_notif_data_{

	node_t *recv_node;
	Interface *recv_interface;
	pkt_block_t *pkt_block;
	hdr_type_t hdr_code;
	int8_t return_code;
} pkt_notif_data_t;

void
cp_punt_promote_pkt_from_layer2_to_layer5(
					 node_t *node,
					  Interface *recv_intf,
        			  pkt_block_t *pkt_block,
					  hdr_type_t hdr_code);

void
promote_pkt_from_layer3_to_layer5(node_t *node,
					  Interface *recv_intf,
        			  pkt_block_t *pkt_block,
					  hdr_type_t hdr_code);

void
tcp_stack_register_l2_pkt_trap_rule(
		node_t *node,
        nfc_pkt_trap pkt_trap_cb,
        nfc_app_cb app_cb);

void
tcp_stack_de_register_l2_pkt_trap_rule(
		node_t *node,
        nfc_pkt_trap pkt_trap_cb,
        nfc_app_cb app_cb);

#endif /* __LAYER5__ */
