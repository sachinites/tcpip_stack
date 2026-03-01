/*
 * =====================================================================================
 *
 *       Filename:  comm.h
 *
 *    Description:  This file defines the structures to setup communication between 
 *    nodes of the topology
 *
 *        Version:  1.0
 *        Created:  Thursday 19 September 2019 10:26:16  IST
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

#ifndef __COMM__
#define __COMM__

#include <stdint.h>
#include "utils.h"
#include "tcpconst.h"

typedef struct node_ node_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct dp_vrf_ dp_vrf_t;

int
dp_inject_packet (dp_ctx_t *dp_ctx, pkt_block_t *pkt_block, dp_intf_t *interface);

/*API to recv packet from interface*/
void
dp_pkt_receive(dp_ctx_t *dp_ctx,
               dp_vrf_t *vrf,
               dp_intf_t *interface,
               pkt_block_t *pkt_block);

/* API to flood the packet out of all interfaces
 * of the node*/
int
send_pkt_flood(dp_ctx_t *dp_ctx,
               dp_intf_t *exempted_intf, 
               pkt_block_t *pkt_block);

#endif /* __COMM__ */
