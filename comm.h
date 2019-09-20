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

#define MAX_PACKET_BUFFER_SIZE   2048

typedef struct node_ node_t;
typedef struct interface_ interface_t;

/* API to send the packet out of the interface.
 * Nbr node must receieve the packet on other end
 * of the link*/
int
send_pkt_out(char *pkt, unsigned int pkt_size, interface_t *interface);

/*API to recv packet from interface*/
int
pkt_receive(node_t *node, interface_t *interface, 
            char *pkt, unsigned int pkt_size);

/* API to flood the packet out of all interfaces
 * of the node*/
int
send_pkt_flood(node_t *node, char *pkt, unsigned int pkt_size);

#endif /* __COMM__ */
