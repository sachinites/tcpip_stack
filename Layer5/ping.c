/*
 * =====================================================================================
 *
 *       Filename:  ping.c
 *
 *    Description:  This file implements the application ping
 *
 *        Version:  1.0
 *        Created:  11/16/2019 06:42:53 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Juniper Networks (https://csepracticals.wixsite.com/csepracticals), sachinites@gmail.com
 *        Company:  Juniper Networks
 *
 *        This file is part of the NetworkGraph distribution (https://github.com/sachinites) 
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

/* This fn sends a dummy packet to test L3 and L2 routing
 * in the project. We send dummy Packet starting from Network
 * Layer on node 'node' to destination address 'dst_ip_addr'
 * using below fn*/

#include "../graph.h"
#include "../Layer3/layer3.h"
#include "../gluethread/glthread.h"
#include "tcpconst.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h> /*for AF_INET*/
#include <arpa/inet.h>  /*for inet_pton and inet_ntop*/

extern void
demote_packet_to_layer3(node_t *node,
        char *pkt, unsigned int size,
        int protocol_number,
        unsigned int dest_ip_address);

void
layer5_ping_fn(node_t *node, char *dst_ip_addr){

    unsigned int addr_int;

    printf("Src node : %s, Ping ip : %s\n", node->node_name, dst_ip_addr);

    inet_pton(AF_INET, dst_ip_addr, &addr_int);
    addr_int = htonl(addr_int);

    /* We dont have any application or transport layer paylod, so, directly prepare
     * L3 hdr*/
    demote_packet_to_layer3(node, NULL, 0, ICMP_PRO, addr_int);
}

void
layer3_ero_ping_fn(node_t *node, char *dst_ip_addr,
        char *ero_ip_address){

    /*Prepare the payload and push it down to the network layer.
     *      The payload shall be inner ip hdr*/
    ip_hdr_t *inner_ip_hdr = calloc(1, sizeof(ip_hdr_t));
    initialize_ip_hdr(inner_ip_hdr);
    inner_ip_hdr->total_length = sizeof(ip_hdr_t)/4;
    inner_ip_hdr->protocol = ICMP_PRO;

    unsigned int addr_int = 0;
    inet_pton(AF_INET, NODE_LO_ADDR(node), &addr_int);
    addr_int = htonl(addr_int);
    inner_ip_hdr->src_ip = addr_int;

    addr_int = 0;
    inet_pton(AF_INET, dst_ip_addr, &addr_int);
    addr_int = htonl(addr_int);
    inner_ip_hdr->dst_ip = addr_int;

    addr_int = 0;
    inet_pton(AF_INET, ero_ip_address, &addr_int);
    addr_int = htonl(addr_int);

    demote_packet_to_layer3(node, (char *)inner_ip_hdr,
            inner_ip_hdr->total_length * 4,
            IP_IN_IP, addr_int);
    free(inner_ip_hdr);
}

