/*
 * =====================================================================================
 *
 *       Filename:  tcp_ip_trace.h
 *
 *    Description:  This file declares the routines for tracing
 *
 *        Version:  1.0
 *        Created:  06/24/2020 08:09:39 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Juniper Networks (https://csepracticals.wixsite.com/csepracticals), sachinites@gmail.com
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
 *        visit website : https://csepracticals.wixsite.com/csepracticals for more courses and projects
 *                                  
 * =====================================================================================
 */

#ifndef __TCP_IP_TRACE__
#define __TCP_IP_TRACE__

#include <stdio.h>  /* for FILE* */
#include "BitOp/bitsop.h"

typedef struct node_ node_t;
typedef struct interface_ interface_t;

typedef enum{

    ETH_HDR,
    IP_HDR
} hdr_type_t;

#define TCP_PRINT_BUFFER_SIZE 1024

typedef struct log_{

    bool_t all;
    bool_t recv;
    bool_t send;
    bool_t is_stdout;
    bool_t l3_fwd;
    FILE *log_file;
} log_t;

void 
tcp_dump_recv_logger(node_t *node, interface_t *intf, 
              char *pkt, uint32_t pkt_size,
              hdr_type_t hdr_type);

void 
tcp_dump_send_logger(node_t *node, interface_t *intf,
              char *pkt, uint32_t pkt_size,
              hdr_type_t hdr_type);

void tcp_ip_init_node_log_info(node_t *node);
void tcp_ip_init_intf_log_info(interface_t *intf);
void tcp_ip_set_all_log_info_params(log_t *log_info, bool_t status);
void tcp_ip_show_log_status(node_t *node);
void tcp_dump_l3_fwding_logger(node_t *node, char *oif_name, char *gw_ip);
void tcp_init_send_logging_buffer(node_t *node);

#define TCP_GET_NODE_SEND_LOG_BUFFER(node)  \
    (node->node_nw_prop.send_log_buffer)
#endif /* __TCP_IP_TRACE__ */
