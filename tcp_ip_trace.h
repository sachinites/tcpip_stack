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

#ifndef __TCP_IP_TRACE__
#define __TCP_IP_TRACE__

#include <stdio.h>  /* for FILE* */
#include "tcpconst.h"
#include "BitOp/bitsop.h"
#include "utils.h"

typedef struct node_ node_t;
class Interface;
typedef struct pkt_block_ pkt_block_t;

#define TCP_PRINT_BUFFER_SIZE 1528

typedef struct access_list_  access_list_t;
typedef struct prefix_lst_ prefix_list_t;

typedef struct log_{

    bool all;
    bool recv;
    bool send;
    bool is_stdout;
    bool l3_fwd;
    FILE *log_file;
    access_list_t *acc_lst_filter;
} log_t;

void 
tcp_dump_recv_logger(node_t *node, Interface *intf, 
              pkt_block_t *pkt_block,
              hdr_type_t hdr_type);

void 
tcp_dump_send_logger(node_t *node, Interface *intf,
              pkt_block_t *pkt_block,
              hdr_type_t hdr_type);

void tcp_ip_init_node_log_info(node_t *node);
void tcp_ip_init_intf_log_info(Interface *intf);
void tcp_ip_set_all_log_info_params(log_t *log_info, bool status);
void tcp_ip_show_log_status(node_t *node);
void tcp_dump_l3_fwding_logger(node_t *node, c_string oif_name, c_string gw_ip);
void tcp_init_send_logging_buffer(node_t *node);

#define TCP_GET_NODE_SEND_LOG_BUFFER(node)  \
    (node->node_nw_prop.send_log_buffer)
#define TCP_GET_NODE_RECV_LOG_BUFFER(node)  \
    (node->node_nw_prop.recv_log_buffer)

extern char tlb[TCP_LOG_BUFFER_LEN];

void
tcp_trace_internal(node_t *node,
               Interface *interface,
               char *buff, const char *fn, int lineno);

#define tcp_trace(node, intf, buff) \
    tcp_trace_internal(node, intf, buff, __FUNCTION__, __LINE__);

void
tcp_ip_toggle_global_console_logging(void);

void
variadic_sprintf (node_t *node, Interface *intf, const char *format, ...);

#endif /* __TCP_IP_TRACE__ */
