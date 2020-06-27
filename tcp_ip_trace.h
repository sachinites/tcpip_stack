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

#include "BitOp/bitsop.h"

typedef struct node_ node_t;
typedef struct interface_ interface_t;

typedef enum{

    ETH_HDR,
    IP_HDR
} hdr_type_t;

typedef struct log_{

    #define ALL_F       0
    bool_t all;
    #define RECV_F      (1 << 1)
    bool_t recv;
    #define SEND_F      (1 << 2)
    bool_t send;
    #define STDOUT_F    (1 << 3)
    bool_t is_stdout;
    #define LOGFILE_F   (1 << 4)
    FILE *log_file;
} log_t;

static inline void
tcp_stack_set_traceoptions(log_t *dst_log, log_t *src_log, uint32_t flags){

    if(IS_BIT_SET(flags, ALL_F))
        dst_log->all = src_log->all;

    if(IS_BIT_SET(flags, RECV_F))
        dst_log->recv = src_log->recv;

    if(IS_BIT_SET(flags, SEND_F))
        dst_log->send = src_log->send;

    if(IS_BIT_SET(flags, STDOUT_F))
        dst_log->is_stdout = src_log->is_stdout;

    if(IS_BIT_SET(flags, LOGFILE_F)){
        if(dst_log->log_file) fclose(dst_log->log_file);
        dst_log->log_file = src_log->log_file;
    }
}

void 
tcp_dump_recv(node_t *node, interface_t *intf, 
              char *pkt, uint32_t pkt_size,
              hdr_type_t hdr_type);

void 
tcp_dump_send(node_t *node, interface_t *intf,
              char *pkt, uint32_t pkt_size,
              hdr_type_t hdr_type);

void tcp_ip_init_node_log_info(node_t *node);
void tcp_ip_init_intf_log_info(interface_t *intf);

#endif /* __TCP_IP_TRACE__ */
