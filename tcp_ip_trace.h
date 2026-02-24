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
typedef struct ethernet_hdr_ ethernet_hdr_t;
typedef struct dp_vrf_ dp_vrf_t;

typedef struct log_{

    bool all;
    bool recv;
    bool send;
    bool is_stdout;
    bool l3_fwd;
    char padding[3];
    FILE *log_file;
    access_list_t *acc_lst_filter;
} __attribute__((aligned(8))) log_t;

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
void tcp_ip_de_init_intf_log_info(Interface *intf);
void tcp_ip_set_all_log_info_params(log_t *log_info, bool status);
void tcp_ip_show_log_status(node_t *node);
void tcp_dump_l3_fwding_logger(dp_vrf_t *vrf, c_string oif_name, c_string gw_ip);
void tcp_init_send_logging_buffer(node_t *node);

/* Packet header dump functions */
int tcp_dump_ethernet_hdr(char *buff, ethernet_hdr_t *eth_hdr, pkt_size_t pkt_size);

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

/* Control Plane Debug Logging */




/* Data Path Debug Logging */
#define DARP (1 << 0)
#define DARP_DET (1 << 1)
#define DL3FWD (1 << 2)
#define DL3FWD_DET (1 << 3)
#define DL2FWD (1 << 4)
#define DL2FWD_DET (1 << 5)
#define DRTM (1 << 6)
#define DRTM_DET (1 << 7)
#define DACL (1 << 8)
#define DACL_DET (1 << 9)
#define DIPC (1 << 10)
#define DIPC_DET (1 << 11)
#define DINTF (1 << 12)
#define DINTF_DET (1 << 13)
#define DFLOW (1 << 14)
#define DFLOW_DET (1 << 15)
#define DTUNNEL (1 << 16)
#define DTUNNEL_DET (1 << 17)
#define DL2SW (1 << 18)
#define DL2SW_DET (1 << 19)
#define DTIMER (1 << 20)
#define DTIMER_DET (1 << 21)
#define DMPLS (1 << 22)
#define DMPLS_DET (1 << 23)
#define DFIB (1 << 24)
#define DFIB_DET (1 << 25)
#define DCONF (1 << 26)
#define DALWAYS_FLUSH (1 << 27)
#define DALL_LOGGING (1 << 28)
#define DERR (1 << 29)


#endif /* __TCP_IP_TRACE__ */
