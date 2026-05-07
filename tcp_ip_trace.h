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
#include "libs/BitOp/bitsop.h"
#include "utils.h"
#include "libs/common/protoIds.h"
#include "libs/pkt-block/pkt_block.h"

#define TCP_PRINT_BUFFER_SIZE 1528

typedef struct access_list_  access_list_t;
typedef struct prefix_lst_ prefix_list_t;
typedef struct ethernet_hdr_ ethernet_hdr_t;
typedef struct node_ node_t;
typedef struct dp_intf_ dp_intf_t;

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
tcp_dump(int sock_fd, 
         FILE *log_file1,
         FILE *log_file2,
         pkt_block_t *pkt_block,
         gen_proto_id_t hdr_type,
         c_string out_buff, 
         uint32_t write_OFFset,
         uint32_t out_buff_size);

void 
tcp_write_data(int sock_fd, 
               FILE *log_file1, 
               FILE *log_file2, 
               char *out_buff, 
               uint32_t buff_size);

void tcp_ip_set_all_log_info_params(log_t *log_info, bool status);
void tcp_ip_show_log_status(node_t *node);

/* Packet header dump functions */
int tcp_dump_ethernet_hdr(char *buff, ethernet_hdr_t *eth_hdr, pkt_size_t pkt_size);

extern char tlb[TCP_LOG_BUFFER_LEN];

void
tcp_trace_internal(node_t *node,
               dp_intf_t *interface,
               char *buff, const char *fn, int lineno);

#define tcp_trace(node, intf, buff) \
    tcp_trace_internal(node, intf, buff, __FUNCTION__, __LINE__);

void
tcp_ip_toggle_global_console_logging(void);

void
variadic_sprintf (node_t *node, dp_intf_t *intf, const char *format, ...);

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
#define DREDIS (1 << 26)
#define DREDIS_DET (1 << 27)
#define DCONF (1 << 28)
#define DALWAYS_FLUSH (1 << 29)
#define DALL_LOGGING (1 << 30)
#define DERR (1 << 31)


#endif /* __TCP_IP_TRACE__ */
