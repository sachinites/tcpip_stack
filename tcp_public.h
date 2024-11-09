/*
 * =====================================================================================
 *
 *       Filename:  tcp_public.h
 *
 *    Description:  This file contains routines and structures which should be exposed to the application for use
 *
 *        Version:  1.0
 *        Created:  05/30/2020 11:13:54 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Juniper Networks (www.csepracticals.com), sachinites@gmail.com
 *        Company:  Juniper Networks
 *
 *        This file is part of the TCP/IP Stack distribution (https://github.com/sachinites) 
 *        Copyright (c) 2019 Abhishek Sagar.
 *        This program is XFREE software: you can redistribute it and/or modify it under the terms of the GNU General 
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

#ifndef __TCP_IP_STACK__
#define __TCP_IP_STACK__

#include <ncurses.h>
#include <pthread.h>
#include "gluethread/glthread.h"
#include "libtimer/WheelTimer.h"
#include "Tree/libtree.h"
#include "EventDispatcher/event_dispatcher.h"
#include "LinuxMemoryManager/uapi_mm.h"
#include "CLIBuilder/libcli.h"
#include "stack/stack.h"
#include "mtrie/mtrie.h"
#include "BitOp/bitmap.h"
#include "BitOp/bitsop.h"
#include "Threads/refcount.h"
#include "c-hashtable/hashtable.h"
#include "c-hashtable/hashtable_itr.h"
#include "FireWall/acl/acldb.h"
#include "prefix-list/prefixlst.h"
#include "PostgresLibpq/postgresLib.h"
#include "Tracer/tracer.h"

/* stdandard pkt headers hdr files*/
#include "common/cmn_struct.h"
#include "common/l3_hdrs.h"
#include "common/l2_hdrs.h"
#include "common/cp2dp.h"

#include "tcpconst.h"
#include "graph.h"
#include "Interface/InterfaceUApi.h"
#include "net.h"
#include "Layer2/layer2.h"
#include "Layer2/arp.h"
#include "Layer3/rt_table/nexthop.h"
#include "Layer3/layer3.h"
#include "Layer3/rt_notif.h"
#include "Layer4/udp.h"
#include "Layer5/layer5.h"
#include "utils.h"
#include "comm.h"
#include "tcp_ip_trace.h"
#include "cmdcodes.h"
#include "Layer5/app_handlers.h"
#include "tcpip_notif.h"
#include "Layer3/netfilter.h"
#include "ted/ted.h"
#include "pkt_block.h"

extern void
display_node_interfaces(param_t *param, ser_buff_t *tlv_buf);

extern void
display_graph_nodes(param_t *param, ser_buff_t *tlv_buf);

extern void
cli_out(unsigned char *buff, size_t buff_size);

extern graph_t * topo;
extern char tlb[TCP_LOG_BUFFER_LEN];

typedef unsigned char byte;
typedef unsigned char uchar_t;
typedef wheel_timer_elem_t timer_event_handle;

#endif /* __TCP_IP_STACK__ */
