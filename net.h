/*
 * =====================================================================================
 *
 *       Filename:  net.h
 *
 *    Description:  This file contains all definitions for structures required for network programming
 *
 *        Version:  1.0
 *        Created:  Wednesday 18 September 2019 08:24:35  IST
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

#ifndef __NET__
#define __NET__

#include <stdlib.h>
#include <memory.h>
#include <stdint.h>
#include <netinet/in.h>
#include <assert.h>
#include <pthread.h>
#include "utils.h"
#include "LinuxMemoryManager/uapi_mm.h"
#include "libtimer/WheelTimer.h"
#include "Tree/libtree.h"
#include "comm.h"
#include "tcpconst.h"
#include "tcp_ip_trace.h"

/*Do not #include Layer2/layer2.h*/

typedef struct graph_ graph_t;
class Interface;
typedef struct node_ node_t;

#pragma pack (push,1)
typedef struct ip_add_ {
    unsigned char ip_addr[16];
} ip_add_t;

typedef struct mac_addr_ {
    unsigned char mac[6];
} mac_addr_t;
#pragma pack(pop)

/*Forward Declaration*/
typedef struct arp_table_ arp_table_t;
typedef struct mac_table_ mac_table_t;
typedef struct rt_table_ rt_table_t;
typedef struct ddcp_db_ ddcp_db_t;
typedef struct nmp_ nmp_t;
typedef struct stp_node_ stp_node_info_t;

typedef struct node_nw_prop_{

    uint32_t flags;

    /*L2 Properties*/
    arp_table_t *arp_table;
    mac_table_t *mac_table;

    rt_table_t *rt_table;

    ddcp_db_t *ddcp_db;
	stp_node_info_t *stp_node_info;

    /*L3 properties*/ 
    bool is_lb_addr_config;
    ip_add_t lb_addr; /*loopback address of node*/

    /*Sending Buffer*/
    c_string send_log_buffer; /*Used for logging */
    /* Receiving Buffer */ 
    c_string recv_log_buffer; /* Used for logging */
    /* Main Log Buffer*/
    c_string log_buffer;
    /* FILE Ptr to main logigng file File*/
    FILE *log_file;
    /*Device level Appln DS*/
    nmp_t *nmp;
    void *isis_node_info;

	/* Traffic generation */
	glthread_t traffic_gen_db_head;
} node_nw_prop_t;

extern void init_arp_table(arp_table_t **arp_table);
extern void init_mac_table(mac_table_t **mac_table);
extern void init_rt_table(node_t *node, rt_table_t **rt_table);
extern void rt_table_set_active_status(rt_table_t *rt_table, bool active);
extern void stp_init_stp_node_info(stp_node_info_t **stp_node_info);
extern void init_tcp_logging(node_t *);

static inline void
init_node_nw_prop(node_t *node, node_nw_prop_t *node_nw_prop) {

    node_nw_prop->flags = 0;
    node_nw_prop->is_lb_addr_config = false;
    memset(node_nw_prop->lb_addr.ip_addr, 0, 16);
    init_arp_table(&(node_nw_prop->arp_table));
    init_mac_table(&(node_nw_prop->mac_table));
    init_rt_table(node, &(node_nw_prop->rt_table));
	//stp_init_stp_node_info(&(node_nw_prop->stp_node_info));
    node_nw_prop->send_log_buffer = (c_string)calloc(1, TCP_PRINT_BUFFER_SIZE);
    node_nw_prop->recv_log_buffer = (c_string)calloc(1, TCP_PRINT_BUFFER_SIZE);
    node_nw_prop->log_buffer =  (c_string)calloc(1, TCP_LOG_BUFFER_LEN);
    init_tcp_logging(node);
	init_glthread(&(node_nw_prop->traffic_gen_db_head));
}

extern void
snp_flow_init_flow_tree_root(avltree_t *avl_root) ;

#define NODE_LO_ADDR(node_ptr) (node_ptr->node_nw_prop.lb_addr.ip_addr)
#define NODE_ARP_TABLE(node_ptr)    (node_ptr->node_nw_prop.arp_table)
#define NODE_MAC_TABLE(node_ptr)    (node_ptr->node_nw_prop.mac_table)
#define NODE_RT_TABLE(node_ptr)     (node_ptr->node_nw_prop.rt_table)
#define NODE_FLAGS(node_ptr)        (node_ptr->node_nw_prop.flags)
#define NODE_LO_ADDR_INT(node_ptr) (tcp_ip_covert_ip_p_to_n(NODE_LO_ADDR(node_ptr)))
#define NODE_LOG_FILE(node_ptr) (node_ptr->node_nw_prop.log_file)
#define NODE_LOG_BUFF(node_ptr) (node_ptr->node_nw_prop.log_buffer)

#define NODE_GET_TRAFFIC_GEN_DB_HEAD(node_ptr)	\
	(&node_ptr->node_nw_prop.traffic_gen_db_head)
#define IF_GET_FLOW_DB(intf_ptr) \
    (&((intf_ptr)->intf_nw_props.flow_avl_root))

/*APIs to set Network Node properties*/
bool node_set_loopback_address(node_t *node, const char *ip_addr);
void node_set_intf_ip_address(node_t *node, const char *local_if, const char *ip_addr, char mask);

/*Dumping Functions to dump network information
 * on nodes and interfaces*/
void dump_nw_graph(graph_t *graph, node_t *node);
void dump_node_nw_props(node_t *node);
void dump_node_interface_stats(node_t *node);
void dump_interface_stats(Interface *interface);


/*Helper Routines*/
Interface *
node_get_matching_subnet_interface(node_t *node, c_string ip_addr);

bool
is_same_subnet(c_string ip_addr,
               char mask,
               c_string other_ip_addr);

byte *
pkt_buffer_shift_right(byte *pkt, uint32_t pkt_size,
                               uint32_t total_buffer_size);

static inline byte *
tcp_ip_get_new_pkt_buffer(uint32_t pkt_size){

    byte *pkt = (byte *)XCALLOC_BUFF(0, MAX_PACKET_BUFFER_SIZE);
    return pkt_buffer_shift_right(pkt, pkt_size, MAX_PACKET_BUFFER_SIZE);
}

static inline void
tcp_ip_free_pkt_buffer(byte *pkt, uint32_t pkt_size){

    XFREE(pkt - (MAX_PACKET_BUFFER_SIZE - pkt_size - PKT_BUFFER_RIGHT_ROOM));
}

/*Macros to Iterate over Nbrs of a node*/
void interface_assign_mac_address(Interface *interface);

#define ITERATE_NODE_NBRS_BEGIN(node_ptr, nbr_ptr, oif_ptr, ip_addr) \
    do{                                                                  \
        int i = 0 ;                                                      \
        Interface *other_intf;                                         \
        for( i = 0 ; i < MAX_INTF_PER_NODE; i++){                        \
            oif_ptr = node_ptr->intf[i];                                 \
            if(!oif_ptr) continue;                                       \
            other_intf = oif_ptr->GetOtherInterface();      \
            if(!other_intf) continue;                                    \
            nbr_ptr = oif_ptr->GetNbrNode ();                 \
            ip_addr = IF_IP(other_intf);                      \

#define ITERATE_NODE_NBRS_END(node_ptr, nbr_ptr, oif_ptr, ip_addr)  }}while(0);

#define EV(node_ptr)    (&node_ptr->ev_dis)
#define EV_DP(node_ptr) (&node_ptr->dp_ev_dis)
#define EV_PURGER(node_ptr) (&node->purger_ev_dis)
#define DP_PKT_Q(node_ptr) (&node_ptr->dp_recvr_pkt_q)
#define CP_TIMER(node_ptr)  (node_ptr->cp_wt)
#define DP_TIMER(node_ptr)  (node_ptr->dp_wt)

#endif /* __NET__ */
