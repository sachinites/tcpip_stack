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
#include "libtimer/WheelTimer.h"
#include "comm.h"
#include "tcpconst.h"
#include "tcp_ip_trace.h"

/*Do not #include Layer2/layer2.h*/

typedef struct graph_ graph_t;
typedef struct interface_ interface_t;
typedef struct node_ node_t;

#pragma pack (push,1)
typedef struct ip_add_ {
    unsigned char ip_addr[16];
} ip_add_t;

typedef struct mac_add_ {
    unsigned char mac[6];
} mac_add_t;
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

    /*Timer Properties*/
    wheel_timer_t *wt;

    /*Sending Buffer*/
    char *send_log_buffer; /*Used for logging */

    /*Device level Appln DS*/
    nmp_t *nmp;

	/* Traffic generation */
	glthread_t traffic_gen_db_head;
} node_nw_prop_t;

extern void init_arp_table(arp_table_t **arp_table);
extern void init_mac_table(mac_table_t **mac_table);
extern void init_rt_table(rt_table_t **rt_table);
extern void rt_table_set_active_status(rt_table_t *rt_table, bool active);
extern void stp_init_stp_node_info(stp_node_info_t **stp_node_info);

static inline void
init_node_nw_prop(node_nw_prop_t *node_nw_prop) {

    node_nw_prop->flags = 0;
    node_nw_prop->is_lb_addr_config = false;
    memset(node_nw_prop->lb_addr.ip_addr, 0, 16);
    init_arp_table(&(node_nw_prop->arp_table));
    init_mac_table(&(node_nw_prop->mac_table));
    init_rt_table(&(node_nw_prop->rt_table));
	//stp_init_stp_node_info(&(node_nw_prop->stp_node_info));
    node_nw_prop->wt = init_wheel_timer(60, 1, TIMER_SECONDS);
    start_wheel_timer(node_nw_prop->wt);
    node_nw_prop->send_log_buffer = calloc(1, TCP_PRINT_BUFFER_SIZE);
	init_glthread(&(node_nw_prop->traffic_gen_db_head));
}

typedef enum{

    ACCESS,
    TRUNK,
    L2_MODE_UNKNOWN
} intf_l2_mode_t;

static inline char *
intf_l2_mode_str(intf_l2_mode_t intf_l2_mode){

    switch(intf_l2_mode){
        case ACCESS:
            return "access";
        case TRUNK:
            return "trunk";
        default:
            return "L2_MODE_UNKNWON";
    }
}

#define MAX_VLAN_MEMBERSHIP 10

typedef struct ddcp_interface_prop_ ddcp_interface_prop_t;
typedef struct intf_nmp_ intf_nmp_t;
typedef struct stp_vlan_intf_info_ stp_vlan_intf_info_t;

typedef struct intf_nw_props_ {

    /*L1 Properties*/
    bool is_up;
	uint32_t ifindex;

    /*L2 properties*/
    mac_add_t mac_add;              /*Mac are hard burnt in interface NIC*/
    intf_l2_mode_t  intf_l2_mode;   /*if IP-address is configured on this interface, then this should be set to UNKNOWN*/
    uint32_t vlans[MAX_VLAN_MEMBERSHIP];    /*If the interface is operating in Trunk mode, it can be a member of these many vlans*/
    bool is_ipadd_config_backup;
    ddcp_interface_prop_t *ddcp_interface_prop;
    intf_nmp_t *nmp;
	stp_vlan_intf_info_t *stp_vlan_intf_info;
    /*L3 properties*/
    bool is_ipadd_config; 
    ip_add_t ip_add;
    char mask;

    /*Interface Statistics*/
    uint32_t pkt_recv;
    uint32_t pkt_sent;
	uint32_t xmit_pkt_dropped;
} intf_nw_props_t;

typedef union intf_prop_changed_ {

        uint32_t intf_metric;
        struct {
            uint32_t ip_addr;
            uint8_t mask;
        } ip_addr;
        bool up_status; /* True for up, false for down */
        intf_l2_mode_t intf_l2_mode;
        uint32_t vlan;
} intf_prop_changed_t;

extern void
init_ddcp_interface_props(ddcp_interface_prop_t **ddcp_interface_prop);

static inline void
init_intf_nw_prop(intf_nw_props_t *intf_nw_props) {

    /*L1 properties*/
    intf_nw_props->is_up = true;
	intf_nw_props->ifindex = get_new_ifindex();

    /*L2 properties*/
    memset(intf_nw_props->mac_add.mac , 0 , 
        sizeof(intf_nw_props->mac_add.mac));
    intf_nw_props->intf_l2_mode = L2_MODE_UNKNOWN;
    memset(intf_nw_props->vlans, 0, sizeof(intf_nw_props->vlans));

    /*L3 properties*/
    intf_nw_props->is_ipadd_config = false;
    memset(intf_nw_props->ip_add.ip_addr, 0, 16);
    intf_nw_props->mask = 0;

    /*Interface Statistics*/
    intf_nw_props->pkt_recv = 0;
    intf_nw_props->pkt_sent = 0;
	intf_nw_props->xmit_pkt_dropped = 0;
}

void
interface_assign_mac_address(interface_t *interface);

/*GET shorthand Macros*/
#define IF_MAC(intf_ptr)   ((intf_ptr)->intf_nw_props.mac_add.mac)
#define IF_IP(intf_ptr)    ((intf_ptr)->intf_nw_props.ip_add.ip_addr)
#define IF_IP_EXIST(intf_ptr) ((intf_ptr)->intf_nw_props.is_ipadd_config)
#define IF_MASK(intf_ptr)  ((intf_ptr)->intf_nw_props.mask)
#define IF_IS_UP(intf_ptr) ((intf_ptr)->intf_nw_props.is_up == true)
#define IF_INDEX(intf_ptr) ((intf_ptr)->intf_nw_props.ifindex)

#define NODE_LO_ADDR(node_ptr) (node_ptr->node_nw_prop.lb_addr.ip_addr)
#define NODE_ARP_TABLE(node_ptr)    (node_ptr->node_nw_prop.arp_table)
#define NODE_MAC_TABLE(node_ptr)    (node_ptr->node_nw_prop.mac_table)
#define NODE_RT_TABLE(node_ptr)     (node_ptr->node_nw_prop.rt_table)
#define NODE_FLAGS(node_ptr)        (node_ptr->node_nw_prop.flags)
#define IF_L2_MODE(intf_ptr)    (intf_ptr->intf_nw_props.intf_l2_mode)
#define IS_INTF_L2_MODE(intf_ptr)                                  \
    (intf_ptr->intf_nw_props.intf_l2_mode == ACCESS ||      \
    intf_ptr->intf_nw_props.intf_l2_mode == TRUNK)

#define IS_INTF_L3_MODE(intf_ptr)   (intf_ptr->intf_nw_props.is_ipadd_config == true)
#define NODE_GET_TRAFFIC_GEN_DB_HEAD(node_ptr)	\
	(&node_ptr->node_nw_prop.traffic_gen_db_head)

/*APIs to set Network Node properties*/
bool node_set_loopback_address(node_t *node, char *ip_addr);
bool node_set_intf_ip_address(node_t *node, char *local_if, char *ip_addr, char mask);
bool node_unset_intf_ip_address(node_t *node, char *local_if);


/*Dumping Functions to dump network information
 * on nodes and interfaces*/
void dump_nw_graph(graph_t *graph, node_t *node);
void dump_node_nw_props(node_t *node);
void dump_intf_props(interface_t *interface);
void dump_node_interface_stats(node_t *node);
void dump_interface_stats(interface_t *interface);

/*Helper Routines*/
interface_t *
node_get_matching_subnet_interface(node_t *node, char *ip_addr);

bool
is_same_subnet(char *ip_addr, char mask,
               char *other_ip_addr);

/*Interface Vlan mgmt APIs*/

/*Should be Called only for interface operating in Access mode*/
uint32_t
get_access_intf_operating_vlan_id(interface_t *interface);
/*Should be Called only for interface operating in Trunk mode*/

bool
is_trunk_interface_vlan_enabled(interface_t *interface, uint32_t vlan_id);  

char *
pkt_buffer_shift_right(char *pkt, uint32_t pkt_size,
                               uint32_t total_buffer_size);

static inline char *
tcp_ip_get_new_pkt_buffer(uint32_t pkt_size){

    char *pkt = calloc(1, MAX_PACKET_BUFFER_SIZE);
    return pkt_buffer_shift_right(pkt, pkt_size, MAX_PACKET_BUFFER_SIZE);
}

static inline void
tcp_ip_free_pkt_buffer(char *pkt, uint32_t pkt_size){

    free(pkt - (MAX_PACKET_BUFFER_SIZE - pkt_size - PKT_BUFFER_RIGHT_ROOM));
}

bool
is_interface_l3_bidirectional(interface_t *interface);


/* Interface Change Flags, used for Notification to 
 * Applications*/
#define IF_UP_DOWN_CHANGE_F         (1 << 0)
#define IF_IP_ADDR_CHANGE_F         (1 << 1)
#define IF_OPER_MODE_CHANGE_F       (1 << 2)
#define IF_VLAN_MEMBERSHIP_CHANGE_F (1 << 3)
#define IF_METRIC_CHANGE_F          (1 << 4)

/*Macros to Iterate over Nbrs of a node*/

#define ITERATE_NODE_NBRS_BEGIN(node_ptr, nbr_ptr, oif_ptr, ip_addr_ptr) \
    do{                                                                  \
        int i = 0 ;                                                      \
        interface_t *other_intf;                                         \
        for( i = 0 ; i < MAX_INTF_PER_NODE; i++){                        \
            oif_ptr = node_ptr->intf[i];                                 \
            if(!oif_ptr) continue;                                       \
            other_intf = &oif_ptr->link->intf1 == oif_ptr ?              \
            &oif_ptr->link->intf2 : &oif_ptr->link->intf1;               \
            if(!other_intf) continue;                                    \
            nbr_ptr = get_nbr_node(oif_ptr);                             \
            ip_addr_ptr = IF_IP(other_intf);                             \

#define ITERATE_NODE_NBRS_END(node_ptr, nbr_ptr, oif_ptr, ip_addr_ptr)  }}while(0);

wheel_timer_t *
node_get_timer_instance(node_t *node);

#endif /* __NET__ */
