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

#include "utils.h"
//include "Layer2/layer2.h"
#include <memory.h>

/* Device IDS */
#define L3_ROUTER   (1 << 0)
#define L2_SWITCH   (1 << 1)
#define HUB         (1 << 2)
#define IP_LEN 16
#define MAC_LEN  6
#define IS_INTF_L3_MODE(intf_ptr) (intf_ptr -> intf_nw_props.is_ipadd_config)

typedef struct graph_ graph_t;
typedef struct interface_ interface_t;
typedef struct node_ node_t;


typedef struct ip_add_ {
    char ip_addr[IP_LEN];
} ip_add_t;

typedef struct mac_add_ {
    unsigned char mac[MAC_LEN];
} mac_add_t;

typedef enum{

    ACCESS,
    TRUNK,
    L2_MODE_UNKNOWN
}intf_l2_mode_t;

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

typedef struct arp_table_ arp_table_t;
typedef struct mac_table_ mac_table_t;
typedef struct node_nw_prop_{

    /* Used to find various device types capabilities of
     * the node and other features*/
    unsigned int flags;

    /* L2 properties */ 
    arp_table_t *arp_table;
    mac_table_t *mac_table;

    /*L3 properties*/ 
    bool_t is_lb_addr_config;
    ip_add_t lb_addr; /*loopback address of node*/
} node_nw_prop_t;

#define NODE_ARP_TABLE(node_ptr) (node_ptr->node_nw_prop.arp_table)
#define NODE_MAC_TABLE(node_ptr) (node_ptr->node_nw_prop.mac_table)
extern void
init_arp_table(arp_table_t **arp_table);
static inline void
init_node_nw_prop(node_nw_prop_t *node_nw_prop) {

    node_nw_prop->flags = 0;
    node_nw_prop-> is_lb_addr_config = FALSE;
    memset(node_nw_prop->lb_addr.ip_addr, 0, IP_LEN);
    init_arp_table(&(node_nw_prop -> arp_table));
}

typedef struct intf_nw_props_ {

    /*L2 properties*/
    mac_add_t mac_add;      /*Mac are hard burnt in interface NIC*/
    intf_l2_mode_t intf_l2_mode;

    /*L3 properties*/
    bool_t is_ipadd_config; /*Set to TRUE if ip add is configured, intf operates in L3 mode if ip address is configured on it*/
    ip_add_t ip_add;
    char mask;
} intf_nw_props_t;


static inline void
init_intf_nw_prop(intf_nw_props_t *intf_nw_props) {

    memset(intf_nw_props->mac_add.mac , 0 , MAC_LEN);
    intf_nw_props->is_ipadd_config = FALSE;
    memset(intf_nw_props->ip_add.ip_addr, 0, IP_LEN);
    intf_nw_props->mask = 0;
}

void
interface_assign_mac_address(interface_t *interface);

/*GET shorthand Macros*/
#define IF_MAC(intf_ptr)   ((intf_ptr)->intf_nw_props.mac_add.mac)
#define IF_IP(intf_ptr)    ((intf_ptr)->intf_nw_props.ip_add.ip_addr)

#define NODE_LO_ADDR(node_ptr) (node_ptr->node_nw_prop.lb_addr.ip_addr)

/*APIs to set Network Node properties*/
bool_t node_set_device_type(node_t *node, unsigned int F);
bool_t node_set_loopback_address(node_t *node, char *ip_addr);
bool_t node_set_intf_ip_address(node_t *node, char *local_if, char *ip_addr, char mask);
bool_t node_unset_intf_ip_address(node_t *node, char *local_if);


interface_t *
node_get_matching_subnet_interface(node_t *node, char *ip_addr);



/*Dumping Functions to dump network information
 * on nodes and interfaces*/
void dump_nw_graph(graph_t *graph);
void dump_node_nw_props(node_t *node);
void dump_intf_props(interface_t *interface);
  
unsigned int
convert_ip_from_str_to_int(char *ip_addr);
void
convert_ip_from_int_to_str(unsigned int ip_addr, char *output_buffer);

/* Shift the data to the right side of the pkt and return the pointer to the data */
char *
pkt_buffer_shift_right(char *pkt, unsigned int pkt_size, unsigned int total_buffer_size);

#endif /* __NET__ */
