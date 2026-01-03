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
#include <stdatomic.h>
#include <atomic>
#include "common/cmn_struct.h"
#include "utils.h"
#include "LinuxMemoryManager/uapi_mm.h"
#include "libtimer/WheelTimer.h"
#include "Tree/libtree.h"
#include "comm.h"
#include "tcpconst.h"
#include "tcp_ip_trace.h"
#include "Interface/InterfaceFwd.h"

/*Do not #include Layer2/layer2.h*/

typedef struct graph_ graph_t;
typedef struct node_ node_t;

/*Forward Declaration*/
typedef struct arp_table_ arp_table_t;
typedef struct mac_table_ mac_table_t;
typedef struct rt_table_ rt_table_t;
typedef struct mpls_rt_table_ mpls_rt_table_t;
typedef struct ddcp_db_ ddcp_db_t;
typedef struct stp_node_ stp_node_info_t;
typedef struct srv6_node_info_ srv6_node_info_t ;
typedef struct srv6_sid_pools_ srv6_sid_pools_t;
typedef struct lfa_ lfa_t;

/* VLAN-VNI Mapping Structure */
/* Forward declaration for VLAN-VNI mapping structures */
typedef struct vxlan_vni_db_ vxlan_vni_db_t;
typedef struct vlan_vni_ht_db_ vlan_vni_ht_db_t;
typedef struct rtm_ rtm_t;
typedef struct fib_ fib_t;
typedef struct def_vrf_ def_vrf_t;

typedef struct node_nw_prop_{

    uint32_t flags;

    /*L2 Properties*/
    arp_table_t *arp_table;
    mac_table_t *mac_table;
    vxlan_vni_db_t *vlan_vni_db;                            /* VLAN-VNI mapping database */
    std::atomic<vlan_vni_ht_db_t *> vlan_vni_ht;   /* VLAN-VNI hashtable for O(1) lookup - atomic pointer */
    NVEInterfaceP nve;
    mac_addr_t rmac;
    char padding[2];

    rt_table_t *rt_table;
    rt_table_t *ipv6_rt_table;
    mpls_rt_table_t *mpls_rt_table;
    rt_table_t *ipv4_mpls_rt_table;

    /* Default VRF containing all RIBs and FIBs */
    def_vrf_t *def_vrf;

    ddcp_db_t *ddcp_db;
	stp_node_info_t *stp_node_info;

    /* Shared Rmac Interface shared across all SVIs in the system*/
    InterfaceP rmac_interface;
    /* Virtual port which represents flood in a vlan */
    InterfaceP vlan_flood_interface;

    /* lo ipv6 addr*/
    uint8_t ipv6_addr[16];

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
    void *isis_node_info;
    void *ldp_node_info;
    /* LFA module*/
    lfa_t *lfa;
    /* Device level SRV6 info */
    srv6_node_info_t *srv6_node_info;

    /* Global pools of SRv6 SIDs */
   srv6_sid_pools_t  *srv6_sid_pools;

} node_nw_prop_t;

#define NODE_LO_ADDR(node_ptr) (node_ptr->node_nw_prop.lb_addr.ip_addr)
#define NODE_ARP_TABLE(node_ptr)    (node_ptr->node_nw_prop.arp_table)
#define NODE_MAC_TABLE(node_ptr)    (node_ptr->node_nw_prop.mac_table)
#define NODE_VLAN_VNI_DB(node_ptr)  (node_ptr->node_nw_prop.vlan_vni_db)
#define NODE_RT_TABLE(node_ptr)     (node_ptr->node_nw_prop.rt_table)
#define NODE_IPV4_MPLS_RT_TABLE(node_ptr)     (node_ptr->node_nw_prop.ipv4_mpls_rt_table)
#define NODE_V6RT_TABLE(node_ptr)     (node_ptr->node_nw_prop.ipv6_rt_table)
#define NODE_MPLS_RT_TABLE(node_ptr)     (node_ptr->node_nw_prop.mpls_rt_table)
#define NODE_FLAGS(node_ptr)        (node_ptr->node_nw_prop.flags)
#define NODE_LO_ADDR_INT(node_ptr) (tcp_ip_convert_ip_p_to_n(NODE_LO_ADDR(node_ptr)))
#define NODE_LOG_FILE(node_ptr) (node_ptr->node_nw_prop.log_file)
#define NODE_LOG_BUFF(node_ptr) (node_ptr->node_nw_prop.log_buffer)
#define NODE_SRv6_SID_POOL(node_ptr) (node_ptr->node_nw_prop.srv6_sid_pools)
#define NODE_RMAC(node_ptr)      (&node_ptr->node_nw_prop.rmac) 
#define NODE_RMAC_INTF(node_ptr)    (node_ptr->node_nw_prop.rmac_interface)
#define NODE_VLAN_FLOOD_INTF(node_ptr) (node_ptr->node_nw_prop.vlan_flood_interface)
#define NODE_NVE_INTF(node_ptr) (node_ptr->node_nw_prop.nve)
#define NODE_GET_TRAFFIC_GEN_DB_HEAD(node_ptr)	\
	(&node_ptr->node_nw_prop.traffic_gen_db_head)
#define INTF_VRF_ID(intf_ptr) (intf_ptr->vrf ? intf_ptr->vrf->vrf_id : 0)

/*APIs to set Network Node properties*/
bool node_set_loopback_address(node_t *node, const char *ip_addr);
void node_set_v6_loopback_address(node_t *node, const char *ipv6_addr );
void node_set_intf_ip_address(node_t *node, const char *local_if, const char *ip_addr, char mask);

/*Dumping Functions to dump network information
 * on nodes and interfaces*/
void dump_nw_graph(graph_t *graph, node_t *node);
void dump_node_nw_props(node_t *node);
void dump_node_interface_stats(node_t *node);
void dump_interface_stats_header();
void dump_interface_stats(Interface *interface);


/*Helper Routines*/
Interface *
node_get_matching_subnet_interface(node_t *node, c_string ip_addr);

bool
is_same_subnet(c_string ip_addr,
               char mask,
               c_string other_ip_addr);

extern int 
cprintf(const char *format, ...);

static inline byte *
tcp_ip_get_new_pkt_buffer(uint32_t pkt_size){

    if (pkt_size > (MAX_PACKET_BUFFER_SIZE - PKT_BUFFER_RIGHT_ROOM)) return NULL;
    byte *pkt = (byte *)XCALLOC_BUFF(0, MAX_PACKET_BUFFER_SIZE);
    return pkt + MAX_PACKET_BUFFER_SIZE - (pkt_size + PKT_BUFFER_RIGHT_ROOM);
}

static inline void
tcp_ip_free_pkt_buffer(byte *pkt, uint32_t pkt_size){

    XFREE(pkt - (MAX_PACKET_BUFFER_SIZE - pkt_size - PKT_BUFFER_RIGHT_ROOM));
}


void interface_assign_mac_address (Interface *interface);

/*Macros to Iterate over Nbrs of a node*/
#define ITERATE_NODE_NBRS_BEGIN(node_ptr, nbr_ptr, oif_ptr, ip_addr)        \
    do{                                                                      \
        Interface *other_intf;                                               \
        if (node_ptr->intf_by_name) {                                        \
            for (auto _it = node_ptr->intf_by_name->begin();                \
                 _it != node_ptr->intf_by_name->end(); _it++) {              \
                oif_ptr = _it->second.get();                                 \
                if(!oif_ptr) continue;                                       \
                other_intf = oif_ptr->GetOtherInterface();                   \
                if(!other_intf) continue;                                    \
                nbr_ptr = oif_ptr->GetNbrNode ();                            \
                ip_addr = IF_IP(other_intf);

#define ITERATE_NODE_NBRS_END(node_ptr, nbr_ptr, oif_ptr, ip_addr)          \
            }                                                                \
        }                                                                    \
    }while(0);

#define EV(node_ptr)    (&node_ptr->ev_dis)
#define EV_DP(node_ptr) (&node_ptr->dp_ev_dis)
#define EV_PURGER(node_ptr) (&node->purger_ev_dis)
#define DP_PKT_Q(node_ptr) (&node_ptr->dp_recvr_pkt_q)
#define CP_TIMER(node_ptr)  (node_ptr->cp_wt)
#define DP_TIMER(node_ptr)  (node_ptr->dp_wt)

#endif /* __NET__ */
