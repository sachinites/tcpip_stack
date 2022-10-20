/*
 * =====================================================================================
 *
 *       Filename:  layer3.h
 *
 *    Description:  This file defines the routines for Layer 3
 *
 *        Version:  1.0
 *        Created:  Tuesday 24 September 2019 01:17:56  IST
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

#ifndef __LAYER3__
#define __LAYER3__

#include <stdint.h>
#include <stdbool.h>
#include "../gluethread/glthread.h"
#include "../notif.h"
#include "../tcpconst.h"
#include "../EventDispatcher/event_dispatcher.h"
#include "../mtrie/mtrie.h"
#include "../LinuxMemoryManager/uapi_mm.h"

#pragma pack (push,1)

/*The Ip hdr format as per the standard specification*/
typedef struct ip_hdr_{

    uint32_t version : 4 ;  /*version number, always 4 for IPv4 protocol*/    
    uint32_t ihl : 4 ;      /*length of IP hdr, in 32-bit words unit. for Ex, if this value is 5, it means length of this ip hdr is 20Bytes*/
    char tos;
    short total_length;         /*length of hdr + ip_hdr payload*/

    /* Fragmentation Related members, we shall not be using below members
     * as we will not be writing fragmentation code. if you wish, take it
     * as a extension of the project*/
    short identification;       
    uint32_t unused_flag : 1 ;
    uint32_t DF_flag : 1;   
    uint32_t MORE_flag : 1; 
    uint32_t frag_offset : 13;  

    char ttl;
    char protocol;
    short checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ip_hdr_t;

#pragma pack(pop)

static inline void
initialize_ip_hdr(ip_hdr_t *ip_hdr){
    
    ip_hdr->version = 4;
    ip_hdr->ihl = 5; /*We will not be using option field, hence hdr size shall always be 5*4 = 20B*/
    ip_hdr->tos = 0;

    ip_hdr->total_length = 0; /*To be filled by the caller*/

    /*Fragmentation related will not be used
     * int this course, initialize them all to zero*/
    ip_hdr->identification = 0; 
    ip_hdr->unused_flag = 0;
    ip_hdr->DF_flag = 1;
    ip_hdr->MORE_flag = 0;
    ip_hdr->frag_offset = 0;

    ip_hdr->ttl = 64; /*Let us use 64*/
    ip_hdr->protocol = 0; /*To be filled by the caller*/
    ip_hdr->checksum = 0; /*Not used in this course*/
    ip_hdr->src_ip = 0; /*To be filled by the caller*/ 
    ip_hdr->dst_ip = 0; /*To be filled by the caller*/
}
#define IP_HDR_DEFAULT_SIZE 20
#define IP_HDR_LEN_IN_BYTES(ip_hdr_ptr)  (ip_hdr_ptr->ihl * 4)
#define IP_HDR_TOTAL_LEN_IN_BYTES(ip_hdr_ptr)   (ip_hdr_ptr->total_length * 4)
#define INCREMENT_IPHDR(ip_hdr_ptr) ((char *)ip_hdr_ptr + (ip_hdr_ptr->ihl * 4))
#define IP_HDR_PAYLOAD_SIZE(ip_hdr_ptr) (IP_HDR_TOTAL_LEN_IN_BYTES(ip_hdr_ptr) - \
        IP_HDR_LEN_IN_BYTES(ip_hdr_ptr))
#define IP_HDR_COMPUTE_DEFAULT_TOTAL_LEN(ip_payload_size)  \
    (5 + (short)(ip_payload_size/4) + (short)((ip_payload_size % 4) ? 1 : 0))

typedef struct prefix_lst_ prefix_list_t;

typedef struct rt_table_{

    mtrie_t route_list;
	bool is_active;
    notif_chain_t nfc_rt_updates;
    glthread_t rt_notify_list_head;
    glthread_t rt_flash_list_head;
    task_t *notif_job;
    task_t *flash_job;
    node_t *node;
    prefix_list_t *import_policy;
    prefix_list_t *export_policy;
    glthread_t flash_request_list_head;
    pthread_rwlock_t rwlock;
} rt_table_t;

#define nexthop_node_name(nexthop_ptr)  \
   ((get_nbr_node(nexthop_ptr->oif))->node_name)

#define RT_ADD_F        (1 << 0)
#define RT_DEL_F         (1 << 1)
#define RT_UPDATE_F (1 << 2)
#define RT_FLASH_REQ_F (1 << 3)

typedef enum {
    proto_nxthop_first,
    proto_nxthop_isis = proto_nxthop_first,
    proto_nxthop_static,
    proto_nxthop_max
} nxthop_proto_id_t;

#define FOR_ALL_NXTHOP_PROTO(nh_proto)  \
    for (nh_proto = proto_nxthop_first; nh_proto < proto_nxthop_max; nh_proto++)

static inline nxthop_proto_id_t
l3_rt_map_proto_id_to_nxthop_index(uint8_t proto_id) {

    switch(proto_id) {
        case PROTO_STATIC:
            return proto_nxthop_static;
        case PROTO_ISIS:
            return proto_nxthop_isis;
        default:
        ;
    }
    return proto_nxthop_max;
}

#define RT_F_PROTO_STATIC   1
#define RT_F_PROTO_ISIS         2

typedef struct l3_route_{

    char dest[16];        /* key*/
    char mask;            /* key*/
    bool is_direct;       /* if set to True, then gw_ip and oif has no meaning*/
    nexthop_t *nexthops[proto_nxthop_max][MAX_NXT_HOPS];
    uint32_t spf_metric[proto_nxthop_max];
    uint16_t nh_count;
    int nxthop_idx;
	time_t install_time;
    uint8_t rt_flags;
    glthread_t notif_glue;
    glthread_t flash_glue;
    uint8_t ref_count;
} l3_route_t;
GLTHREAD_TO_STRUCT(notif_glue_to_l3_route, l3_route_t, notif_glue);
GLTHREAD_TO_STRUCT(flash_glue_to_l3_route, l3_route_t, flash_glue);

#define RT_UP_TIME(l3_route_ptr)	\
	hrs_min_sec_format((unsigned int)difftime(time(NULL), l3_route_ptr->install_time))

static inline void
l3_route_lock (l3_route_t *l3_route) {

    l3_route->ref_count++;
}

bool
l3_is_direct_route(l3_route_t *l3_route);

static inline void
l3_route_free(l3_route_t *l3_route){

    /* Assume the route has already been removed from main routing table */
    nxthop_proto_id_t nxthop_proto_id;
    assert(l3_route->ref_count == 0);
    assert(IS_GLTHREAD_LIST_EMPTY(&l3_route->notif_glue));
    assert(IS_GLTHREAD_LIST_EMPTY(&l3_route->flash_glue));
    FOR_ALL_NXTHOP_PROTO(nxthop_proto_id) {
        nh_flush_nexthops(l3_route->nexthops[nxthop_proto_id]);
    }
    XFREE(l3_route);
}

static inline void
l3_route_unlock (l3_route_t *l3_route) {

    if (l3_route->ref_count == 0) {
        l3_route_free(l3_route);
        return;
    }

    l3_route->ref_count--;
    if (l3_route->ref_count > 0) return;
    l3_route_free(l3_route);
}

nexthop_t *
l3_route_get_active_nexthop(l3_route_t *l3_route);

/* Routing Table APIs */
void
init_rt_table(node_t *node, rt_table_t **rt_table);

/* MP Safe */
void
clear_rt_table(rt_table_t *rt_table, uint16_t proto);

/* MP Safe */
void
rt_table_delete_route(rt_table_t *rt_table, c_string ip_addr, char mask, uint16_t proto_id);

/* MP Safe */
void
rt_table_add_route(rt_table_t *rt_table, 
                   const char *dst, char mask,
                   const char *gw, 
                   interface_t *oif,
                   uint32_t spf_metric,
                   uint8_t proto_id);

/* MP Safe */
void
rt_table_add_direct_route(rt_table_t *rt_table,
                                          const char *dst,
                                          char mask);

/* MP Safe */
void
dump_rt_table(rt_table_t *rt_table);

/* MP Unsafe */
l3_route_t *
l3rib_lookup_lpm(rt_table_t *rt_table,
                 uint32_t dest_ip);

/* MP Unsafe */
l3_route_t *
l3rib_lookup(rt_table_t *rt_table, uint32_t dest_ip, char mask);

/* MP Unsafe */
l3_route_t *
rt_table_lookup_exact_match(rt_table_t *rt_table, c_string ip_addr, char mask);

/* Routing Table APIs */

void
tcp_ip_send_ip_data(node_t *node, char *app_data, uint32_t data_size,
                    int L5_protocol_id, uint32_t dest_ip_address);


/* config of Layer 3 properties of interface*/
void
interface_set_ip_addr(node_t *node, interface_t *intf,  char *intf_ip_addr, uint8_t mask);

void
interface_unset_ip_addr(node_t *node, interface_t *intf, char *intf_ip_addr, uint8_t mask);

#endif /* __LAYER3__ */
