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
#include "../pkt_block.h"

#pragma pack (push,1)

typedef struct ref_count_  * ref_count_t;
class Interface;
typedef struct nexthop_ nexthop_t;

typedef struct prefix_lst_ prefix_list_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct node_ node_t;

typedef struct rt_table_{

    mtrie_t route_list;
    notif_chain_t nfc_rt_updates;
    glthread_t rt_notify_list_head;
    glthread_t rt_flash_list_head;
    task_t *notif_job;
    task_t *flash_job;
    node_t *node;
    prefix_list_t *import_policy;
    prefix_list_t *export_policy;
    glthread_t flash_request_list_head;
    bool is_active;
} __attribute__((aligned(8)))  rt_table_t;

#define RT_ADD_F        (1 << 0)
#define RT_DEL_F         (1 << 1)
#define RT_UPDATE_F (1 << 2)
#define RT_FLASH_REQ_F (1 << 3)

static inline char *
RT_FLAGS_STR (uint8_t flags, char *buffer, uint16_t buffer_size) {

    memset (buffer, 0, buffer_size);

    if (flags & RT_ADD_F) {
        strcat(buffer, "ADD_F ");
    }

    if (flags & RT_DEL_F) {
        strcat(buffer, "DEL_F ");
    }

    if (flags & RT_UPDATE_F) {
        strcat(buffer, "UPDATE_F ");
    }

    if (flags & RT_FLASH_REQ_F) {
        strcat(buffer, "FLASH_REQ_F ");
    }

    return buffer;
}

/* If you are changing the order of these enums, pls 
    change the next fn also ...*/
typedef enum {

    proto_nxthop_first,
    proto_nxthop_static = proto_nxthop_first,
    proto_nxthop_srv6, // pref 14
    proto_nxthop_isis_srv6,
    proto_nxthop_isis, // pref 15
    proto_nxthop_max

} nxthop_proto_id_t;

static inline  nxthop_proto_id_t
next_next_hop_proto ( nxthop_proto_id_t proto_id ) {

    switch (proto_id) {

        case proto_nxthop_static:
            return proto_nxthop_srv6;
        case proto_nxthop_srv6:
            return proto_nxthop_isis_srv6;
        case proto_nxthop_isis_srv6:
            return proto_nxthop_isis;
        case proto_nxthop_isis:
            return proto_nxthop_max;
        case proto_nxthop_max:
            assert(0);
            return proto_nxthop_max;
    }
    return proto_nxthop_max;
}

static inline  nxthop_proto_id_t
next_next_hop_first ( void ) {

    return proto_nxthop_first;
}

#define FOR_ALL_NXTHOP_PROTO(nh_proto)  \
    for (nh_proto =proto_nxthop_first; nh_proto < proto_nxthop_max; \
         nh_proto = next_next_hop_proto(nh_proto))

static inline nxthop_proto_id_t
l3_rt_map_proto_id_to_nxthop_index(uint16_t proto_id) {

    switch(proto_id) {

        case PROTO_STATIC:
            return proto_nxthop_static;
        case PROTO_ISIS:
            return proto_nxthop_isis;
        case PROTO_SRv6:
            return proto_nxthop_srv6;
        case PROTO_ISIS_SRv6:
            return proto_nxthop_isis_srv6;
        default:
        ;
    }
    return proto_nxthop_max;
}

static inline int
l3_rt_map_nxthop_index_proto_std(uint16_t proto_index) {

    switch(proto_index) {
        case proto_nxthop_static:
            return PROTO_STATIC;
        case proto_nxthop_isis:
            return PROTO_ISIS;
        case proto_nxthop_srv6:
            return PROTO_SRv6;
        case proto_nxthop_isis_srv6:
            return PROTO_ISIS_SRv6;
        default:
        ;
    }
    return PROTO_ANY;
}

#define proto_index_to_str(proto_index) \
    (proto_name_str (l3_rt_map_nxthop_index_proto_std (proto_index)))

#define RT_F_PROTO_STATIC   1
#define RT_F_PROTO_ISIS         2

typedef struct l3_route_{

    byte dest[16];        /* key*/
    char mask;            /* key*/
    uint8_t rt_flags;
    bool is_direct;       /* if set to True, then gw_ip and oif has no meaning*/
    char padding1[1];
    uint16_t nh_count;
    char padding2[2];
    nexthop_t *nexthops[proto_nxthop_max][MAX_NXT_HOPS];
    uint32_t spf_metric[proto_nxthop_max];
    int nxthop_idx;
    time_t install_time;
    char padding3[4];
    glthread_t notif_glue;
    glthread_t flash_glue;
    uint32_t rt_ref_count;
} __attribute__((aligned(8))) l3_route_t;

GLTHREAD_TO_STRUCT(notif_glue_to_l3_route, l3_route_t, notif_glue);
GLTHREAD_TO_STRUCT(flash_glue_to_l3_route, l3_route_t, flash_glue);

#define RT_UP_TIME(l3_route_ptr, buff, size)	\
	hrs_min_sec_format((unsigned int)difftime(time(NULL), \
        l3_route_ptr->install_time), buff, size)

l3_route_t * l3_route_get_new_route () ;
void l3_route_free(l3_route_t *l3_route);

uint32_t
l3_route_dec_ref_count ( l3_route_t *l3_route) ;

void 
l3_route_inc_ref_count ( l3_route_t *l3_route);

bool
l3_is_direct_route(l3_route_t *l3_route);

nexthop_t *
l3_route_get_active_nexthop(l3_route_t *l3_route, dp_intf_t *exclude_oif);

/* Routing Table APIs */
void
init_rt_table(node_t *node, rt_table_t **rt_table);
void
init_rtv6_table(node_t *node, rt_table_t **rt_table);

/* MP Safe */
void
clear_rt_table(rt_table_t *rt_table, uint16_t proto);

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

/* Routing Table APIs */
void
rt_table_perform_app_operation_on_routes (
                            rt_table_t *rt_table, 
                            void (*app_cbk) (mtrie_t *, mtrie_node_t *, void *));

void layer3_ip_route_pkt(dp_ctx_t *dp_ctx,
                         dp_vrf_t *vrf,
                         dp_intf_t *interface,
                         pkt_block_t *pkt_block);

void
np_tcp_ip_send_ip_data (dp_ctx_t *dp_ctx, dp_vrf_t *vrf, pkt_block_t *pkt_block);

#endif /* __LAYER3__ */
