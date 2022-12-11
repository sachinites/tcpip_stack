/*
 * =====================================================================================
 *
 *       Filename:  route_map.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  05/16/2022 01:45:19 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */
#include <stdint.h>
#include <stdbool.h>
#include "../../gluethread/glthread.h"

#define RMAP_MAX_NAME_LENGTH 64
class Interface;

/*
 * Client processes that make use of of route-maps library
 */
typedef enum route_map_client_type {
    ROUTE_MAP_CLIENT_BLOB,
    ROUTE_MAP_CLIENT_ROUTING_PROC,
    ROUTE_MAP_CLIENT_NAT,
    ROUTE_MAP_CLIENT_PBR,
    ROUTE_MAP_CLIENT_MAX
} route_map_client_type;

typedef enum {
    /*
     * IPV4
     */
    PBR_ROUTE_MAP_DF_SET                = 0x00000001,
    PBR_ROUTE_MAP_DSCP_SET              = 0x00000002,
    PBR_ROUTE_MAP_NEXT_HOP_VERIFY_TRACK = 0x00000004,
    PBR_ROUTE_MAP_NEXT_HOP_SET          = 0x00000008,
    PBR_ROUTE_MAP_GATEWAY_SET           = 0x00000010,
    PBR_ROUTE_MAP_DEFAULT_NEXT_HOP_SET  = 0x00000020,
    PBR_ROUTE_MAP_INTERFACE_SET         = 0x00000040,
    PBR_ROUTE_MAP_DEFAULT_INTERFACE_SET = 0x00000080,
    /*
     * IPV6
     */
    PBR_ROUTE_MAP_IPV6_NH_SET           = 0x00000100,
    PBR_ROUTE_MAP_IPV6_DEFAULT_NH_SET   = 0x00000200,
    PBR_ROUTE_MAP_IPV6_DSCP_SET         = 0x00000400,
    PBR_ROUTE_MAP_ADAPTIVE_INTERFACE_SET= 0x00000800,
    PBR_ROUTE_MAP_IPV6_GATEWAY_SET      = 0x00001000,
} np_pbr_set_flags_t;

typedef struct route_map_client_entry_ {
    struct route_map_client_entry_ *next;
    route_map_client_type          type;
    int  refcnt;
} route_map_client_entry;

typedef struct access_list_ access_list_t;

typedef struct route_map_matchtype_ {
    uint32_t		      match_flags;
    access_list_t       *ip_address;
} route_map_matchtype;

typedef struct route_map_interface_ {
    Interface                      *idb;      /* Valid on RP, NULL on LC */
    uint32_t                        if_number; /* fib uses this, both on RP/LC*/
    struct route_maptype_       *map;      /* back ptr */
    bool is_cost;           /* adaptive_interface cost set*/
    uint32_t cost;
} route_map_interface;

typedef struct route_map_settype_ {
    uint64_t            set_flags;
    route_map_interface  *adaptive_interface[8];
}  route_map_settype;

/* This is a DP structure used by traffic in DP */ 
typedef struct np_pbr_action_t_ {
    bool permit;
    unsigned char rmap_name[RMAP_MAX_NAME_LENGTH];
    np_pbr_set_flags_t set_flags;
    glthread_t adaptive_interface; /* list of adaptive interfaces configured */
    rmeifc_set_t *pbra_ris;
} np_pbr_action_t;

typedef struct pbr_np_action_ {
    np_pbr_action_t *np_action;
    int ref_count;
} pbr_np_action_t;

typedef struct route_map_headtype_ {
    unsigned char   map_tag[RMAP_MAX_NAME_LENGTH];   /* Name of the route-map */
    glthread_t  map_queue;            /* Glue into the linked list */
    uint32_t    match_flags;            /* bit map for match criteria */
    uint64_t    set_flags;                 /* bit map for actions */
    route_map_client_entry *client_list;  /* List of clients interested in this route-map updates */
    route_map_matchtype   match_list;   /* Stores all type of matches */
    route_map_settype     set_list;          /* Stores all types of actions */
    bool grant;                                          /* route-map permit or deny */
    pbr_np_action_t       *np_action;       /* Actions translated into a form that could be installed in DP */
} route_map_headtype_t;
GLTHREAD_TO_STRUCT(map_queue_to_route_map, route_map_headtype_t, map_queue );
