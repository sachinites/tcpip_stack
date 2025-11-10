#ifndef __RTM_ROUTE__
#define __RTM_ROUTE__
#pragma pack(push, 8)

#include <stdint.h>
#include <stdbool.h>
#include "../gluethread/glthread.h"
#include "../Tree/libtree.h"
#include "rtm.h"
#include "rtm_enums.h"
#include "rtm_common.h"
#include "rtm_error.h"
#include "rtm_nh.h"

typedef struct rtm_route_ {

        /* List of Nexthops of this route*/
        glthread_t path_list;

        /* List of loost of nexthops pending to be resolved by this route,
        list of lnh_list_t objects */
        glthread_t unresolved_paths;

        /* List of nexthops resolved by this route, list of lnh_list_t */
        glthread_t resolved_paths;

        /* Glues */
        /* Glue in RTM main tree */
        avltree_node_t route_glue;
        /* Glue in FIB Tree */
        avltree_node_t fib_glue;

        /* Prefix for this route */
        rtm_prefix_t prefix;

        uint16_t flags;

        /* Number of nexthops */
        uint16_t nh_count;

        uint32_t ref_count;

} rtm_route;

#pragma pack(pop)

/* Methods */
void rtm_route_initialize(rtm_route *route);

bool rtm_validate_with_route(rtm_t *rtm, rtm_prefix_t *prefix);

/* Route Mgmt Functions */
rtm_route *rtm_route_lookup(const rtm_t *rtm, rtm_prefix_t *prefix_key);
rtm_error_t rtm_route_add(const rtm_t *rtm, rtm_route *route);
rtm_error_t rtm_route_remove(const rtm_t *rtm, rtm_prefix_t *prefix_key);

/* Nexthop Mgmt*/
rtm_nh *rtm_route_lookup_nh(rtm_route *route, rtm_nh *nh_template);
rtm_error_t rtm_route_add_nh(rtm_t *rtm, rtm_route *route, rtm_nh *nh);
rtm_error_t remove_nh(rtm_route *route, rtm_nh *nh);

void rtm_route_reference(rtm_route *route);
void rtm_route_dereference(rtm_route *route);

#endif