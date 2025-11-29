#ifndef __RTM_PRIV_API__
#define __RTM_PRIV_API__

#include "rtm_enums.h"
#include <stdbool.h>

typedef struct rtm_ rtm_t;
typedef struct rtm_route_ rtm_route;
typedef struct rtm_nh_ rtm_nh;
typedef struct rtm_prefix_ rtm_prefix_t;
typedef struct node_ node_t;

RTM_AD_T
rtm_get_admin_distance(RTM_PROTO_T proto, RTM_SUB_PROTO_T sub_proto) ;

void
 rtm_route_add_nh_to_route_path_list (rtm_t *rtm, rtm_route *route, rtm_nh *nh);

char *rtm_format_prefix(rtm_prefix_t *prefix, char *buffer, size_t buflen) ;

char* rtm_format_nexthop(rtm_prefix_t *prefix, char *buffer, size_t buflen) ;

rtm_t *rtm_get_by_name (node_t *node, char *rtm_name);

#endif 