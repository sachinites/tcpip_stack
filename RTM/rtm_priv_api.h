#ifndef __RTM_PRIV_API__
#define __RTM_PRIV_API__

#include "rtm_enums.h"

typedef struct rtm_ rtm_t;
typedef struct rtm_route_ rtm_route;
typedef struct rtm_nh_ rtm_nh;

RTM_AD_T
rtm_get_admin_distance(RTM_PROTO_T proto, RTM_SUB_PROTO_T sub_proto) ;

void
 rtm_route_add_nh_to_route_path_list (rtm_t *rtm, rtm_route *route, rtm_nh *nh);

#endif 