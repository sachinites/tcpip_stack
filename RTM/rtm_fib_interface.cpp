
#include "../Tracer/tracer.h"
#include "../graph.h"
#include "rtm.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_fib_interface.h"
#include "rtm_priv_api.h"

void 
rtm_fib_uninstall (rtm_t *rtm, rtm_route *route, rtm_nh *nh) {

    char rt_str[48];
    char nh_str[128];

    tracer (rtm->node->cptr, DRTM,
        "RTM[%s] : Route %s, NH %s\n",
        rtm->name,
        rtm_nh_one_liner_trace(nh, nh_str, sizeof(nh_str)),
        rtm_format_prefix(&route->prefix, rt_str, sizeof(rt_str)));
}

void 
rtm_fib_install (rtm_t *rtm, rtm_route *route, rtm_nh *nh) {

    char rt_str[48];
    char nh_str[128];
    
    tracer (rtm->node->cptr, DRTM,
        "RTM[%s] : Route %s, NH %s\n",
        rtm->name,
        rtm_nh_one_liner_trace(nh, nh_str, sizeof(nh_str)),
        rtm_format_prefix(&route->prefix, rt_str, sizeof(rt_str)));
}