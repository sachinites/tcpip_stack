#ifndef __RTM_RESOLUTION__
#define __RTM_RESOLUTION__

#include <stdint.h>
#include <stdbool.h>
#include "../gluethread/glthread.h"
#include "../Tree/libtree.h"
#include "rtm_enums.h"
#include "rtm_error.h"
#include "rtm_fib_common.h"

typedef struct rtm_ rtm_t;
typedef struct rtm_nh_ rtm_nh;
typedef struct rtm_route_ rtm_route;

/* Cases to cover : 
1. When new INH is added - Done 
2. When INH is removed - Done
3. When new DNH is added
4. When DNH is removed 
5. When new Route is added with DNH
6. When Route is deleted with DNH 
*/

void
rtm_resolve_routes_recursively (rtm_t *rtm, rtm_route *route) ;

void 
rtm_schedule_nh_resolution_worker (rtm_t *rtm) ;

void 
rtm_schedule_nh_resolution_worker_of_dependent_rtms (rtm_t *rtm) ;

void 
rtm_schedule_route_propogation_worker (rtm_t *rtm) ;

void 
rtm_copy_route_active_nhs_to_inh_direct_nh_set(
        rtm_t *rtm, rtm_route *route, rtm_nh *indirect_nh);

void 
rtm_resolution_nh_withdraw (rtm_t *rtm, rtm_nh *nh);

void 
rtm_schedule_route_propogation (rtm_t *rtm, rtm_route *route) ;

rtm_route *
rtm_get_resolver_route (rtm_t *rtm, rtm_nh *indirect_nh);

rtm_t *
rtm_get_resolver_rtm (node_t *node, rtm_nh *indirect_nh);

void 
rtm_all_inh_unresolve(rtm_t *rtm,  cmn_prefix_t *route);

void 
rtm_try_unresolvable_paths_resolution (rtm_t *rtm, int *resolved_count);

void 
rtm_re_resolve_inhs (rtm_t *rtm, cmn_prefix_t  *route);

uint32_t 
rtm_re_resolve_inhs_per_protocol (rtm_t *rtm, cmn_prefix_t *route, RTM_PROTO_T proto);

#endif
