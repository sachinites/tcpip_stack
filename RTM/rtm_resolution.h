#ifndef __RTM_RESOLUTION__
#define __RTM_RESOLUTION__



#include <stdint.h>
#include <stdbool.h>
#include "../gluethread/glthread.h"
#include "../Tree/libtree.h"
#include "rtm_enums.h"
#include "rtm_error.h"
#include "rtm_common.h"

typedef struct rtm_ rtm_t;
typedef struct rtm_nh_ rtm_nh;
typedef struct rtm_route_ rtm_route;

#pragma pack(push, 8)

#pragma pack(pop)

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
rtm_schedule_route_propogation_worker (rtm_t *rtm) ;

void 
rtm_copy_route_active_nhs_to_inh_direct_nh_set(
        rtm_t *rtm, rtm_route *route, rtm_nh *indirect_nh);

void 
rtm_resolution_nh_withdraw (rtm_t *rtm, rtm_nh *nh);

void 
rtm_re_resolve_inhs (rtm_t *rtm, rtm_prefix_t  *route);

#endif
