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
rtm_track_inh_for_resolution (rtm_t *rtm, rtm_nh *indirect_nh);

void 
rtm_untrack_inh_for_resolution (rtm_t *rtm, rtm_nh *indirect_nh);

void
rtm_resolve_routes_recursively (rtm_t *rtm, rtm_route *route) ;

#endif
