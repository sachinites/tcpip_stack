#ifndef __SRV6_RTR__H__
#define __SRV6_RTR__H__

#include <stdint.h>
#include "srv6_struct.h"
#include "../common/srv6_const.h"

typedef struct mtrie_ mtrie_t;
typedef struct tracer_ tracer_t;

typedef struct srv6_node_info_ {

    /* Configured locator */
    srv6_locator_t loc;   
    /* Configured prefix sids*/
    mtrie_t *configured_pfx_sids;
    /* Configured Adjacency Sids */
    mtrie_t *configured_adj_sids;    
    /* SRv6 IGP routes */
    mtrie_t *igp_routes;
    /* Tracer*/
    tracer_t *tr;

} srv6_node_info_t;

#endif 