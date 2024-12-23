#ifndef __SRV6_RTR__H__
#define __SRV6_RTR__H__

#include <stdint.h>
#include "srv6_struct.h"
#include "srv6_const.h"

typedef struct mtrie_ mtrie_t;

typedef struct srv6_node_info_ {

    /* Configured locator */
    srv6_locator_t loc;   
    /* Configured Static Routes (prefix sids/Adj Sids/Remote routes )*/
    mtrie_t *configured_sids;
    /* Srv6 Condnifured Sid Routes */
    mtrie_t *configured_sid_routes;
    /* SRv6 IGP routes */
    mtrie_t *igp_routes;

} srv6_node_info_t;

#endif 