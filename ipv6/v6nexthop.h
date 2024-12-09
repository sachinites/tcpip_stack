#ifndef __V6NEXTHOP__
#define __V6NEXTHOP__

#include "../utils.h"
#include "../Interface/InterfaceFwd.h"
#include "ipv6_hdrs.h"

typedef struct v6nexthop_{

    /* Below 3 fields are the keys of the nexthop */
    uint32_t ifindex;  
    ipv6_addr_t gw;
    uint16_t proto;
    /* internal fields */
    uint32_t ref_count;
    InterfaceP oif;
    long long unsigned int hit_count;
} v6nexthop_t;


int
v6nh_flush_nexthops(v6nexthop_t **nexthop);

bool 
v6nh_insert_new_nexthop_nh_array(
                       v6nexthop_t **nexthop_arry, 
                       v6nexthop_t *nxthop);

bool
v6nh_is_nexthop_exist_in_nh_array(
                        v6nexthop_t **nexthop_array, 
                        v6nexthop_t *nxthop);

 int
v6nh_union_nexthops_arrays(v6nexthop_t **src, v6nexthop_t **dst);

v6nexthop_t *
v6nexthop_find (v6nexthop_t **nexthops, ipv6_addr_t *gw, uint32_t ifindex, uint16_t proto, int *index);

#endif 