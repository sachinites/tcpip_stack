#include <stdint.h>
#include <stdbool.h>

#include "../utils.h"
#include "../Interface/InterfaceFwd.h"
#include "../gluethread/glthread.h"
#include "../Layer3/layer3.h"
#include "SRv6/SRv6-EndPoint.h"
#include "ipv6_hdrs.h"
#include "v6nexthop.h"


typedef struct ipv6_route_ {

    ipv6_addr_t prefix;
    uint8_t prefix_len;
    bool is_direct;       /* if set to True, then gw_ip and oif has no meaning*/
    Srv6_endpcode_t endfn;
    Srv6_flavor_t flavor;
    v6nexthop_t *nexthops[proto_nxthop_max][MAX_NXT_HOPS];
    uint32_t spf_metric[proto_nxthop_max];
    uint16_t nh_count;
    int nxthop_idx;
	time_t install_time;
    uint8_t rt_flags;
    glthread_t notif_glue;
    glthread_t flash_glue;
    uint32_t rt_ref_count;

} ipv6_route_t;

static inline uint32_t
l3_v6route_dec_ref_count (ipv6_route_t *l3_route) {

    assert (l3_route->rt_ref_count);
    l3_route->rt_ref_count--;
    if ( l3_route->rt_ref_count ) return l3_route->rt_ref_count;
    free (l3_route);
    return 0;
}

static inline void 
l3_v6route_inc_ref_count (ipv6_route_t *l3_route) {

    l3_route->rt_ref_count++;
}

ipv6_route_t* 
l3rib_v6lookup_lpm ( rt_table_t *v6rt_table, uint8_t (*ipv6_addr)[16]);

ipv6_route_t* 
l3rib_v6lookup_lpm2 ( rt_table_t *v6rt_table, ipv6_addr_t *ipv6_addr);

void 
 layer3_ipv6_forward_nexthop (node_t *node, ipv6_route_t *route, pkt_block_t *pkt_block);

ipv6_route_t* 
l3rib_v6route_lookup_exact_match ( rt_table_t *v6rt_table, ipv6_addr_t *prefix, uint8_t prefix_len);

 bool 
 ipv6_route_install (node_t *node, 
                                ipv6_addr_t *prefix,
                                uint8_t prefix_len,
                                ipv6_addr_t *gw,
                                Interface* oif, 
                                uint32_t spf_metric,
                                uint16_t proto_id);

 bool 
 ipv6_route_delete (node_t *node, 
                                ipv6_addr_t *prefix,
                                uint8_t prefix_len,
                                ipv6_addr_t *gw,
                                Interface* oif, 
                                uint16_t proto_id);

void 
v6_rt_table_show (rt_table_t *rt_table) ;