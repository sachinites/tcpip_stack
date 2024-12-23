#include <stdint.h>
#include <stdbool.h>

#include "../utils.h"
#include "../Interface/InterfaceFwd.h"
#include "../gluethread/glthread.h"
#include "../Layer3/layer3.h"
#include "../Layer5/SegmentRouting/SRv6/dp/SRv6-EndPoint.h"
#include "ipv6_hdrs.h"
#include "v6nexthop.h"

#define V6RT_F_LOCAL  (1 ) 
#define V6RT_F_REMOTE  (2)

typedef struct ipv6_route_ {

    ipv6_addr_t prefix;
    v6nexthop_t *nexthops[proto_nxthop_max][MAX_NXT_HOPS];
    glthread_t notif_glue;
    glthread_t flash_glue;
    time_t install_time;
    int nxthop_idx;
    uint32_t rt_ref_count;
    uint16_t nh_count;
    bool is_direct; 
    uint8_t prefix_len;
    
} __attribute__((aligned(8))) ipv6_route_t;

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
 ipv6_layer3_forward_nexthop (node_t *node, v6nexthop_t *nexthop, pkt_block_t *pkt_block);

ipv6_route_t* 
l3rib_v6route_lookup_exact_match ( rt_table_t *v6rt_table, ipv6_addr_t *prefix, uint8_t prefix_len);

 void
layer3_ipv6_route_pkt(node_t *node,
							    Interface *interface,
					            pkt_block_t *pkt_block) ;

void 
v6_rt_table_show (rt_table_t *rt_table) ;
