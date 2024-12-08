#include <stdint.h>
#include <stdbool.h>

#include "../utils.h"
#include "../Interface/InterfaceFwd.h"
#include "../gluethread/glthread.h"
#include "../Layer3/layer3.h"
#include "SRv6/SRv6-EndPoint.h"
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

ipv6_route_t* 
l3rib_v6lookup_lpm(   rt_table_t *v6rt_table, uint8_t (*ipv6_addr)[16]);

void 
 layer3_ipv6_forward_nexthop (node_t *node, ipv6_route_t *route, pkt_block_t *pkt_block);