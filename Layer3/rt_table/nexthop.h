#ifndef __NEXTHOP__
#define __NEXTHOP__

#include "../../utils.h"
#include "../../Interface/InterfaceFwd.h"

typedef struct nexthop_{

    /* Below 3 fields are the keys of the nexthop */
    uint32_t ifindex;  
    byte gw_ip[16];
    uint16_t proto;
    unsigned char node_name[NODE_NAME_SIZE];
    /* internal fields */
    uint32_t ref_count;
    InterfaceP oif;
    long long unsigned int hit_count;

    /* Insert a constructor here */

    nexthop_() {
        ifindex = 0;
        memset(gw_ip, 0, 16);
        proto = 0;
        memset(node_name, 0, NODE_NAME_SIZE);
        ref_count = 0;
        oif = nullptr;
        hit_count = 0;
    };

} __attribute__((aligned(8))) nexthop_t;

int
nh_flush_nexthops(nexthop_t **nexthop);

nexthop_t *
nh_create_new_nexthop(c_string node_name, uint32_t oif_index, c_string gw_ip, uint16_t proto);

bool 
nh_insert_new_nexthop_nh_array(
                       nexthop_t **nexthop_arry, 
                       nexthop_t *nxthop);

bool
nh_is_nexthop_exist_in_nh_array(
                        nexthop_t **nexthop_array, 
                        nexthop_t *nxthop);

 int
nh_union_nexthops_arrays(nexthop_t **src, nexthop_t **dst);

c_string
nh_nexthops_str(nexthop_t **nexthops,  c_string buffer,  uint16_t buffer_size);

#endif 