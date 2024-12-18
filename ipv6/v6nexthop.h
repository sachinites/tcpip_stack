#ifndef __V6NEXTHOP__
#define __V6NEXTHOP__

#include "../utils.h"
#include "../Interface/InterfaceFwd.h"
#include "ipv6_hdrs.h"
#include "SRv6/SRv6-EndPoint.h"

typedef struct v6nexthop_{

    long long unsigned int hit_count;
    ipv6_addr_t gw;
    InterfaceP oif;
    uint32_t ifindex;  
    uint32_t ref_count;
    uint16_t proto;

    /* Protocol specific data*/
    union
    {
        struct
        {
            uint8_t srv6_flavors;
            Srv6_endpcode_t endfn;
            uint32_t metric;
            #define SRV6_REMOTE_RT 1
            #define SRV6_LOCAL_RT 2
            #define BINDING_SID 4
            uint8_t flags;
            uint8_t n_segment_list;
            ipv6_addr_t *segment_lst;
        } srv6;
    } u;

    v6nexthop_() {
        ifindex = 0;
        memset(&gw, 0, 16);
        proto = 0;
        ref_count = 0;
        oif = nullptr;
        hit_count = 0;
        memset (&u, 0, sizeof(u));
    };

    ~v6nexthop_() {
        if (this->u.srv6.segment_lst) free (this->u.srv6.segment_lst); 
    }

} __attribute__((aligned(8))) v6nexthop_t;

void 
nexthop_init (v6nexthop_t *nexthop);

int
v6nh_flush_nexthops(v6nexthop_t **nexthop);

bool 
v6nh_insert_new_nexthop_nh_array(
                       v6nexthop_t **nexthop_arry, 
                       v6nexthop_t *nxthop);

int
v6nh_is_nexthop_exist_in_nh_array(
                        v6nexthop_t **nexthop_array, 
                        v6nexthop_t *nxthop,  int *index);

 int
v6nh_union_nexthops_arrays(v6nexthop_t **src, v6nexthop_t **dst);

v6nexthop_t *
v6nexthop_find (v6nexthop_t **nexthops, ipv6_addr_t *gw, uint32_t ifindex, uint16_t proto, int *index);

#endif 