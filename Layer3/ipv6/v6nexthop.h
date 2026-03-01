#ifndef __V6NEXTHOP__
#define __V6NEXTHOP__

#include <time.h>
#include "../../utils.h"
#include "../../Interface/InterfaceFwd.h"
#include "ipv6_hdrs.h"
#include "../../datapath/Layer3/SRv6/srv6-endpoint.h"

typedef struct v6nexthop_{

    long long unsigned int hit_count;
    ipv6_addr_t gw;
    InterfaceP oif;
    time_t install_time;
    uint32_t ifindex;  
    uint32_t ref_count;
    uint32_t metric;
    uint16_t proto;
    #define IPV6_REMOTE_RT 1
    #define IPV6_LOCAL_RT 2
    #define BINDING_SID 4
    uint8_t flags;

    /* Protocol specific data*/
    union
    {
        struct
        {
            Srv6_endpcode_t endfn;
            uint8_t n_segment_list;
            ipv6_addr_t *segment_lst;
        } srv6;
    } u;

    v6nexthop_() {
        ifindex = 0;
        memset(&gw, 0, 16);
        proto = 0;
        ref_count = 0;
        metric = 0;
        oif = nullptr;
        hit_count = 0;
        install_time = time (NULL);
        memset (&u, 0, sizeof(u));
    };

    ~v6nexthop_() {
        if (this->u.srv6.segment_lst) free (this->u.srv6.segment_lst); 
        assert (ref_count == 0);
    }

} __attribute__((aligned(8))) v6nexthop_t;

void 
nexthop_init (v6nexthop_t *nexthop);

int
v6nh_flush_nexthops(v6nexthop_t **nexthop, bool dont_flush_local);

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

static inline void 
v6nexthop_lock (v6nexthop_t  *nexthop) { nexthop->ref_count++; }

static inline uint32_t
v6nexthop_unlock (v6nexthop_t  *nexthop) { 
    assert (nexthop->ref_count);
    nexthop->ref_count--;
    uint32_t rc = nexthop->ref_count;
    if (nexthop->ref_count == 0) {
        delete nexthop; 
        return 0;
    }
    return rc;
}

#endif 
