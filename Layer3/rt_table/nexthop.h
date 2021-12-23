#ifndef __NEXTHOP__
#define __NEXTHOP__

typedef struct nexthop_{

    /* Below 3 fields are the keys of the nexthop */
    uint32_t ifindex;  
    char gw_ip[16];
    uint8_t proto;

    /* internal fields */
    uint32_t ref_count;
    interface_t *oif;
    long long unsigned int hit_count;
} nexthop_t;

int
nh_flush_nexthops(nexthop_t **nexthop);

nexthop_t *
nh_create_new_nexthop(uint32_t oif_index, char *gw_ip, uint8_t proto);

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

char *
nh_nexthops_str(nexthop_t **nexthops);

#endif 