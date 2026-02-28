#ifndef __NEXTHOP__
#define __NEXTHOP__

#include <memory.h>

#include "../../utils.h"
#include "../../Interface/InterfaceFwd.h"
#include "../../LinuxMemoryManager/uapi_mm.h"
#include "../../tcpconst.h"


typedef struct mpls_lstack_ mpls_lstack_t;

typedef struct nexthop_{

    InterfaceP oif;
    byte gw_ip[16];
    unsigned char node_name[NODE_NAME_SIZE];
    mpls_lstack_t *lbls;
    long long unsigned int hit_count;
    uint32_t ifindex;  
    uint32_t ref_count;
    uint16_t proto;
    
    /* Insert a constructor here */

    nexthop_() {
        ifindex = 0;
        memset(gw_ip, 0, 16);
        proto = 0;
        memset(node_name, 0, NODE_NAME_SIZE);
        lbls = NULL;
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

bool 
nh_remove_nexthop_from_nh_array (
                        nexthop_t **nexthop_array, 
                        nexthop_t *nxthop);

 int
nh_union_nexthops_arrays(nexthop_t **src, nexthop_t **dst);

c_string
nh_nexthops_str(nexthop_t **nexthops,  c_string buffer,  uint16_t buffer_size);

static void
nexthop_reference (nexthop_t *nexthop) {nexthop->ref_count++;}

static void
nexthop_dereference (nexthop_t *nexthop) {
    
    if (nexthop->ref_count == 0) {
        if (nexthop->lbls) XFREE (nexthop->lbls);
        if (nexthop->oif) nexthop->oif = nullptr;
        delete nexthop;
        return;
    }

    nexthop->ref_count--;

    if (nexthop->ref_count == 0) {
        if (nexthop->lbls) XFREE (nexthop->lbls);
        if (nexthop->oif) nexthop->oif = nullptr;
        delete nexthop;
    }    
}

int8_t
nxthop_compare (nexthop_t *nh1, nexthop_t *nh2) ;

#endif 
