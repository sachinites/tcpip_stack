/* This file Implementes the SRv6 SID Pooling */
#include "../../../../BitOp/bitmap.h"
#include "../../../ipv6/ipv6_hdrs.h"
#include "../../../../Tree/libtree.h"
#include "../../../../graph.h"
#include "../../../../mtrie/mtrie.h"
#include <memory.h>
#include <time.h>

typedef enum sid_client_{

    sid_client_isis,
    sid_client_srv6,
    sid_client_bgp,
    sid_client_ospfv3,
    sid_client_max

} sid_client_t;

typedef struct adj_sid_key_ {

    uint32_t ifindex;
    ipv6_addr_t gw_addr;

} adj_sid_key_t ;

typedef struct pool_entry_ {

    /* Allocated SID*/
    ipv6_addr_t sid;
    /* Client to which this sid is allocated*/
    sid_client_t sid_client;
    /* Adj Sid key*/
    adj_sid_key_t adj_sid_key;
    /* time when this sid was allocated */
    time_t alloc_time;

} pool_entry_t;



typedef struct srv6_locator_pool_ {

    ipv6_addr_t loc; // key
    avltree_node_t avl_glue; // keyed by loc & prefix len
    char loc_name[64];  
    avltree_node_t avl_glue; // keyed by loc name
    bitmap_t bm;
    avltree_t sid_tree;
    uint8_t loc_pfx_len; //key

} srv6_locator_pool_t;

int
avltree_locator_comp_fn  (const avltree_node_t *data1, const avltree_node_t *data2) {

    srv6_locator_pool_t *pool1 = (srv6_locator_pool_t *)avltree_container_of(data1, srv6_locator_pool_t, avl_glue);
    srv6_locator_pool_t *pool2 = (srv6_locator_pool_t *)avltree_container_of(data2, srv6_locator_pool_t, avl_glue);


}

typedef struct srv6_sid_pools_ {

    avltree_t locator_pools;
    avltree_t locator_pool_by_name;

/* 
    In SRv6, User can configure multiple locators on the same router.
    Now take the example : 
    Are these two locators allowed to configure  2001:dbe8:1::/48 and 2001:dbe8:1:1::/64   ? 
    looks like they conflict each other. One locator cannot be prefix of the other. 
    General Rule:
        Each locator must be a distinct, non-overlapping prefix.
        No locator should be a subset of another to prevent conflicts in SID allocation and routing.
    
    Therefore, LPM tree (mtrie) is required to enforce this check
*/
    mtrie_t locators_lpm_tree;

} srv6_sid_pools_t;

void 
srv6_init_srv6_pools (srv6_sid_pools_t **srv6_sid_pools) {

    assert (srv6_sid_pools);
    *srv6_sid_pools = (srv6_sid_pools_t *)calloc (1, sizeof (srv6_sid_pools_t));
    srv6_sid_pools_t *temp = *srv6_sid_pools;
    
}

void 
srv6_pool_create (node_t *node, ipv6_addr_t *locator_prefix, uint8_t prefix_len) {


}