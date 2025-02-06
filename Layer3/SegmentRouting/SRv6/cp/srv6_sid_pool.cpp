/* This file Implementes the SRv6 SID Pooling */

#include "../../../../BitOp/bitmap.h"
#include "../../../ipv6/ipv6_hdrs.h"
#include "../../../../Tree/libtree.h"
#include "../../../../graph.h"
#include "../../../../mtrie/mtrie.h"
#include <memory.h>
#include <assert.h>
#include "srv6_sid_pool.h"

#define MAX_LOCATOR_NAME_LEN 64

static bitmap_t bm_wcard_1;

typedef struct adj_sid_key_ {

    uint32_t ifindex;
    ipv6_addr_t gw_addr;

} adj_sid_key_t ;

typedef struct pool_entry_ {

    /* Allocated SID*/
    ipv6_addr_t sid;
    avltree_node_t avl_glue_sid;

    /* Client to which this sid is allocated*/
    srv6_sid_client_t sid_client;
    /* Adj Sid key*/
    adj_sid_key_t adj_sid_key;
    avltree_node_t avl_glue_asid;

} pool_entry_t;


typedef struct srv6_locator_pool_ {

    ipv6_addr_t loc; // key
    uint8_t loc_pfx_len; //key
    avltree_node_t avl_glue_loc; // keyed by loc & prefix len
    char loc_name[MAX_LOCATOR_NAME_LEN];  
    avltree_node_t avl_glue_by_name; // keyed by loc name
    bitmap_t static_sid_bm;
    bitmap_t dynamic_sid_bm;
    avltree_t sid_tree;
    avltree_t sid_tree_by_asid;
    
} srv6_locator_pool_t;


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

/* Comparison fn for locator pools */
static int 
ipv6_addr_cmp (ipv6_addr_t *addr1, ipv6_addr_t *addr2) {

    for (int i = 0; i < 16; i++) {

        if (addr1->addr[i] < addr2->addr[i]) {
            return -1;
        } else if (addr1->addr[i] > addr2->addr[i]) {
            return 1;
        }
    }
    return 0;
}

static int
avltree_locator_comp_fn  (const avltree_node_t *data1, const avltree_node_t *data2) {

    srv6_locator_pool_t *pool1 = (srv6_locator_pool_t *)avltree_container_of(data1, srv6_locator_pool_t, avl_glue_loc);
    srv6_locator_pool_t *pool2 = (srv6_locator_pool_t *)avltree_container_of(data2, srv6_locator_pool_t, avl_glue_loc);

    if (ipv6_addr_cmp(&pool1->loc, &pool2->loc) < 0) {
        return -1;
    } else if (ipv6_addr_cmp(&pool1->loc, &pool2->loc) > 0) {
        return 1;
    } else {
        if (pool1->loc_pfx_len < pool2->loc_pfx_len) {
            return -1;
        } else if (pool1->loc_pfx_len > pool2->loc_pfx_len) {
            return 1;
        } else {
            return 0;
        }
    }
}

static int
avltree_locator_comp_fn_by_name  (const avltree_node_t *data1, const avltree_node_t *data2) {

    srv6_locator_pool_t *pool1 = (srv6_locator_pool_t *)avltree_container_of(data1, srv6_locator_pool_t, avl_glue_loc);
    srv6_locator_pool_t *pool2 = (srv6_locator_pool_t *)avltree_container_of(data2, srv6_locator_pool_t, avl_glue_loc);

    return strcmp(pool1->loc_name, pool2->loc_name);
}

static int 
avltree_sid_comp_fn  (const avltree_node_t *data1, const avltree_node_t *data2) {

    pool_entry_t *entry1 = (pool_entry_t *)avltree_container_of(data1, pool_entry_t, avl_glue_sid);
    pool_entry_t *entry2 = (pool_entry_t *)avltree_container_of(data2, pool_entry_t, avl_glue_sid);

    return ipv6_addr_cmp(&entry1->sid, &entry2->sid);
}

static int
avltree_sid_comp_fn_by_asid  (const avltree_node_t *data1, const avltree_node_t *data2) {

    pool_entry_t *entry1 = (pool_entry_t *)avltree_container_of(data1, pool_entry_t, avl_glue_asid);
    pool_entry_t *entry2 = (pool_entry_t *)avltree_container_of(data2, pool_entry_t, avl_glue_asid);

    if (entry1->adj_sid_key.ifindex < entry2->adj_sid_key.ifindex) {
        return -1;
    } else if (entry1->adj_sid_key.ifindex > entry2->adj_sid_key.ifindex) {
        return 1;
    } else {
        return ipv6_addr_cmp(&entry1->adj_sid_key.gw_addr, &entry2->adj_sid_key.gw_addr);
    }

}

static void 
mtrie_node_delete_fn (mtrie_node_t *mnode) {

    if (!mnode->data) return;
    pool_entry_t *pool_entry = (pool_entry_t *)mnode->data;
    free (pool_entry);
    mnode->data = NULL;
}

/* ====================== Data Structure Setup Done ========================= */



/* ====================== Helper APIs Begin  ========================= */

/* Look up locator by v6addr/prefix_len*/

static srv6_locator_pool_t *
srv6_pool_avl_lookup_locator (
                                                    srv6_sid_pools_t *srv6_sid_pools, 
                                                    ipv6_addr_t *loc_prefix,
                                                    uint8_t prefix_len) {

    srv6_locator_pool_t tmplate;

    memset (&tmplate, 0, sizeof (tmplate));
    memcpy (&tmplate.loc, loc_prefix, sizeof (*loc_prefix));
    tmplate.loc_pfx_len = prefix_len;

    avltree_node_t *res = avltree_lookup (&tmplate.avl_glue_loc, &srv6_sid_pools->locator_pools);
    if (!res) return NULL;
    return (srv6_locator_pool_t *)avltree_container_of (res, srv6_locator_pool_t, avl_glue_loc);
}

static srv6_locator_pool_t *
srv6_pool_avl_lookup_locator_by_name (
                                                    srv6_sid_pools_t *srv6_sid_pools, 
                                                    char *loc_name) {

    srv6_locator_pool_t tmplate;

    memset (&tmplate, 0, sizeof (tmplate));
    strncpy (tmplate.loc_name, loc_name, MAX_LOCATOR_NAME_LEN - 1);
    tmplate.loc_name[MAX_LOCATOR_NAME_LEN - 1] = '\0';

    avltree_node_t *res = avltree_lookup (&tmplate.avl_glue_by_name, &srv6_sid_pools->locator_pools);
    if (!res) return NULL;
    return (srv6_locator_pool_t *)avltree_container_of (res, srv6_locator_pool_t, avl_glue_by_name);
}

static srv6_locator_pool_t *
srv6_pool_avl_lookup_locator_by_lpm (
                                                    srv6_sid_pools_t *srv6_sid_pools, 
                                                    ipv6_addr_t *loc_prefix) {

    bitmap_t bm;

    bitmap_init (&bm, 128);
    memcpy(bm.bits, loc_prefix->addr, 16);

    mtrie_node_t *mnode = mtrie_longest_prefix_match_search (
                                            &srv6_sid_pools->locators_lpm_tree, 
                                            &bm);

    bitmap_free_internal (&bm);
    if (!mnode) return NULL;
    return (srv6_locator_pool_t *)mnode->data;
}
/* ====================== Helper APIs Done  ========================= */


/* ======================  Public APIs  ========================= */
void 
srv6_init_srv6_pools (srv6_sid_pools_t **srv6_sid_pools) {

    assert (srv6_sid_pools);
    *srv6_sid_pools = (srv6_sid_pools_t *)calloc (1, sizeof (srv6_sid_pools_t));
    srv6_sid_pools_t *temp = *srv6_sid_pools;
    
    avltree_init (&temp->locator_pools, avltree_locator_comp_fn);
    avltree_init (&temp->locator_pool_by_name, avltree_locator_comp_fn_by_name);
    init_mtrie (&temp->locators_lpm_tree, 128, mtrie_node_delete_fn);

    bitmap_init (&bm_wcard_1, 128);
    memset (bm_wcard_1.bits, 0xFF, 16);
}

/* Called when locator is configured for the first time*/
pool_error_codes_t
srv6_create_locator (srv6_sid_pools_t *srv6_sid_pools, 
                            ipv6_addr_t *loc_prefix, 
                            uint8_t prefix_len, 
                            char *loc_name,
                            char* err_msg_out) {

    /* Check if this locator doesnt already exist */
    srv6_locator_pool_t *loc = srv6_pool_avl_lookup_locator (
                                            srv6_sid_pools, loc_prefix, prefix_len);

    if (loc) {
        snprintf (err_msg_out, 256, "Error : Locator already configured as %s", loc->loc_name);
        return SRv6_POOL_ERR_DUP_LOCATOR;
    }

    /* Check if there is a name conflict */
    loc = srv6_pool_avl_lookup_locator_by_name (
                                            srv6_sid_pools, loc_name);

    if (loc) {
        snprintf (err_msg_out, 256, "Error : Locator name %s already in use", loc_name);
        return SRv6_POOL_ERR_LOCATOR_NAME_CONFLICT;
    }

    /*  Check if there is already a locator with LPM 
        For example : locator 2001:dbe8:1::/48 is already configured, 
        then 2001:dbe8:1:1::/64 cannot be configured
    */
    loc = srv6_pool_avl_lookup_locator_by_lpm (
                                            srv6_sid_pools, loc_prefix);

    if (loc) {
        snprintf (err_msg_out, 256, "Error : Prefixed Locator already configured as %s", loc->loc_name);
        return SRv6_POOL_ERR_DUP_LOCATOR;
    }

    /* To Do : Check if suffixed locator is not already configured 
        For example : locator 2001:dbe8:1:1::/64 is already configured, 
        then 2001:dbe8:1::/48 cannot be configured
    */

    /* All checks are passed, now we can instantiate a new locator pool  */
    srv6_locator_pool_t *new_loc = (srv6_locator_pool_t *)calloc (1, sizeof (srv6_locator_pool_t));

    memcpy (&new_loc->loc, loc_prefix, sizeof (*loc_prefix));
    new_loc->loc_pfx_len = prefix_len;
    strncpy (new_loc->loc_name, loc_name, MAX_LOCATOR_NAME_LEN - 1);
    new_loc->loc_name[MAX_LOCATOR_NAME_LEN - 1] = '\0';

    /* Each locator has function length of 16 bits for sids allocation. So total sids  allocated is 2 ^ 16  - 1 = 65535. This space [1, 65535] is further divided into static and dynamic sids. Therefore, static sid space =  [1, 32767] which is [0x1, 0x7FFF]
    and dynamic sid space = [32768, 65535] which is 0x8000 to 0xFFFF
    */
    bitmap_init (&new_loc->static_sid_bm, 32768);
    bitmap_set_bit_at (&new_loc->static_sid_bm, 0); 
    bitmap_init (&new_loc->dynamic_sid_bm, 32768);

    avltree_init (&new_loc->sid_tree, avltree_sid_comp_fn);
    avltree_init (&new_loc->sid_tree_by_asid, avltree_sid_comp_fn_by_asid);

    assert (!avltree_insert (&new_loc->avl_glue_loc, &srv6_sid_pools->locator_pools));
    assert (!avltree_insert (&new_loc->avl_glue_by_name, &srv6_sid_pools->locator_pool_by_name));

    /* Insert into LPM tree */
    bitmap_t bm_pfx;
    bitmap_init (&bm_pfx, 128);
    memcpy(bm_pfx.bits, loc_prefix->addr, 16);
   
    mtrie_node_t *mnode = NULL;
    mtrie_ops_result_code_t res = mtrie_insert_prefix (
                                                &srv6_sid_pools->locators_lpm_tree, 
                                                &bm_pfx, &bm_wcard_1, 
                                                128,  &mnode);
    
    bitmap_free_internal (&bm_pfx);

    assert (res == MTRIE_INSERT_SUCCESS);
    return SRv6_POOL_OK;
}

/* Called when locator is Unconfigured */
pool_error_codes_t
srv6_delete_locator (srv6_sid_pools_t *srv6_sid_pools, 
                            char *loc_name,
                            char* err_msg_out) {

    srv6_locator_pool_t *loc = srv6_pool_avl_lookup_locator_by_name (
                                            srv6_sid_pools, loc_name);

    if (!loc) {
        snprintf (err_msg_out, 256, "Error : Locator name %s not found", loc_name);
        return SRv6_POOL_ERR_LOCATOR_NOT_FOUND;
    }

    /* Check if there are any sids allocated */
    if (!avltree_is_empty (&loc->sid_tree)) {
        snprintf (err_msg_out, 256, "Error : Cannot Delete Locator %s,  SIDs in use", loc_name);
        return SRv6_POOL_ERR_LOCATOR_IN_USE;
    }

    assert (avltree_is_empty (&loc->sid_tree_by_asid));

    /* Remove from LPM tree */
    bitmap_t bm_pfx;
    bitmap_init (&bm_pfx, 128);
    memcpy(bm_pfx.bits, loc->loc.addr, 16);

    srv6_locator_pool_t *loc1 = NULL;
    mtrie_ops_result_code_t res = mtrie_delete_prefix (
                                                &srv6_sid_pools->locators_lpm_tree, 
                                                &bm_pfx, &bm_wcard_1, (void **)&loc1);

    bitmap_free_internal (&bm_pfx);

    assert (res == MTRIE_DELETE_SUCCESS);
    assert (loc == loc1);

    /* Remove from AVL tree */
    avltree_remove (&loc->avl_glue_loc, &srv6_sid_pools->locator_pools);
    avltree_remove (&loc->avl_glue_by_name, &srv6_sid_pools->locator_pool_by_name);

    bitmap_free_internal (&loc->static_sid_bm);
    bitmap_free_internal (&loc->dynamic_sid_bm);

    free (loc);
    return SRv6_POOL_OK;
}

pool_error_codes_t
srv6_alloc_available_pfx_sid (
                                    srv6_sid_pools_t *srv6_sid_pools, 
                                    char *loc_name ,
                                    srv6_sid_client_t sid_client,
                                    ipv6_addr_t *sid_out,
                                    char *err_msg_out) {

    srv6_locator_pool_t *loc = srv6_pool_avl_lookup_locator_by_name (
                                            srv6_sid_pools, loc_name);

    if (!loc) {
        snprintf (err_msg_out, 256, "Error : Locator %s not found", loc_name);
        return SRv6_POOL_ERR_LOCATOR_NOT_FOUND;
    }

    /* Check if there are any sids available */
    

}