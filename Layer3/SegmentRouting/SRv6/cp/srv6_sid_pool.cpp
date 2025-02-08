/* This file Implementes the SRv6 SID Pooling */

#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <assert.h>
#include <arpa/inet.h>

#include "../../../../BitOp/bitmap.h"
#include "../../../ipv6/ipv6_utils.h"
#include "../../../../Tree/libtree.h"
#include "../../../../mtrie/mtrie.h"
#include "srv6_sid_pool.h"

#define MAX_LOCATOR_NAME_LEN 64

extern int cprintf (const char* format, ...) ;

typedef struct adj_sid_key_ {

    uint32_t ifindex;
    ipv6_addr_t gw_addr;
    srv6_sid_client_t client;

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
    /* Who are the clients using this locator */
    uint8_t use_clients;
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

    srv6_locator_pool_t *pool1 = (srv6_locator_pool_t *)avltree_container_of(data1, srv6_locator_pool_t, avl_glue_by_name);
    srv6_locator_pool_t *pool2 = (srv6_locator_pool_t *)avltree_container_of(data2, srv6_locator_pool_t, avl_glue_by_name);

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
        int rc =  ipv6_addr_cmp(&entry1->adj_sid_key.gw_addr, &entry2->adj_sid_key.gw_addr);
        if (rc) return rc;
        return entry1->adj_sid_key.client - entry2->adj_sid_key.client;
    }

    assert(0);
    return 0;
}

#if 0
static void 
mtrie_node_delete_fn (mtrie_node_t *mnode) {

    if (!mnode->data) return;
    pool_entry_t *pool_entry = (pool_entry_t *)mnode->data;
    free (pool_entry);
    mnode->data = NULL;
}
#endif 

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

    avltree_node_t *res = avltree_lookup (&tmplate.avl_glue_by_name, 
                                        &srv6_sid_pools->locator_pool_by_name);

    if (!res) return NULL;
    return (srv6_locator_pool_t *)avltree_container_of (res, srv6_locator_pool_t, avl_glue_by_name);
}

static srv6_locator_pool_t *
srv6_pool_lookup_locator_by_lpm (
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

static bool 
srv6_pool_validate_sid_format (srv6_locator_pool_t *loc, ipv6_addr_t *sid) {

    uint16_t (*loc_ptr)[8] = (uint16_t (*)[8])(&loc->loc.addr);
    uint16_t (*sid_ptr)[8] = (uint16_t (*)[8])(&sid->addr);
    uint8_t function_index = loc->loc_pfx_len / 16;

    uint8_t i;

    for (i = 0; i < function_index; i++) {
        if ( (*loc_ptr)[i] != (*sid_ptr)[i] ) return false; 
    }

    if ( (*sid_ptr)[i] == 0) return false;

    i++;

    for ( ; i < 8; i++) {
        if ( (*sid_ptr)[i] ) return false;
    }    

    return true;
}

/* ====================== Helper APIs Done  ========================= */


/* ======================  Public APIs  ========================= */
void 
srv6_pool_init_srv6_pools (srv6_sid_pools_t **srv6_sid_pools) {

    assert (srv6_sid_pools);
    *srv6_sid_pools = (srv6_sid_pools_t *)calloc (1, sizeof (srv6_sid_pools_t));
    srv6_sid_pools_t *temp = *srv6_sid_pools;
    
    avltree_init (&temp->locator_pools, avltree_locator_comp_fn);
    avltree_init (&temp->locator_pool_by_name, avltree_locator_comp_fn_by_name);
    init_mtrie (&temp->locators_lpm_tree, 128, NULL);
}

/* Called when locator is configured for the first time*/
pool_error_codes_t
srv6_pool_create_locator (srv6_sid_pools_t *srv6_sid_pools, 
                            ipv6_addr_t *loc_prefix, 
                            uint8_t prefix_len, 
                            char *loc_name,
                            char* err_msg_out) {

    if (prefix_len % 16 ) {
        snprintf (err_msg_out, 256, "Error : Locator %s Prefix length must be multiple of 16", loc_name);
        return SRv6_POOL_ERR_LOCATOR_INVALID;
    }

    if (prefix_len <= 32) {
        snprintf (err_msg_out, 256, "Error : Locator %s Prefix length too short", loc_name);
        return SRv6_POOL_ERR_LOCATOR_INVALID;
    }

    /* Check if this locator doesnt already exist */
    srv6_locator_pool_t *loc = srv6_pool_avl_lookup_locator (
                                            srv6_sid_pools, loc_prefix, prefix_len);

    if (loc) {
        snprintf (err_msg_out, 256, "Error : Locator %s already configured", loc->loc_name);
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
    loc = srv6_pool_lookup_locator_by_lpm (
                                            srv6_sid_pools, loc_prefix);

    if (loc) {
        snprintf (err_msg_out, 256, "Error : Locator name %s is in conflict", loc->loc_name);
        return SRv6_POOL_ERR_DUP_LOCATOR;
    }

    /* To Do : Check if suffixed locator is not already configured 
        For example : locator 2001:dbe8:1:1::/64 is already configured, 
        then 2001:dbe8:1::/48 cannot be configured. This check would be 
        required when multiple locators would be supported
    */

    /* All checks are passed, now we can instantiate a new locator pool  */
    srv6_locator_pool_t *new_loc = (srv6_locator_pool_t *)calloc (1, sizeof (srv6_locator_pool_t));

    memcpy (&new_loc->loc, loc_prefix, sizeof (*loc_prefix));
    new_loc->loc_pfx_len = prefix_len;
    strncpy (new_loc->loc_name, loc_name, MAX_LOCATOR_NAME_LEN - 1);
    new_loc->loc_name[MAX_LOCATOR_NAME_LEN - 1] = '\0';

    /* Each locator has function length of 16 bits for sids allocation. So total sids  
    allocated is 2 ^ 16  - 1 = 65535. This space [1, 65535] is further divided into static 
    and dynamic sids. Therefore, static sid space =  [1, 32767] which is [0x1, 0x7FFF]
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

    bitmap_t bm_wc;
    bitmap_init (&bm_wc, 128);
    for (int i = 0; i < prefix_len; i++)
        bitmap_set_bit_at(&bm_wc, i);
    bitmap_inverse (&bm_wc, 128);
   
    mtrie_node_t *mnode = NULL;
    mtrie_ops_result_code_t res = mtrie_insert_prefix (
                                                &srv6_sid_pools->locators_lpm_tree, 
                                                &bm_pfx, &bm_wc,
                                                128,  &mnode);
    
    bitmap_free_internal (&bm_pfx);
    bitmap_free_internal (&bm_wc);

    assert (res == MTRIE_INSERT_SUCCESS);
    mnode->data = (void *)new_loc;
    return SRv6_POOL_OK;
}

/* Called when locator is Unconfigured */
pool_error_codes_t
srv6_pool_delete_locator (srv6_sid_pools_t *srv6_sid_pools, 
                            char *loc_name,
                            char* err_msg_out) {

    srv6_locator_pool_t *loc = srv6_pool_avl_lookup_locator_by_name (
                                            srv6_sid_pools, loc_name);

    if (!loc) {
        snprintf (err_msg_out, 256, "Error : Locator %s not found", loc_name);
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

    bitmap_t bm_wc;
    bitmap_init (&bm_wc, 128);
    for (int i = 0; i < loc->loc_pfx_len; i++)
        bitmap_set_bit_at(&bm_wc, i);
    bitmap_inverse (&bm_wc, 128);

    srv6_locator_pool_t *loc1 = NULL;

    /* Remove from LPM Tree*/
    mtrie_ops_result_code_t res = mtrie_delete_prefix (
                                                &srv6_sid_pools->locators_lpm_tree, 
                                                &bm_pfx, &bm_wc, (void **)&loc1);

    bitmap_free_internal (&bm_pfx);
    bitmap_free_internal (&bm_wc);

    assert (res == MTRIE_DELETE_SUCCESS);
    assert (loc == loc1);

    /* Remove from AVL trees */
    avltree_remove (&loc->avl_glue_loc, &srv6_sid_pools->locator_pools);
    avltree_remove (&loc->avl_glue_by_name, &srv6_sid_pools->locator_pool_by_name);

    /* Destroy bitmaps */
    bitmap_free_internal (&loc->static_sid_bm);
    bitmap_free_internal (&loc->dynamic_sid_bm);

    free (loc);
    return SRv6_POOL_OK;
}

pool_error_codes_t
srv6_pool_client_borrow_locator (srv6_sid_pools_t *srv6_sid_pools, 
                            char *loc_name,
                            srv6_sid_client_t client,
                            char *err_msg_out) {

    srv6_locator_pool_t *loc = srv6_pool_avl_lookup_locator_by_name (
                                            srv6_sid_pools, loc_name);

    if (!loc) {
        snprintf (err_msg_out, 256, "Error : Locator %s not found", loc_name);
        return SRv6_POOL_ERR_LOCATOR_NOT_FOUND;
    }

    if (loc->use_clients & client) {

        snprintf (err_msg_out, 256, "Error : Locator %s already claimed by client %s", 
            loc_name, srv6_sid_client_str (client));
        return SRv6_POOL_ERR_INVALID_SID_REQUEST;
    }

    loc->use_clients |= client;

    return SRv6_POOL_OK;
}

pool_error_codes_t
srv6_pool_client_unborrow_locator (srv6_sid_pools_t *srv6_sid_pools, 
                            char *loc_name,
                            srv6_sid_client_t client,
                            char *err_msg_out) {

    srv6_locator_pool_t *loc = srv6_pool_avl_lookup_locator_by_name (
                                            srv6_sid_pools, loc_name);

    if (!loc) {
        snprintf (err_msg_out, 256, "Error : Locator %s not found", loc_name);
        return SRv6_POOL_ERR_LOCATOR_NOT_FOUND;
    }

    if (!(loc->use_clients & client)) {

        snprintf (err_msg_out, 256, "Error : Locator %s already not claimed by client %s", 
            loc_name, srv6_sid_client_str (client));
        return SRv6_POOL_ERR_INVALID_SID_REQUEST;
    }

    loc->use_clients &=  ~client;

    return SRv6_POOL_OK;
}


bool 
srv6_pool_is_locator_being_used_by_any_client (
                                    srv6_sid_pools_t *srv6_sid_pools,
                                    char *loc_name) {

    srv6_locator_pool_t *loc = srv6_pool_avl_lookup_locator_by_name (
                                            srv6_sid_pools, loc_name);

    if (!loc) {
        return false;
    }

    return (loc->use_clients != 0);
}

static pool_entry_t *
srv6_pool_adj_sid_conflict_check (srv6_locator_pool_t *loc,
                                    srv6_sid_client_t sid_client, 
                                    uint32_t ifindex,
                                    ipv6_addr_t *gw_addr) {

    pool_entry_t tmplate;
    avltree_node_t *res;

    if (ifindex == 0) {
        return NULL;
    }

    memset (&tmplate, 0, sizeof (tmplate));

    tmplate.adj_sid_key.client = sid_client;
    tmplate.adj_sid_key.ifindex = ifindex;
    if (gw_addr) {
        memcpy (&tmplate.adj_sid_key.gw_addr, gw_addr, 
            sizeof (tmplate.adj_sid_key.gw_addr));
    }

    res = avltree_lookup (&tmplate.avl_glue_asid, &loc->sid_tree_by_asid);

    if (!res) return NULL;

    return (pool_entry_t *)
                avltree_container_of (res, pool_entry_t, avl_glue_asid);
}

/* Allocate only Dynamic SIDs*/
pool_error_codes_t
srv6_pool_alloc_dynamic_sid (
                                    srv6_sid_pools_t *srv6_sid_pools, 
                                    char *loc_name ,
                                    srv6_sid_client_t sid_client,
                                    uint32_t ifindex,
                                    ipv6_addr_t *gw_addr,
                                    ipv6_addr_t *sid_out,
                                    char *err_msg_out) {

    char ipv6_addr_str[48];
    char ipv6_sid_str[48];
    pool_entry_t *pool_entry;

    srv6_locator_pool_t *loc = srv6_pool_avl_lookup_locator_by_name (
                                            srv6_sid_pools, loc_name);

    if (!loc) {
        snprintf (err_msg_out, 256, "Error : Locator %s not found", loc_name);
        return SRv6_POOL_ERR_LOCATOR_NOT_FOUND;
    }

    /* Check for Adj SID conflict. We should not have any sid assigned to
        this adjacency already !*/
    pool_entry = srv6_pool_adj_sid_conflict_check (loc, 
                                sid_client, ifindex,  gw_addr);

    if (pool_entry) {

        snprintf (err_msg_out, 256, "Error : Adj SID Conflict : SID %s already assigned to "
                "adjacency [%s 0x%x %s]", 
                inet_ntop6(&pool_entry->sid, ipv6_sid_str),
                srv6_sid_client_str (pool_entry->sid_client), 
                pool_entry->adj_sid_key.ifindex, 
                inet_ntop6(&pool_entry->adj_sid_key.gw_addr, ipv6_addr_str));
            
        return SRv6_POOL_ERR_INVALID_SID_REQUEST;
    }

    /* Check if there are any sids available */
    uint16_t aval_sid = bitmap_get_unset_bit (&loc->dynamic_sid_bm);

    if (aval_sid == UINT16_MAX) {
        snprintf (err_msg_out, 256, "Error : Locator %s : No Dynamic SIDs available", loc_name);
        return SRv6_POOL_ERR_LOCATOR_NO_DYN_SID_AVAIL;
    }

    /* Allocate the SID */
    bitmap_set_bit_at (&loc->dynamic_sid_bm, aval_sid);
    aval_sid += 32768;

    uint16_t loc_function_index = (loc->loc_pfx_len / 16) ;

    memcpy (sid_out, &loc->loc, sizeof (ipv6_addr_t));
    uint16_t (*ptr)[8] = (uint16_t (*)[8])sid_out->addr;
    (*ptr)[loc_function_index] = htons (aval_sid);

    /* Create a new pool entry */
    pool_entry_t *new_entry = (pool_entry_t *)calloc (1, sizeof (pool_entry_t));
    memcpy (&new_entry->sid, sid_out, sizeof (*sid_out));
    new_entry->sid_client = sid_client;
    new_entry->adj_sid_key.ifindex = ifindex;
    new_entry->adj_sid_key.client = sid_client;
    if (gw_addr) memcpy (&new_entry->adj_sid_key.gw_addr, gw_addr, sizeof (*gw_addr));

    assert (!avltree_insert (&new_entry->avl_glue_sid, &loc->sid_tree));

    if (ifindex) {
        assert (!avltree_insert (&new_entry->avl_glue_asid, &loc->sid_tree_by_asid));
    }

    return SRv6_POOL_OK;
}

pool_error_codes_t
srv6_pool_alloc_static_sid (
                                    srv6_sid_pools_t *srv6_sid_pools, 
                                    ipv6_addr_t *sid,
                                    srv6_sid_client_t sid_client,
                                    uint32_t ifindex,
                                    ipv6_addr_t *gw_addr,
                                    char *err_msg_out) {


    char ipv6_addr_str[48];
    char ipv6_sid_str[48];
    pool_entry_t *pool_entry;
    
    srv6_locator_pool_t *loc = srv6_pool_lookup_locator_by_lpm (
                                                    srv6_sid_pools, sid);

    if (!loc) {

        snprintf (err_msg_out, 256, "Error : No Locator found for SID %s", 
            inet_ntop6(sid, ipv6_addr_str));
        return SRv6_POOL_ERR_LOCATOR_NOT_FOUND;
    }

    if (!srv6_pool_validate_sid_format (loc, sid)) {

        snprintf (err_msg_out, 256, "Error : SID %s is not in compliant format with locator %s", 
            inet_ntop6(sid, ipv6_sid_str), loc->loc_name);
        return SRv6_POOL_ERR_INVALID_SID_REQUEST;
    }

    /* Check if the SID is already allocated */
    pool_entry_t tmplate;
    memset (&tmplate, 0, sizeof (tmplate));

    memcpy (&tmplate.sid, sid, sizeof (tmplate.sid));

    avltree_node_t *res = avltree_lookup (&tmplate.avl_glue_sid, &loc->sid_tree);

    /* Check for SID conflict*/
    if (res) {

        snprintf (err_msg_out, 256, "Error : SID %s already in use", 
            inet_ntop6 (sid, ipv6_addr_str));
        return SRv6_POOL_ERR_SID_IN_USE;
    }

    /* Check for Adj SID conflict. We should not have any sid assigned to
        this adjacency already !*/
    pool_entry = srv6_pool_adj_sid_conflict_check (loc, 
                                sid_client, ifindex, gw_addr);

    if (pool_entry) {

        snprintf (err_msg_out, 256, "Error : Adj SID Conflict : SID %s already assigned to "
                "adjacency [%s 0x%x %s]", 
                inet_ntop6(&pool_entry->sid, ipv6_sid_str),
                srv6_sid_client_str (pool_entry->sid_client), 
                pool_entry->adj_sid_key.ifindex, 
                inet_ntop6(&pool_entry->adj_sid_key.gw_addr, ipv6_addr_str));
            
        return SRv6_POOL_ERR_INVALID_SID_REQUEST;
    }

    uint16_t (*ptr)[8] = (uint16_t (*)[8])sid->addr;
    uint16_t sid_index = (*ptr)[(loc->loc_pfx_len / 16)];
    sid_index = htons (sid_index);

    if (sid_index > 32767) {
        snprintf (err_msg_out, 256, "Error : Static SIDs must be in range [0x1, 0x7FFF]");
        return SRv6_POOL_ERR_INVALID_SID_REQUEST;
    }
    
    assert (bitmap_at (&loc->static_sid_bm, sid_index) == false);
    /* Reserve the sid */
    bitmap_set_bit_at (&loc->static_sid_bm, sid_index);

    /* Create a new pool entry */
    pool_entry_t *new_entry = (pool_entry_t *)calloc (1, sizeof (pool_entry_t));
    memcpy (&new_entry->sid, sid, sizeof (new_entry->sid));
    new_entry->sid_client = sid_client;
    new_entry->adj_sid_key.client = sid_client;
    new_entry->adj_sid_key.ifindex = ifindex;
    if (gw_addr) {
        memcpy (&new_entry->adj_sid_key.gw_addr, 
            gw_addr, sizeof (new_entry->adj_sid_key.gw_addr));
    }
    
    assert (!avltree_insert (&new_entry->avl_glue_sid, &loc->sid_tree));

    if (ifindex) {
        assert (!avltree_insert (&new_entry->avl_glue_asid, &loc->sid_tree_by_asid));
    }

    return SRv6_POOL_OK;
}


/* Works for both : static and dynamic SIDs */
pool_error_codes_t
srv6_release_sid (
                            srv6_sid_pools_t *srv6_sid_pools, 
                            ipv6_addr_t *sid,
                            char *err_msg_out) {

    char ipv6_addr_str[48];

    /* Look up the locator using LPM */
    srv6_locator_pool_t *loc = srv6_pool_lookup_locator_by_lpm (
                                                    srv6_sid_pools, sid);

    if (!loc) {
        snprintf (err_msg_out, 256, "Error : No Locator found for SID %s", 
            inet_ntop6(sid, ipv6_addr_str));
        return SRv6_POOL_ERR_LOCATOR_NOT_FOUND;
    }

    if (!srv6_pool_validate_sid_format (loc, sid)) {

        snprintf (err_msg_out, 256, "Error : SID %s is not in compliant format with locator %s", 
            inet_ntop6(sid, ipv6_addr_str), loc->loc_name);
        return SRv6_POOL_ERR_INVALID_SID_REQUEST;
    }

    /* Look up the SID in the locator */
    pool_entry_t tmplate;
    memset (&tmplate, 0, sizeof (tmplate));

    memcpy (&tmplate.sid, sid, sizeof (tmplate.sid));

    avltree_node_t *res = avltree_lookup (&tmplate.avl_glue_sid, &loc->sid_tree);

    if (!res) {
        snprintf (err_msg_out, 256, "Error : SID %s not found", inet_ntop6(sid, ipv6_addr_str));
        return SRv6_POOL_ERR_SID_NOT_FOUND;
    }

    pool_entry_t *entry = (pool_entry_t *)avltree_container_of (res, pool_entry_t, avl_glue_sid);

    /* Remove the SID */
    avltree_remove (&entry->avl_glue_sid, &loc->sid_tree);

    if (entry->adj_sid_key.ifindex) {
        avltree_remove (&entry->avl_glue_asid, &loc->sid_tree_by_asid);
    }

    /* Update the bitmap*/
    uint16_t (*ptr)[8] = (uint16_t (*)[8])sid->addr;
    uint16_t sid_index = (*ptr)[(loc->loc_pfx_len / 16)];
    sid_index = htons (sid_index);    

    if (sid_index >= 32768) {
        sid_index -= 32768;
        bitmap_unset_bit_at (&loc->dynamic_sid_bm, sid_index);
    } else {
        bitmap_unset_bit_at (&loc->static_sid_bm, sid_index);
    }

    free (entry);
    return SRv6_POOL_OK;
}

pool_error_codes_t
srv6_pool_lookup_adj_sid (
                                    srv6_sid_pools_t *srv6_sid_pools, 
                                    char *loc_name,
                                   uint32_t ifindex,
                                    ipv6_addr_t *gw_addr,
                                    srv6_sid_client_t sid_client,
                                    ipv6_addr_t *sid_out,
                                    char *err_msg_out) {

    char ipv6_addr_str[48];
    ipv6_addr_t gateway_addr;

    srv6_locator_pool_t *loc = srv6_pool_avl_lookup_locator_by_name (
                                            srv6_sid_pools, loc_name);

    if (!loc) {
        snprintf (err_msg_out, 256, "Error : Locator %s not found", loc_name);
        return SRv6_POOL_ERR_LOCATOR_NOT_FOUND;
    }

    memset (&gateway_addr, 0, sizeof (gateway_addr));
    if (gw_addr) memcpy (&gateway_addr, gw_addr, sizeof (gateway_addr));

    pool_entry_t tmplate;
    memset (&tmplate, 0, sizeof (tmplate));

    tmplate.adj_sid_key.ifindex = ifindex;
    memcpy (&tmplate.adj_sid_key.gw_addr, &gateway_addr, sizeof (gateway_addr));
    tmplate.sid_client = sid_client;

    avltree_node_t *res = avltree_lookup (&tmplate.avl_glue_asid, &loc->sid_tree_by_asid);

    if (!res) {

        snprintf (err_msg_out, 256, 
            "Error : Could not find Adj SID for [%s 0x%x %s]",
            srv6_sid_client_str(sid_client), 
            ifindex, 
            inet_ntop6 (&gateway_addr, ipv6_addr_str));

        return SRv6_POOL_ERR_SID_NOT_FOUND;
    }

    pool_entry_t *entry = (pool_entry_t *)avltree_container_of (
                                            res, pool_entry_t, avl_glue_asid);

    memcpy (sid_out, &entry->sid, sizeof (*sid_out));
    return SRv6_POOL_OK;
}

const char * 
srv6_sid_client_str (srv6_sid_client_t client) {

    switch (client) {

    case srv6_sid_client_isis:
        return "isis-srv6";
    case srv6_sid_client_srv6:
        return "srv6-sid-mgr";
    case srv6_sid_client_bgp:
        return "bgp-srv6";
    case srv6_sid_client_ospfv3:
        return "ospfv3-srv6";
    default:
        return NULL;
    }

    return NULL;
}

/*
router# show segment-routing srv6 sid 
SID                  Locator      Behavior          Context            		          Owner
---                  -------      --------          -------            	              -----
FC01:101:2::          loc1         uN (PSP/USD)                                       SID-MGR 
FC01:101:2:E000::     loc1         uDT4                                               ospfv3-srv6
FC01:101:2:E001::     loc1         uDT6                                               bgp-srv6
FC01:101:2:E002::     loc1         uA (PSP/USD)      Ethernet2/0 2001::99:2:3:3       isis-srv6 
FC01:101:2:E003::     loc1         uA (PSP/USD)      Ethernet2/1 2001::100:2:3:3      isis-srv6 
FC01:101:2:E004::     loc1         uA (PSP/USD)      Ethernet3/0 2001::99:2:4:4       isis-srv6 
FC01:101:2:E005::     loc1         uA (PSP/USD)      Ethernet3/1 2001::100:2:4:4      isis-srv6 
FC01:101:2:E006::     loc1         uA (PSP/USD)      Ethernet4/0 2001::99:2:5:5       isis-srv6 
FC01:101:2:E007::     loc1         uA (PSP/USD)      Ethernet4/1 2001::100:2:5:5      isis-srv6 
*/

static void 
srv6_pool_show_one_locator(srv6_locator_pool_t *loc) {

    avltree_node_t *curr;
    pool_entry_t *sid_entry;
    char ipv6_addr_str[48];
    char ipv6_addr_gw_str[48];

    cprintf ("%s : %s/%d\n", loc->loc_name, 
        inet_ntop6 (&loc->loc, ipv6_addr_str), loc->loc_pfx_len);

    ITERATE_AVL_TREE_BEGIN ((&loc->sid_tree), curr) {

        sid_entry = (pool_entry_t *)avltree_container_of (curr, pool_entry_t, avl_glue_sid);

        if (sid_entry->adj_sid_key.ifindex) {

            cprintf ("  %s    %s     %u - %s\n", 
                inet_ntop6 (&sid_entry->sid, ipv6_addr_str), 
                srv6_sid_client_str (sid_entry->sid_client), 
                sid_entry->adj_sid_key.ifindex,
                inet_ntop6 (&sid_entry->adj_sid_key.gw_addr, ipv6_addr_gw_str));
        }
        else {
            
            cprintf ("  %s    %s\n", 
                inet_ntop6 (&sid_entry->sid, ipv6_addr_str), 
                srv6_sid_client_str (sid_entry->sid_client));
        }

    } ITERATE_AVL_TREE_END;

}
 
void 
srv6_show_locator (srv6_sid_pools_t *srv6_sid_pools, char *loc_name)  {

    avltree_node_t *curr;
    srv6_locator_pool_t *loc;

    cprintf ("\nSRv6 sid pool \n--------------\n");

    if (loc_name) {

        loc = srv6_pool_avl_lookup_locator_by_name(
            srv6_sid_pools, loc_name);

        if (loc) {
            srv6_pool_show_one_locator(loc);
        }

        return;
    }

    ITERATE_AVL_TREE_BEGIN ((&srv6_sid_pools->locator_pools), curr) {

        loc = (srv6_locator_pool_t *) avltree_container_of(
                curr, srv6_locator_pool_t, avl_glue_loc);

        srv6_pool_show_one_locator(loc);

        cprintf ("\n");

    } ITERATE_AVL_TREE_END;
}

