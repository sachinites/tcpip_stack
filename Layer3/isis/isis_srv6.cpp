#include <assert.h>
#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_srv6.h"
#include "isis_advt.h"
#include "isis_tlv_struct.h"
#include "../../Tracer/tracer.h"
#include "../SegmentRouting/SRv6/cp/srv6_sid_pool.h"

extern void 
External_srv6_import_locator_config (
        node_t *node,
        const char *loc_name, 
        ipv6_addr_t *prefix, 
        uint8_t *prefix_len,
        uint32_t *metric,
        uint16_t *mt_id,
        uint8_t *algorithm,
        uint8_t *flags);

/* 0 if locator is enable and matching
    1 if locator is set, but not mathching 
     -1 if locator is not even set
*/
int8_t 
isis_srv6_is_loc_enabled (node_t *node, char *locator_name) {

    isis_srv6_config_t *srv6_config = isis_srv6_get_config(node);
    
    if (!srv6_config) return -1;

    int old_loc_len = strlen(srv6_config->loc.locator_name);
    int new_loc_len = strlen(locator_name);

    if (old_loc_len != new_loc_len) return 1;

    if (strncmp(srv6_config->loc.locator_name, locator_name, 
        old_loc_len) == 0) return 0;

    return 1;
}

isis_srv6_config_t *
isis_srv6_get_config(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return NULL;

    return node_info->srv6_config;
}

int 
 avltree_pfx_sid_cmp (const avltree_node_t *data1, const avltree_node_t *data2) {

    isis_srv6_pfx_sid_t *pfxsid1 = 
        (isis_srv6_pfx_sid_t *)avltree_container_of(data1, isis_srv6_pfx_sid_t, avl_glue);
    
    isis_srv6_pfx_sid_t *pfxsid2 = 
        (isis_srv6_pfx_sid_t *)avltree_container_of(data2, isis_srv6_pfx_sid_t, avl_glue);

    if (memcmp(pfxsid1->prefix.addr, pfxsid2->prefix.addr, 16) < 0) return -1;
    if (memcmp(pfxsid1->prefix.addr, pfxsid2->prefix.addr, 16) > 0) return 1;
    
    return 0;
 }

int
avltree_adj_sid_cmp (const avltree_node_t *data1, const avltree_node_t *data2) {

    isis_srv6_adj_sid_t *adjsid1 = 
        (isis_srv6_adj_sid_t *)avltree_container_of(data1, isis_srv6_adj_sid_t, avl_glue);
    
    isis_srv6_adj_sid_t *adjsid2 = 
        (isis_srv6_adj_sid_t *)avltree_container_of(data2, isis_srv6_adj_sid_t, avl_glue);

    if (memcmp(adjsid1->prefix.addr, adjsid2->prefix.addr, 16) < 0) return -1;
    if (memcmp(adjsid1->prefix.addr, adjsid2->prefix.addr, 16) > 0) return 1;

    return 0;
}

int
isis_srv6_new_locator_set (node_t *node, char *new_locator) {

    uint8_t flags;
    uint32_t metric;
    uint16_t mt_id;
    uint8_t algorithm;
    uint8_t prefix_len;
    ipv6_addr_t loc_prefix;
    char err_msg[256];
    pool_error_codes_t prc = SRv6_POOL_OK;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    External_srv6_import_locator_config (node, new_locator, 
        &loc_prefix, &prefix_len, &metric, &mt_id, &algorithm, &flags);

    if (is_ipv6_addr_unspecified (&loc_prefix.addr)) {

        cprintf ("Error : Non-existing locator\n");
        return -1;
    }

    int8_t rc = isis_srv6_is_loc_enabled  (node, new_locator);

    switch (rc) {
        case 1:
            cprintf ("Error : Remove the existing locator first\n");
            return -1;
        case 0:
            return 0;
        case -1:
            break;
    }

    /* Claim that this client is using the locator */
    prc = srv6_pool_client_borrow_locator (
             (NODE_SRv6_SID_POOL(node)), 
             new_locator,  srv6_sid_client_isis, 
             err_msg);

    if (prc != SRv6_POOL_OK) {
        cprintf ("%s : %s, err-code : %d\n", node->node_name, err_msg, prc);
        return -1;
    }

    if (!node_info->srv6_config) {
        node_info->srv6_config = (isis_srv6_config_t *)XCALLOC(0, 1, isis_srv6_config_t);
        avltree_init (&node_info->srv6_config->pfxsid_tree, avltree_pfx_sid_cmp);
        avltree_init (&node_info->srv6_config->adj_sid_tree, avltree_adj_sid_cmp);
    }

    strncpy(node_info->srv6_config->loc.locator_name, new_locator, 
        sizeof (node_info->srv6_config->loc.locator_name));
    memcpy(&node_info->srv6_config->loc.prefix, 
        &loc_prefix, sizeof (loc_prefix));

    node_info->srv6_config->loc.prefix_len = prefix_len;
    node_info->srv6_config->loc.metric = metric;
    node_info->srv6_config->loc.mt_id = mt_id;
    node_info->srv6_config->loc.flags = flags;
    node_info->srv6_config->loc.algorithm = algorithm;

    isis_srv6_locator_t *loc = &node_info->srv6_config->loc;

    isis_advertise_locator_ipv6_reachability_tlv236 (node, loc);
    isis_advertise_locator_ipv6_reachability_mt_tlv237 (node, loc);
    isis_advertise_locator_tlv27_instance (node, loc, true);

    return 0;
}

void
isis_srv6_stop_adj_sid_advertisement (node_t *node) {}

void
isis_srv6_locator_unset (node_t *node) {

    char err_msg[256];
    avltree_node_t *curr = NULL;
    isis_srv6_pfx_sid_t *pfxsid = NULL;
    isis_srv6_adj_sid_t *adjsid = NULL;
    pool_error_codes_t prc = SRv6_POOL_OK;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    if (!node_info->srv6_config) return;

    isis_srv6_locator_t *loc = ISIS_SRV6_LOC(node);

    isis_withdraw_locator_ipv6_reachability_tlv236 (node, loc); 
    isis_withdraw_locator_ipv6_reachability_mt_tlv237 (node, loc); 
    isis_srv6_stop_adj_sid_advertisement (node);
    isis_withdraw_locator_tlv27_all_instances  (node);

    assert (!loc->loc_adv_tlv236);
    assert (!loc->loc_adv_tlv237);
    assert (IS_GLTHREAD_LIST_EMPTY (&loc->adv_data_list_head));
    // ToDo : assert < check all adj sid are freed >

    ITERATE_AVL_TREE_BEGIN(&node_info->srv6_config->pfxsid_tree, curr) {
        
        pfxsid = avltree_container_of(curr, isis_srv6_pfx_sid_t , avl_glue);
        assert (!pfxsid->adv_data);
        avltree_remove(&pfxsid->avl_glue, &node_info->srv6_config->pfxsid_tree);

        prc = srv6_release_sid (
                            (NODE_SRv6_SID_POOL(node)), 
                            &pfxsid->prefix,
                            err_msg);

        assert (prc == SRv6_POOL_OK);

        XFREE(pfxsid);

    } ITERATE_AVL_TREE_END;

    ITERATE_AVL_TREE_BEGIN(&node_info->srv6_config->adj_sid_tree, curr) {
        
        adjsid = avltree_container_of(curr, isis_srv6_adj_sid_t, avl_glue);
        assert (!adjsid->adv_data);
        avltree_remove(&adjsid->avl_glue, &node_info->srv6_config->adj_sid_tree);

        prc = srv6_release_sid (
                            (NODE_SRv6_SID_POOL(node)), 
                            &adjsid->prefix,
                            err_msg);

        assert (prc == SRv6_POOL_OK);

        XFREE(adjsid);

    } ITERATE_AVL_TREE_END;

    prc = srv6_pool_client_unborrow_locator (
             (NODE_SRv6_SID_POOL(node)), 
             loc->locator_name,  srv6_sid_client_isis, 
             err_msg);

    assert (prc == SRv6_POOL_OK);

    XFREE(node_info->srv6_config);
    node_info->srv6_config = NULL;
}

static void 
isis_advertise_locator_ipv6_reachability_tlv236 (
                        node_t *node, 
                        isis_srv6_locator_t *loc) {

    isis_advt_info_t advt_info;
    isis_adv_data_t *advt_data;

    assert (!loc->loc_adv_tlv236);

    loc->loc_adv_tlv236 = (isis_adv_data_t *)XCALLOC (0, 1, isis_adv_data_t);
    advt_data = loc->loc_adv_tlv236 ;

    memcpy (advt_data->u.v6pfx.prefix, loc->prefix.addr, 16);
    advt_data->u.v6pfx.metric = loc->metric;
    advt_data->u.v6pfx.mask = loc->prefix_len;
    advt_data->u.v6pfx.flags = loc->flags;

    advt_data->fragment = NULL;
    advt_data->src.holder = &loc->loc_adv_tlv236;
    init_glthread (&advt_data->glue);
    advt_data->tlv_no = ISIS_TLV_IPV6_REACH;
    advt_data->tlv_size = isis_get_adv_data_size (advt_data);
    advt_data->flags = 0;

    /* Now Advertise the TLV*/
    isis_advertise_tlv (node, 0, advt_data, &advt_info);
}

void 
isis_withdraw_locator_ipv6_reachability_tlv236 (
                        node_t *node, 
                        isis_srv6_locator_t *loc) {

    isis_adv_data_t *advt_data;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    assert(loc->loc_adv_tlv236);

    advt_data = loc->loc_adv_tlv236;

    if (IS_BIT_SET(advt_data->flags, ISIS_ADVT_DATA_F_WAIT_LISTED))
        isis_wait_list_advt_data_remove(node, advt_data);
    else
        isis_withdraw_tlv_advertisement(node, advt_data);
    
    isis_advt_data_clear_backlinkage(node_info, advt_data);
    isis_free_advt_data(advt_data);
    loc->loc_adv_tlv236 = NULL;
}

void 
isis_advertise_locator_ipv6_reachability_mt_tlv237 (
                        node_t *node, 
                        isis_srv6_locator_t *loc) {

    isis_advt_info_t advt_info;
    isis_adv_data_t *advt_data;

    assert (!loc->loc_adv_tlv237);

    loc->loc_adv_tlv237 = (isis_adv_data_t *)XCALLOC (0, 1, isis_adv_data_t);
    advt_data = loc->loc_adv_tlv237 ;

    memcpy (advt_data->u.v6pfx.prefix, loc->prefix.addr, 16);
    advt_data->u.v6pfx.metric = loc->metric;
    advt_data->u.v6pfx.mask = loc->prefix_len;
    advt_data->u.v6pfx.flags = loc->flags;

    advt_data->fragment = NULL;
    advt_data->src.holder = &loc->loc_adv_tlv237;
    init_glthread (&advt_data->glue);
    advt_data->tlv_no = ISIS_TLV_IPV6_MT_REACH;
    advt_data->tlv_size = isis_get_adv_data_size (advt_data);
    advt_data->flags = 0;

    /* Now Advertise the TLV*/
    isis_advertise_tlv (node, 0, advt_data, &advt_info);
}

void 
isis_withdraw_locator_ipv6_reachability_mt_tlv237 (
                        node_t *node, 
                        isis_srv6_locator_t *loc) {

    isis_adv_data_t *advt_data;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    assert(loc->loc_adv_tlv237);

    advt_data = loc->loc_adv_tlv237;

    if (IS_BIT_SET(advt_data->flags, ISIS_ADVT_DATA_F_WAIT_LISTED))
        isis_wait_list_advt_data_remove(node, advt_data);
    else
        isis_withdraw_tlv_advertisement(node, advt_data);
    
    isis_advt_data_clear_backlinkage(node_info, advt_data);
    isis_free_advt_data(advt_data);
    loc->loc_adv_tlv237 = NULL;
}

/* 
    CMP_PREFERRED - favoring data1
    CMP_NOT_PREFERRED - favoring data2
*/
static int 
 locator_advt_data_comp_fn (void *_data1, void *_data2) {

    isis_adv_data_t *data1 = ( isis_adv_data_t *)_data1;
    isis_adv_data_t *data2 = ( isis_adv_data_t *)_data2;

    if ( IS_BIT_SET(data1->flags , ISIS_ADVT_DATA_F_WAIT_LISTED ))   return CMP_NOT_PREFERRED;
    if ( IS_BIT_SET(data2->flags , ISIS_ADVT_DATA_F_WAIT_LISTED ))   return CMP_PREFERRED;

    if (!data1->fragment) return CMP_PREFERRED;
    if (!data2->fragment) return CMP_NOT_PREFERRED;

    if (data1->fragment->bytes_filled < data2->fragment->bytes_filled) return CMP_PREFERRED;
    if (data1->fragment->bytes_filled > data2->fragment->bytes_filled) return CMP_NOT_PREFERRED;

    return CMP_PREF_EQUAL;
 }

isis_adv_data_t *
isis_advertise_locator_tlv27_instance (node_t *node, 
                    isis_srv6_locator_t *loc, bool advertise) {

    isis_advt_info_t advt_info;
    isis_adv_data_t *advt_data;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    advt_data = (isis_adv_data_t *)XCALLOC (0, 1, isis_adv_data_t);

    memcpy(advt_data->u.srv6_loc.prefix.addr, loc->prefix.addr, 16);
    advt_data->u.srv6_loc.prefix_len = loc->prefix_len;
    advt_data->u.srv6_loc.metric = loc->metric;
    advt_data->u.srv6_loc.mt_id = loc->mt_id;
    advt_data->u.srv6_loc.algorithm = loc->algorithm;
    advt_data->u.srv6_loc.flags = loc->flags;
    init_glthread(&advt_data->u.srv6_loc.sibling_glue);
    init_glthread(&advt_data->u.srv6_loc.pfxsid_list_head);

    /* No back linkage, we will destroy back linkage by searching this locator
        TLV in loc->adv_data_list_head list*/
    advt_data->fragment = NULL;
    advt_data->src.holder = NULL;
    init_glthread(&advt_data->glue);
    advt_data->tlv_no = ISIS_TLV_LOCATOR;
    advt_data->tlv_size = isis_get_adv_data_size(advt_data);
    advt_data->flags = 0;

    if (advertise)
        isis_advertise_tlv(node, 0, advt_data, &advt_info);

    /* Whether fragment is allocated or not, put the locator TLV in
        sibling list. If fragment is not assigned, it will be de-prioritized*/
    glthread_priority_insert (&loc->adv_data_list_head, 
                    &advt_data->u.srv6_loc.sibling_glue, 
                    locator_advt_data_comp_fn, 
                    (int) (&((isis_adv_data_t *)0)->u.srv6_loc.sibling_glue));

    return advt_data;
}

void 
isis_withdraw_locator_tlv27_instance (node_t *node, isis_adv_data_t *advt_data) {

    glthread_t *curr;
    isis_adv_data_t *pfxsid_adv_data;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    assert (advt_data->tlv_no == ISIS_TLV_LOCATOR);

    if (IS_BIT_SET(advt_data->flags, ISIS_ADVT_DATA_F_WAIT_LISTED))
        isis_wait_list_advt_data_remove(node, advt_data);
    else
        isis_withdraw_tlv_advertisement(node, advt_data);
        
    isis_advt_data_clear_backlinkage(node_info, advt_data);

    /* Delete all pfx sids advertisement data */
    while ((curr = dequeue_glthread_first (&advt_data->u.srv6_loc.pfxsid_list_head))) {
        pfxsid_adv_data = srv6_pfxsid_sibling_glue_to_pfxsid_adv_data (curr);
        isis_advt_data_clear_backlinkage(node_info, pfxsid_adv_data);
        advt_data->tlv_size -= pfxsid_adv_data->tlv_size;
        advt_data->u.srv6_loc.subtlv_len -= pfxsid_adv_data->tlv_size;
        isis_free_advt_data(pfxsid_adv_data);
    }

    remove_glthread(&advt_data->u.srv6_loc.sibling_glue);
    isis_free_advt_data(advt_data);
}

void 
isis_withdraw_locator_tlv27_all_instances (node_t *node) {

    glthread_t *curr;
    isis_adv_data_t *advt_data;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if (!node_info) return;

    isis_srv6_config_t *srv6_config = isis_srv6_get_config(node);

    if (!srv6_config) return;

    isis_srv6_locator_t *loc = ISIS_SRV6_LOC(node);

    while ((curr = dequeue_glthread_first(&loc->adv_data_list_head))) {
        advt_data = srv6_loc_sibling_glue_to_locator_adv_data(curr);
        isis_withdraw_locator_tlv27_instance (node, advt_data);
    }
}

void
isis_srv6_advertise_prefix_sid (node_t *node, isis_srv6_pfx_sid_t *pfx_sid ) {

    isis_advt_info_t advt_info;
    isis_adv_data_t *pfx_sid_advt_data;

    assert (!pfx_sid->adv_data);

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if (!node_info) return;

    isis_srv6_config_t *srv6_config = isis_srv6_get_config (node);

    if (!srv6_config) return;

    isis_srv6_locator_t *loc = ISIS_SRV6_LOC(node);

    isis_adv_data_t *loc_adv_data = srv6_loc_sibling_glue_to_locator_adv_data (
                                        glthread_get_next (&loc->adv_data_list_head));

    /* Do not attempt to advertise prefix sids unless locator itself is advertised */
    assert(loc_adv_data);

    pfx_sid_advt_data = (isis_adv_data_t *)XCALLOC(0, 1, isis_adv_data_t);
    pfx_sid->adv_data = pfx_sid_advt_data;

    pfx_sid_advt_data->tlv_no = ISIS_LOCATOR_PFX_SID_SUBTLV;
    memcpy(pfx_sid_advt_data->u.srv6_pfxsid.prefix.addr, pfx_sid->prefix.addr, 16);
    pfx_sid_advt_data->u.srv6_pfxsid.flags = pfx_sid->flags;
    pfx_sid_advt_data->u.srv6_pfxsid.endfn = (Srv6_endpcode_t)pfx_sid->endfn;
    pfx_sid_advt_data->u.srv6_pfxsid.subtlv_len = 0;
    pfx_sid_advt_data->src.holder = &pfx_sid->adv_data;
    pfx_sid_advt_data->u.srv6_pfxsid.parent = NULL;
    init_glthread(&pfx_sid_advt_data->u.srv6_pfxsid.sibling_glue);
    init_glthread(&pfx_sid_advt_data->glue);
    pfx_sid_advt_data->tlv_size = isis_get_adv_data_size(pfx_sid_advt_data);    

    /* Check if the locator TLV can accomodate this subtlv or not*/
    if (
        ((loc_adv_data->tlv_size + pfx_sid_advt_data->tlv_size) <= 255)
        &&
        ((loc_adv_data->u.srv6_loc.subtlv_len + pfx_sid_advt_data->tlv_size) <= 255)
        ) {

        /* If locator TLV was advertised, remove and readvertise it again. Dont just
            regen the fragment because we dont know whether the fragment can acoomodate
            the bloated locator TLV now or not */
        if (IS_BIT_SET (loc_adv_data->flags, ISIS_ADVT_DATA_F_ADVERTISED )) {
            isis_withdraw_tlv_advertisement (node, loc_adv_data);
        }

        /* Update the size and tlv len. Note that, never change the length of TLVs
            if it is being advertised. Thats why in prev step we un-advertise it first*/
        loc_adv_data->tlv_size += pfx_sid_advt_data->tlv_size;
        loc_adv_data->u.srv6_loc.subtlv_len += pfx_sid_advt_data->tlv_size;

        /* Update the linkages*/
        pfx_sid_advt_data->u.srv6_pfxsid.parent = loc_adv_data;
        glthread_add_next (&loc_adv_data->u.srv6_loc.pfxsid_list_head, 
            &pfx_sid_advt_data->u.srv6_pfxsid.sibling_glue);

        /* Reposition the locator TLV in siblings list*/
        remove_glthread(&loc_adv_data->u.srv6_loc.sibling_glue);
        glthread_priority_insert (&loc->adv_data_list_head, 
                    &loc_adv_data->u.srv6_loc.sibling_glue, 
                    locator_advt_data_comp_fn, 
                    (int) (&((isis_adv_data_t *)0)->u.srv6_loc.sibling_glue));

        if (!IS_BIT_SET (loc_adv_data->flags, ISIS_ADVT_DATA_F_WAIT_LISTED)) {
            isis_advertise_tlv(node, 0, loc_adv_data, &advt_info);
            tracer (ISIS_TR(node), TR_ISIS_SRV6, 
                "%s : Locator TLV Updated/advertised after absorbing new pfx sid subtlv\n",  ISIS_SRV6 );
        }

        return;
    }

    /* The Best locator TLV cannot accomodate a new subtlv*/

    /* Create a new Locator TLV*/
    loc_adv_data = isis_advertise_locator_tlv27_instance(node, loc, false);

    /* Update the size and tlv len. Note that, never change the length of TLVs
        if it is being advertised. Thats why in prev step we un-advertise it first*/
    loc_adv_data->tlv_size += pfx_sid_advt_data->tlv_size;
    loc_adv_data->u.srv6_loc.subtlv_len += pfx_sid_advt_data->tlv_size;

    /* Update the linkages*/
    pfx_sid_advt_data->u.srv6_pfxsid.parent = loc_adv_data;
    glthread_add_next(&loc_adv_data->u.srv6_loc.pfxsid_list_head,
                      &pfx_sid_advt_data->u.srv6_pfxsid.sibling_glue);
    
    isis_advertise_tlv(node, 0, loc_adv_data, &advt_info);
    tracer (ISIS_TR(node), TR_ISIS_SRV6, 
                "%s : New Locator TLV advertised after absorbing new pfx sid subtlv\n",  ISIS_SRV6 );    
}

void
isis_srv6_advertise_all_prefix_sids (node_t *node ) {

    avltree_node_t *curr = NULL;
    isis_srv6_pfx_sid_t *pfxsid = NULL;

    isis_adv_data_t *pfx_sid_advt_data;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if (!node_info) return;

    isis_srv6_config_t *srv6_config = isis_srv6_get_config (node);

    if (!srv6_config) return;

    ITERATE_AVL_TREE_BEGIN(&srv6_config->pfxsid_tree, curr) {
        
        pfxsid = avltree_container_of(curr, isis_srv6_pfx_sid_t , avl_glue);
        if (pfxsid->adv_data) continue;
        isis_srv6_advertise_prefix_sid (node, pfxsid);

    } ITERATE_AVL_TREE_END;    

}

void 
isis_srv6_withdraw_pfxsid_advertisement (node_t *node, isis_srv6_pfx_sid_t *pfx_sid) {

    isis_adv_data_t *pfxsid_adv_data;

    if (!pfx_sid->adv_data) return;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if (!node_info) return;

    isis_srv6_config_t *srv6_config = isis_srv6_get_config (node);

    if (!srv6_config) return;

    isis_srv6_locator_t *loc = ISIS_SRV6_LOC(node);

    /* Break bidirectional linkage between pfxsid_adv_data and pfx_sid */
    pfxsid_adv_data = pfx_sid->adv_data;
    isis_advt_data_clear_backlinkage(node_info, pfxsid_adv_data );

    isis_adv_data_t *loc_adv_data = pfxsid_adv_data->u.srv6_pfxsid.parent;

    /* Break the linkage between prefix sid advt data and locator advt data*/
    remove_glthread (&pfxsid_adv_data->u.srv6_pfxsid.sibling_glue);
    pfxsid_adv_data->u.srv6_pfxsid.parent = NULL;

    loc_adv_data->tlv_size -= pfxsid_adv_data->tlv_size;
    loc_adv_data->u.srv6_loc.subtlv_len -= pfxsid_adv_data->tlv_size;
    
    isis_free_advt_data (pfxsid_adv_data);

    if (IS_BIT_SET (loc_adv_data->flags, ISIS_ADVT_DATA_F_ADVERTISED)) {
        isis_schedule_regen_fragment (node, loc_adv_data->fragment, isis_event_tlv_removed);
    }
    
    tracer (ISIS_TR(node), TR_ISIS_SRV6, 
        "%s : Locator TLV Updated/advertised after removing pfx sid subtlv\n",  ISIS_SRV6 );    

    if (IS_GLTHREAD_LIST_EMPTY (&loc_adv_data->u.srv6_loc.pfxsid_list_head)) {

        /* Get rid of LOC TLV only if it is non-last loc TLV*/
        if ((glthread_get_next (&loc->adv_data_list_head) != &loc_adv_data->u.srv6_loc.sibling_glue) ||
                    glthread_get_next (&loc_adv_data->u.srv6_loc.sibling_glue) ) {

            isis_withdraw_locator_tlv27_instance(node, loc_adv_data);
            return;
        }
    }

}

void
isis_add_prefix_sid_to_locator (node_t *node, 
                                char *loc_name, 
                                ipv6_addr_t *prefix_sid, 
                                Srv6_endpcode_t endfn, 
                                uint8_t flavors) {

    char ipv4_addr_str[16];
    char ipv6_addr_str[48];

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    isis_srv6_config_t *srv6_config = isis_srv6_get_config(node);

    if (!srv6_config) return;

    /* Ignore if locator is not configured first */
    if (isis_srv6_is_loc_enabled(node, loc_name)) {

        tracer (ISIS_TR(node), TR_ISIS_SRV6, 
            "%s : Ignoring PFX SID ADD : %s/128  as locator is not set\n", 
                ISIS_ERROR,
                inet_ntop6(prefix_sid, ipv6_addr_str));
        return;
    }

    /* Ignore if prefix sid is already learnt from ISIS*/   
    isis_srv6_pfx_sid_t pfx_sid_template;
    memset(&pfx_sid_template.avl_glue, 0, sizeof (pfx_sid_template.avl_glue));
    memcpy (pfx_sid_template.prefix.addr, prefix_sid->addr, 16);

    if (avltree_lookup(&pfx_sid_template.avl_glue, &srv6_config->pfxsid_tree)) {

        tracer (ISIS_TR(node), TR_ISIS_SRV6, 
            "%s : Ignoring PFX SID ADD : %s/128 as it is already learnt\n", 
                ISIS_ERROR,
                inet_ntop6(prefix_sid, ipv6_addr_str));
        return;
    }

    isis_srv6_pfx_sid_t *pfx_sid = (isis_srv6_pfx_sid_t *)XCALLOC(0, 1, isis_srv6_pfx_sid_t);
    memcpy(pfx_sid->prefix.addr, prefix_sid->addr, 16);
    pfx_sid->flags = flavors;
    pfx_sid->endfn = endfn;

    avltree_insert(&pfx_sid->avl_glue, &srv6_config->pfxsid_tree);

    tracer (ISIS_TR(node), TR_ISIS_SRV6, 
        "%s : AVL TREE PFX SID ADD : %s/128 Success\n", 
            ISIS_SRV6,
            inet_ntop6(prefix_sid, ipv6_addr_str));

    /* Update the locator Advertisement */
    isis_srv6_advertise_prefix_sid (node, pfx_sid );
}

void
isis_delete_prefix_sid_from_locator (node_t *node, 
                                char *loc_name, 
                                ipv6_addr_t *prefix_sid) {

    char ipv4_addr_str[16];
    char ipv6_addr_str[48];
    isis_srv6_locator_t *loc;
    isis_advt_info_t advt_info;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    isis_srv6_config_t *srv6_config = isis_srv6_get_config(node);

    if (!srv6_config) return;

    /* Ignore if locator is not configured first */
    if (isis_srv6_is_loc_enabled(node, loc_name)) return;

    loc = ISIS_SRV6_LOC(node);

    /* Ignore if prefix sid is already learnt from ISIS*/   
    isis_srv6_pfx_sid_t pfx_sid_template;
    memset(&pfx_sid_template.avl_glue, 0, sizeof (pfx_sid_template.avl_glue));
    memcpy (pfx_sid_template.prefix.addr, prefix_sid->addr, 16);

    avltree_node_t *avl_node = avltree_lookup(&pfx_sid_template.avl_glue, 
                                                            &srv6_config->pfxsid_tree);

    if (!avl_node) {

        tracer (ISIS_TR(node), TR_ISIS_SRV6 | TR_ISIS_ERRORS,
            "%s : Error : PFX SID DEL : %s/128 Failed, Avl look-up failed\n", 
                ISIS_SRV6,
                inet_ntop6(prefix_sid, ipv6_addr_str));      

        cprintf(
            "%s: %s : Error : PFX SID DEL : %s/128 Failed, Avl look-up failed\n", 
                node->node_name,
                ISIS_SRV6,
                inet_ntop6(prefix_sid, ipv6_addr_str)); 
        return;
    }

    isis_srv6_pfx_sid_t *pfx_sid = avltree_container_of (
                                    avl_node, isis_srv6_pfx_sid_t, avl_glue);

    avltree_remove (&pfx_sid->avl_glue, &srv6_config->pfxsid_tree);

    tracer (ISIS_TR(node), TR_ISIS_SRV6, 
        "%s : PFX SID DEL : %s/128 from Success\n", 
            ISIS_SRV6,
            inet_ntop6(prefix_sid, ipv6_addr_str));      

    isis_srv6_withdraw_pfxsid_advertisement (node, pfx_sid);
    XFREE(pfx_sid);
}
