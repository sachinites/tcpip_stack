#include <assert.h>
#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_srv6.h"
#include "isis_advt.h"
#include "isis_tlv_struct.h"
#include "../../Tracer/tracer.h"

extern 
void isis_recv_ipc_updates (node_t *node, 
                                             ips_major_code_t major_code,
                                             uint32_t minor_code,
                                             void *msg,
                                             uint32_t msg_size) ;

/* 0 if locator is enable and matching
    1 if locator is set, but not mathching 
     -1 if locator is not even set
*/
int8_t 
isis_srv6_is_loc_enabled (node_t *node, char *locator_name) {

    isis_srv6_config_t *srv6_config = isis_srv6_get_config(node);
    
    if (!srv6_config) return -1;

    int old_loc_len = strlen(srv6_config->locator_name);
    int new_loc_len = strlen(locator_name);

    if (old_loc_len != new_loc_len) return 1;

    if (strncmp(srv6_config->locator_name, locator_name, 
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

    isis_srv6_pfx_sid_t *pfxsid1 = (isis_srv6_pfx_sid_t *)data1;
    isis_srv6_pfx_sid_t *pfxsid2 = (isis_srv6_pfx_sid_t *)data2;

    if (memcmp(pfxsid1->prefix.addr, pfxsid2->prefix.addr, 16) < 0) return -1;
    if (memcmp(pfxsid1->prefix.addr, pfxsid2->prefix.addr, 16) > 0) return 1;
    return 0;
 }

int
avltree_adj_sid_cmp (const avltree_node_t *data1, const avltree_node_t *data2) {

    isis_srv6_adj_sid_t *adjsid1 = (isis_srv6_adj_sid_t *)data1;
    isis_srv6_adj_sid_t *adjsid2 = (isis_srv6_adj_sid_t *)data2;

    if (memcmp(adjsid1->prefix.addr, adjsid2->prefix.addr, 16) < 0) return -1;
    if (memcmp(adjsid1->prefix.addr, adjsid2->prefix.addr, 16) > 0) return 1;
    return 0;
}

void
isis_srv6_new_locator_set (node_t *node, char *new_locator) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    if (!node_info->srv6_config) {
        node_info->srv6_config = (isis_srv6_config_t *)XCALLOC(0, 1, isis_srv6_config_t);
        avltree_init (&node_info->srv6_config->pfxsid_tree, avltree_pfx_sid_cmp);
        avltree_init (&node_info->srv6_config->adj_sid_tree, avltree_adj_sid_cmp);
    }

    strncpy(node_info->srv6_config->locator_name, new_locator, 32);
    
    cp_ips_join (node, IPC_SRV6_INFO, 
        IPC_ALL_MINOR_UPDATES, isis_recv_ipc_updates);
    
    /* Request SRv6 to send us all SRv6 SID Data*/
    cp_ipc_send (node, IPC_IGP_REQUEST_SRV6_PUBLISH_SIDs, 
        IPC_REQ_SRV6_PUBLISH_PFX_SIDS | IPC_REQ_SRV6_PUBLISH_ADJ_SIDS, 
        0, 0, false);
}

void
isis_srv6_locator_unset (node_t *node) {

    avltree_node_t *curr = NULL;
    isis_srv6_pfx_sid_t *pfxsid = NULL;
    isis_srv6_adj_sid_t *adjsid = NULL;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    if (!node_info->srv6_config) return;

     isis_srv6_stop_locator_advertisement (node);
     isis_srv6_stop_adj_sid_advertisement (node);

    assert (!node_info->tlv_global_advt.v6loc_adv_data_tlv236);
    assert (!node_info->tlv_global_advt.v6loc_adv_data_tlv237);
    assert (!node_info->tlv_global_advt.v6loc_adv_data_tlv27);
    // assert < check all adj sid are freed >

    ITERATE_AVL_TREE_BEGIN(&node_info->srv6_config->pfxsid_tree, curr) {
        
        pfxsid = avltree_container_of(curr, isis_srv6_pfx_sid_t , avl_glue);
        assert(pfxsid);
        XFREE(pfxsid);

    } ITERATE_AVL_TREE_END;

    ITERATE_AVL_TREE_BEGIN(&node_info->srv6_config->adj_sid_tree, curr) {
        
        adjsid = avltree_container_of(curr, isis_srv6_adj_sid_t, avl_glue);
        assert(adjsid);
        XFREE(adjsid);

    } ITERATE_AVL_TREE_END;

    XFREE(node_info->srv6_config);
    node_info->srv6_config = NULL;

    cp_ips_unjoin (node, IPC_SRV6_INFO, isis_recv_ipc_updates);
}

void
 isis_srv6_stop_adj_sid_advertisement (node_t *node) {}

void 
isis_srv6_advertise_locator (node_t *node,  ips_srv6_data_t *msg ) {

    isis_advt_info_t advt_info;
    isis_adv_data_t *advt_data;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    /* We need to advertise the locator in 3 TLVs */

    /* Advertise the locator in TLV 236 - IPV6 Reach TLV*/
    advt_data = node_info->tlv_global_advt.v6loc_adv_data_tlv236;

    if (!advt_data) {

        node_info->tlv_global_advt.v6loc_adv_data_tlv236 =
            (isis_adv_data_t *)XCALLOC(0, 1, isis_adv_data_t);

        advt_data = node_info->tlv_global_advt.v6loc_adv_data_tlv236;
        advt_data->tlv_no = ISIS_TLV_IPV6_REACH;
        memcpy(advt_data->u.v6pfx.prefix, msg->u.locator.prefix.addr, 16);
        advt_data->u.v6pfx.mask = msg->u.locator.prefix_len;
        advt_data->u.v6pfx.metric = msg->u.locator.metric;
        advt_data->u.v6pfx.flags = msg->u.locator.flags;
        SET_BIT(advt_data->flags, ISIS_ADVT_DATA_F_EXTERNAL_SRC);
    }

    advt_data->src.holder = &node_info->tlv_global_advt.v6loc_adv_data_tlv236;
    init_glthread(&advt_data->glue);
    advt_data->tlv_size = isis_get_adv_data_size(advt_data);
    advt_data->fragment = NULL;
    isis_advertise_tlv(node, 0, advt_data, &advt_info);



    /* Advertise the Locator in Locator in MT TLV */
    advt_data = node_info->tlv_global_advt.v6loc_adv_data_tlv237;

    if (!advt_data) {

        node_info->tlv_global_advt.v6loc_adv_data_tlv237 =
            (isis_adv_data_t *)XCALLOC(0, 1, isis_adv_data_t);
        advt_data = node_info->tlv_global_advt.v6loc_adv_data_tlv237;

        advt_data->tlv_no = ISIS_TLV_IPV6_MT_REACH;
        memcpy(advt_data->u.v6pfx.prefix, msg->u.locator.prefix.addr, 16);
        advt_data->u.v6pfx.mask = msg->u.locator.prefix_len;
        advt_data->u.v6pfx.metric = msg->u.locator.metric;
        advt_data->u.v6pfx.flags = msg->u.locator.flags;
        SET_BIT(advt_data->flags, ISIS_ADVT_DATA_F_EXTERNAL_SRC);
    }

    advt_data->src.holder = &node_info->tlv_global_advt.v6loc_adv_data_tlv237;
    init_glthread(&advt_data->glue);
    advt_data->tlv_size = isis_get_adv_data_size(advt_data);
    advt_data->fragment = NULL;
    isis_advertise_tlv(node, 0, advt_data, &advt_info);



    /* Advertise the locator in locator TLV */
    advt_data = node_info->tlv_global_advt.v6loc_adv_data_tlv27;

    if (!advt_data) {

        node_info->tlv_global_advt.v6loc_adv_data_tlv27 =
            (isis_adv_data_t *)XCALLOC(0, 1, isis_adv_data_t);
        advt_data = node_info->tlv_global_advt.v6loc_adv_data_tlv27;

        advt_data->tlv_no = ISIS_TLV_LOCATOR;
        memcpy(advt_data->u.srv6_loc.prefix.addr, msg->u.locator.prefix.addr, 16);
        advt_data->u.srv6_loc.prefix_len = msg->u.locator.prefix_len;
        advt_data->u.srv6_loc.metric = msg->u.locator.metric;
        advt_data->u.srv6_loc.mt_id = msg->u.locator.mt_id;
        advt_data->u.srv6_loc.algorithm = msg->u.locator.algorithm;
        advt_data->u.srv6_loc.flags = msg->u.locator.flags;
        SET_BIT(advt_data->flags, ISIS_ADVT_DATA_F_EXTERNAL_SRC);
    }

    advt_data->src.holder = &node_info->tlv_global_advt.v6loc_adv_data_tlv27;
    init_glthread(&advt_data->glue);
    advt_data->tlv_size = isis_get_adv_data_size(advt_data);
    advt_data->fragment = NULL;
    isis_advertise_tlv(node, 0, advt_data, &advt_info);
}

void 
isis_srv6_stop_locator_advertisement (node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(
    node);

    isis_adv_data_t *advt_data = node_info->tlv_global_advt.v6loc_adv_data_tlv236;

    if (advt_data) {

        isis_advt_data_clear_backlinkage(node_info, advt_data);
        if (!advt_data->fragment)
            isis_wait_list_advt_data_remove(node, advt_data);
        else 
            isis_withdraw_tlv_advertisement(node, advt_data);
        isis_free_advt_data(advt_data);
    }

    advt_data = node_info->tlv_global_advt.v6loc_adv_data_tlv237;        

    if (advt_data) {

        isis_advt_data_clear_backlinkage(node_info, advt_data);
        if (!advt_data->fragment)
            isis_wait_list_advt_data_remove(node, advt_data);
        else 
            isis_withdraw_tlv_advertisement(node, advt_data);
        isis_free_advt_data(advt_data);
    }    


    advt_data = node_info->tlv_global_advt.v6loc_adv_data_tlv27;        

    if (advt_data) {

        isis_advt_data_clear_backlinkage(node_info, advt_data);
        if (!advt_data->fragment)
            isis_wait_list_advt_data_remove(node, advt_data);
        else 
            isis_withdraw_tlv_advertisement(node, advt_data);

        /* Free SubTLVs*/
        isis_adv_data_t *sub_tlv_advt_data = advt_data->u.srv6_loc.next;
        isis_adv_data_t *next_sub_tlv_advt_data;

        while (sub_tlv_advt_data) {
            next_sub_tlv_advt_data = sub_tlv_advt_data->u.srv6_pfxsid.next;
            /* It is suffice to remove parent TLV from fragment*/
            isis_free_advt_data(sub_tlv_advt_data);
            sub_tlv_advt_data = next_sub_tlv_advt_data;
        }  
        advt_data->u.srv6_loc.next = NULL;
        isis_free_advt_data(advt_data);
    }    

}

void
isis_add_prefix_sid_to_locator (node_t *node, ips_srv6_data_t *msg) {

    char ipv4_addr_str[16];
    char ipv6_addr_str[48];
    isis_advt_info_t advt_info;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    isis_srv6_config_t *srv6_config = isis_srv6_get_config(node);

    if (!srv6_config) return;

    /* Ignore if locator is not configured first */
    if (isis_srv6_is_loc_enabled(node, srv6_config->locator_name)) {
        tracer (ISIS_TR(node), TR_ISIS_SRV6, 
            "%s : Ignoring PFX SID ADD : %s/128 from node %s as locator is not set\n", 
                ISIS_ERROR,
                inet_ntop6(&msg->u.prefix_sid.prefix, ipv6_addr_str), 
                tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));
        return;
    }

    /* Ignore if prefix sid is already learnt from ISIS*/   
    isis_srv6_pfx_sid_t pfx_sid_template;
    memcpy (pfx_sid_template.prefix.addr, msg->u.prefix_sid.prefix.addr, 16);

    if (avltree_lookup(&pfx_sid_template.avl_glue, &srv6_config->pfxsid_tree)) {
        tracer (ISIS_TR(node), TR_ISIS_SRV6, 
            "%s : Ignoring PFX SID ADD : %s/128 from node %s as it is already learnt\n", 
                ISIS_ERROR,
                inet_ntop6(&msg->u.prefix_sid.prefix, ipv6_addr_str), 
                tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));
        return;
    }

    isis_srv6_pfx_sid_t *pfx_sid = (isis_srv6_pfx_sid_t *)XCALLOC(0, 1, isis_srv6_pfx_sid_t);
    memcpy(pfx_sid->prefix.addr, msg->u.prefix_sid.prefix.addr, 16);
    pfx_sid->flags = msg->u.prefix_sid.flags;
    pfx_sid->endfn = msg->u.prefix_sid.endfn;

    avltree_insert(&pfx_sid->avl_glue, &srv6_config->pfxsid_tree);

    tracer (ISIS_TR(node), TR_ISIS_SRV6, 
        "%s : PFX SID ADD : %s/128 from node %s Success\n", 
            ISIS_SRV6,
            inet_ntop6(&msg->u.prefix_sid.prefix, ipv6_addr_str), 
            tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));

    /* Update the locator Advertisement */
    isis_adv_data_t *loc_advt_data = node_info->tlv_global_advt.v6loc_adv_data_tlv27;
    assert (loc_advt_data);

    if (IS_BIT_SET (loc_advt_data->flags, ISIS_ADVT_DATA_F_ADVERTISED)) {
        assert (loc_advt_data->fragment);
        isis_withdraw_tlv_advertisement(node, loc_advt_data);
    }

    if (IS_BIT_SET (loc_advt_data->flags, ISIS_ADVT_DATA_F_WAIT_LISTED)) {
        assert (!loc_advt_data->fragment);
        isis_wait_list_advt_data_remove (node, loc_advt_data);
    }

    isis_adv_data_t *pfx_sid_advt_data = (isis_adv_data_t *)XCALLOC(0, 1, isis_adv_data_t);
    pfx_sid_advt_data->tlv_no = ISIS_LOCATOR_PFX_SID_SUBTLV;
    memcpy(pfx_sid_advt_data->u.srv6_pfxsid.prefix.addr, pfx_sid->prefix.addr, 16);
    pfx_sid_advt_data->u.srv6_pfxsid.flags = pfx_sid->flags;
    pfx_sid_advt_data->u.srv6_pfxsid.endfn = (Srv6_endpcode_t)pfx_sid->endfn;
    pfx_sid_advt_data->u.srv6_pfxsid.subtlv_len = 0;
    pfx_sid_advt_data->src.holder = NULL;
    init_glthread(&pfx_sid_advt_data->glue);
    pfx_sid_advt_data->tlv_size = isis_get_adv_data_size(pfx_sid_advt_data);

    /* Update parent locator TLV size*/
    loc_advt_data->tlv_size += pfx_sid_advt_data->tlv_size;
    loc_advt_data->u.srv6_loc.subtlv_len += pfx_sid_advt_data->tlv_size;

    /* update the linkage*/
    pfx_sid_advt_data->u.srv6_pfxsid.next = loc_advt_data->u.srv6_loc.next;
    loc_advt_data->u.srv6_loc.next = pfx_sid_advt_data;

    /* Now re-advertise the locator TLV with all its SubTLVs included */
    if (isis_advertise_tlv(node, 0, loc_advt_data, &advt_info) == 
            ISIS_TLV_RECORD_ADVT_SUCCESS ) {
        tracer (ISIS_TR(node), TR_ISIS_SRV6, 
            "%s : Locator TLV Updated/advertised after absorbing new pfx sid subtlv\n",  ISIS_SRV6 );
    }
}

void
isis_delete_prefix_sid_from_locator (node_t *node, ips_srv6_data_t *msg) {

    char ipv4_addr_str[16];
    char ipv6_addr_str[48];
    isis_advt_info_t advt_info;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    isis_srv6_config_t *srv6_config = isis_srv6_get_config(node);

    if (!srv6_config) return;

    /* Ignore if locator is not configured first */
    if (isis_srv6_is_loc_enabled(node, srv6_config->locator_name)) return;

    /* Ignore if prefix sid is already learnt from ISIS*/   
    isis_srv6_pfx_sid_t pfx_sid_template;
    memcpy (pfx_sid_template.prefix.addr, msg->u.prefix_sid.prefix.addr, 16);

    avltree_node_t *avl_node = avltree_lookup(&pfx_sid_template.avl_glue, 
                                                            &srv6_config->pfxsid_tree);

    if (!avl_node)return;

    isis_srv6_pfx_sid_t *pfx_sid = avltree_container_of (
                                    avl_node, isis_srv6_pfx_sid_t, avl_glue);

    avltree_remove (&pfx_sid->avl_glue, &srv6_config->pfxsid_tree);

    tracer (ISIS_TR(node), TR_ISIS_SRV6, 
        "%s : PFX SID DEL : %s/128 from node %s Success\n", 
            ISIS_SRV6,
            inet_ntop6(&msg->u.prefix_sid.prefix, ipv6_addr_str), 
            tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));

    /* Update the locator Advertisement */
    isis_adv_data_t *loc_advt_data = node_info->tlv_global_advt.v6loc_adv_data_tlv27;
    assert (loc_advt_data);

    if (IS_BIT_SET (loc_advt_data->flags, ISIS_ADVT_DATA_F_ADVERTISED)) {
        assert (loc_advt_data->fragment);
        isis_withdraw_tlv_advertisement(node, loc_advt_data);
    }

    if (IS_BIT_SET (loc_advt_data->flags, ISIS_ADVT_DATA_F_WAIT_LISTED)) {
        assert (!loc_advt_data->fragment);
        isis_wait_list_advt_data_remove (node, loc_advt_data);
    }

    isis_adv_data_t *pfx_sid_advt_data;
    isis_adv_data_t *pfx_sid_advt_data_prev = NULL;

    for (pfx_sid_advt_data = loc_advt_data->u.srv6_loc.next; 
            pfx_sid_advt_data; 
            pfx_sid_advt_data = pfx_sid_advt_data->u.srv6_pfxsid.next) {

        if (memcmp(pfx_sid_advt_data->u.srv6_pfxsid.prefix.addr, 
            pfx_sid->prefix.addr, 16) == 0) break;

        pfx_sid_advt_data_prev = pfx_sid_advt_data;
    }

    assert (pfx_sid_advt_data);
    XFREE(pfx_sid);

    /*update the linkage : Remove the pfx_sid_advt_data from list */
    if (loc_advt_data->u.srv6_loc.next == pfx_sid_advt_data) {
        loc_advt_data->u.srv6_loc.next = pfx_sid_advt_data->u.srv6_pfxsid.next;
    } else {
        pfx_sid_advt_data_prev->u.srv6_pfxsid.next = pfx_sid_advt_data->u.srv6_pfxsid.next;
    }

    pfx_sid_advt_data->u.srv6_pfxsid.next = NULL;
   
    /* Update parent locator TLV size*/
    loc_advt_data->tlv_size -= pfx_sid_advt_data->tlv_size;
    loc_advt_data->u.srv6_loc.subtlv_len -= pfx_sid_advt_data->tlv_size;
    
    XFREE(pfx_sid_advt_data);

    /* Now re-advertise the locator TLV with all its SubTLVs excluded */
    if (isis_advertise_tlv(node, 0, loc_advt_data, &advt_info) == 
            ISIS_TLV_RECORD_ADVT_SUCCESS ) {
        tracer (ISIS_TR(node), TR_ISIS_SRV6, 
            "%s : Locator TLV Updated/advertised after removing pfx sid subtlv\n",  ISIS_SRV6 );
    }
}