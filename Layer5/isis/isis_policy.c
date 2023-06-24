#include <stdbool.h>
#include "../../tcp_public.h"
#include "isis_enums.h"
#include "isis_rtr.h"
#include "isis_policy.h"
#include "isis_tlv_struct.h"
#include "isis_advt.h"

extern void isis_ipv4_rt_notif_cbk (
        event_dispatcher_t *ev_dis,
        void *rt_notif_data, unsigned int arg_size);

extern void
isis_process_ipv4_route_notif (node_t *node, l3_route_t *l3route) ;

int
isis_config_import_policy(node_t *node, const char *prefix_lst_name) {

    isis_node_info_t *node_info;

    prefix_list_t *prefix_lst = prefix_lst_lookup_by_name(
                                                &node->prefix_lst_db, prefix_lst_name);
    
    if (!prefix_lst) {
        cprintf ("Error : Prefix List Do Not Exist\n");
        return -1;
    }

    node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node) ||
          isis_is_protocol_shutdown_in_progress(node)) {
        return -1;
    }

    if (node_info->import_policy == prefix_lst ) return 0;

    if (node_info->import_policy &&
        node_info->import_policy !=  prefix_lst) {

        cprintf ("Error : Other Import policy %s is already being used\n",
            node_info->import_policy->name);
        return -1;
    }

    node_info->import_policy =  prefix_lst;
    prefix_list_reference( prefix_lst);
    isis_schedule_spf_job(node, ISIS_EVENT_ADMIN_CONFIG_CHANGED_BIT);
    return 0;
}

int
isis_config_export_policy(node_t *node, const char *prefix_lst_name) {

    isis_node_info_t *node_info;

    prefix_list_t *prefix_lst = prefix_lst_lookup_by_name(
                                                &node->prefix_lst_db, prefix_lst_name);
    
    if (!prefix_lst) {
        cprintf ("Error : Prefix List Do Not Exist\n");
        return -1;
    }

    node_info = ISIS_NODE_INFO(node);

    if ( !isis_is_protocol_enable_on_node(node) ||
          isis_is_protocol_shutdown_in_progress(node)) {
        return -1;
    }

    if (node_info->export_policy == prefix_lst ) return 0;

    if (node_info->export_policy &&
         node_info->export_policy != prefix_lst) {

        cprintf ("Error : Other Export policy %s is already being used\n",
            node_info->export_policy->name);
        return -1;
    }

    node_info->export_policy = prefix_lst;
    prefix_list_reference(prefix_lst);
    nfc_ipv4_rt_request_flash (node, isis_ipv4_rt_notif_cbk);
    return 0;
}

int
isis_unconfig_import_policy(node_t *node, const char *prefix_lst_name) {

    prefix_list_t *import_policy;
    isis_node_info_t *node_info;

    node_info = ISIS_NODE_INFO(node);

    if (!node_info) return 0;

    if (!node_info->import_policy) return 0;

    if (prefix_lst_name) {
        
        import_policy = prefix_lst_lookup_by_name(
                                                &node->prefix_lst_db, prefix_lst_name);

        if (!import_policy) {
            cprintf ("Error : Prefix List Do Not Exist\n");
            return -1;
        }
    }
    else {
        import_policy = node_info->import_policy;
    }

    if (!import_policy && !prefix_lst_name) return 0;

    prefix_list_dereference(node_info->import_policy);
    node_info->import_policy = NULL;
    if (isis_is_protocol_shutdown_in_progress(node)) return;
    isis_schedule_spf_job(node, ISIS_EVENT_ADMIN_CONFIG_CHANGED_BIT);
    return 0;
}

void
isis_free_all_exported_rt_advt_data (node_t *node) {

    glthread_t *curr;
    uint8_t mask;
    byte ip_addr_str[16];
    mtrie_node_t *mnode;
    isis_fragment_t *fragment;
    isis_adv_data_t *advt_data;
    isis_tlv_wd_return_code_t rc;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;
    
    curr = glthread_get_next(&node_info->exported_routes.list_head);

    while (curr) {

        mnode = list_glue_to_mtrie_node(curr);
        advt_data = (isis_adv_data_t *)(mnode->data);
        fragment = advt_data->fragment;

        if (!fragment) {
             isis_wait_list_advt_data_remove(node, advt_data);
             isis_free_advt_data (advt_data);
             mnode->data = NULL;
             curr = mtrie_node_delete_while_traversal (&node_info->exported_routes, mnode);
             continue;
        }

        tcp_ip_covert_ip_n_to_p (htonl(advt_data->u.pfx.prefix), ip_addr_str);
        mask = advt_data->u.pfx.mask;

        rc = isis_withdraw_tlv_advertisement(node, advt_data);

        switch (rc)
        {
        case ISIS_TLV_WD_SUCCESS:
            trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : UnExporting Route %s/%d is successful\n",
                    ISIS_EXPOLICY, ip_addr_str, mask);
            break;
        case ISIS_TLV_WD_FRAG_NOT_FOUND:
            trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : UnExporting Route %s/%d failed, Fragment Not Found\n", ISIS_EXPOLICY, ip_addr_str, mask);
            break;
        case ISIS_TLV_WD_TLV_NOT_FOUND:
            trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : UnExporting Route %s/%d failed, TLV Not Found\n",
                    ISIS_EXPOLICY, ip_addr_str, mask);
            break;
        case ISIS_TLV_WD_FAILED:
            trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : UnExporting Route %s/%d failed, reason Unknown\n", ISIS_EXPOLICY, ip_addr_str, mask);
            break;
        }
        mnode->data = NULL;
        isis_free_advt_data (advt_data);
        curr = mtrie_node_delete_while_traversal (&node_info->exported_routes, mnode);
    }
}

int
isis_unconfig_export_policy(node_t *node, const char *prefix_lst_name) {

    prefix_list_t *export_policy;
    isis_node_info_t *node_info;

    node_info = ISIS_NODE_INFO(node);

    if (!node_info)
        return 0;

    if (!node_info->export_policy) {
        if (isis_is_protocol_admin_shutdown(node) ||
             isis_is_protocol_shutdown_in_progress(node)) {
            mtrie_destroy(&node_info->exported_routes);
            return 0;
        }
    }

    if (prefix_lst_name) {

        export_policy =  prefix_lst_lookup_by_name(
                                            &node->prefix_lst_db, prefix_lst_name);
        if (!export_policy) {
            cprintf("Error : Prefix List Do Not Exist\n");
            return -1;
        }
    }
    else
    {
        export_policy = node_info->export_policy;
    }

    if (!export_policy && !prefix_lst_name) {

        if (isis_is_protocol_shutdown_in_progress(node) ||
             isis_is_protocol_admin_shutdown(node)) {
            mtrie_destroy(&node_info->exported_routes);
        }
        return 0;
    }

    prefix_list_dereference(node_info->export_policy);
    node_info->export_policy = NULL;
    isis_free_all_exported_rt_advt_data(node);
    mtrie_destroy(&node_info->exported_routes);
    if (isis_is_protocol_admin_shutdown(node)) return 0;
    init_mtrie(&node_info->exported_routes, 32, NULL);
    return 0;
}

pfx_lst_result_t
isis_evaluate_policy (node_t *node, prefix_list_t *policy, uint32_t dest_nw, uint8_t mask) {

    pfx_lst_node_t *pfx_lst_node = NULL;

    uint32_t subnet_mask = ~0;

    if (!policy) return PFX_LST_SKIP;

    if (mask) {
        subnet_mask = subnet_mask << (32 - mask);
    }
    else {
        subnet_mask = 0;
    }

    dest_nw &= subnet_mask;

    return prefix_list_evaluate (dest_nw, mask, policy);
}

void
isis_prefix_list_change(node_t *node, prefix_list_t *prefix_list); 

void
isis_prefix_list_change(node_t *node, prefix_list_t *prefix_list) {

    isis_node_info_t *node_info;

    if (!isis_is_protocol_enable_on_node(node) ||
          isis_is_protocol_shutdown_in_progress(node)) return;

    node_info = ISIS_NODE_INFO(node);

    if (node_info->import_policy == prefix_list) {
         isis_schedule_spf_job(node, ISIS_EVENT_ADMIN_CONFIG_CHANGED_BIT);
    }

    if (node_info->export_policy == prefix_list) {
         nfc_ipv4_rt_request_flash (node, isis_ipv4_rt_notif_cbk);
    }
}

isis_adv_data_t *
isis_is_route_exported (node_t *node, l3_route_t *l3route ) {

    uint32_t bin_ip, bin_mask;
    bitmap_t prefix_bm, mask_bm;
    isis_node_info_t *node_info;

    bin_ip = tcp_ip_covert_ip_p_to_n (l3route->dest);
    bin_ip = htonl(bin_ip);

    bin_mask = tcp_ip_convert_dmask_to_bin_mask(l3route->mask);
    bin_mask = ~bin_mask;
    bin_mask = htonl(bin_mask);

    bitmap_init(&prefix_bm, 32);
    bitmap_init(&mask_bm, 32);

    prefix_bm.bits[0] = bin_ip;
    mask_bm.bits[0] = bin_mask;

    node_info = ISIS_NODE_INFO(node);

    mtrie_node_t *mnode = mtrie_exact_prefix_match_search(
                            &node_info->exported_routes,
                            &prefix_bm,
                            &mask_bm);

    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);

    if (mnode && mnode->data) {
        return ( isis_adv_data_t *)(mnode->data);
    }

    return NULL;
}

isis_advt_tlv_return_code_t
isis_export_route (node_t *node, l3_route_t *l3route) {

    mtrie_node_t *mnode;
    uint32_t bin_ip, bin_mask;
    isis_node_info_t *node_info;
    isis_adv_data_t *exported_rt;
    isis_advt_info_t advt_info_out;
    bitmap_t prefix_bm, mask_bm;
    isis_advt_tlv_return_code_t rc;

    trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : Exporting Route %s/%d\n",
        ISIS_EXPOLICY, l3route->dest, l3route->mask);

    exported_rt = (isis_adv_data_t *)XCALLOC(0, 1, isis_adv_data_t);
    exported_rt->tlv_no = ISIS_TLV_IP_REACH;
    exported_rt->u.pfx.prefix = htonl(tcp_ip_covert_ip_p_to_n (l3route->dest));
    exported_rt->u.pfx.mask = l3route->mask;
    exported_rt->u.pfx.metric = ISIS_DEFAULT_INTF_COST;
    exported_rt->tlv_size = isis_get_adv_data_size (exported_rt);

    node_info = ISIS_NODE_INFO(node);
    bin_ip = tcp_ip_covert_ip_p_to_n(l3route->dest);
    bin_ip = htonl(bin_ip);
    bin_mask = tcp_ip_convert_dmask_to_bin_mask(l3route->mask);
    bin_mask = ~bin_mask;
    bin_mask = htonl(bin_mask);

    bitmap_init(&prefix_bm, 32);
    bitmap_init(&mask_bm, 32);

    prefix_bm.bits[0] = bin_ip;
    mask_bm.bits[0] = bin_mask;

    if (mtrie_insert_prefix(&node_info->exported_routes,
                                            &prefix_bm,
                                            &mask_bm,
                                            32,
                                            &mnode) != MTRIE_INSERT_SUCCESS) {
        
        trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : Exporting Route %s/%d failed\n",
            ISIS_EXPOLICY, l3route->dest, l3route->mask);
        bitmap_free_internal(&prefix_bm);
        bitmap_free_internal(&mask_bm);
        isis_free_advt_data (exported_rt);
        return ISIS_TLV_RECORD_ADVT_FAILED;
    }
    mnode->data = (void *)exported_rt;

    rc =  isis_advertise_tlv(node, 0, 
                                (isis_adv_data_t *)exported_rt,
                                &advt_info_out);

    switch (rc) {

        case ISIS_TLV_RECORD_ADVT_SUCCESS:
            trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : Route %s/%d advertised in LSP [%hu][%hu]\n",
                ISIS_EXPOLICY, l3route->dest, l3route->mask, advt_info_out.pn_no, advt_info_out.fr_no);
            break;
        case ISIS_TLV_RECORD_ADVT_ALREADY:
            trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : Route %s/%d is already advertised\n", ISIS_EXPOLICY, l3route->dest, l3route->mask);
            break;
        case ISIS_TLV_RECORD_ADVT_NO_SPACE:
        case ISIS_TLV_RECORD_ADVT_NO_FRAG:
            trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : Route %s/%d Failed to advertised, No Space available\n", ISIS_EXPOLICY, l3route->dest, l3route->mask);
            break;
        default:
            assert(0);
    }

    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);
    return rc;
}

bool
isis_unexport_route (node_t *node, l3_route_t *l3route) {

    bool res = false;
    mtrie_node_t *mnode;
    void *exported_rt_data;
    isis_adv_data_t *adv_data;
    uint32_t bin_ip, bin_mask;
    isis_tlv_wd_return_code_t rc;
    isis_node_info_t *node_info;
    bitmap_t prefix_bm, mask_bm;

    node_info = ISIS_NODE_INFO(node);

    if (!node_info) return false;

    trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : UnExporting Route %s/%d\n",
        ISIS_EXPOLICY, l3route->dest, l3route->mask);

    bin_ip = tcp_ip_covert_ip_p_to_n (l3route->dest);
    bin_ip = htonl(bin_ip);

    bin_mask = tcp_ip_convert_dmask_to_bin_mask(l3route->mask);
    bin_mask = ~bin_mask;
    bin_mask = htonl(bin_mask);

    bitmap_init(&prefix_bm, 32);
    bitmap_init(&mask_bm, 32);

    prefix_bm.bits[0] = bin_ip;
    mask_bm.bits[0] = bin_mask;

    mnode = mtrie_exact_prefix_match_search(
                &node_info->exported_routes,
                &prefix_bm, &mask_bm);

    if (!mnode) {
        
        bitmap_free_internal(&prefix_bm);
        bitmap_free_internal(&mask_bm);
        return false;
    }

    exported_rt_data = mnode->data;
    assert(exported_rt_data);
    adv_data = (isis_adv_data_t *)exported_rt_data;

    if (!adv_data->fragment) {
       isis_wait_list_advt_data_remove(node, adv_data);
       isis_free_advt_data (adv_data);
       mnode->data = NULL;
       mtrie_delete_leaf_node (&node_info->exported_routes, mnode);
       return true;
    }

    rc = isis_withdraw_tlv_advertisement (node, (isis_adv_data_t *)exported_rt_data);

    switch(rc) {
        case ISIS_TLV_WD_SUCCESS:
            trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : Export Policy : UnExporting Route %s/%d is successful\n", ISIS_EXPOLICY, l3route->dest, l3route->mask);
            res = true;
            break;
        case ISIS_TLV_WD_FRAG_NOT_FOUND:
           trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : Export Policy : UnExporting Route %s/%d failed, Fragment Not Found\n",ISIS_EXPOLICY, l3route->dest, l3route->mask);
            break;            
        case ISIS_TLV_WD_TLV_NOT_FOUND:
            trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : Export Policy : UnExporting Route %s/%d failed, TLV Not Found\n", ISIS_EXPOLICY, l3route->dest, l3route->mask);
            break;
        case ISIS_TLV_WD_FAILED:
            trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : Export Policy : UnExporting Route %s/%d failed, reason Unknown\n", ISIS_EXPOLICY, l3route->dest, l3route->mask);
            break;            
    }

    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);
    mnode->data = NULL;
    isis_free_advt_data (exported_rt_data);
    mtrie_delete_leaf_node ( &node_info->exported_routes, mnode);
    return res;
}

void
 isis_process_ipv4_route_notif (node_t *node, l3_route_t *l3route) {

    bool policy_eval_failed;
    isis_adv_data_t *exported_rt;
    isis_node_info_t *node_info;
    isis_advt_tlv_return_code_t rc;
    
      trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : Recv notif for Route %s/%d with code %d\n",
        ISIS_EXPOLICY, l3route->dest, l3route->mask, l3route->rt_flags);

    node_info = ISIS_NODE_INFO(node);

    if (!node_info->export_policy) {
        return;
    }

    policy_eval_failed = isis_evaluate_policy(node,
                                 node_info->export_policy,
                                 tcp_ip_covert_ip_p_to_n(l3route->dest), l3route->mask) != PFX_LST_PERMIT;

    if (policy_eval_failed) {

        isis_unexport_route (node, l3route);
        return;
    }

    /* Dont export the deleted route*/
    if (IS_BIT_SET (l3route->rt_flags, RT_DEL_F)) {

        isis_unexport_route (node, l3route);
        return;
    }

    nxthop_proto_id_t nxthop_proto =
        l3_rt_map_proto_id_to_nxthop_index(PROTO_ISIS);

    /* Reject routes which ISIS already knows */
    if (l3route->nexthops[nxthop_proto][0]) {

        trace (ISIS_TR(node), TR_ISIS_POLICY, "%s : Route %s/%d already known to ISIS\n",
            ISIS_EXPOLICY, l3route->dest, l3route->mask);
        return;
    }

    rc = isis_export_route (node, l3route);

    if (rc == ISIS_TLV_RECORD_ADVT_NO_SPACE ||
        rc == ISIS_TLV_RECORD_ADVT_NO_FRAG) {

        trace (ISIS_TR(node), TR_ISIS_POLICY | TR_ISIS_ERRORS,
                "%s : Route %s/%d could not be exported, space Exhaustion\n",
                ISIS_EXPOLICY, l3route->dest, l3route->mask);
    }
 }
