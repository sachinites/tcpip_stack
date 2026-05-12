#include <stdbool.h>
#include "../../tcp_public.h"
#include "isis_enums.h"
#include "isis_rtr.h"
#include "isis_policy.h"
#include "isis_tlv_struct.h"
#include "isis_advt.h"
#include "isis_utils.h"
#include "../../libs/common/cmn_prefix.h"
#include "../../RTM/rtm_nb_integ.h"

int
isis_config_import_policy(isis_node_info_t *node_info, const char *prefix_lst_name) {

    node_t *node = node_info->vrf->node;

    prefix_list_t *prefix_lst = prefix_lst_lookup_by_name(
        &node->prefix_lst_db, prefix_lst_name);
    
    if (!prefix_lst) {
        cprintf ("Error : Prefix List Do Not Exist\n");
        return -1;
    }

    if (!isis_is_protocol_enable_on_node(node_info->vrf) ||
          isis_is_protocol_shutdown_in_progress(node_info)) {
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
    isis_schedule_spf_job(node_info, ISIS_EVENT_ADMIN_CONFIG_CHANGED_BIT);
    return 0;
}

int
isis_unconfig_import_policy(isis_node_info_t *node_info, const char *prefix_lst_name) {

    prefix_list_t *import_policy;
    node_t *node = node_info->vrf->node;

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
    
    if (isis_is_protocol_shutdown_in_progress(node_info)) return 0;

    isis_schedule_spf_job(node_info, ISIS_EVENT_ADMIN_CONFIG_CHANGED_BIT);
    return 0;
}

void
isis_free_all_exported_rt_advt_data (isis_node_info_t *node_info) {

    uint8_t mask;
    glthread_t *curr;
    byte ip_addr_str[IPV4_ADDR_LEN_STR];
    mtrie_node_t *mnode;
    isis_fragment_t *fragment;
    isis_adv_data_t *advt_data;
    isis_tlv_wd_return_code_t rc;

    if (!node_info) return;
    
    curr = glthread_get_next(&node_info->exported_routes.list_head);

    while (curr) {

        mnode = list_glue_to_mtrie_node(curr);
        advt_data = (isis_adv_data_t *)(mnode->data);
        fragment = advt_data->fragment;

        if (!fragment) {

            if (advt_data->flags & ISIS_ADVT_DATA_F_WAIT_LISTED){
                isis_wait_list_advt_data_remove(node_info, advt_data);
            }
            
             isis_free_advt_data (advt_data);
             mnode->data = NULL;
             curr = mtrie_node_delete_while_traversal (&node_info->exported_routes, mnode);
             continue;
        }

        tcp_ip_covert_ip_n_to_p (htonl(advt_data->u.pfx.prefix), ip_addr_str);
        mask = advt_data->u.pfx.mask;

        rc = isis_withdraw_tlv_advertisement(node_info, advt_data);

        switch (rc)
        {
        case ISIS_TLV_WD_SUCCESS:
            tracer (ISIS_TR(node_info), TR_ISIS_POLICY, "%s : UnExporting Route %s/%d is successful\n",
                    ISIS_EXPOLICY, ip_addr_str, mask);
            break;
        case ISIS_TLV_WD_FRAG_NOT_FOUND:
            tracer (ISIS_TR(node_info), TR_ISIS_POLICY, "%s : UnExporting Route %s/%d failed, Fragment Not Found\n", ISIS_EXPOLICY, ip_addr_str, mask);
            break;
        case ISIS_TLV_WD_TLV_NOT_FOUND:
            tracer (ISIS_TR(node_info), TR_ISIS_POLICY, "%s : UnExporting Route %s/%d failed, TLV Not Found\n",
                    ISIS_EXPOLICY, ip_addr_str, mask);
            break;
        case ISIS_TLV_WD_FAILED:
            tracer (ISIS_TR(node_info), TR_ISIS_POLICY, "%s : UnExporting Route %s/%d failed, reason Unknown\n", ISIS_EXPOLICY, ip_addr_str, mask);
            break;
        }
        mnode->data = NULL;
        isis_free_advt_data (advt_data);
        curr = mtrie_node_delete_while_traversal (&node_info->exported_routes, mnode);
    }
}

pfx_lst_result_t
isis_evaluate_policy (isis_node_info_t *node_info, 
                      prefix_list_t *policy, 
                      uint32_t dest_nw, uint8_t mask) {

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
isis_prefix_list_change(node_t *node, vrf_t *vrf, 
        uint32_t instance_no, prefix_list_t *prefix_list);

void
isis_prefix_list_change(node_t *node, vrf_t *vrf, 
        uint32_t instance_no, prefix_list_t *prefix_list) {

    if (!isis_is_protocol_enable_on_node(vrf) ||
          isis_is_protocol_shutdown_in_progress(vrf->isis_node_info)) return;

    if (vrf->isis_node_info->import_policy == prefix_list) {
         isis_schedule_spf_job(vrf->isis_node_info,
            ISIS_EVENT_ADMIN_CONFIG_CHANGED_BIT);
    }

    rtm_dist_mgr_client_request_route_replay (
            node->dist_mgr,
            RTM_PROTO_ISIS, 0, vrf->vrf_id);         
    
}

isis_adv_data_t *
isis_is_route_exported (isis_node_info_t *node_info, cmn_prefix_t *prefix) {

    bitmap_t prefix_bm, mask_bm;
    mtrie_node_t *mnode;
    isis_adv_data_t *adv_data = NULL;

    if (!node_info || !prefix || prefix->afi != AF_IPV4) return NULL;

    cmn_prefix_to_bitmap (prefix, &prefix_bm, &mask_bm);

    mnode = mtrie_exact_prefix_match_search (
                &node_info->exported_routes,
                &prefix_bm, &mask_bm);

    if (mnode && mnode->data) {
        adv_data = (isis_adv_data_t *)mnode->data;
    }

    bitmap_free_internal (&prefix_bm);
    bitmap_free_internal (&mask_bm);
    return adv_data;
}

isis_advt_tlv_return_code_t
isis_export_route (isis_node_info_t *node_info, cmn_prefix_t *prefix, uint32_t metric) {

    char rt_str[48];
    mtrie_node_t *mnode;
    bitmap_t prefix_bm, mask_bm;
    isis_adv_data_t *exported_rt;
    isis_advt_info_t advt_info_out;
    isis_advt_tlv_return_code_t rc;

    if (!node_info || !prefix || prefix->afi != AF_IPV4) {
        return ISIS_TLV_RECORD_ADVT_FAILED;
    }

    memset (rt_str, 0, sizeof (rt_str));
    cmn_prefix_to_string (prefix, &rt_str);

    tracer (ISIS_TR(node_info), TR_ISIS_POLICY,
            "%s : Exporting Route %s\n", ISIS_EXPOLICY, rt_str);

    cmn_prefix_to_bitmap (prefix, &prefix_bm, &mask_bm);

    /* If the route is already exported, nothing to do. */
    mnode = mtrie_exact_prefix_match_search (
                &node_info->exported_routes,
                &prefix_bm, &mask_bm);

    if (mnode && mnode->data) {

        tracer (ISIS_TR(node_info), TR_ISIS_POLICY,
                "%s : Route %s is already advertised\n",
                ISIS_EXPOLICY, rt_str);
        bitmap_free_internal (&prefix_bm);
        bitmap_free_internal (&mask_bm);
        return ISIS_TLV_RECORD_ADVT_ALREADY;
    }

    exported_rt = (isis_adv_data_t *)XCALLOC2 (0, 1, isis_adv_data_t);
    exported_rt->tlv_no = ISIS_TLV_IP_REACH;
    exported_rt->u.pfx.prefix = prefix->u.v4_addr;
    exported_rt->u.pfx.mask = prefix->prefix_len;
    exported_rt->u.pfx.metric = metric ? metric : ISIS_DEFAULT_INTF_COST;
    exported_rt->u.pfx.flags = 0;
    init_glthread (&exported_rt->glue);
    SET_BIT(exported_rt->flags, ISIS_ADVT_DATA_F_IP_REACH_EXPORTED);
    exported_rt->tlv_size = isis_get_adv_data_size (exported_rt);

    if (mtrie_insert_prefix (&node_info->exported_routes,
                             &prefix_bm,
                             &mask_bm,
                             32,
                             &mnode) != MTRIE_INSERT_SUCCESS) {

        tracer (ISIS_TR(node_info), TR_ISIS_POLICY,
                "%s : Exporting Route %s failed\n", ISIS_EXPOLICY, rt_str);
        bitmap_free_internal (&prefix_bm);
        bitmap_free_internal (&mask_bm);
        isis_free_advt_data (exported_rt);
        return ISIS_TLV_RECORD_ADVT_FAILED;
    }
    mnode->data = (void *)exported_rt;

    rc = isis_advertise_tlv (node_info, 0, exported_rt, &advt_info_out);

    switch (rc) {

        case ISIS_TLV_RECORD_ADVT_SUCCESS:
            tracer (ISIS_TR(node_info), TR_ISIS_POLICY,
                    "%s : Route %s advertised in LSP [%hu][%hu]\n",
                    ISIS_EXPOLICY, rt_str,
                    advt_info_out.pn_no, advt_info_out.fr_no);
            break;
        case ISIS_TLV_RECORD_ADVT_ALREADY:
            tracer (ISIS_TR(node_info), TR_ISIS_POLICY,
                    "%s : Route %s is already advertised\n",
                    ISIS_EXPOLICY, rt_str);
            break;
        case ISIS_TLV_RECORD_ADVT_NO_SPACE:
        case ISIS_TLV_RECORD_ADVT_NO_FRAG:
            tracer (ISIS_TR(node_info), TR_ISIS_POLICY,
                    "%s : Route %s failed to advertise, no space available\n",
                    ISIS_EXPOLICY, rt_str);
            break;
        default:
            assert (0);
    }

    bitmap_free_internal (&prefix_bm);
    bitmap_free_internal (&mask_bm);
    return rc;
}

bool
isis_unexport_route (isis_node_info_t *node_info, cmn_prefix_t *prefix) {

    bool res = false;
    char rt_str[48];
    mtrie_node_t *mnode;
    isis_adv_data_t *adv_data;
    bitmap_t prefix_bm, mask_bm;
    isis_tlv_wd_return_code_t rc;

    if (!node_info || !prefix || prefix->afi != AF_IPV4) return false;

    memset (rt_str, 0, sizeof (rt_str));
    cmn_prefix_to_string (prefix, &rt_str);

    tracer (ISIS_TR(node_info), TR_ISIS_POLICY,
            "%s : UnExporting Route %s\n", ISIS_EXPOLICY, rt_str);

    cmn_prefix_to_bitmap (prefix, &prefix_bm, &mask_bm);

    mnode = mtrie_exact_prefix_match_search (
                &node_info->exported_routes,
                &prefix_bm, &mask_bm);

    if (!mnode || !mnode->data) {

        bitmap_free_internal (&prefix_bm);
        bitmap_free_internal (&mask_bm);
        return false;
    }

    adv_data = (isis_adv_data_t *)mnode->data;

    /* Not yet committed to a fragment - drop bookkeeping only. */
    if (!adv_data->fragment) {

        if (adv_data->flags & ISIS_ADVT_DATA_F_WAIT_LISTED) {
            isis_wait_list_advt_data_remove (node_info, adv_data);
        }
        isis_free_advt_data (adv_data);
        mnode->data = NULL;
        mtrie_delete_leaf_node (&node_info->exported_routes, mnode);
        bitmap_free_internal (&prefix_bm);
        bitmap_free_internal (&mask_bm);
        return true;
    }

    rc = isis_withdraw_tlv_advertisement (node_info, adv_data);

    switch (rc) {
        case ISIS_TLV_WD_SUCCESS:
            tracer (ISIS_TR(node_info), TR_ISIS_POLICY,
                    "%s : UnExporting Route %s is successful\n",
                    ISIS_EXPOLICY, rt_str);
            res = true;
            break;
        case ISIS_TLV_WD_FRAG_NOT_FOUND:
            tracer (ISIS_TR(node_info), TR_ISIS_POLICY,
                    "%s : UnExporting Route %s failed, Fragment Not Found\n",
                    ISIS_EXPOLICY, rt_str);
            break;
        case ISIS_TLV_WD_TLV_NOT_FOUND:
            tracer (ISIS_TR(node_info), TR_ISIS_POLICY,
                    "%s : UnExporting Route %s failed, TLV Not Found\n",
                    ISIS_EXPOLICY, rt_str);
            break;
        case ISIS_TLV_WD_FAILED:
            tracer (ISIS_TR(node_info), TR_ISIS_POLICY,
                    "%s : UnExporting Route %s failed, reason Unknown\n",
                    ISIS_EXPOLICY, rt_str);
            break;
    }

    mnode->data = NULL;
    isis_free_advt_data (adv_data);
    mtrie_delete_leaf_node (&node_info->exported_routes, mnode);

    bitmap_free_internal (&prefix_bm);
    bitmap_free_internal (&mask_bm);
    return res;
}

void
isis_rtm_route_notif (vrf_t *vrf, rt_advert_info_t  *rt_advert) {

    char rt_str[48];
    isis_advt_tlv_return_code_t rc;
    isis_node_info_t *node_info = vrf->isis_node_info;

    if (!node_info) return;
    if (!rt_advert) return;

    memset (rt_str, 0, sizeof (rt_str));
    cmn_prefix_to_string (&rt_advert->route, &rt_str);

    tracer (ISIS_TR(node_info), TR_ISIS_POLICY,
            "%s : Recv notif for Route %s with code %s\n",
            ISIS_EXPOLICY, rt_str,
            rt_advert->code == RTM_CLIENT_RT_ADD ? "Add" : "Del");

    /* Export DB only tracks IPv4 reachability TLVs (TLV 130). */
    if (rt_advert->route.afi != AF_IPV4) return;

    /* Withdraw on delete notification. */
    if (rt_advert->code == RTM_CLIENT_RT_DEL) {
        isis_unexport_route (node_info, &rt_advert->route);
        return;
    }

    /* Don't redistribute ISIS-sourced routes back into ISIS. */
    if (rt_advert->src_proto == RTM_PROTO_ISIS) {
        tracer (ISIS_TR(node_info), TR_ISIS_POLICY,
                "%s : Route %s sourced by ISIS, skip\n",
                ISIS_EXPOLICY, rt_str);
        return;
    }

    rc = isis_export_route (node_info, &rt_advert->route, rt_advert->out_cost);

    if (rc == ISIS_TLV_RECORD_ADVT_NO_SPACE ||
        rc == ISIS_TLV_RECORD_ADVT_NO_FRAG) {

        tracer (ISIS_TR(node_info), TR_ISIS_POLICY | TR_ISIS_ERRORS,
                "%s : Route %s could not be exported, space exhausted\n",
                ISIS_EXPOLICY, rt_str);
    }
}