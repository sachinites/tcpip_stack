#include <stdbool.h>
#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_policy.h"
#include "isis_tlv_struct.h"
#include "isis_advt.h"

extern void isis_ipv4_rt_notif_cbk (
        event_dispatcher_t *ev_dis,
        void *rt_notif_data, unsigned int arg_size);

int
isis_config_import_policy(node_t *node, const char *prefix_lst_name) {

    isis_node_info_t *node_info;

    prefix_list_t *prefix_lst = prefix_lst_lookup_by_name(
                                                &node->prefix_lst_db, prefix_lst_name);
    
    if (!prefix_lst) {
        printf ("Error : Prefix List Do Not Exist\n");
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

        printf ("Error : Other Import policy %s is already being used\n",
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
        printf ("Error : Prefix List Do Not Exist\n");
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

        printf ("Error : Other Export policy %s is already being used\n",
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
            printf ("Error : Prefix List Do Not Exist\n");
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
isis_free_all_exported_rt_advt_data(node_t *node) {

    glthread_t *curr;
    uint8_t mask;
    byte ip_addr_str[16];
    mtrie_node_t *mnode;
    isis_adv_data_t *advt_data;
    isis_tlv_wd_return_code_t rc;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    curr = glthread_get_next(&node_info->exported_routes.list_head);

    while (curr) {

        mnode = list_glue_to_mtrie_node(curr);
        advt_data = (isis_adv_data_t *)(mnode->data);

        /* Break the backlinkage because to prevent mnode deletion so that our
            loop runs wihout any problem*/
        assert(advt_data->src.mnode);
        advt_data->src.mnode = NULL;

        tcp_ip_covert_ip_n_to_p (advt_data->u.pfx.prefix, ip_addr_str);
        mask = advt_data->u.pfx.mask;

        rc = isis_withdraw_tlv_advertisement(node, advt_data);

        switch (rc)
        {
        case ISIS_TLV_WD_SUCCESS:
            sprintf(tlb, "%s : Export Policy : UnExporting Route %s/%d is successful\n",
                    ISIS_LSPDB_MGMT, ip_addr_str, mask);
            tcp_trace(node, 0, tlb);
            break;
        case ISIS_TLV_WD_FRAG_NOT_FOUND:
            sprintf(tlb, "%s : Export Policy : UnExporting Route %s/%d failed, Fragment Not Found\n",
                    ISIS_LSPDB_MGMT, ip_addr_str, mask);
            tcp_trace(node, 0, tlb);
            break;
        case ISIS_TLV_WD_TLV_NOT_FOUND:
            sprintf(tlb, "%s : Export Policy : UnExporting Route %s/%d failed, TLV Not Found\n",
                    ISIS_LSPDB_MGMT, ip_addr_str, mask);
            tcp_trace(node, 0, tlb);
            break;
        case ISIS_TLV_WD_FAILED:
            sprintf(tlb, "%s : Export Policy : UnExporting Route %s/%d failed, reason Unknown\n",
                    ISIS_LSPDB_MGMT, ip_addr_str, mask);
            tcp_trace(node, 0, tlb);
            break;
        }

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
            printf("Error : Prefix List Do Not Exist\n");
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
    if (isis_is_protocol_shutdown_in_progress(node) ||
             isis_is_protocol_admin_shutdown(node)) return 0;
    init_mtrie(&node_info->exported_routes, 32, NULL);
    isis_schedule_lsp_pkt_generation (node, isis_event_admin_config_changed);
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

static isis_adv_data_t *
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


isis_adv_data_t *
isis_export_route (node_t *node, l3_route_t *l3route) {

    mtrie_node_t *mnode;
    uint32_t bin_ip, bin_mask;
    isis_node_info_t *node_info;
    isis_adv_data_t *exported_rt;
    isis_advt_info_t advt_info_out;
    bitmap_t prefix_bm, mask_bm;
    isis_tlv_record_advt_return_code_t rc;

    sprintf(tlb, "Export Policy : Exporting Route %s/%d\n", l3route->dest, l3route->mask);
    tcp_trace(node, 0, tlb);

    if ((exported_rt = isis_is_route_exported (node, l3route))) {

        if (IS_BIT_SET (l3route->rt_flags, RT_DEL_F)) {

            isis_unexport_route (node, l3route);
        }

        else if (IS_BIT_SET (l3route->rt_flags, RT_ADD_F)) {
           /* No Action */
        }

        else if (IS_BIT_SET (l3route->rt_flags, RT_UPDATE_F)) {
            /* No Action */
        }
        return exported_rt;
    }

    exported_rt = (isis_adv_data_t *)XCALLOC(0, 1, isis_adv_data_t);
    exported_rt->tlv_no = ISIS_TLV_IP_REACH;
    exported_rt->u.pfx.prefix = tcp_ip_covert_ip_p_to_n (l3route->dest);
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
        
        sprintf(tlb, "Export Policy : Exporting Route %s/%d failed\n",
            l3route->dest, l3route->mask);
        tcp_trace(node, 0, tlb);
        bitmap_free_internal(&prefix_bm);
        bitmap_free_internal(&mask_bm);
        XFREE(exported_rt);
        return NULL;
    }
    mnode->data = (void *)exported_rt;
    exported_rt->src.mnode = mnode;

    rc =  isis_record_tlv_advertisement(node, 0, 
                                (isis_adv_data_t *)exported_rt,
                                NULL, &advt_info_out);

    switch (rc) {

        case ISIS_TLV_RECORD_ADVT_SUCCESS:
            sprintf(tlb, "%s : Route %s/%d advertised\n", ISIS_LSPDB_MGMT,
                l3route->dest, l3route->mask);
            tcp_trace(node, 0, tlb);
            isis_schedule_lsp_pkt_generation(node, isis_event_route_rib_update);
            break;
        case ISIS_TLV_RECORD_ADVT_ALREADY:
            sprintf(tlb, "%s : Route %s/%d is already advertised\n", ISIS_LSPDB_MGMT,
                l3route->dest, l3route->mask);
            tcp_trace(node, 0, tlb);
            break;
        case ISIS_TLV_RECORD_ADVT_NO_SPACE:
            sprintf(tlb, "%s : Route %s/%d Failed to advertised, No Space available\n",
                ISIS_LSPDB_MGMT,
                l3route->dest, l3route->mask);
            tcp_trace(node, 0, tlb);
            break;
        default:
            assert(0);
    }

    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);
    return exported_rt;
}

bool
isis_unexport_route (node_t *node, l3_route_t *l3route) {

    bool res = false;
    mtrie_node_t *mnode;
    void *exported_rt_data;
    uint32_t bin_ip, bin_mask;
    isis_tlv_wd_return_code_t rc;
    isis_node_info_t *node_info;
    bitmap_t prefix_bm, mask_bm;

    node_info = ISIS_NODE_INFO(node);

    if (!node_info) return false;

    sprintf(tlb, "Export Policy : UnExporting Route %s/%d\n", l3route->dest, l3route->mask);
    tcp_trace(node, 0, tlb);

    bin_ip = tcp_ip_covert_ip_p_to_n (l3route->dest);
    bin_ip = htonl(bin_ip);

    bin_mask = tcp_ip_convert_dmask_to_bin_mask(l3route->mask);
    bin_mask = ~bin_mask;
    bin_mask = htonl(bin_mask);

    bitmap_init(&prefix_bm, 32);
    bitmap_init(&mask_bm, 32);

    prefix_bm.bits[0] = bin_ip;
    mask_bm.bits[0] = bin_mask;

    if ((mnode = mtrie_exact_prefix_match_search(
                &node_info->exported_routes,
                &prefix_bm, &mask_bm))) {

        bitmap_free_internal(&prefix_bm);
        bitmap_free_internal(&mask_bm);
        return false;
    }

    exported_rt_data = mnode->data;
    assert(exported_rt_data);

    rc = isis_withdraw_tlv_advertisement (node, (isis_adv_data_t *)exported_rt_data);
    switch(rc) {
        case ISIS_TLV_WD_SUCCESS:
            sprintf(tlb, "%s : Export Policy : UnExporting Route %s/%d is successful\n",
                ISIS_LSPDB_MGMT, l3route->dest, l3route->mask);
            tcp_trace(node, 0, tlb);
            isis_schedule_lsp_pkt_generation(node, isis_event_route_rib_update);
            res = true;
            break;
        case ISIS_TLV_WD_FRAG_NOT_FOUND:
            sprintf(tlb, "%s : Export Policy : UnExporting Route %s/%d failed, Fragment Not Found\n",
                ISIS_LSPDB_MGMT, l3route->dest, l3route->mask);
            tcp_trace(node, 0, tlb);
            break;            
        case ISIS_TLV_WD_TLV_NOT_FOUND:
            sprintf(tlb, "%s : Export Policy : UnExporting Route %s/%d failed, TLV Not Found\n",
                ISIS_LSPDB_MGMT, l3route->dest, l3route->mask);
            tcp_trace(node, 0, tlb);
            break;
        case ISIS_TLV_WD_FAILED:
            sprintf(tlb, "%s : Export Policy : UnExporting Route %s/%d failed, reason Unknown\n",
                ISIS_LSPDB_MGMT, l3route->dest, l3route->mask);
            tcp_trace(node, 0, tlb);
            break;            
    }

    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);
    return res;
}

size_t
isis_size_requirement_for_exported_routes (node_t *node) {

    glthread_t *curr = NULL;
    isis_node_info_t *node_info;
    size_t size_required = 0;

    const size_t tlv_unit_size = 
        sizeof (isis_tlv_130_t) + TLV_OVERHEAD_SIZE;

    node_info = ISIS_NODE_INFO(node);

    if (!node_info) return 0;

    ITERATE_GLTHREAD_BEGIN(&node_info->exported_routes.list_head, curr){

        size_required +=  tlv_unit_size;
    }ITERATE_GLTHREAD_END(&node_info->exported_routes.list_head, curr);

    return size_required;
}

size_t
isis_advertise_exported_routes (node_t *node,
                                                    byte *lsp_tlv_buffer,
                                                    size_t space_remaining) {

    byte ip_addr_str[16];
    mtrie_node_t *mnode;    
    glthread_t *curr = NULL;
    size_t bytes_encoded = 0;
    isis_node_info_t *node_info;
    isis_adv_data_t *exported_rt;
    isis_tlv_130_t  tlv_130_data;

    const size_t tlv_unit_size = 
        sizeof (isis_tlv_130_t) + TLV_OVERHEAD_SIZE;

    node_info = ISIS_NODE_INFO(node);

    if (!node_info) return 0;

    ITERATE_GLTHREAD_BEGIN(&node_info->exported_routes.list_head, curr){

        mnode = list_glue_to_mtrie_node(curr);
        exported_rt = (isis_adv_data_t *)(mnode->data);
        memset (&tlv_130_data, 0, sizeof(tlv_130_data));
        tlv_130_data.prefix = htonl(exported_rt->u.pfx.prefix);
        tlv_130_data.mask = exported_rt->u.pfx.mask;
        tlv_130_data.metric = htonl(exported_rt->u.pfx.metric);
        tlv_130_data.flags |=  ISIS_EXTERN_ROUTE_F;

        if (space_remaining >= tlv_unit_size) {

          lsp_tlv_buffer = tlv_buffer_insert_tlv(lsp_tlv_buffer,
                                        ISIS_TLV_IP_REACH,
                                        sizeof(isis_tlv_130_t), 
                                        (byte *)&tlv_130_data);

            bytes_encoded += tlv_unit_size;
            space_remaining -= tlv_unit_size;
        }
        else {
            sprintf(tlb, "%s : FATAL : LSP Pkt ran out of space\n", ISIS_LSPDB_MGMT);
            tcp_trace(node, 0 , tlb);
            return bytes_encoded;
        }

    } ITERATE_GLTHREAD_END(&node_info->exported_routes.list_head, curr);

    return bytes_encoded;
}
