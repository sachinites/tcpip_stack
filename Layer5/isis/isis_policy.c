#include <stdbool.h>
#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_policy.h"
#include "isis_tlv_struct.h"

extern void
isis_ipv4_rt_notif_cbk (
        void *rt_notif_data, size_t arg_size) ;

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
    isis_schedule_spf_job(node, ISIS_EVENT_ADMIN_CONFIG_CHANGED_BIT);
    return 0;
}

void isis_free_exported_rt(mtrie_node_t *mnode);
void
isis_free_exported_rt(mtrie_node_t *mnode) {

    if (!mnode->data) return;
    isis_exported_rt_t *exported_rt = (isis_exported_rt_t *)mnode->data;
    free(exported_rt);
    mnode->data = NULL;
}

int
isis_unconfig_export_policy(node_t *node, const char *prefix_lst_name) {

    prefix_list_t *export_policy;
    isis_node_info_t *node_info;

    node_info = ISIS_NODE_INFO(node);

    if (!node_info)
        return 0;

    if (!node_info->export_policy)
        return 0;

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

    if (!export_policy && !prefix_lst_name)
        return 0;

    prefix_list_dereference(node_info->export_policy);
    node_info->export_policy = NULL;
    mtrie_destroy_with_app_data(&node_info->exported_routes);
    init_mtrie(&node_info->exported_routes, 32, isis_free_exported_rt);
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

static isis_exported_rt_t *
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
        return ( isis_exported_rt_t *)(mnode->data);
    }

    return NULL;
}


isis_exported_rt_t *
isis_export_route (node_t *node, l3_route_t *l3route) {

    mtrie_node_t *mnode;
    isis_node_info_t *node_info;
    isis_exported_rt_t *exported_rt;
    uint32_t bin_ip, bin_mask;
    bitmap_t prefix_bm, mask_bm;

    sprintf(tlb, "Export Policy : Exporting Route %s/%d\n", l3route->dest, l3route->mask);
    tcp_trace(node, 0, tlb);

    if (exported_rt = isis_is_route_exported (node, l3route)) {

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

    exported_rt = (isis_exported_rt_t *)XCALLOC(0, 1, isis_exported_rt_t);
    exported_rt->prefix = tcp_ip_covert_ip_p_to_n (l3route->dest);
    exported_rt->mask = l3route->mask;
    exported_rt->metric = ISIS_DEFAULT_INTF_COST;

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
        
        sprintf(tlb, "Export Policy : Exporting Route %s/%d failed\n", l3route->dest, l3route->mask);
        tcp_trace(node, 0, tlb);
        bitmap_free_internal(&prefix_bm);
        bitmap_free_internal(&mask_bm);
        XFREE(exported_rt);
        return NULL;
    }
    mnode->data = (void *)exported_rt;
    isis_schedule_lsp_pkt_generation(node, isis_event_route_rib_update);
    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);
    return exported_rt;
}

bool
isis_unexport_route (node_t *node, l3_route_t *l3route) {


    void *exported_rt_data;
    uint32_t bin_ip, bin_mask;
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

    if (mtrie_delete_prefix(
                &node_info->exported_routes,
                &prefix_bm,
                &mask_bm, &exported_rt_data) == MTRIE_DELETE_FAILED) {

        bitmap_free_internal(&prefix_bm);
        bitmap_free_internal(&mask_bm);
        return false;
    }

    assert(exported_rt_data);
    XFREE(exported_rt_data);
    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);
    isis_schedule_lsp_pkt_generation(node, isis_event_route_rib_update);
    sprintf(tlb, "Export Policy : UnExporting Route %s/%d is successful\n", l3route->dest, l3route->mask);
    tcp_trace(node, 0, tlb);
    return true;
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
isis_advertise_exported_routes (node_t *node, byte *lsp_tlv_buffer, size_t space_remaining) {

    glthread_t *curr = NULL;
    size_t bytes_encoded = 0;
    isis_node_info_t *node_info;
    mtrie_node_t *mnode;
    isis_exported_rt_t *exported_rt;
    isis_tlv_130_t  tlv_130_data;

    const size_t tlv_unit_size = 
        sizeof (isis_tlv_130_t) + TLV_OVERHEAD_SIZE;

    node_info = ISIS_NODE_INFO(node);

    if (!node_info) return 0;

    ITERATE_GLTHREAD_BEGIN(&node_info->exported_routes.list_head, curr){

        mnode = list_glue_to_mtrie_node(curr);
        exported_rt = (isis_exported_rt_t *)mnode->data;
        memset (&tlv_130_data, 0, sizeof(tlv_130_data));
        tlv_130_data.prefix = htonl(exported_rt->prefix);
        tlv_130_data.mask = exported_rt->mask;
        tlv_130_data.metric = htonl(exported_rt->metric);
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
            sprintf(tlb, "FATAL : LSP Pkt ran out of space\n", ISIS_LSPDB_MGMT);
            tcp_trace(node, 0 , tlb);            
            return bytes_encoded;
        }

    } ITERATE_GLTHREAD_END(&node_info->exported_routes.list_head, curr);

    return bytes_encoded;
}