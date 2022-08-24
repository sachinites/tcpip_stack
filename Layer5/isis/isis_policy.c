#include <stdbool.h>
#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_policy.h"

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

int
isis_unconfig_export_policy(node_t *node, const char *prefix_lst_name) {

    prefix_list_t *export_policy;
    isis_node_info_t *node_info;

    node_info = ISIS_NODE_INFO(node);

    if (!node_info)
        return 0;

    if (!node_info->import_policy)
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
    nfc_ipv4_rt_request_flash (node, isis_ipv4_rt_notif_cbk);
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

