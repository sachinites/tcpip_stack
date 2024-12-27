#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_srv6.h"
#include "isis_advt.h"

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

void
isis_srv6_new_locator_set (node_t *node, char *new_locator) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    if (!node_info->srv6_config) {
        node_info->srv6_config = (isis_srv6_config_t *)XCALLOC(0, 1, isis_srv6_config_t);
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

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    if (!node_info->srv6_config) return;

     isis_srv6_withdraw_locator_all_sids (node, 
        node_info->srv6_config->locator_name);

    assert (!node_info->tlv_global_advt.v6loc_adv_data_tlv236);
    assert (!node_info->tlv_global_advt.v6loc_adv_data_tlv237);

    XFREE(node_info->srv6_config);
    node_info->srv6_config = NULL;

    cp_ips_unjoin (node, IPC_SRV6_INFO, isis_recv_ipc_updates);
}


void 
isis_srv6_withdraw_locator_all_sids (node_t *node,  char *locator) {

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

}