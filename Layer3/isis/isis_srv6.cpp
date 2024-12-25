#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_srv6.h"

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
    isis_srv6_advt_locator_all_sids (node, new_locator);
}

void
isis_srv6_locator_unset (node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    if (!node_info->srv6_config) return;

     isis_srv6_withdraw_locator_all_sids (node, 
        node_info->srv6_config->locator_name);

    XFREE(node_info->srv6_config);
    node_info->srv6_config = NULL;
}

void 
isis_srv6_advt_locator_all_sids (node_t *node, char *locator) {

}

void 
isis_srv6_withdraw_locator_all_sids (node_t *node,  char *locator) {

}