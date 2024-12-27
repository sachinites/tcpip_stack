#ifndef __ISIS_SRV6__
#define __ISIS_SRV6__

typedef struct isis_srv6_config_ {

    char locator_name[32];

}isis_srv6_config_t;

int8_t 
isis_srv6_is_loc_enabled (node_t *node, char *locator_name) ;

isis_srv6_config_t *
isis_srv6_get_config(node_t *node);

void
isis_srv6_new_locator_set (node_t *node, char *loc_name);

void
isis_srv6_locator_unset (node_t *node);

void 
isis_srv6_withdraw_locator_all_sids (node_t *node,  char *locator);

#endif 