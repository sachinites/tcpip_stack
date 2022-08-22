#ifndef __ISIS_POLICY__
#define __ISIS_POLICY__

typedef struct node_ node_t;

int
isis_config_import_policy(node_t *node, const char *access_lst_name);

int
isis_config_export_policy(node_t *node, const char *access_lst_name);

int
isis_unconfig_import_policy(node_t *node, const char *access_lst_name);

int
isis_unconfig_export_policy(node_t *node, const char *access_lst_name);

pfx_lst_result_t
isis_evaluate_policy (node_t *node, prefix_list_t *policy, uint32_t dest_nw, uint8_t mask);

#endif 