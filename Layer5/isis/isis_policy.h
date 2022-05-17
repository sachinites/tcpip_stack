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

bool
isis_evaluate_export_policy (node_t *node, access_list_t *policy, l3_route_t *route);

bool
isis_evaluate_import_policy (node_t *node, access_list_t *policy, uint32_t prefix);

#endif 