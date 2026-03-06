#ifndef __ISIS_POLICY__
#define __ISIS_POLICY__

#include <stdbool.h>
#include "isis_advt.h"

typedef struct isis_node_info_ isis_node_info_t;
typedef struct l3_route_ l3_route_t;
typedef struct isis_adv_data_ isis_adv_data_t;

int
isis_config_import_policy (isis_node_info_t *node_info, const char *access_lst_name);

int
isis_config_export_policy (isis_node_info_t *node_info, const char *access_lst_name);

int
isis_unconfig_import_policy (isis_node_info_t *node_info, const char *access_lst_name);

int
isis_unconfig_export_policy (isis_node_info_t *node_info, const char *access_lst_name);

pfx_lst_result_t
isis_evaluate_policy (isis_node_info_t *node_info, prefix_list_t *policy, uint32_t dest_nw, uint8_t mask);

isis_advt_tlv_return_code_t
isis_export_route (isis_node_info_t *node_info, l3_route_t *l3route);


isis_adv_data_t *
isis_is_route_exported (isis_node_info_t *node_info, l3_route_t *l3route );

bool
isis_unexport_route (isis_node_info_t *node_info, l3_route_t *l3route);

void
isis_free_all_exported_rt_advt_data (isis_node_info_t *node_info);

#endif 
