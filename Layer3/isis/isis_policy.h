#ifndef __ISIS_POLICY__
#define __ISIS_POLICY__

#include <stdbool.h>
#include "isis_advt.h"
#include "../../libs/common/cmn_prefix.h"

typedef struct isis_node_info_ isis_node_info_t;
typedef struct isis_adv_data_ isis_adv_data_t;
typedef struct rt_advert_info_ rt_advert_info_t;
typedef struct node_ node_t;

int
isis_config_import_policy (isis_node_info_t *node_info, const char *access_lst_name);

int
isis_unconfig_import_policy (isis_node_info_t *node_info, const char *access_lst_name);

pfx_lst_result_t
isis_evaluate_policy (isis_node_info_t *node_info, prefix_list_t *policy, uint32_t dest_nw, uint8_t mask);

isis_advt_tlv_return_code_t
isis_export_route (isis_node_info_t *node_info, cmn_prefix_t *prefix, uint32_t metric);

isis_adv_data_t *
isis_is_route_exported (isis_node_info_t *node_info, cmn_prefix_t *prefix);

bool
isis_unexport_route (isis_node_info_t *node_info, cmn_prefix_t *prefix);

void
isis_free_all_exported_rt_advt_data (isis_node_info_t *node_info);

void
isis_rtm_route_notif (node_t *node, rt_advert_info_t *rt_advert);

#endif 
