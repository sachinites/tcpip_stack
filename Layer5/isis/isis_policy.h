#ifndef __ISIS_POLICY__
#define __ISIS_POLICY__

#include <stdbool.h>

typedef struct node_ node_t;
typedef struct l3_route_ l3_route_t;

typedef struct isis_exported_rt_ {

    uint32_t prefix;
    uint8_t mask;
    uint32_t metric;
}isis_exported_rt_t;

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

isis_exported_rt_t *
isis_export_route (node_t *node, l3_route_t *l3route);

bool
isis_unexport_route (node_t *node, l3_route_t *l3route);

size_t
isis_size_requirement_for_exported_routes (node_t *node) ;

size_t
isis_advertise_exported_routes (node_t *node, byte *lsp_tlv_buffer, size_t space_remaining) ;

#endif 