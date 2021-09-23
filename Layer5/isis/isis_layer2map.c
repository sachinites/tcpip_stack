#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_adjacency.h"
#include "isis_layer2map.h"

int
isis_config_layer2_map (node_t *node) {

    return 0;
}

int
isis_un_config_layer2_map (node_t *node) {

    return 0;
}

bool
isis_is_layer2_mapping_enabled (node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if ( !node_info ) return false;
    return node_info->layer2_mapping;
}

uint32_t
isis_build_layer2_mapping (node_t *node) {

    return 0;
}

uint32_t
isis_destroy_layer2_mapping (node_t *node) {

    return 0;
}

bool
isis_update_layer2_mapping_on_adjacency_up (isis_adjacency_t *adjacency) {

    return true;
}

bool
isis_update_layer2_mapping_on_adjacency_down (isis_adjacency_t *adjacency) {

    return true;
}

bool
isis_update_layer2_mapping_on_adjacency_change (isis_adjacency_t *adjacency) {

    return true;
}