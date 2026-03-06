#ifndef __ISIS_LAYER2MAP__
#define __ISIS_LAYER2MAP__

bool
isis_is_layer2_mapping_enabled (isis_node_info_t *node_info);

int
isis_config_layer2_map (isis_node_info_t *node_info);

int
isis_un_config_layer2_map (isis_node_info_t *node_info);

bool
isis_update_layer2_mapping_on_adjacency_up (isis_adjacency_t *adjacency);

bool
isis_update_layer2_mapping_on_adjacency_down (isis_adjacency_t *adjacency);

#endif /* __ISIS_LAYER2MAP__ */
