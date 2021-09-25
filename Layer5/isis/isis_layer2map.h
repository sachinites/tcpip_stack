#ifndef __ISIS_LAYER2MAP__
#define __ISIS_LAYER2MAP__

bool
isis_is_layer2_mapping_enabled (node_t *node);

int
isis_config_layer2_map (node_t *node);

int
isis_un_config_layer2_map (node_t *node);

bool
isis_update_layer2_mapping_on_adjacency_up (isis_adjacency_t *adjacency);

bool
isis_update_layer2_mapping_on_adjacency_down (isis_adjacency_t *adjacency);

#endif /* __ISIS_LAYER2MAP__ */