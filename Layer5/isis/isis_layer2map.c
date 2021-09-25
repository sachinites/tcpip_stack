#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_layer2map.h"

static int
isis_build_layer2_mapping (node_t *node) {

    interface_t *intf;
    glthread_t *curr;
    isis_adjacency_t *adjacency;

    if (!isis_is_layer2_mapping_enabled (node)) {
        return 0;
    }

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if (! isis_node_intf_is_enable(intf)) continue;

        ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

            adjacency = glthread_to_isis_adjacency(curr);
            if (adjacency->adj_state != ISIS_ADJ_STATE_UP) continue;
            isis_update_layer2_mapping_on_adjacency_up(adjacency);

        } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr) ;

    } ITERATE_NODE_INTERFACES_END(node, intf);

    return 0;
}

static int
isis_destroy_layer2_mapping (node_t *node) {

    interface_t *intf;
    glthread_t *curr;
    isis_adjacency_t *adjacency;

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if (! isis_node_intf_is_enable(intf)) continue;

        ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

            adjacency = glthread_to_isis_adjacency(curr);
            if (adjacency->adj_state != ISIS_ADJ_STATE_UP) continue;
            isis_update_layer2_mapping_on_adjacency_down(adjacency);

        } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr) ;

    } ITERATE_NODE_INTERFACES_END(node, intf);

    return 0;
}

int
isis_config_layer2_map (node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) {
        printf(ISIS_ERROR_PROTO_NOT_ENABLE "\n");
        return -1;
    }

    if (node_info->layer2_mapping) return 0;

    node_info->layer2_mapping = true;
    isis_build_layer2_mapping(node);
    return 0;
}

int
isis_un_config_layer2_map (node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) {
        return -1;
    }

    if (!node_info->layer2_mapping) return 0;
    isis_destroy_layer2_mapping (node);
    node_info->layer2_mapping = false;
    return 0;
}

bool
isis_is_layer2_mapping_enabled (node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if ( !node_info ) return false;
    return node_info->layer2_mapping;
}

bool
isis_update_layer2_mapping_on_adjacency_up (isis_adjacency_t *adjacency) {

    if (!isis_is_layer2_mapping_enabled(adjacency->intf->att_node)) {
        return true;
    }

    return arp_entry_add(adjacency->intf->att_node, 
                            tcp_ip_covert_ip_n_to_p (adjacency->nbr_intf_ip, 0),
                            adjacency->nbr_mac,
                            adjacency->intf, PROTO_ISIS);
}

bool
isis_update_layer2_mapping_on_adjacency_down (isis_adjacency_t *adjacency) {

    if (!isis_is_layer2_mapping_enabled(adjacency->intf->att_node)) {
        return true;
    }
    arp_entry_delete(adjacency->intf->att_node, 
                                 tcp_ip_covert_ip_n_to_p(adjacency->nbr_intf_ip, 0),
                                 PROTO_ISIS);
    return true;
}
