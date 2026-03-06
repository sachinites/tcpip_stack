#include "../../tcp_public.h"
#include "isis_utils.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_layer2map.h"

static int
isis_build_layer2_mapping (isis_node_info_t *node_info) {

    Interface *intf;
    glthread_t *curr;
    isis_adjacency_t *adjacency;

    if (!isis_is_layer2_mapping_enabled (node_info)) {
        return 0;
    }

    ITERATE_NODE_ISIS_INTERFACES_BEGIN(node_info, intf) {

        if (! isis_is_protocol_enable_on_intf(intf)) continue;

        ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

            adjacency = glthread_to_isis_adjacency(curr);
            if (adjacency->adj_state != ISIS_ADJ_STATE_UP) continue;
            isis_update_layer2_mapping_on_adjacency_up(adjacency);

        } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr) ;

    } ITERATE_NODE_ISIS_INTERFACES_END;

    return 0;
}

static int
isis_destroy_layer2_mapping (isis_node_info_t *node_info) {

    Interface *intf;
    glthread_t *curr;
    isis_adjacency_t *adjacency;

    ITERATE_NODE_ISIS_INTERFACES_BEGIN(node_info, intf) {

        if (! isis_is_protocol_enable_on_intf(intf)) continue;

        ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

            adjacency = glthread_to_isis_adjacency(curr);
            if (adjacency->adj_state != ISIS_ADJ_STATE_UP) continue;
            isis_update_layer2_mapping_on_adjacency_down(adjacency);

        } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr) ;

    } ITERATE_NODE_ISIS_INTERFACES_END;

    return 0;
}

int
isis_config_layer2_map (isis_node_info_t *node_info) {

    if (node_info->layer2_mapping) return 0;

    node_info->layer2_mapping = true;
    isis_build_layer2_mapping(node_info);
    return 0;
}

int
isis_un_config_layer2_map (isis_node_info_t *node_info) {

    if (!node_info->layer2_mapping) return 0;
    isis_destroy_layer2_mapping (node_info);
    node_info->layer2_mapping = false;
    return 0;
}

bool
isis_is_layer2_mapping_enabled (isis_node_info_t *node_info) {

    return node_info->layer2_mapping;
}

bool
isis_update_layer2_mapping_on_adjacency_up (isis_adjacency_t *adjacency) {

    char ip_addr[IPV4_ADDR_LEN_STR];

    if (!isis_is_layer2_mapping_enabled(ISIS_CTX_ADJ(adjacency))) {
        return true;
    }

    return false;
    #if 0
    return arp_entry_add(adjacency->intf->att_node, 
                            tcp_ip_covert_ip_n_to_p (adjacency->nbr_intf_ip, ip_addr),
                            adjacency->nbr_mac,
                            adjacency->intf, PROTO_ISIS);
    #endif
}

bool
isis_update_layer2_mapping_on_adjacency_down (isis_adjacency_t *adjacency) {

    char ip_addr[IPV4_ADDR_LEN_STR];

    if (!isis_is_layer2_mapping_enabled(ISIS_CTX_ADJ(adjacency))) {
        return true;
    }
    
    return true;
    #if 0
    arp_entry_delete(adjacency->intf->att_node, 
                     tcp_ip_covert_ip_n_to_p(adjacency->nbr_intf_ip, ip_addr),
                     PROTO_ISIS);
    return true;
    #endif
}
