#include "../../tcp_public.h"
#include "isis_rtr.h"

bool
isis_is_protocol_enable_on_node(node_t *node) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
    if (!isis_node_info) {

        return false;
    }
    return true;
}

void
 isis_init (node_t *node) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node); 

    if (isis_node_info) return;

    isis_node_info = calloc(1, sizeof(isis_node_info_t));
    //ISIS_NODE_INFO(node) = isis_node_info;
    node->node_nw_prop.isis_node_info = isis_node_info;
 }

void
 isis_de_init (node_t *node) {

     isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node); 

    if (!isis_node_info) return;

    free(isis_node_info);
    //ISIS_NODE_INFO(node) = NULL;
    node->node_nw_prop.isis_node_info = NULL;
 }

 void
 isis_show_node_protocol_state(node_t *node) {

     printf("ISIS Protocol : %s\n", 
        isis_is_protocol_enable_on_node(node) ? "Enable" : "Disable");
 }