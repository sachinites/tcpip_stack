#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_pkt.h"
#include "isis_intf.h"
#include "isis_adjacency.h"

/* Checkig if protocol enable at node & intf level */
bool
isis_node_is_enable(node_t *node) {

    return !(node->node_nw_prop.isis_node_info == NULL);
}

void
isis_protocol_shut_down(node_t *node) {

}

void
isis_show_node_protocol_state(node_t *node) {

    bool is_enabled ;
    interface_t *intf;

    is_enabled = isis_node_is_enable(node);

    printf("ISIS Protocol : %sabled\n", is_enabled ? "En" : "Dis");

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {    

        if (!isis_node_intf_is_enable(intf)) continue;
        isis_show_interface_protocol_state(intf);
    } ITERATE_NODE_INTERFACES_END(node, intf);
}

void
isis_init(node_t *node ) {

    size_t lsp_pkt_size = 0;

    if (isis_node_is_enable(node)) return;

    /* Register for interested pkts */
    tcp_stack_register_l2_pkt_trap_rule(
			node, isis_pkt_trap_rule, isis_pkt_recieve);

    isis_node_info_t *isis_node_info = calloc(1, sizeof(isis_node_info_t));
    node->node_nw_prop.isis_node_info = isis_node_info;

    isis_node_info->isis_self_lsp_pkt = isis_generate_lsp_pkt(node);

    isis_install_lsp_pkt_in_lspdb(node, &isis_node_info->isis_self_lsp_pkt);
}

void
isis_de_init(node_t *node) {

    if (!isis_node_is_enable(node)) return;

    /* De-Register for interested pkts */
    tcp_stack_de_register_l2_pkt_trap_rule(
			node, isis_pkt_trap_rule, isis_pkt_recieve);

    isis_protocol_shut_down(node);
    
    assert(!node->node_nw_prop.isis_node_info);
}

void
isis_one_time_registration() {

    nfc_intf_register_for_events(isis_interface_updates);
    nfc_register_for_pkt_tracing(ISIS_ETH_PKT_TYPE, isis_print_hello_pkt);
}
