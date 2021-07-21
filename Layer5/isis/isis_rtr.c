#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_struct.h"
#include "isis_pkt.h"

/* Checkig if protocol enable at node & intf level */
bool
isis_node_is_enable(node_t *node) {

    return !(node->node_nw_prop.isis_node_info == NULL);
}

void
isis_protocol_shut_down(node_t *node) {

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

    isis_node_info->local_lsp_pkt = isis_generate_lsp_pkt(node, &lsp_pkt_size);
    isis_node_info->lsp_pkt_size = lsp_pkt_size;

    isis_install_lsp_pkt_in_lspdb(node, isis_node_info->local_lsp_pkt, lsp_pkt_size);
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
