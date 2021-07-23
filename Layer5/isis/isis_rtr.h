#ifndef __ISIS_RTR__
#define __ISIS_RTR__

#include "isis_pkt.h"

typedef struct isis_node_info_ {

    isis_pkt_t isis_self_lsp_pkt;  /* defiend in isis_pkt.h */
    task_t *isis_lsp_pkt_gen_task;
} isis_node_info_t;

#define ISIS_NODE_INFO(node_ptr)    \
    (isis_node_info_t *)(node_ptr->node_nw_prop.isis_node_info)

bool
isis_node_is_enable(node_t *node) ;

void
isis_init(node_t *node );

void
isis_de_init(node_t *node) ;

void
isis_protocol_shut_down(node_t *node);

void
isis_show_node_protocol_state(node_t *node);

#endif