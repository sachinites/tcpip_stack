#ifndef __ISIS_FLOOD__
#define __ISIS_FLOOD__

typedef struct isis_lsp_xmit_elem_ {

    isis_lsp_pkt_t *lsp_pkt;
    glthread_t glue;
} isis_lsp_xmit_elem_t;
GLTHREAD_TO_STRUCT(glue_to_lsp_xmit_elem, 
    isis_lsp_xmit_elem_t, glue);

void
isis_start_lsp_pkt_periodic_flooding(node_t *node) ;

void
isis_stop_lsp_pkt_periodic_flooding(node_t *node);

void
isis_queue_lsp_pkt_for_transmission(interface_t *intf, isis_lsp_pkt_t *lsp_pkt);

#endif 