#ifndef __ISIS_FLOOD__
#define __ISIS_FLOOD__

typedef struct isis_lsp_xmit_elem_ {

    isis_lsp_pkt_t *lsp_pkt;
    glthread_t glue;
} __attribute__((aligned(8))) isis_lsp_xmit_elem_t;
GLTHREAD_TO_STRUCT(glue_to_lsp_xmit_elem, 
    isis_lsp_xmit_elem_t, glue);

void
isis_queue_lsp_pkt_for_transmission(
        Interface *intf,
        isis_lsp_pkt_t *lsp_pkt);

void
isis_intf_purge_lsp_xmit_queue(Interface *intf);

void
isis_schedule_lsp_flood(isis_node_info_t *node_info, 
                        isis_lsp_pkt_t *lsp_pkt,
                        Interface *exempt_intf);

void
isis_schedule_purge_lsp_flood_cbk (isis_node_info_t *node_info, isis_lsp_pkt_t *lsp_pkt);

void
isis_lsp_pkt_flood_complete(isis_node_info_t *node_info, isis_lsp_pkt_t *lsp_pkt);

void
isis_mark_isis_lsp_pkt_flood_ineligible(
        isis_node_info_t *node_info, isis_lsp_pkt_t *lsp_pkt);

void
isis_walk_all_self_zero_lsps (isis_node_info_t *node_info, void (*fn_ptr)(node_t *, isis_lsp_pkt_t *));

void 
isis_cancel_lsp_xmit_job (Interface *intf) ;

#endif /* __ISIS_FLOOD__ */
