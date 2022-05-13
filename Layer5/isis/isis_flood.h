#ifndef __ISIS_FLOOD__
#define __ISIS_FLOOD__


typedef struct isis_lsp_xmit_elem_ {

    isis_lsp_pkt_t *lsp_pkt;
    glthread_t glue;
} isis_lsp_xmit_elem_t;
GLTHREAD_TO_STRUCT(glue_to_lsp_xmit_elem, 
    isis_lsp_xmit_elem_t, glue);

void
isis_queue_lsp_pkt_for_transmission(
        interface_t *intf,
        isis_lsp_pkt_t *lsp_pkt);

void
isis_intf_purge_lsp_xmit_queue(interface_t *intf);

void
isis_schedule_lsp_flood(node_t *node, 
                        isis_lsp_pkt_t *lsp_pkt,
                        interface_t *exempt_intf,
                        isis_event_type_t event_type);

void
isis_lsp_pkt_flood_complete(node_t *node, isis_lsp_pkt_t *lsp_pkt);

void
isis_start_lsp_pkt_periodic_flooding(node_t *node);

void
isis_stop_lsp_pkt_periodic_flooding(node_t *node);

void
isis_mark_isis_lsp_pkt_flood_ineligible(
        node_t *node, isis_lsp_pkt_t *lsp_pkt);

void
isis_enter_reconciliation_phase(node_t *node);

void
isis_exit_reconciliation_phase(node_t *node);

void
isis_restart_reconciliation_timer(node_t *node);

void
isis_start_reconciliation_timer(node_t *node);

void
isis_stop_reconciliation_timer(node_t *node);

bool
isis_is_reconciliation_in_progress(node_t *node);

#endif /* __ISIS_FLOOD__ */
