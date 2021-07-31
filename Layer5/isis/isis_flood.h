#ifndef __ISIS_FLOOD__
#define __ISIS_FLOOD__

void
isis_queue_lsp_pkt_for_transmission(
        interface_t *intf,
        isis_pkt_t *lsp_pkt);

void
isis_intf_purge_lsp_xmit_queue(interface_t *intf);

void
isis_schedule_lsp_flood(node_t *node, 
                        isis_pkt_t *lsp_pkt,
                        interface_t *exempt_intf,
                        isis_event_type_t event_type);

void
isis_lsp_pkt_flood_complete(node_t *node, isis_pkt_t *lsp_pkt);

void
isis_start_lsp_pkt_periodic_flooding(node_t *node);

void
isis_stop_lsp_pkt_periodic_flooding(node_t *node);

void
isis_update_lsp_flood_timer_with_new_lsp_pkt(node_t *node,
        isis_pkt_t *lsp_pkt);

void
isis_mark_isis_lsp_pkt_flood_ineligible(
        node_t *node, isis_pkt_t *lsp_pkt);

#endif /* __ISIS_FLOOD__ */