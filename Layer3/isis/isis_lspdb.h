#ifndef __ISIS_LSPDB__
#define __ISIS_LSPDB__

#include "isis_struct.h"

avltree_t *
isis_get_lspdb_root(node_t *node);

isis_lsp_pkt_t *
isis_lookup_lsp_from_lsdb(node_t *node, uint32_t rtr_id, pn_id_t pn_id, uint8_t fr_no);

void
isis_install_lsp(node_t *node,
                 Interface *iif,
                 isis_lsp_pkt_t *new_lsp_pkt);

void
isis_cleanup_lsdb(node_t *node, bool ted_remove);

bool
isis_is_lsp_diff(isis_lsp_pkt_t *lsp_pk1, isis_lsp_pkt_t *lsp_pkt2);

bool
isis_our_lsp(node_t *node, isis_lsp_pkt_t *lsp_pkt);

byte *
isis_print_lsp_id (isis_lsp_pkt_t *lsp_pkt, byte *lsp_id_str);

/* LSP pkt Timers */
void
isis_start_lsp_pkt_installation_timer(node_t *node, isis_lsp_pkt_t *lsp_pkt);

void
isis_stop_lsp_pkt_installation_timer(isis_lsp_pkt_t *lsp_pkt);

void
isis_refresh_lsp_pkt_installation_timer(node_t *node, isis_lsp_pkt_t *lsp_pkt);

void
isis_remove_lsp_pkt_from_lspdb(node_t *node, isis_lsp_pkt_t *lsp_pkt );

void
isis_remove_lsp_from_lspdb(node_t *node, uint32_t rtr_id, 
                                               pn_id_t pn_id, uint8_t fr_no);

bool
isis_add_lsp_pkt_in_lspdb(node_t *node, isis_lsp_pkt_t *lsp_pkt);

bool
isis_is_lsp_pkt_installed_in_lspdb(isis_lsp_pkt_t *lsp_pkt);

void
isis_parse_lsp_tlvs(node_t *node,
                    isis_lsp_pkt_t *new_lsp_pkt,
                    isis_lsp_pkt_t *old_lsp_pkt,
                    isis_event_type_t event_type);

int
isis_show_one_lsp_pkt( isis_lsp_pkt_t *lsp_pkt, byte *buff);
                    
 void
isis_show_lspdb(node_t *node) ;

void
isis_free_dummy_lsp_pkt(node_t *node);

#endif /* */
