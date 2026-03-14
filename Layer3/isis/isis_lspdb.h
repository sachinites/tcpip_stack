#ifndef __ISIS_LSPDB__
#define __ISIS_LSPDB__

#include "isis_struct.h"

avltree_t *
isis_get_lspdb_root(isis_node_info_t *node_info);

isis_lsp_pkt_t *
isis_lookup_lsp_from_lsdb(isis_node_info_t *node_info, uint32_t rtr_id, pn_id_t pn_id, uint8_t fr_no);

void
isis_install_lsp(isis_node_info_t *node_info,
                 Interface *iif,
                 isis_lsp_pkt_t *new_lsp_pkt);

void
isis_cleanup_lsdb(isis_node_info_t *node_info, bool ted_remove);

bool
isis_is_lsp_diff(isis_lsp_pkt_t *lsp_pk1, isis_lsp_pkt_t *lsp_pkt2);

bool
isis_our_lsp(isis_node_info_t *node_info, isis_lsp_pkt_t *lsp_pkt);

byte *
isis_print_lsp_id (isis_lsp_pkt_t *lsp_pkt, byte *lsp_id_str);

/* LSP pkt Timers */
void
isis_start_lsp_pkt_installation_timer(isis_node_info_t *node_info, isis_lsp_pkt_t *lsp_pkt);

void
isis_stop_lsp_pkt_installation_timer(isis_lsp_pkt_t *lsp_pkt);

void
isis_refresh_lsp_pkt_installation_timer(isis_node_info_t *node_info, isis_lsp_pkt_t *lsp_pkt);

void
isis_remove_lsp_pkt_from_lspdb(isis_node_info_t *node_info, isis_lsp_pkt_t *lsp_pkt );

void
isis_remove_lsp_from_lspdb(isis_node_info_t *node_info, uint32_t rtr_id, 
                                               pn_id_t pn_id, uint8_t fr_no);

bool
isis_add_lsp_pkt_in_lspdb(isis_node_info_t *node_info, isis_lsp_pkt_t *lsp_pkt);

bool
isis_is_lsp_pkt_installed_in_lspdb(isis_lsp_pkt_t *lsp_pkt);

int
isis_show_one_lsp_pkt( isis_lsp_pkt_t *lsp_pkt, byte *buff);
                    
 void
isis_show_lspdb(isis_node_info_t *node_info) ;

void
isis_free_dummy_lsp_pkt(isis_node_info_t *node_info);

void 
isis_ips_send_lsp_update (isis_node_info_t *node_info, isis_lsp_pkt_t *lsp_pkt, bool add);
void 
isis_ips_send_lsp_seqno_update (isis_node_info_t *node_info, isis_lsp_pkt_t *lsp_pkt ) ;

#endif /* */
