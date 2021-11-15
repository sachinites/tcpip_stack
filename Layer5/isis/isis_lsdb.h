#ifndef __ISIS_LSDB__
#define __ISIS_LSDB__

typedef struct isis_pkt_hdr_ isis_pkt_hdr_t;

void isis_cleanup_lsdb(node_t *node);

avltree_t *
isis_get_lspdb_root(node_t *node);

void
isis_remove_lsp_pkt_from_lsdb(node_t *node, isis_lsp_pkt_t *lsp_pkt) ;

bool
isis_add_lsp_pkt_in_lsdb(node_t *node, isis_lsp_pkt_t *lsp_pkt);

void
isis_remove_lsp_from_lsdb(node_t *node, uint32_t rtr_id) ;

isis_lsp_pkt_t *
isis_lookup_lsp_from_lsdb(node_t *node, uint32_t rtr_id);

void
isis_free_dummy_lsp_pkt(void) ;

bool
isis_our_lsp(node_t *node, isis_lsp_pkt_t *lsp_pkt);

byte*
isis_print_lsp_id(isis_lsp_pkt_t *lsp_pkt);

uint32_t *
isis_get_lsp_pkt_rtr_id(isis_lsp_pkt_t *lsp_pkt);

uint32_t *
isis_get_lsp_pkt_seq_no(isis_lsp_pkt_t *lsp_pkt);

uint32_t 
isis_show_one_lsp_pkt_detail (byte *buff, 
                                                  isis_pkt_hdr_t *lsp_pkt_hdr,
                                                  size_t pkt_size);

void
isis_show_lspdb(node_t *node) ;

void
isis_schedule_lsp_pkt_generation(node_t *node);

void
isis_install_lsp(node_t *node,
                 interface_t *iif,
                 isis_lsp_pkt_t *new_lsp_pkt);
                 
#endif 