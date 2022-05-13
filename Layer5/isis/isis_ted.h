#ifndef __ISIS_TED__
#define __ISIS_TED__


#define ISIS_TED_DB(node_ptr)   \
     ((ISIS_NODE_INFO(node_ptr))->ted_db)

void
isis_ted_uninstall_lsp(node_t *node, isis_lsp_pkt_t *lsp_pkt) ;

void
isis_ted_install_lsp (node_t *node, isis_lsp_pkt_t *lsp_pkt);

void
isis_cleanup_teddb_root(node_t *node) ;

void
 isis_ted_refresh_seq_no (node_t *node, uint32_t new_seq_no) ;

#endif /**/
