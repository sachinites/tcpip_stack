#ifndef __ISIS_TED__
#define __ISIS_TED__

#include <stdint.h>

#define ISIS_TED_DB(node_ptr)   \
     ((ISIS_NODE_INFO(node_ptr))->ted_db)

void
isis_ted_uninstall_lsp(node_t *node, isis_lsp_pkt_t *lsp_pkt) ;

void
isis_ted_detach_lsp (node_t *node, isis_lsp_pkt_t *lsp_pkt);

void
isis_ted_update_or_install_lsp (node_t *node, isis_lsp_pkt_t *lsp_pkt);

void
isis_cleanup_teddb_root (node_t *node) ;

void
isis_cleanup_teddb (node_t *node) ;

void
isis_ted_increase_seq_no (node_t *node, uint32_t rtr_id, uint8_t pn_no);

#endif /**/
