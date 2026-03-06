#ifndef __ISIS_TED__
#define __ISIS_TED__

#include <stdint.h>

#define ISIS_TED_DB(node_info_ptr)   \
     ((node_info_ptr)->ted_db)

void
isis_ted_uninstall_lsp(isis_node_info_t *node_info, ted_db_t *ted_db, isis_lsp_pkt_t *lsp_pkt) ;

void
isis_ted_update_or_install_lsp (isis_node_info_t *node_info,  ted_db_t *ted_db, isis_lsp_pkt_t *lsp_pkt);

void
isis_cleanup_teddb_root (isis_node_info_t *node_info) ;

void
isis_cleanup_teddb (isis_node_info_t *node_info) ;


#endif /**/
