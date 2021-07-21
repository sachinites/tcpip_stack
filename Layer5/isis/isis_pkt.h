#ifndef __ISIS_PKT__
#define __ISIS_PKT__

bool
isis_pkt_trap_rule(char *pkt, size_t pkt_size);

void
isis_pkt_recieve(void *arg, size_t arg_size);

void
isis_install_lsp_pkt_in_lspdb(node_t *node, char *isis_lsp_pkt, size_t lsp_pkt_size);

char *
isis_generate_lsp_pkt(node_t *node, size_t *lsp_pkt_size);

#endif // !__ISIS_PKT__