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

char *
isis_get_hello_pkt(interface_t *intf, size_t *hello_pkt_size);

void
isis_print_hello_pkt(void *arg, size_t arg_size);

typedef struct isis_pkt_meta_data_ {

    node_t *node;
    interface_t *intf;
    char *pkt;
    size_t pkt_size;
} isis_pkt_meta_data_t;

#endif // !__ISIS_PKT__