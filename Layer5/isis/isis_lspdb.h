#ifndef __ISIS_LSPDB__
#define __ISIS_LSPDB__

/* A Data structure which holds the data to be advertised as TLVs in 
    LSPs */
typedef struct isis_adv_data_ {

    uint16_t tlv_no;

    union {
        
        uint32_t rtr_id;

        struct {

            char nbr_name[NODE_NAME_SIZE];
            uint32_t nbr_rtr_id;
            uint32_t metric;
            uint32_t local_ifindex;
            uint32_t remote_ifindex;
            uint32_t local_intf_ip;
            uint32_t remote_intf_ip;
        } adj_data;

        bool on_demand_tlv;
      
        char host_name[NODE_NAME_SIZE];

        uint32_t flags;

        struct {
            uint32_t prefix;
            uint8_t mask;
            uint32_t cost;
        } pfx;

    }u;

    glthread_t glue;
    
} isis_adv_data_t;
GLTHREAD_TO_STRUCT(glue_to_isis_advt_data, isis_adv_data_t, glue);

avltree_t *
isis_get_lspdb_root(node_t *node);

int
isis_install_lsp_pkt_in_lspdb(node_t *node, 
                              isis_lsp_pkt_t *isis_lsp_pkt);

isis_lsp_pkt_t *
isis_lookup_lsp_from_lsdb(node_t *node, uint32_t rtr_id);

void
isis_install_lsp(node_t *node,
                 interface_t *iif,
                 isis_lsp_pkt_t *new_lsp_pkt);

void
isis_cleanup_lsdb(node_t *node);

bool
isis_is_lsp_diff(isis_lsp_pkt_t *lsp_pk1, isis_lsp_pkt_t *lsp_pkt2);

bool
isis_our_lsp(node_t *node, isis_lsp_pkt_t *lsp_pkt);

byte*
isis_print_lsp_id(isis_lsp_pkt_t *lsp_pkt);

/* LSP pkt Timers */
void
isis_start_lsp_pkt_installation_timer(node_t *node, isis_lsp_pkt_t *lsp_pkt);

void
isis_stop_lsp_pkt_installation_timer(isis_lsp_pkt_t *lsp_pkt);

void
isis_refresh_lsp_pkt_installation_timer(node_t *node, isis_lsp_pkt_t *lsp_pkt);

void
isis_remove_lsp_pkt_from_lspdb(node_t *node, isis_lsp_pkt_t *lsp_pkt);

void
isis_remove_lsp_from_lspdb(node_t *node, uint32_t rtr_id);

bool
isis_add_lsp_pkt_in_lspdb(node_t *node, isis_lsp_pkt_t *lsp_pkt);

bool
isis_is_lsp_pkt_installed_in_lspdb(isis_lsp_pkt_t *lsp_pkt);

void
isis_parse_lsp_tlvs(node_t *node,
                    isis_lsp_pkt_t *new_lsp_pkt,
                    isis_lsp_pkt_t *old_lsp_pkt,
                    isis_event_type_t event_type);

void
isis_show_one_lsp_pkt_detail(node_t *node, char *rtr_id_str) ;

int
isis_show_one_lsp_pkt( isis_lsp_pkt_t *lsp_pkt, byte *buff);
                    
 void
isis_show_lspdb(node_t *node) ;

#endif /* */
