#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_pkt.h"
#include "../../ted/ted.h"
#include "isis_ted.h"
#include "isis_tlv_struct.h"

extern int
avltree_prefix_tree_comp_fn(const avltree_node_t *n1, const avltree_node_t *n2) ;

void
isis_ted_install_lsp (node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    uint16_t n_tlv22;
    uint32_t metric;
    uint16_t subtlv_len;
    uint32_t ip_addr_int;
    byte *subtlv_navigator;
    avltree_t *prefix_tree_root = NULL;

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)lsp_pkt->pkt;
    isis_pkt_hdr_t *lsp_pkt_hdr = (isis_pkt_hdr_t *)(eth_hdr->payload);
    uint16_t eth_payload_size = lsp_pkt->pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD;

    byte *tlv_buffer = (byte *)(lsp_pkt_hdr + 1);

    uint16_t tlv_buff_size = eth_payload_size - sizeof(isis_pkt_hdr_t);

    n_tlv22 = isis_count_tlv_occurrences(tlv_buffer, tlv_buff_size, ISIS_IS_REACH_TLV);

    ted_template_node_data_t *node_data = (ted_template_node_data_t *)
        XCALLOC_BUFF(0, sizeof(ted_template_node_data_t) +
                            (n_tlv22 * sizeof(ted_template_nbr_data_t)));

    node_data->flags = lsp_pkt_hdr->flags;
    node_data->rtr_id = lsp_pkt_hdr->rtr_id;
    node_data->seq_no = lsp_pkt_hdr->seq_no;

    ted_template_nbr_data_t *nbr_data;
    byte tlv_type, tlv_len, *tlv_value = NULL;
    int nbr_index = 0;

    ITERATE_TLV_BEGIN(tlv_buffer, tlv_type,
                      tlv_len, tlv_value, tlv_buff_size) {

        switch (tlv_type) {

        case ISIS_TLV_HOSTNAME:
            string_copy((char *)node_data->node_name, tlv_value, tlv_len);
            break;
        case ISIS_IS_REACH_TLV:
            nbr_data = &node_data->nbr_data[nbr_index];
            nbr_index++;
            ip_addr_int = *(uint32_t *)tlv_value;
            metric = *(uint32_t *)(((uint32_t *)tlv_value) + 1);
            subtlv_len = *(uint8_t *)((uint32_t *)tlv_value + 2);

            nbr_data->nbr_rtr_id = ip_addr_int;
            nbr_data->metric = metric;

            subtlv_navigator = tlv_value +
                               sizeof(uint32_t) + // 4B IP Addr
                               sizeof(uint32_t) + // 4B metric
                               sizeof(uint8_t);   // 1B subtlv len

            /* Now Read the Sub TLVs */
            byte tlv_type2, tlv_len2, *tlv_value2 = NULL;

            ITERATE_TLV_BEGIN(subtlv_navigator, tlv_type2,
                              tlv_len2, tlv_value2, subtlv_len) {

                switch (tlv_type2)
                {
                case ISIS_TLV_IF_INDEX:
                    nbr_data->local_if_index = *(uint32_t *)tlv_value2;
                    nbr_data->remote_if_index = *(uint32_t *)((uint32_t *)tlv_value2 + 1);
                    break;
                case ISIS_TLV_LOCAL_IP:
                    nbr_data->local_ip = *(uint32_t *)tlv_value2;
                    break;
                case ISIS_TLV_REMOTE_IP:
                    nbr_data->remote_ip = *(uint32_t *)tlv_value2;
                    break;
                default:;
                }
            }
            ITERATE_TLV_END(subtlv_navigator, tlv_type2,
                            tlv_len2, tlv_value2, subtlv_len);
            break;
        case ISIS_TLV_IP_REACH:
        {
            if (!prefix_tree_root)
            {
                prefix_tree_root = (avltree_t *)XCALLOC(0, 1, avltree_t);
                avltree_init(prefix_tree_root, avltree_prefix_tree_comp_fn);
            }
            isis_tlv_130_t *tlv_130 = (isis_tlv_130_t *)tlv_value;
            ted_prefix_t *ted_prefix = (ted_prefix_t *)XCALLOC(0, 1, ted_prefix_t);
            ted_prefix->prefix = htonl(tlv_130->prefix);
            ted_prefix->mask = tlv_130->mask;
            ted_prefix->metric = htonl(tlv_130->metric);
            ted_prefix->flags = tlv_130->flags;
            avltree_insert(&ted_prefix->avl_glue, prefix_tree_root);
        }
        break;
        default:;
        }
    }
    ITERATE_TLV_END(tlv_buffer, tlv_type,
                    tlv_len, tlv_value, tlv_buff_size);

    node_data->n_nbrs = n_tlv22;
    ted_db_t *ted_db = ISIS_TED_DB(node);
    ted_create_or_update_node(ted_db, node_data, prefix_tree_root);
    XFREE(node_data);
}

void
isis_ted_uninstall_lsp(node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    ted_db_t *ted_db = ISIS_TED_DB(node);
    uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(lsp_pkt);
    ted_node_t *ted_node = ted_lookup_node(ted_db, *rtr_id);
    assert(ted_node);
    isis_spf_cleanup_spf_data(ted_node);
    ted_delete_node (ted_db, ted_node);
}

void
isis_cleanup_teddb_root(node_t *node) {

    ted_db_t *ted_db = ISIS_TED_DB(node);
    if (!ted_db) return;
    assert(avltree_is_empty(&ted_db->teddb));
    XFREE(ted_db);
    ISIS_TED_DB(node) = NULL;
 }

 void
 isis_ted_refresh_seq_no (node_t *node, uint32_t new_seq_no) {

     ted_db_t *ted_db = ISIS_TED_DB(node);

     if (!ted_db || avltree_is_empty(&ted_db->teddb)) return;

     ted_refresh_node_seq_no (ted_db,
            tcp_ip_covert_ip_p_to_n ( NODE_LO_ADDR(node)),
            new_seq_no);
 }
