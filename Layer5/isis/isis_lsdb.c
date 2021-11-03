#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_lsdb.h"
#include "isis_const.h"

static isis_lsp_pkt_t *gl_dummy_lsp_pkt = NULL;

static isis_lsp_pkt_t *
isis_get_dummy_lsp_pkt_with_key(uint32_t rtr_id) {

    if (!gl_dummy_lsp_pkt) {

        gl_dummy_lsp_pkt = calloc(1, sizeof(isis_lsp_pkt_t));

        gl_dummy_lsp_pkt->pkt = 
            tcp_ip_get_new_pkt_buffer(ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(isis_pkt_hdr_t));
        gl_dummy_lsp_pkt->pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(isis_pkt_hdr_t);
        gl_dummy_lsp_pkt->installed_in_db = false;
    }

    uint32_t *rtr_id_addr = isis_get_lsp_pkt_rtr_id(gl_dummy_lsp_pkt);
    *rtr_id_addr = rtr_id;
    return gl_dummy_lsp_pkt;
}

void
isis_free_dummy_lsp_pkt(void) {

    if (gl_dummy_lsp_pkt) {
        tcp_ip_free_pkt_buffer(gl_dummy_lsp_pkt->pkt, gl_dummy_lsp_pkt->pkt_size);
        free(gl_dummy_lsp_pkt);
        gl_dummy_lsp_pkt = NULL;
    }
}

avltree_t *
isis_get_lspdb_root(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if(node_info) {
        return &node_info->lspdb_avl_root;
    }
    return NULL;
}

void
isis_remove_lsp_pkt_from_lsdb(node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    avltree_t *lsdb = isis_get_lspdb_root(node);
    if (!lsdb) return;

    if (lsp_pkt->installed_in_db == false) return;

    avltree_remove(&lsp_pkt->avl_node_glue, lsdb);
    lsp_pkt->installed_in_db = false;
}

void
isis_remove_lsp_from_lsdb(node_t *node, uint32_t rtr_id) {

    avltree_t *lspdb = isis_get_lspdb_root(node);
    if (!lspdb) return ;

    isis_lsp_pkt_t *lsp_pkt = isis_lookup_lsp_from_lsdb(node, rtr_id);
    if (!lsp_pkt) return;
    isis_remove_lsp_pkt_from_lsdb(node, lsp_pkt);
}

bool
isis_add_lsp_pkt_in_lsdb(node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    avltree_t *lsdb = isis_get_lspdb_root(node);
    if (!lsdb) return false;

    if (lsp_pkt->installed_in_db) return false;

    avltree_insert(&lsp_pkt->avl_node_glue, lsdb);
    lsp_pkt->installed_in_db = true;
    return true;
}

isis_lsp_pkt_t *
isis_lookup_lsp_from_lsdb(node_t *node, uint32_t rtr_id) {

    avltree_t *lsdb = isis_get_lspdb_root(node);
    if ( !lsdb) return NULL;

    isis_lsp_pkt_t *dummy_lsp_pkt = isis_get_dummy_lsp_pkt_with_key(rtr_id);

    avltree_node_t *avl_node = 
        avltree_lookup(&dummy_lsp_pkt->avl_node_glue, lsdb);

    if (!avl_node) return NULL;

    return avltree_container_of(avl_node, isis_lsp_pkt_t, avl_node_glue);
}

void isis_cleanup_lsdb(node_t *node) {

    avltree_node_t *curr;
    isis_lsp_pkt_t *lsp_pkt;
    avltree_t *lsdb = isis_get_lspdb_root(node);

    if (!lsdb) return;

    ITERATE_AVL_TREE_BEGIN(lsdb, curr) {

        lsp_pkt = avltree_container_of(curr, isis_lsp_pkt_t, avl_node_glue);
        isis_remove_lsp_pkt_from_lsdb(node, lsp_pkt);
    } ITERATE_AVL_TREE_END;
}

bool
isis_our_lsp(node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(lsp_pkt);
    uint32_t node_lo_addr = tcp_ip_covert_ip_p_to_n(NODE_LO_ADDR(node));

    return *rtr_id == node_lo_addr;
}

uint32_t *
isis_get_lsp_pkt_rtr_id(isis_lsp_pkt_t *lsp_pkt) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)lsp_pkt->pkt;
    isis_pkt_hdr_t *lsp_hdr = (isis_pkt_hdr_t *)(eth_hdr->payload);

   return &lsp_hdr->rtr_id;
}

uint32_t *
isis_get_lsp_pkt_seq_no(isis_lsp_pkt_t *lsp_pkt) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)lsp_pkt->pkt;
    isis_pkt_hdr_t *lsp_hdr = (isis_pkt_hdr_t *)(eth_hdr->payload);

   return &lsp_hdr->seq_no;
}

/* Printing LSP packets */

static uint32_t
isis_print_formatted_nbr_tlv22(byte *out_buff, 
                             byte *nbr_tlv_buffer,
                             uint8_t tlv_buffer_len) {

    uint32_t rc = 0;
    uint8_t subtlv_len;
    byte *subtlv_navigator;
    unsigned char *ip_addr;
    uint32_t ip_addr_int, metric;
    byte tlv_type, tlv_len, *tlv_value = NULL;

    ITERATE_TLV_BEGIN(nbr_tlv_buffer, tlv_type,
                        tlv_len, tlv_value, tlv_buffer_len) {

        rc += sprintf(out_buff + rc,
                      "\tTLV%d  Len : %d\n", tlv_type, tlv_len);

        ip_addr_int = *(uint32_t *)tlv_value;
        metric = *(uint32_t *)(((uint32_t *)tlv_value) + 1);
        subtlv_len = *(uint8_t *)((uint32_t *)tlv_value + 2);

        rc += sprintf(out_buff + rc, "\t\tNbr Rtr ID : %s   Metric : %u   SubTLV Len : %d\n",
                      tcp_ip_covert_ip_n_to_p(ip_addr_int, 0),
                      metric, subtlv_len);

        subtlv_navigator = tlv_value + 
                            sizeof(uint32_t) +  // 4B IP Addr
                            sizeof(uint32_t) +  // 4B metric
                            sizeof(uint8_t);    // 1B subtlv len

        /* Now Read the Sub TLVs */
        byte tlv_type2, tlv_len2, *tlv_value2 = NULL;

        ITERATE_TLV_BEGIN(subtlv_navigator, tlv_type2,
                        tlv_len2, tlv_value2, subtlv_len) {

            switch(tlv_type2) {
                case ISIS_TLV_IF_INDEX:

                    rc += sprintf(out_buff + rc,
                                  "\tSubTLV%d  Len : %d   if-indexes [local : %u, remote : %u]\n",
                                  tlv_type2, tlv_len2,
                                  *(uint32_t *)tlv_value2,
                                  *(uint32_t *)((uint32_t *)tlv_value2 + 1));

                    break;
                case ISIS_TLV_LOCAL_IP:
                    ip_addr_int = *(uint32_t *)tlv_value2;

                    rc += sprintf(out_buff + rc,
                                  "\tSubTLV%d  Len : %d   Local IP : %s\n",
                                  tlv_type2, tlv_len2,
                                  tcp_ip_covert_ip_n_to_p(ip_addr_int, 0));

                    break;
                case ISIS_TLV_REMOTE_IP:
                    ip_addr_int = *(uint32_t *)tlv_value2;

                    rc += sprintf(out_buff + rc,
                                  "\tSubTLV%d  Len : %d   Remote IP : %s\n",
                                  tlv_type2, tlv_len2,
                                  tcp_ip_covert_ip_n_to_p(ip_addr_int, 0));

                    break;
                default:
                    ;
            }

        } ITERATE_TLV_END(subtlv_navigator, tlv_type2,
                        tlv_len2, tlv_value2, subtlv_len);
 
    } ITERATE_TLV_END(nbr_tlv_buffer, tlv_type,
                        tlv_len, tlv_value, tlv_buffer_len);
    return rc;
}

uint32_t 
isis_show_one_lsp_pkt_detail (byte *buff, 
                                                  isis_pkt_hdr_t *lsp_pkt_hdr,
                                                  size_t pkt_size) {

    uint32_t rc = 0;
    isis_lsp_pkt_t *lsp_pkt;
    
    byte tlv_type, tlv_len, *tlv_value = NULL;

    rc += sprintf(buff + rc, "LSP : %s(%u)\n",
             tcp_ip_covert_ip_n_to_p(lsp_pkt_hdr->rtr_id, 0), 
            lsp_pkt_hdr->seq_no);

    rc += sprintf(buff + rc,  "Flags : 0x%x\n", lsp_pkt_hdr->flags);
    
    rc += sprintf(buff + rc, "TLVs\n");

    byte *lsp_tlv_buffer = (byte *)(lsp_pkt_hdr + 1);
    uint16_t lsp_tlv_buffer_size = (uint16_t)(lsp_pkt->pkt_size -
                                        ETH_HDR_SIZE_EXCL_PAYLOAD -
                                        sizeof(isis_pkt_hdr_t)) ;

    ITERATE_TLV_BEGIN(lsp_tlv_buffer, tlv_type,
                        tlv_len, tlv_value,
                        lsp_tlv_buffer_size) {

        switch(tlv_type) {
            case ISIS_TLV_HOSTNAME:
                rc += sprintf(buff + rc,  "\tTLV%d Host-Name : %s\n", 
                        tlv_type, tlv_value);
            break;
            case ISIS_IS_REACH_TLV:
                 rc += isis_print_formatted_nbr_tlv22( buff + rc,
                        tlv_value - TLV_OVERHEAD_SIZE,
                        tlv_len + TLV_OVERHEAD_SIZE);
                break;
            default: ;
        }
    } ITERATE_TLV_END(lsp_tlv_buffer, tlv_type,
                        tlv_len, tlv_value,
                        lsp_tlv_buffer_size);

    return rc;
}
