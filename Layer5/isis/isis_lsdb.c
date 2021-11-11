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
 isis_print_formatted_nbr_tlv22 (byte *buff,
                            byte *nbr_tlv_buffer, 
                            uint8_t tlv_buffer_len) {

    uint32_t rc = 0;
    byte *subtlv_ptr;
    uint32_t ip_addr_int, metric;
    uint8_t subtlv_len;

    byte tlv_type, tlv_len, *tlv_value = NULL;

    ITERATE_TLV_BEGIN(nbr_tlv_buffer, tlv_type, tlv_len, tlv_value, tlv_buffer_len) {

        if (buff) {
        rc += sprintf (buff + rc , 
                    "\tTLV%d  Len : %d\n", tlv_type, tlv_len);
        }
        else {
            rc += printf( "\tTLV%d  Len : %d\n", tlv_type, tlv_len);
        }
        /* Now we shall extract IP Addr, metric and subtlv len */
        ip_addr_int = *(uint32_t *)tlv_value;
        metric = *(uint32_t *)(((uint32_t *)tlv_value) + 1);
        subtlv_len = *(uint8_t *)((uint32_t *)tlv_value + 2);

        if (buff) {
        rc += sprintf(buff + rc, "\t\tNbr Rtr ID : %s     metric : %u    SubTLV len : %d\n",
                      tcp_ip_covert_ip_n_to_p(ip_addr_int, 0), metric, subtlv_len);
        }
        else {
            rc += printf ("\t\tNbr Rtr ID : %s     metric : %u    SubTLV len : %d\n",
                      tcp_ip_covert_ip_n_to_p(ip_addr_int, 0), metric, subtlv_len);
        }
        subtlv_ptr = tlv_value + 
                            sizeof (uint32_t) +    // 4B of IP Addr ( nbr lo addr )
                            sizeof(uint32_t) +     // 4B of metric  
                            sizeof(uint8_t);         // 1B of subtlv len

        /* Now Read the Sub TLVs */
        byte tlv_type2, tlv_len2, *tlv_value2 = NULL;

        ITERATE_TLV_BEGIN (subtlv_ptr, tlv_type2, tlv_len2, tlv_value2, subtlv_len) {

            switch (tlv_type2) {
                case ISIS_TLV_IF_INDEX:
                    if (buff) {
                    rc += sprintf (buff + rc, 
                                "\tSubTLV%d  Len : %d   if-indexes [local : %u, remote : %u]\n",
                                tlv_type2, tlv_len2, *(uint32_t *)tlv_value2, 
                                *(uint32_t *)((uint32_t *)tlv_value2 + 1));
                    }
                    else {
                        rc += printf ( "\tSubTLV%d  Len : %d   if-indexes [local : %u, remote : %u]\n",
                                tlv_type2, tlv_len2, *(uint32_t *)tlv_value2, 
                                *(uint32_t *)((uint32_t *)tlv_value2 + 1));
                    }
                        break;
                case ISIS_TLV_LOCAL_IP:
                    ip_addr_int = *(uint32_t *)tlv_value2;
                    if (buff) {
                    rc += sprintf (buff + rc , "\tSubTLV%d  Len : %d  Local IP : %s\n",
                                tlv_type2, tlv_len2, 
                                tcp_ip_covert_ip_n_to_p(ip_addr_int, 0));
                    }
                    else {
                        rc += printf ("\tSubTLV%d  Len : %d  Local IP : %s\n",
                                tlv_type2, tlv_len2, 
                                tcp_ip_covert_ip_n_to_p(ip_addr_int, 0));
                    }
                        break;
                case ISIS_TLV_REMOTE_IP:
                    ip_addr_int = *(uint32_t *)tlv_value2;
                    if (buff) {
                    rc += sprintf (buff + rc , "\tSubTLV%d  Len : %d  Remote IP : %s\n",
                                tlv_type2, tlv_len2, 
                                tcp_ip_covert_ip_n_to_p(ip_addr_int, 0));
                    }
                    else {
                        rc += printf ("\tSubTLV%d  Len : %d  Remote IP : %s\n",
                                tlv_type2, tlv_len2, 
                                tcp_ip_covert_ip_n_to_p(ip_addr_int, 0));
                    }
                        break;
                default: ;
            }
        } ITERATE_TLV_END (subtlv_ptr, tlv_type2, tlv_len2, tlv_value2, subtlv_len);
    }ITERATE_TLV_END(nbr_tlv_buffer, tlv_type, tlv_len, tlv_value, tlv_buffer_len);
    return rc;
}


uint32_t 
isis_show_one_lsp_pkt_detail (byte *buff, 
                                                  isis_pkt_hdr_t *lsp_pkt_hdr,
                                                  size_t pkt_size) {

    uint32_t rc = 0;
    byte tlv_type, tlv_len, *tlv_value = NULL;

    if (buff) {
        rc += sprintf(buff + rc , "LSP : %s(%u)\n", 
                            tcp_ip_covert_ip_n_to_p(lsp_pkt_hdr->rtr_id, 0),
                            lsp_pkt_hdr->seq_no);
    }
    else {
        rc += printf ( "LSP : %s(%u)\n", 
                            tcp_ip_covert_ip_n_to_p(lsp_pkt_hdr->rtr_id, 0),
                            lsp_pkt_hdr->seq_no);
    }

    if (buff) {
        rc += sprintf (buff + rc , "Flags : 0x%x\n", lsp_pkt_hdr->flags);
    }
    else {
        rc += printf ("Flags : 0x%x\n", lsp_pkt_hdr->flags);
    }

    if (buff) {
        rc += sprintf(buff + rc , "TLVs\n");
    }
    else {
        rc += printf ("TLVs\n");
    }

    byte *lsp_tlv_buffer = (byte *)(lsp_pkt_hdr + 1);
    uint16_t lsp_tlv_buffer_size = (uint16_t) (pkt_size -
                                                    sizeof(isis_pkt_hdr_t));

    ITERATE_TLV_BEGIN (lsp_tlv_buffer, tlv_type, 
                                                tlv_len, tlv_value,
                                                lsp_tlv_buffer_size) {

        switch(tlv_type) {

            case ISIS_TLV_HOSTNAME:
                if (buff) {
                    rc += sprintf (buff + rc , "\tTLV%d Host-Name : %s\n", 
                            tlv_type, tlv_value);
                }
                else {
                    rc += printf ( "\tTLV%d Host-Name : %s\n",  tlv_type, tlv_value);
                }
            break;
            case ISIS_IS_REACH_TLV:
                rc += isis_print_formatted_nbr_tlv22(buff ? buff + rc  : NULL,
                                tlv_value - TLV_OVERHEAD_SIZE,
                                tlv_len + TLV_OVERHEAD_SIZE);
            break;
            default:;
        }

    } ITERATE_TLV_END (lsp_tlv_buffer, tlv_type, 
                                                tlv_len, tlv_value,
                                                lsp_tlv_buffer_size); 
    return rc;
}

void
isis_show_lspdb(node_t *node) {

    isis_node_info_t *node_info;

    if ( !isis_is_protocol_enable_on_node(node)) return;

    node_info = ISIS_NODE_INFO(node);
    
    isis_lsp_pkt_t *lsp_pkt = node_info->self_lsp_pkt;
    if (!lsp_pkt) return;

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)(lsp_pkt->pkt);
    isis_pkt_hdr_t *lsp_pkt_hdr = (isis_pkt_hdr_t *)(eth_hdr->payload);
    size_t lsp_pkt_size = lsp_pkt->pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD;

    isis_show_one_lsp_pkt_detail (NULL, lsp_pkt_hdr, lsp_pkt_size);
}

static void
 isis_generate_lsp_pkt(void *arg, uint32_t arg_size) {

     node_t *node = (node_t *)arg;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

     sprintf(tlb, "%s : Self-LSP Generation task %p triggered\n",
            ISIS_LSPDB_MGMT,  node_info->lsp_pkt_gen_task);
    tcp_trace(node, 0, tlb);
    
    node_info->lsp_pkt_gen_task = NULL;

    isis_create_fresh_lsp_pkt(node);
 }

void
isis_schedule_lsp_pkt_generation(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    if (node_info->lsp_pkt_gen_task) {

        sprintf(tlb, "%s : LSP generation Already scheduled\n",
                ISIS_LSPDB_MGMT);
        tcp_trace(node, 0, tlb);
        return;
    }

    node_info->lsp_pkt_gen_task = 
        task_create_new_job(node, isis_generate_lsp_pkt, TASK_ONE_SHOT);

    sprintf(tlb, "%s : LSP pkt generation task scheduled\n",
             ISIS_LSPDB_MGMT);
}

byte*
isis_print_lsp_id(isis_lsp_pkt_t *lsp_pkt) {

    static byte lsp_id[32];
    
    memset(lsp_id, 0, sizeof(lsp_id));
    uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(lsp_pkt);
    uint32_t *seq_no = isis_get_lsp_pkt_seq_no(lsp_pkt);

    sprintf(lsp_id, "%s-%u", tcp_ip_covert_ip_n_to_p(*rtr_id, 0), *seq_no);
    return lsp_id;
}