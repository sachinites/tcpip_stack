#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_pkt.h"
#include "isis_lspdb.h"
#include "isis_flood.h"
#include "isis_spf.h"
#include "isis_events.h"
#include "isis_adjacency.h"
#include "isis_ted.h"
#include "isis_tlv_struct.h"
#include "isis_advt.h"

void
isis_parse_lsp_tlvs_internal(isis_lsp_pkt_t *new_lsp_pkt, 
                             bool *on_demand_tlv);

static isis_lsp_pkt_t *
isis_get_dummy_lsp_pkt_with_key(node_t *node, uint32_t rtr_id, pn_id_t pn_id, uint8_t fr_no) {

    uint32_t pkt_size;
    uint32_t *rtr_id_addr;
    isis_node_info_t *node_info ;

    node_info = ISIS_NODE_INFO(node);
    
    if (!node_info || !isis_is_protocol_enable_on_node(node)) return;

    if (!node_info->lsp_dummy_pkt) {
    
        node_info->lsp_dummy_pkt = (isis_lsp_pkt_t *)XCALLOC(0, 1, isis_lsp_pkt_t);
        pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + ISIS_LSP_HDR_SIZE;
        node_info->lsp_dummy_pkt->pkt = tcp_ip_get_new_pkt_buffer ( pkt_size);
        isis_mark_isis_lsp_pkt_flood_ineligible(0, node_info->lsp_dummy_pkt);
        node_info->lsp_dummy_pkt->pkt_size = pkt_size;
	    node_info->lsp_dummy_pkt->alloc_size = pkt_size;
        node_info->lsp_dummy_pkt->expiry_timer = NULL;
        node_info->lsp_dummy_pkt->installed_in_db = false;
        isis_ref_isis_pkt(node_info->lsp_dummy_pkt);
    }
    
    rtr_id_addr = isis_get_lsp_pkt_rtr_id(node_info->lsp_dummy_pkt);
    *rtr_id_addr = rtr_id;

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)(node_info->lsp_dummy_pkt->pkt);
    isis_pkt_hdr_t *lsp_hdr = (isis_pkt_hdr_t *)(eth_hdr->payload);
    lsp_hdr->pn_no = pn_id;
    lsp_hdr->fr_no = fr_no;

    return node_info->lsp_dummy_pkt;
}

void
isis_free_dummy_lsp_pkt(node_t *node){

    int rc;
    isis_node_info_t *node_info ;
    node_info = ISIS_NODE_INFO(node);

    if (!node_info || !isis_is_protocol_enable_on_node(node)) return;

    if(!node_info->lsp_dummy_pkt) return ;
    rc = isis_deref_isis_pkt(node, node_info->lsp_dummy_pkt);
    if (rc == 0) node_info->lsp_dummy_pkt = NULL;
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
isis_install_lsp(node_t *node,
                 Interface *iif,
                 isis_lsp_pkt_t *new_lsp_pkt) {

    bool self_lsp;
    uint32_t *rtr_id;
    ip_add_t rtr_id_str;
    bool duplicate_lsp;
    bool recvd_via_intf;
    isis_lsp_pkt_t *old_lsp_pkt;
    isis_event_type_t event_type;
    uint32_t *old_seq_no = NULL;
    isis_pkt_hdr_flags_t lsp_flags;
    byte lsp_id_str_old[ISIS_LSP_ID_STR_SIZE];
    byte lsp_id_str_new[ISIS_LSP_ID_STR_SIZE];
    
    recvd_via_intf = iif ? true : false;
    self_lsp = isis_our_lsp(node, new_lsp_pkt);
    event_type = isis_event_none;
    lsp_flags = isis_lsp_pkt_get_flags(new_lsp_pkt);
    rtr_id = isis_get_lsp_pkt_rtr_id(new_lsp_pkt);

    isis_print_lsp_id (new_lsp_pkt, lsp_id_str_new);
    strcpy (lsp_id_str_old, "Nil");

    bool purge_lsp = lsp_flags & ISIS_LSP_PKT_F_PURGE_BIT;

    old_lsp_pkt = isis_lookup_lsp_from_lsdb(
                    node, *rtr_id, 
                    isis_get_lsp_pkt_pn_id(new_lsp_pkt) , 
                    isis_get_lsp_pkt_fr_no (new_lsp_pkt)); 

    if (old_lsp_pkt) {
        isis_ref_isis_pkt(old_lsp_pkt);
        old_seq_no = isis_get_lsp_pkt_seq_no(old_lsp_pkt);
        isis_print_lsp_id (old_lsp_pkt, lsp_id_str_old);
    }

    uint32_t *new_seq_no = isis_get_lsp_pkt_seq_no(new_lsp_pkt);

    sprintf(tlb, "%s : Lsp Recvd : %s on intf %s, old lsp : %s\n",
            ISIS_LSPDB_MGMT,
            lsp_id_str_new,
            iif ? iif->if_name.c_str() : "Nil",
            lsp_id_str_old);
    tcp_trace(node, iif, tlb);

    duplicate_lsp = (old_lsp_pkt && (*new_seq_no == *old_seq_no));

    if (self_lsp && duplicate_lsp) {

        event_type = isis_event_self_duplicate_lsp;
        sprintf(tlb, "\t%s : Event : %s : self Duplicate LSP, No Action\n",
            ISIS_LSPDB_MGMT, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        /* Action :
            1. if foriegn lsp then do nothing
            2. if self originated lsp then assert, impossible case*/
        if (recvd_via_intf) {

             // no action
        } else {

            assert(0);
        }
    }

    else if (self_lsp && !old_lsp_pkt) {

        event_type = isis_event_self_fresh_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_MGMT, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        /* Action :
            1. if foriegn rtr has send me my own LSP, and I never had such a LSP in my local db
            then ignore such a LSP.
            2. if self originated lsp then install in db and flood on all intf*/
        if (recvd_via_intf) {
            return;
            assert(0);     
        } else {
            sprintf(tlb, "\t%s : Event : %s : LSP to be Added in LSPDB and flood\n",
                ISIS_LSPDB_MGMT, isis_event_str(event_type));
            tcp_trace(node, iif, tlb);
            isis_add_lsp_pkt_in_lspdb(node, new_lsp_pkt);
            isis_schedule_lsp_flood(node, new_lsp_pkt, 0);
        }
    }

    else if (self_lsp && old_lsp_pkt && (*new_seq_no > *old_seq_no)) {

        event_type = isis_event_self_new_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_MGMT, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        /* Action :
            1. if foreign lsp, regenerate self lsp with higher 
                sequence no and flood on all intf
            2. if self originated lsp then replace it in db and 
                install new one and flood it on all intf */
        if (recvd_via_intf) {
            old_lsp_pkt->fragment->seq_no = *new_seq_no;
            sprintf(tlb, "\t%s : Event : %s : LSP %s to be generated with seq no %u\n",
                ISIS_LSPDB_MGMT, lsp_id_str_old, isis_event_str(event_type), 
                *new_seq_no + 1);
            tcp_trace(node, iif, tlb);
            isis_schedule_regen_fragment(node, old_lsp_pkt->fragment, event_type);
        } else {
            sprintf(tlb, "\t%s : Event : %s : LSP %s to be replaced in LSPDB "
                "with new LSP %s and flood\n",
                ISIS_LSPDB_MGMT, isis_event_str(event_type),
                lsp_id_str_old, lsp_id_str_new);
            tcp_trace(node, iif, tlb);
            isis_remove_lsp_pkt_from_lspdb(node, old_lsp_pkt);
            isis_mark_isis_lsp_pkt_flood_ineligible(node, old_lsp_pkt);
            isis_add_lsp_pkt_in_lspdb(node, new_lsp_pkt);
            isis_schedule_lsp_flood(node, new_lsp_pkt, 0);
        }
    }

    else if (self_lsp && old_lsp_pkt && (*new_seq_no < *old_seq_no)) {

        event_type = isis_event_self_old_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_MGMT, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        /* Action :
            1. if foreign lsp, then flood existing one on all intf
            2. if self originated lsp then assert, impossible case */
        if (recvd_via_intf) {
            sprintf(tlb, "\t%s : Event : %s : LSP %s to be flooded\n",
                ISIS_LSPDB_MGMT, isis_event_str(event_type),
                lsp_id_str_old);
            tcp_trace(node, iif, tlb);
            isis_schedule_lsp_flood(node, old_lsp_pkt, 0);
        } else {

            assert(0);
        }
    }

    else if (!self_lsp && duplicate_lsp) {

        event_type = isis_event_non_local_duplicate_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_MGMT, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        /* Action :
            1. if foreign lsp then do nothing
            2. if self originated lsp then assert, impossible case */
        if (recvd_via_intf) {
            sprintf(tlb, "\t%s : Event : %s Recvd Duplicate LSP %s, no Action\n",
                ISIS_LSPDB_MGMT, isis_event_str(event_type), lsp_id_str_new);
            tcp_trace(node, iif, tlb);
        } else {
            assert(0);
        }
    }

    else if (!self_lsp && !old_lsp_pkt) {

        event_type = isis_event_non_local_fresh_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_MGMT, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        /* Action :
            1. if foreign lsp then install in db and flood forward it
            2. if self originated lsp then assert, impossible case */
        if (recvd_via_intf) {
            sprintf(tlb, "\t%s : Event : %s : LSP %s to be Added in LSPDB and flood\n",
                ISIS_LSPDB_MGMT, isis_event_str(event_type), lsp_id_str_new);
            tcp_trace(node, iif, tlb);
            if (!purge_lsp) {
                isis_add_lsp_pkt_in_lspdb(node, new_lsp_pkt);
                /* Do not flood purge LSP if it do not removes LSP from our DB*/
                isis_schedule_lsp_flood(node, new_lsp_pkt, iif);
            }
        } else {

            assert(0);
        }
    }

    else if (!self_lsp && old_lsp_pkt && (*new_seq_no > *old_seq_no)) {

        event_type = isis_event_non_local_new_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_MGMT, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        /* Action :
            1. if foreign lsp then replace in db and flood forward it
            2. if self originated lsp then assert, impossible case */
        if (recvd_via_intf) {
            if (!purge_lsp) {
                sprintf(tlb, "\t%s : Event : %s : LSP %s to be replaced in LSPDB with"
                    " LSP %s and flood\n",
                    ISIS_LSPDB_MGMT, isis_event_str(event_type),
                    lsp_id_str_new, lsp_id_str_old);
            }
            else {
                sprintf(tlb, "\t%s : Event : %s : New LSP %s will cause Purge and flood\n",
                    ISIS_LSPDB_MGMT, isis_event_str(event_type), lsp_id_str_new);
            }
            tcp_trace(node, iif, tlb);
            isis_remove_lsp_pkt_from_lspdb(node, old_lsp_pkt);
            isis_mark_isis_lsp_pkt_flood_ineligible(node, old_lsp_pkt);
            if (!purge_lsp) {
                isis_add_lsp_pkt_in_lspdb(node, new_lsp_pkt);
            }
            isis_schedule_lsp_flood(node, new_lsp_pkt, iif);
        } else {

            assert(0);
        }
    }

    else if (!self_lsp && old_lsp_pkt && (*new_seq_no < *old_seq_no)) {

        event_type = isis_event_non_local_old_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_MGMT, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        /* Action :
            1. if foreign lsp then shoot out lsp back on recv intf
            2. if self originated lsp then assert, impossible case */
        if (recvd_via_intf) {
            sprintf(tlb, "\t%s : Event : %s Old LSP %s will be back fired out of intf %s\n",
                ISIS_LSPDB_MGMT, isis_event_str(event_type),
                lsp_id_str_old,
                iif->if_name.c_str());
            tcp_trace(node, iif, tlb);
            isis_queue_lsp_pkt_for_transmission(iif, old_lsp_pkt);
        } else {
            assert(0);
        }
    }

    sprintf(tlb, "%s : LSPDB Updated  for new Lsp Recvd : %s, old lsp : %s, Event : %s\n",
            ISIS_LSPDB_MGMT,
            lsp_id_str_new,
            lsp_id_str_old,
            isis_event_str(event_type));
    tcp_trace(node, iif, tlb);

    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[event_type]);
    
    if (purge_lsp && event_type == isis_event_non_local_new_lsp) {

        /* purge LSP actually caused deletion from our DB, trigger spf*/
        isis_schedule_spf_job(node, event_type);
    }

    /* Now Decide what we need to do after updating LSP DB */
    if (!purge_lsp) {
        isis_parse_lsp_tlvs(node, new_lsp_pkt, old_lsp_pkt, event_type);
    }

    if (old_lsp_pkt) {
        isis_deref_isis_pkt(node, old_lsp_pkt);
    }
}

void
isis_parse_lsp_tlvs_internal(isis_lsp_pkt_t *new_lsp_pkt, 
                             bool *on_demand_tlv) {

    *on_demand_tlv = false;

    /* Now parse and see on demand TLV is present */

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)(new_lsp_pkt->pkt);
    byte *lsp_hdr = eth_hdr->payload;
    byte *lsp_tlv_buffer = lsp_hdr + ISIS_LSP_HDR_SIZE;
    uint16_t lsp_tlv_buffer_size = new_lsp_pkt->pkt_size - 
                                   ETH_HDR_SIZE_EXCL_PAYLOAD -
                                   ISIS_LSP_HDR_SIZE;

    byte tlv_type, tlv_len, *tlv_value = NULL;

    ITERATE_TLV_BEGIN(lsp_tlv_buffer, tlv_type, 
                      tlv_len, tlv_value, 
                      lsp_tlv_buffer_size) {

        switch(tlv_type) {

            case ISIS_TLV_ON_DEMAND:
                *on_demand_tlv = true;
            break;
            default: ;
        }
    } ITERATE_TLV_END(lsp_tlv_buffer, tlv_type, 
                      tlv_len, tlv_value,
                      lsp_tlv_buffer_size)
}

void
isis_parse_lsp_tlvs(node_t *node,
                    isis_lsp_pkt_t *new_lsp_pkt,
                    isis_lsp_pkt_t *old_lsp_pkt,
                    isis_event_type_t event_type) {

    ip_add_t rtr_id_str;
    bool need_spf = false;
    bool pkt_diff = false;
    bool on_demand_tlv = false;
    bool need_pkt_diff = false;
    bool need_on_demand_flood = false;
    byte lsp_id_str1[ISIS_LSP_ID_STR_SIZE];
    byte lsp_id_str2[ISIS_LSP_ID_STR_SIZE];

    uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(new_lsp_pkt);
    uint32_t *old_seq_no = old_lsp_pkt ? isis_get_lsp_pkt_seq_no(old_lsp_pkt) : 0;
    uint32_t *new_seq_no = isis_get_lsp_pkt_seq_no(new_lsp_pkt);

    tcp_ip_covert_ip_n_to_p(*rtr_id, rtr_id_str.ip_addr);

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    isis_parse_lsp_tlvs_internal(new_lsp_pkt, &on_demand_tlv);

    switch(event_type) {
        case isis_event_self_duplicate_lsp:
        break;
        case isis_event_self_fresh_lsp:
            need_spf = true;
        break;
        case isis_event_self_new_lsp:
            /* spf would have scheduled already when event causing
               lsp generation happened */
            need_pkt_diff = true;
        break;
        case isis_event_self_old_lsp:
        break;
        case isis_event_non_local_duplicate_lsp:
        break;
        case isis_event_non_local_fresh_lsp:
            need_spf = true;
            if (on_demand_tlv) need_on_demand_flood = true;
            break;
        case isis_event_non_local_new_lsp:
            need_pkt_diff = true;
            if (on_demand_tlv) need_on_demand_flood = true;
            break;
        case isis_event_non_local_old_lsp:
        break;
        default: ;
    }
    
    if (!need_spf && need_pkt_diff) {

        pkt_diff = isis_is_lsp_diff(new_lsp_pkt, old_lsp_pkt);
        
        if (pkt_diff) {
            need_spf = true;
        }
    }

    if (need_spf) {
        isis_schedule_spf_job(node, event_type);
    }

    sprintf(tlb, "%s : Lsp Recvd : %s, old lsp : %s, Event : %s\n"
            "\tneed_spf : %u  on_demand_tlv : %u  need_on_demand_flood : %u\n",
            ISIS_LSPDB_MGMT,
            isis_print_lsp_id(new_lsp_pkt, lsp_id_str1),
            old_lsp_pkt ? isis_print_lsp_id(old_lsp_pkt, lsp_id_str2) : "none",
            isis_event_str(event_type),
            need_spf, on_demand_tlv, need_on_demand_flood);
    tcp_trace(node, 0, tlb);

}

isis_lsp_pkt_t *
isis_lookup_lsp_from_lsdb(node_t *node, uint32_t rtr_id, pn_id_t pn_id, uint8_t fr_no) {

    avltree_t *lspdb = isis_get_lspdb_root(node);

    if (!lspdb) return NULL;

    isis_lsp_pkt_t *dummy_lsp_pkt = isis_get_dummy_lsp_pkt_with_key(node, rtr_id, pn_id, fr_no);

    avltree_node_t *avl_node =
        avltree_lookup(&dummy_lsp_pkt->avl_node_glue, lspdb);

    if (!avl_node) return NULL;

    return avltree_container_of(avl_node, isis_lsp_pkt_t, avl_node_glue);
}

bool
isis_our_lsp(node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(lsp_pkt);
    uint32_t self_loop_back = tcp_ip_covert_ip_p_to_n(
                                NODE_LO_ADDR(node));

    return *rtr_id == self_loop_back;
}

void
isis_cleanup_lsdb (node_t *node) {

    avltree_node_t *curr;
    isis_lsp_pkt_t *lsp_pkt;
    avltree_t *lspdb = isis_get_lspdb_root(node);

    if (!lspdb) return;

    ITERATE_AVL_TREE_BEGIN(lspdb, curr){

        lsp_pkt = avltree_container_of(curr, isis_lsp_pkt_t, avl_node_glue);
        isis_remove_lsp_pkt_from_lspdb(node, lsp_pkt);
    } ITERATE_AVL_TREE_END;
}

void
isis_show_lspdb(node_t *node) {

    int rc = 0;
    isis_lsp_pkt_t *lsp_pkt;
    avltree_node_t *curr;
    avltree_t *lspdb = isis_get_lspdb_root(node);
    byte *buff = node->print_buff;
    memset(buff, 0, NODE_PRINT_BUFF_LEN);
    
    if (!lspdb) return;

    ITERATE_AVL_TREE_BEGIN(lspdb, curr){

        lsp_pkt = avltree_container_of(curr, isis_lsp_pkt_t, avl_node_glue);

        rc += isis_show_one_lsp_pkt(lsp_pkt, buff + rc );

    } ITERATE_AVL_TREE_END;

    cli_out (buff, rc);
}

/* lsp pkt printing */
int
isis_show_one_lsp_pkt( isis_lsp_pkt_t *lsp_pkt, byte *buff) {

    int rc = 0;
    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];
    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)lsp_pkt->pkt;
    byte *lsp_hdr = eth_hdr->payload;

    byte *lsp_tlv_buffer = lsp_hdr + ISIS_LSP_HDR_SIZE;

    rc += sprintf(buff + rc, "LSP : %s  size(B) : %-4lu    "
            "ref_c : %-3u   ",
            isis_print_lsp_id (lsp_pkt,  lsp_id_str),
            lsp_pkt->pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD,
            lsp_pkt->ref_count);

    if (lsp_pkt->expiry_timer) {
        rc += sprintf(buff + rc, "Life Time Remaining : %u sec\n",
            wt_get_remaining_time(lsp_pkt->expiry_timer)/1000);
    }
    else {
        rc += sprintf(buff + rc, "\n");
    }
   return rc;
}

bool
isis_is_lsp_diff(isis_lsp_pkt_t *lsp_pkt1, isis_lsp_pkt_t *lsp_pkt2) {

    if ((lsp_pkt1 && !lsp_pkt2) || (!lsp_pkt1 && lsp_pkt2)) {

        return true;
    }

    if (lsp_pkt1->pkt_size != lsp_pkt2->pkt_size) {

        return true;
    }

    ethernet_hdr_t *lsp_eth_hdr1 = (ethernet_hdr_t *)lsp_pkt1->pkt;
    ethernet_hdr_t *lsp_eth_hdr2 = (ethernet_hdr_t *)lsp_pkt2->pkt;

    isis_pkt_hdr_t *lsp_hdr1 = (isis_pkt_hdr_t *)lsp_eth_hdr1->payload;
    isis_pkt_hdr_t *lsp_hdr2 = (isis_pkt_hdr_t *)lsp_eth_hdr2->payload;

    assert(lsp_hdr1->rtr_id == lsp_hdr2->rtr_id);
    assert(lsp_hdr1->pn_no == lsp_hdr2->pn_no);
    assert(lsp_hdr1->fr_no == lsp_hdr2->fr_no);

    if (lsp_hdr1->flags != lsp_hdr2->flags) return true;

    return memcmp( (byte *) (lsp_hdr1 + 1) , 
                                (byte *) (lsp_hdr2 + 1),
                                lsp_pkt1->pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD - ISIS_LSP_HDR_SIZE);
}

byte *
isis_print_lsp_id (isis_lsp_pkt_t *lsp_pkt, byte *lsp_id_str) {

    pn_id_t pn_id;
    uint8_t fr_no;
    unsigned char ip_addr[16];
    
    memset(lsp_id_str, 0, ISIS_LSP_ID_STR_SIZE);
    uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(lsp_pkt);
    uint32_t *seq_no = isis_get_lsp_pkt_seq_no(lsp_pkt);
    pn_id = isis_get_lsp_pkt_pn_id(lsp_pkt);
    fr_no = isis_get_lsp_pkt_fr_no(lsp_pkt);
    sprintf(lsp_id_str, "%s-%hu-%hu[%u]", 
                    tcp_ip_covert_ip_n_to_p(*rtr_id, ip_addr), 
                    pn_id, fr_no, *seq_no);
    return (byte *)lsp_id_str;
}

/* LSP pkt Timers */

static void
isis_lsp_pkt_delete_from_lspdb_timer_cb(event_dispatcher_t *ev_dis,
                                         void *arg, uint32_t arg_size){

    if (!arg) return;

    isis_timer_data_t *timer_data = 
            (isis_timer_data_t *)arg;

    node_t *node = timer_data->node;
    isis_lsp_pkt_t *lsp_pkt = (isis_lsp_pkt_t *)timer_data->data;

    timer_data->data = NULL;
    XFREE(timer_data);

    timer_de_register_app_event(lsp_pkt->expiry_timer);
    lsp_pkt->expiry_timer = NULL;

    avltree_remove(&lsp_pkt->avl_node_glue, isis_get_lspdb_root(node));
    lsp_pkt->installed_in_db = false;
    isis_ted_uninstall_lsp(node, lsp_pkt);
    isis_deref_isis_pkt(node, lsp_pkt);
}

void
isis_start_lsp_pkt_installation_timer(node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    if (lsp_pkt->expiry_timer) return;

    isis_timer_data_t *timer_data = XCALLOC(0, 1, isis_timer_data_t);
    timer_data->node = node;
    timer_data->data = (void *)lsp_pkt;
    timer_data->data_size = sizeof(isis_lsp_pkt_t);
    
    lsp_pkt->expiry_timer = timer_register_app_event(CP_TIMER(node),
                                isis_lsp_pkt_delete_from_lspdb_timer_cb,
                                (void *)timer_data,
                                sizeof(isis_timer_data_t),
                                ISIS_NODE_INFO(node)->lsp_lifetime_interval * 1000,
                                0);
}

void
isis_stop_lsp_pkt_installation_timer(isis_lsp_pkt_t *lsp_pkt) {

    if (!lsp_pkt->expiry_timer) return;

    isis_timer_data_t *timer_data = wt_elem_get_and_set_app_data(
                                        lsp_pkt->expiry_timer, 0);
    XFREE(timer_data);                                 
    timer_de_register_app_event(lsp_pkt->expiry_timer);
    lsp_pkt->expiry_timer = NULL;
}

void
isis_refresh_lsp_pkt_installation_timer(node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    isis_stop_lsp_pkt_installation_timer(lsp_pkt);
    isis_start_lsp_pkt_installation_timer(node, lsp_pkt);
}

bool
isis_is_lsp_pkt_installed_in_lspdb(isis_lsp_pkt_t *lsp_pkt) {

    return lsp_pkt->installed_in_db;
}

void
isis_remove_lsp_pkt_from_lspdb(node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];

    avltree_t *lspdb = isis_get_lspdb_root(node);

    if (!lspdb) return;

    if (!isis_is_lsp_pkt_installed_in_lspdb(lsp_pkt)) return;

    avltree_remove(&lsp_pkt->avl_node_glue, lspdb);
    lsp_pkt->installed_in_db = false;
    isis_ted_uninstall_lsp(node, lsp_pkt);
    isis_stop_lsp_pkt_installation_timer(lsp_pkt);
    isis_print_lsp_id (lsp_pkt,  lsp_id_str);
    sprintf(tlb, "%s : LSP %s removed from LSPDB\n", ISIS_LSPDB_MGMT ,
    lsp_id_str);
    tcp_trace(node, 0, tlb);
    isis_deref_isis_pkt(node, lsp_pkt);
}

bool
isis_add_lsp_pkt_in_lspdb(node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];

    avltree_t *lspdb = isis_get_lspdb_root(node);

     if (!lspdb) return false;

     if (isis_is_lsp_pkt_installed_in_lspdb(lsp_pkt)) return false;

     avltree_insert(&lsp_pkt->avl_node_glue, lspdb);
     lsp_pkt->installed_in_db = true;
     isis_ted_install_lsp(node, lsp_pkt);

    isis_our_lsp(node, lsp_pkt) ? \
        isis_lsp_pkt_flood_timer_start (node, lsp_pkt) :        \
        isis_start_lsp_pkt_installation_timer(node, lsp_pkt);

     isis_ref_isis_pkt(lsp_pkt);
     isis_print_lsp_id (lsp_pkt,  lsp_id_str);
     sprintf(tlb, "%s : LSP %s added to LSPDB\n", ISIS_LSPDB_MGMT , 
     lsp_id_str);
     tcp_trace(node, 0, tlb);
     return true;
}

void
isis_remove_lsp_from_lspdb(node_t *node, uint32_t rtr_id, pn_id_t pn_id, uint8_t fr_no) {

    avltree_t *lspdb = isis_get_lspdb_root(node);

    if (!lspdb) return ;

    isis_lsp_pkt_t *lsp_pkt = isis_lookup_lsp_from_lsdb(node, rtr_id, pn_id, fr_no);

    if (!lsp_pkt) return;

    isis_remove_lsp_pkt_from_lspdb(node, lsp_pkt);
}
