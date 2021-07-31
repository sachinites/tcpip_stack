#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_pkt.h"
#include "isis_lspdb.h"
#include "isis_flood.h"
#include "isis_spf.h"
#include "isis_events.h"

void
isis_show_one_lsp_pkt(isis_pkt_t *lsp_pkt);

static isis_pkt_t *gl_lsp_dummy_pkt = NULL;

static isis_pkt_t *
isis_get_dummy_lsp_pkt_with_key(uint32_t rtr_id) {

    uint32_t pkt_size;
    uint32_t *rtr_id_addr;

    if (!gl_lsp_dummy_pkt) {
    
        gl_lsp_dummy_pkt = calloc(1, sizeof(isis_pkt_t));

        pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD +
                    ISIS_LSP_HDR_SIZE;

        gl_lsp_dummy_pkt->pkt = tcp_ip_get_new_pkt_buffer ( pkt_size);
                        
        gl_lsp_dummy_pkt->isis_pkt_type = ISIS_LSP_PKT_TYPE;
        isis_mark_isis_lsp_pkt_flood_ineligible(0, gl_lsp_dummy_pkt);
        gl_lsp_dummy_pkt->pkt_size = pkt_size;
        gl_lsp_dummy_pkt->expiry_timer = NULL;
        gl_lsp_dummy_pkt->installed_in_db = false;
        isis_ref_isis_pkt(gl_lsp_dummy_pkt);
    }
    
    rtr_id_addr = isis_get_lsp_pkt_rtr_id(gl_lsp_dummy_pkt);
    *rtr_id_addr = rtr_id;
    return gl_lsp_dummy_pkt;
}

void
isis_free_dummy_lsp_pkt(void){

    int rc;
    if(!gl_lsp_dummy_pkt) return ;
    rc = isis_deref_isis_pkt(gl_lsp_dummy_pkt);
    if (rc == 0) gl_lsp_dummy_pkt = NULL;
}

avltree_t *
isis_get_lspdb_root(node_t *node) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
    if(isis_node_info) {
        return &isis_node_info->lspdb_avl_root;
    }
    return NULL;
}

void
isis_install_lsp(node_t *node,
                 interface_t *iif,
                 isis_pkt_t *new_lsp_pkt) {

    bool self_lsp;
    bool foreign_lsp;
    uint32_t *rtr_id;
    isis_pkt_t *old_lsp_pkt;
    isis_event_type_t event_type;
    bool duplicate_lsp;
    
    foreign_lsp = iif ? true : false;
    self_lsp = isis_our_lsp(node, new_lsp_pkt);
    event_type = isis_event_none;

    rtr_id = isis_get_lsp_pkt_rtr_id(new_lsp_pkt);

    old_lsp_pkt = isis_lookup_lsp_from_lsdb(
                    node, *rtr_id);

    if (old_lsp_pkt) {
        isis_ref_isis_pkt(old_lsp_pkt);
    }

    uint32_t *old_seq_no = NULL;

    if (old_lsp_pkt) {
        old_seq_no = isis_get_lsp_pkt_seq_no(old_lsp_pkt);
    }

    uint32_t *new_seq_no = isis_get_lsp_pkt_seq_no(new_lsp_pkt);

    duplicate_lsp = (old_lsp_pkt && (*new_seq_no == *old_seq_no));

    if (self_lsp && duplicate_lsp) {

        event_type = isis_event_self_duplicate_lsp;
        /* Action :
            1. if foriegn lsp then do nothing
            2. if self originated lsp then assert, impossible case*/
        if (foreign_lsp) {

             // no action
        } else {

            assert(0);
        }
    }

    else if (self_lsp && !old_lsp_pkt) {

        event_type = isis_event_self_fresh_lsp;
        /* Action :
            1. if foriegn lsp then ignore, and regenerate self lsp with higher sequence no and flood on all intf
            2. if self originated lsp then install in db and flood on all intf*/
        if (foreign_lsp) {

            ((isis_node_info_t *)(node->node_nw_prop.isis_node_info))->seq_no = *new_seq_no;
            isis_schedule_lsp_pkt_generation(node, isis_event_self_fresh_lsp);
        } else {

            isis_add_lsp_pkt_in_lspdb(node, new_lsp_pkt);
            isis_schedule_lsp_flood(node, new_lsp_pkt, 0, event_type);
        }
    }

    else if (self_lsp && old_lsp_pkt && (*new_seq_no > *old_seq_no)) {

        event_type = isis_event_self_new_lsp;
        /* Action :
            1. if foreign lsp, regenerate self lsp with higher 
                sequence no and flood on all intf
            2. if self originated lsp then replace it in db and 
                install new one and flood it on all intf */
        if (foreign_lsp) {

            ((isis_node_info_t *)(node->node_nw_prop.isis_node_info))->seq_no = *new_seq_no;
            isis_schedule_lsp_pkt_generation(node, isis_event_self_fresh_lsp);
        } else {

            isis_remove_lsp_pkt_from_lspdb(node, old_lsp_pkt);
            isis_mark_isis_lsp_pkt_flood_ineligible(node, old_lsp_pkt);
            isis_add_lsp_pkt_in_lspdb(node, new_lsp_pkt);
            isis_schedule_lsp_flood(node, new_lsp_pkt, 0, event_type);
        }
    }

    else if (self_lsp && old_lsp_pkt && (*new_seq_no < *old_seq_no)) {

        event_type = isis_event_self_old_lsp;
        /* Action :
            1. if foreign lsp, then flood existing one on all intf
            2. if self originated lsp then assert, impossible case */
        if (foreign_lsp) {

            isis_schedule_lsp_flood(node, new_lsp_pkt, 0, event_type);
        } else {

            assert(0);
        }
    }

    else if (!self_lsp && duplicate_lsp) {

        event_type = isis_event_non_local_duplicate_lsp;
        /* Action :
            1. if foreign lsp then do nothing
            2. if self originated lsp then assert, impossible case */
        if (foreign_lsp) {

            
        } else {

            assert(0);
        }
    }

    else if (!self_lsp && !old_lsp_pkt) {

        event_type = isis_event_non_local_fresh_lsp;
        /* Action :
            1. if foreign lsp then install in db and flood forward it
            2. if self originated lsp then assert, impossible case */
        if (foreign_lsp) {

            isis_add_lsp_pkt_in_lspdb(node, new_lsp_pkt);
            isis_schedule_lsp_flood(node, new_lsp_pkt, iif, event_type);
        } else {

            assert(0);
        }
    }

    else if (!self_lsp && old_lsp_pkt && (*new_seq_no > *old_seq_no)) {

        event_type = isis_event_non_local_new_lsp;
        /* Action :
            1. if foreign lsp then replace in db and flood forward it
            2. if self originated lsp then assert, impossible case */
        if (foreign_lsp) {

            isis_remove_lsp_pkt_from_lspdb(node, old_lsp_pkt);
            isis_mark_isis_lsp_pkt_flood_ineligible(node, old_lsp_pkt);
            isis_add_lsp_pkt_in_lspdb(node, new_lsp_pkt);
            isis_schedule_lsp_flood(node, new_lsp_pkt, iif, event_type);
        } else {

            assert(0);
        }
    }

    else if (!self_lsp && old_lsp_pkt && (*new_seq_no < *old_seq_no)) {

        event_type = isis_event_non_local_old_lsp;
        /* Action :
            1. if foreign lsp then shoot out lsp back on recv intf
            2. if self originated lsp then assert, impossible case */
        if (foreign_lsp) {

            isis_queue_lsp_pkt_for_transmission(iif, new_lsp_pkt);
        } else {

            assert(0);
        }
    }

    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[event_type]);
    
    /* Now Decide what we need to do after updating LSP DB */
    isis_parse_lsp_tlvs(node, new_lsp_pkt, old_lsp_pkt, event_type);

    if (old_lsp_pkt) {
        isis_deref_isis_pkt(old_lsp_pkt);
    }
}

static void
isis_parse_lsp_tlvs_internal(isis_pkt_t *new_lsp_pkt, 
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
                    isis_pkt_t *new_lsp_pkt,
                    isis_pkt_t *old_lsp_pkt,
                    isis_event_type_t event_type) {

    bool need_spf = false;
    bool pkt_diff = false;
    bool on_demand_tlv = false;
    bool need_pkt_diff = false;
    bool need_on_demand_flood = false;

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

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
        break;
        case isis_event_self_old_lsp:
        break;
        case isis_event_non_local_duplicate_lsp:
        break;
        case isis_event_non_local_fresh_lsp:
            need_spf = true;
            if (on_demand_tlv) need_on_demand_flood = true;
        case isis_event_non_local_new_lsp:
            need_pkt_diff = true;
            if (on_demand_tlv) need_on_demand_flood = true;
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
        isis_schedule_spf_job(node);
    }

    if (need_on_demand_flood) {

        /* Somebody requested us On-Demand Flood */
        if (isis_node_info->isis_lsp_pkt_gen_task) {
            return;
        }

        if (isis_node_info->isis_self_lsp_pkt &&
            isis_node_info->isis_self_lsp_pkt->flood_eligibility) {

                uint32_t *seq_no = isis_get_lsp_pkt_seq_no(isis_node_info->isis_self_lsp_pkt);
                ISIS_INCREMENT_NODE_STATS(node, seq_no);
                *seq_no = isis_node_info->seq_no;
                isis_schedule_lsp_flood(node, isis_node_info->isis_self_lsp_pkt,
                                        0, isis_event_on_demand_flood);
        }
        else {
            isis_schedule_lsp_pkt_generation(node, isis_event_on_demand_flood);
        }
    }
}

isis_pkt_t *
isis_lookup_lsp_from_lsdb(node_t *node, uint32_t rtr_id) {

    avltree_t *lspdb = isis_get_lspdb_root(node);

    if (!lspdb) return NULL;

    isis_pkt_t *dummy_lsp_pkt = isis_get_dummy_lsp_pkt_with_key(rtr_id);

    avltree_node_t *avl_node =
        avltree_lookup(&dummy_lsp_pkt->avl_node_glue, lspdb);

    if (!avl_node) return NULL;

    return avltree_container_of(avl_node, isis_pkt_t, avl_node_glue);
}

bool
isis_our_lsp(node_t *node, isis_pkt_t *lsp_pkt) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(lsp_pkt);
    uint32_t self_loop_back = tcp_ip_covert_ip_p_to_n(
                                NODE_LO_ADDR(node));

    return *rtr_id == self_loop_back;
}

void
isis_cleanup_lsdb(node_t *node) {

    avltree_node_t *curr;
    isis_pkt_t *lsp_pkt;
    avltree_t *lspdb = isis_get_lspdb_root(node);

    if (!lspdb) return;

    ITERATE_AVL_TREE_BEGIN(lspdb, curr){

        lsp_pkt = avltree_container_of(curr, isis_pkt_t, avl_node_glue);
        isis_remove_lsp_pkt_from_lspdb(node, lsp_pkt);
    } ITERATE_AVL_TREE_END;
}

void
isis_show_lspdb(node_t *node) {

    isis_pkt_t *lsp_pkt;
    avltree_node_t *curr;
    avltree_t *lspdb = isis_get_lspdb_root(node);

    if (!lspdb) return;

    ITERATE_AVL_TREE_BEGIN(lspdb, curr){

        lsp_pkt = avltree_container_of(curr, isis_pkt_t, avl_node_glue);

        isis_show_one_lsp_pkt(lsp_pkt);

    } ITERATE_AVL_TREE_END;
}

bool
isis_is_lsp_diff(isis_pkt_t *lsp_pkt1, isis_pkt_t *lsp_pkt2) {

    if ((lsp_pkt1 && !lsp_pkt2) || (!lsp_pkt1 && lsp_pkt2)) {

        return true;
    }

    if (lsp_pkt1->pkt_size != lsp_pkt2->pkt_size) {

        return true;
    }

    ethernet_hdr_t *lsp_eth_hdr1 = (ethernet_hdr_t *)lsp_pkt1->pkt;
    ethernet_hdr_t *lsp_eth_hdr2 = (ethernet_hdr_t *)lsp_pkt2->pkt;

    byte* lsp_body1 = lsp_eth_hdr1->payload;
    byte* lsp_body2 = lsp_eth_hdr2->payload;

    /* Compare only TLV Section */
    return memcmp(lsp_body1 + ISIS_LSP_HDR_SIZE, 
                  lsp_body2 + ISIS_LSP_HDR_SIZE,
                  lsp_pkt1->pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD - ISIS_LSP_HDR_SIZE);
}

/* lsp pkt printing */

void
isis_show_one_lsp_pkt(isis_pkt_t *lsp_pkt) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)lsp_pkt->pkt;
    byte *lsp_hdr = eth_hdr->payload;

    uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(lsp_pkt);
    uint32_t *seq_no = isis_get_lsp_pkt_seq_no(lsp_pkt);

    byte *lsp_tlv_buffer = lsp_hdr + ISIS_LSP_HDR_SIZE;

    unsigned char *rtr_id_str = tcp_ip_covert_ip_n_to_p(*rtr_id, 0);
    printf("LSP : %-16s   Seq # : %-4u    size(B) : %-4lu    "
            "ref_c : %-3u   ",
            rtr_id_str, *seq_no, 
            lsp_pkt->pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD,
            lsp_pkt->ref_count);

    if (lsp_pkt->expiry_timer) {
        printf("Life Time Remaining : %u msec\n",
            wt_get_remaining_time(lsp_pkt->expiry_timer));
    }
    else {
        printf("\n");
    }
}

byte*
isis_print_lsp_id(isis_pkt_t *lsp_pkt) {

    static byte lsp_id[32];
    
    uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(lsp_pkt);
    uint32_t *seq_no = isis_get_lsp_pkt_seq_no(lsp_pkt);

    sprintf(lsp_id, "%s-%u", tcp_ip_covert_ip_n_to_p(*rtr_id, 0), *seq_no);
    return lsp_id;
}

/* LSP pkt Timers */

static void
isis_lsp_pkt_delete_from_lspdb_timer_cb(void *arg, uint32_t arg_size){

    if (!arg) return;

    isis_timer_data_t *timer_data = 
            (isis_timer_data_t *)arg;

    node_t *node = timer_data->node;
    isis_pkt_t *lsp_pkt = (isis_pkt_t *)timer_data->data;

    timer_data->data = NULL;
    free(timer_data);

    timer_de_register_app_event(lsp_pkt->expiry_timer);
    lsp_pkt->expiry_timer = NULL;

    avltree_remove(&lsp_pkt->avl_node_glue, isis_get_lspdb_root(node));
    lsp_pkt->installed_in_db = false;
    isis_deref_isis_pkt(lsp_pkt);
}

void
isis_start_lsp_pkt_installation_timer(node_t *node, isis_pkt_t *lsp_pkt) {

    wheel_timer_t *wt;
    isis_node_info_t *isis_node_info;

    isis_node_info = ISIS_NODE_INFO(node);

    wt = node_get_timer_instance(node);

    if (lsp_pkt->expiry_timer) return;

    isis_timer_data_t *timer_data = calloc(1, sizeof(isis_timer_data_t));
    timer_data->node = node;
    timer_data->data = (void *)lsp_pkt;
    timer_data->data_size = sizeof(isis_pkt_t);
    
    lsp_pkt->expiry_timer = timer_register_app_event(wt,
                                isis_lsp_pkt_delete_from_lspdb_timer_cb,
                                (void *)timer_data,
                                sizeof(isis_timer_data_t),
                                ISIS_NODE_INFO(node)->lsp_lifetime_interval * 1000,
                                0);
}

void
isis_stop_lsp_pkt_installation_timer(isis_pkt_t *lsp_pkt) {

    if (!lsp_pkt->expiry_timer) return;

    isis_timer_data_t *timer_data = wt_elem_get_and_set_app_data(
                                        lsp_pkt->expiry_timer, 0);
    free(timer_data);                                 
    timer_de_register_app_event(lsp_pkt->expiry_timer);
    lsp_pkt->expiry_timer = NULL;
}

void
isis_refresh_lsp_pkt_installation_timer(node_t *node, isis_pkt_t *lsp_pkt) {

    isis_stop_lsp_pkt_installation_timer(lsp_pkt);
    isis_start_lsp_pkt_installation_timer(node, lsp_pkt);
}

bool
isis_is_lsp_pkt_installed_in_lspdb(isis_pkt_t *lsp_pkt) {
#if 0
    avltree_node_t *avl_node = &lsp_pkt->avl_node_glue;

    if ( avl_node->parent == 0 &&
         avl_node->left == NULL   &&
         avl_node->right == NULL ) {

        return false;
    }
    return true;
#endif
    return lsp_pkt->installed_in_db;
}

void
isis_remove_lsp_pkt_from_lspdb(node_t *node, isis_pkt_t *lsp_pkt) {

    avltree_t *lspdb = isis_get_lspdb_root(node);

    if (!lspdb) return;

    if (!isis_is_lsp_pkt_installed_in_lspdb(lsp_pkt)) return;

    avltree_remove(&lsp_pkt->avl_node_glue, lspdb);
    lsp_pkt->installed_in_db = false;
    isis_stop_lsp_pkt_installation_timer(lsp_pkt);
    isis_deref_isis_pkt(lsp_pkt);
}

bool
isis_add_lsp_pkt_in_lspdb(node_t *node, isis_pkt_t *lsp_pkt) {

    avltree_t *lspdb = isis_get_lspdb_root(node);

     if (!lspdb) return false;

     if (isis_is_lsp_pkt_installed_in_lspdb(lsp_pkt)) return false;

     avltree_insert(&lsp_pkt->avl_node_glue, lspdb);
     lsp_pkt->installed_in_db = true;

     if (!isis_our_lsp(node, lsp_pkt)) {
         isis_start_lsp_pkt_installation_timer(node, lsp_pkt);
     }
     isis_ref_isis_pkt(lsp_pkt);
     return true;
}

void
isis_remove_lsp_from_lspdb(node_t *node, uint32_t rtr_id) {

    avltree_t *lspdb = isis_get_lspdb_root(node);

    if (!lspdb) return ;

    isis_pkt_t *lsp_pkt = isis_lookup_lsp_from_lsdb(node, rtr_id);

    if (!lsp_pkt) return;

    isis_remove_lsp_pkt_from_lspdb(node, lsp_pkt);
}
