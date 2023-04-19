#include <assert.h>
#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_advt.h"
#include "isis_flood.h"

static uint64_t isis_advt_id = 0;

static inline uint64_t
isis_gen_avt_id () {

    return (++isis_advt_id);
}


static int 
isis_get_new_fragment_no (isis_advt_db_t *advt_db) {

    int i;

    for (i = 0; i < ISIS_MAX_FRAGMENT_SUPPORTED; i++) {
        if (!advt_db->fragments[i]) return i;
    }
    return -1;
}

static isis_adv_data_t *
isis_fragment_lookup_advt_data(isis_fragment_t *fragment, advt_id_t adv_id ) {

    glthread_t *curr;
    isis_adv_data_t *adv_data;

    ITERATE_GLTHREAD_BEGIN(&fragment->tlv_list_head, curr) {

        adv_data = glue_to_isis_advt_data(curr);
        if (adv_data->advt_id == adv_id) return adv_data;

    } ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr);

    return NULL;
}

uint16_t 
isis_get_adv_data_size (isis_adv_data_t *adv_data) {

    return 0;
}

static uint8_t
isis_get_adv_data_tlv_type (isis_adv_data_t *advt_data) {

    return 0;
}

static byte *
isis_get_adv_data_tlv_content(isis_adv_data_t *advt_data,  byte *tlv_content) {

    return tlv_content;
}

static int
 isis_fragment_size_comp_fn (void *data1, void *data2){

    isis_fragment_t  *frag_info1 = (isis_fragment_t  *)data1;
    isis_fragment_t  *frag_info2 = (isis_fragment_t  *)data2;

    if (frag_info1->bytes_filled < frag_info2->bytes_filled) return -1;
    if (frag_info1->bytes_filled > frag_info2->bytes_filled) return 1;
    return 0;
 }

/* Fragmebt generate and delete */
static void
isis_delete_fragment (isis_node_info_t *node_info, isis_fragment_t *fragment){

}

static void
isis_schedule_regen_fragment (node_t *node, isis_fragment_t *fragment) {

}

isis_tlv_record_advt_return_code_t
isis_record_tlv_advertisement (node_t *node, 
                                    uint8_t pn_no,
                                    isis_adv_data_t *adv_data,
                                    isis_advt_info_t *advt_info_out) {

    int frag_no;
    glthread_t *curr;
    bool new_frag = false;
    bool new_advt_db = false;
    isis_pkt_hdr_t *lsp_pkt_hdr;
    isis_node_info_t *node_info;
    isis_fragment_t  *fragment = NULL;

    node_info = ISIS_NODE_INFO(node);

    if (!node_info) return ISIS_TLV_RECORD_ADVT_FAILED;

    uint8_t tlv_size = isis_get_adv_data_size(adv_data);

    isis_advt_db_t *advt_db = node_info->advt_db[pn_no];

    if (!advt_db) {
        isis_create_advt_db (node_info, pn_no);
        advt_db =  node_info->advt_db[pn_no];
        new_advt_db = true;
    }

    curr = glthread_get_next(&advt_db->fragment_priority_list);

    if (curr) {
        fragment = isis_priority_list_glue_to_fragment(curr);
    }

    if (!curr || (fragment && 
            (ISIS_LSP_MAX_PKT_SIZE - fragment->bytes_filled) < tlv_size)) {

        frag_no = (uint8_t)isis_get_new_fragment_no(advt_db);
        
        if (frag_no < 0) {

            if (new_advt_db) {
                XFREE(node_info->advt_db[pn_no]);
                node_info->advt_db[pn_no] = NULL;
            }
            return ISIS_TLV_RECORD_ADVT_NO_FRAG;
        }

        fragment = (isis_fragment_t  *)XCALLOC(0, 1, isis_fragment_t);
        new_frag = true;
        fragment->seq_no = 0;
        fragment->fr_no = frag_no;
        fragment->pn_no = pn_no;
        fragment->ref_count = 0;
        fragment->bytes_filled = ETH_HDR_SIZE_EXCL_PAYLOAD +  sizeof(isis_pkt_hdr_t);
        init_glthread(&fragment->priority_list_glue);
        init_glthread(&fragment->tlv_list_head);
        advt_db->fragments[frag_no] = fragment;
        isis_fragment_lock(fragment);
    }

    assert(IS_GLTHREAD_LIST_EMPTY(&adv_data->glue));
    glthread_add_last(&fragment->tlv_list_head, &adv_data->glue);
    fragment->bytes_filled += tlv_size;
    remove_glthread(&fragment->priority_list_glue);
    glthread_priority_insert(&advt_db->fragment_priority_list,
                             &fragment->priority_list_glue,
                             isis_fragment_size_comp_fn,
                             (int)&((isis_fragment_t *)0)->priority_list_glue);
    if (new_frag) {
        isis_fragment_lock(fragment);
    }
    advt_info_out->advt_id = adv_data->advt_id;
    advt_info_out->pn_no = pn_no;
    advt_info_out->fr_no = frag_no;

    return ISIS_TLV_RECORD_ADVT_SUCCESS;
}

void
isis_regenerate_lsp_fragment (node_t *node, isis_fragment_t *fragment, uint32_t regen_ctrl_flags) {

    glthread_t *curr;
    uint16_t tlv_size;
    uint16_t bytes_filled;
    bool create_purge_lsp;
    ethernet_hdr_t *eth_hdr;
    isis_node_info_t *node_info;
    isis_pkt_hdr_t *lsp_pkt_hdr;

    node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    bytes_filled = 0;

    /* When protocol shut is in progress, then only zero fragment
        is allowed to be regenerated and advertised */
    if (isis_is_protocol_shutdown_in_progress(node) &&
            (fragment->pn_no || fragment->fr_no)) {
        return;
    }

    if (!fragment->lsp_pkt) {
        fragment->lsp_pkt = pkt_block_get_new (NULL, fragment->bytes_filled);
        pkt_block_set_starting_hdr_type(fragment->lsp_pkt, ETH_HDR);
        pkt_block_reference(fragment->lsp_pkt);
    }

    /* Drain the older pkt contents */
    eth_hdr = pkt_block_get_ethernet_hdr(fragment->lsp_pkt);

    /* Re-manufacture ethernet hdr */
    if (IS_BIT_SET (regen_ctrl_flags, ISIS_SHOULD_REWRITE_ETH_HDR)) {
        memset((byte *)eth_hdr, 0, fragment->bytes_filled);
        // memset (eth_hdr->src_mac.mac, 0, sizeof(mac_addr_t));
        layer2_fill_with_broadcast_mac(eth_hdr->dst_mac.mac);
        eth_hdr->type = ISIS_HELLO_ETH_PKT_TYPE;
    }

    bytes_filled += (ETH_HDR_SIZE_EXCL_PAYLOAD - ETH_FCS_SIZE);

    /* Re-manufactue LSP Pkt Hdr */
    lsp_pkt_hdr = (isis_pkt_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr);

    if (IS_BIT_SET (regen_ctrl_flags, ISIS_SHOULD_RENEW_LSP_PKT_HDR)) {
        lsp_pkt_hdr->isis_pkt_type = ISIS_L1_LSP_PKT_TYPE;
        lsp_pkt_hdr->seq_no = (++fragment->seq_no);
        lsp_pkt_hdr->rtr_id = tcp_ip_covert_ip_p_to_n(NODE_LO_ADDR(node));
        lsp_pkt_hdr->pn_no = fragment->pn_no;
        lsp_pkt_hdr->fr_no = fragment->fr_no;
    }

    bytes_filled += sizeof (isis_pkt_hdr_t);

    if (IS_BIT_SET(regen_ctrl_flags, ISIS_SHOULD_INCL_PURGE_BIT) ) {
        SET_BIT(lsp_pkt_hdr->flags, ISIS_LSP_PKT_F_PURGE_BIT);
    }

    if (IS_BIT_SET(regen_ctrl_flags, ISIS_SHOULD_INCL_OL_BIT) ) {
        SET_BIT(lsp_pkt_hdr->flags, ISIS_LSP_PKT_F_OVERLOAD_BIT);
    }

    if (IS_BIT_SET(regen_ctrl_flags, ISIS_SHOULD_INCL_ON_DEM_BIT)) {
        SET_BIT(lsp_pkt_hdr->flags, ISIS_LSP_PKT_F_ON_DEMAND_BIT);
    }

    byte tlv_content[255];
    isis_adv_data_t *advt_data;
    byte *lsp_tlv_buffer = (byte *)(lsp_pkt_hdr + 1);

    ITERATE_GLTHREAD_BEGIN(&fragment->tlv_list_head, curr) {

        advt_data = glue_to_isis_advt_data(curr);
        tlv_size =  isis_get_adv_data_size(advt_data);

        lsp_tlv_buffer = tlv_buffer_insert_tlv(
                                        lsp_tlv_buffer,
                                        isis_get_adv_data_tlv_type (advt_data),
                                        tlv_size,
                                        isis_get_adv_data_tlv_content(advt_data,  tlv_content));

        bytes_filled += tlv_size;

    } ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr) ;

    assert ((bytes_filled + ETH_FCS_SIZE ) == fragment->bytes_filled);
}

isis_tlv_wd_return_code_t
isis_withdraw_tlv_advertisement (node_t *node,
                                    isis_advt_info_t *advt_info){

    
    isis_adv_data_t *adv_data;
    isis_fragment_t *fragment;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return ISIS_TLV_WD_SUCCESS;

    if (!advt_info->advt_id) return ISIS_TLV_WD_FAILED;

    fragment = ISIS_GET_FRAGMENT(node_info, advt_info);

    if (!fragment) ISIS_TLV_WD_FRAG_NOT_FOUND;

    adv_data = isis_fragment_lookup_advt_data(fragment, advt_info->advt_id);

    if (!adv_data) return ISIS_TLV_WD_TLV_NOT_FOUND;
    
    remove_glthread (&adv_data->glue);

    fragment->bytes_filled -= isis_get_adv_data_size(adv_data);

    XFREE(adv_data);

    if (IS_GLTHREAD_LIST_EMPTY(&fragment->tlv_list_head)) {
        /* Empty fragment, remove it if it is non-zero fragment */
        if (fragment->fr_no) {
            isis_delete_fragment (node_info, fragment);
        }
    }
    else {
        isis_schedule_regen_fragment (node, fragment);
    }
    return ISIS_TLV_WD_SUCCESS;
}


void 
isis_create_advt_db(isis_node_info_t *node_info, uint8_t pn_no) {

    isis_advt_db_t *advt_db = node_info->advt_db[pn_no];
    assert(!advt_db);
    advt_db = (isis_advt_db_t *)XCALLOC(0, 1, isis_advt_db_t );
    node_info->advt_db[pn_no] = advt_db;
    init_glthread(&advt_db->fragment_priority_list);
}

void
isis_destroy_advt_db (isis_node_info_t *node_info, uint8_t pn_no) {

    int i;
    isis_advt_db_t *advt_db;
    isis_fragment_t *fragment;

    if (!node_info) return;
     
     advt_db = node_info->advt_db[pn_no];
    
    if (!advt_db) return;

    for (i = 0; i < ISIS_MAX_FRAGMENT_SUPPORTED; i++) {

        fragment = advt_db->fragments[i];
        if (!fragment) continue;
        advt_db->fragments[i] = NULL;
        isis_discard_fragment (fragment, false);
    }

    XFREE(advt_db);
    node_info->advt_db[pn_no] = NULL;
}

void
isis_discard_fragment (isis_fragment_t *fragment, bool purge) {

    
}

void
 isis_destroy_all_advt_db(isis_node_info_t *node_info) {

    int i;

    for (i = 0; i < ISIS_MAX_PN_SUPPORTED; i++) {
        isis_destroy_advt_db(node_info, i);
    }  
 }

void
isis_assert_check_all_advt_db_cleanedup (isis_node_info_t *node_info) {

    int i;

    for (i = 0; i < ISIS_MAX_PN_SUPPORTED; i++) {
        if (!node_info->advt_db[i]) continue;
        assert(0);
    }
}

