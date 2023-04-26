#include <assert.h>
#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_advt.h"
#include "isis_flood.h"
#include "isis_lspdb.h"
#include "isis_tlv_struct.h"
#include "isis_utils.h"

static advt_id_t isis_advt_id = 0;
advt_id_t isis_gen_avt_id (); 

advt_id_t
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

pkt_size_t
isis_get_adv_data_size(isis_adv_data_t *adv_data)
{
    pkt_size_t ptlv_data_len = 0;
    pkt_size_t total_subtlv_len = 0;

    switch (adv_data->tlv_no) {
    
    case ISIS_IS_REACH_TLV:
        ptlv_data_len += TLV_OVERHEAD_SIZE;
        ptlv_data_len += sizeof(isis_system_id_t); /* Nbr Sys Id */
        ptlv_data_len += 4;                                      /* Cost/Metric */
        ptlv_data_len += 1;                                      /* total Sub TLV len */

        /* encode subtlv 4 */
        total_subtlv_len += TLV_OVERHEAD_SIZE + 4 + 4;
        /* encode subtlv 6 */
        total_subtlv_len += TLV_OVERHEAD_SIZE + 4;
        /* encode subtlv 8 */
        total_subtlv_len += TLV_OVERHEAD_SIZE + 4;

        ptlv_data_len += total_subtlv_len;
        break;

    case ISIS_TLV_IP_REACH:
        ptlv_data_len += sizeof (isis_tlv_130_t) + TLV_OVERHEAD_SIZE;
        break;
    default: ;
    }
    return ptlv_data_len;
}

static byte *
isis_get_adv_data_tlv_content(isis_adv_data_t *advt_data,  byte *tlv_content) {

    return tlv_content;
}

static int
 isis_fragment_size_comp_fn (void *data1, void *data2){

    isis_fragment_t  *frag_info1 = (isis_fragment_t  *)data1;
    isis_fragment_t  *frag_info2 = (isis_fragment_t  *)data2;

    if (frag_info1->bytes_filled < frag_info2->bytes_filled) return CMP_PREFERRED;
    if (frag_info1->bytes_filled > frag_info2->bytes_filled) return CMP_NOT_PREFERRED;
    return CMP_PREF_EQUAL;
 }

void
isis_cancel_lsp_fragment_regen_job (node_t *node) {

    glthread_t *curr;
    isis_fragment_t *fragment;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info->lsp_fragment_gen_task) return;

    task_cancel_job (EV(node), node_info->lsp_fragment_gen_task);
    node_info->lsp_fragment_gen_task = NULL;

    while ((curr = dequeue_glthread_first(&node_info->pending_lsp_gen_queue))) {

        fragment = isis_frag_regen_glue_to_fragment (curr);
        isis_fragment_unlock (node_info, fragment);
    }
}

static void
isis_lsp_fragment_regen_cbk (event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    glthread_t *curr;
    isis_fragment_t *fragment;

    node_t *node = (node_t *)(arg);
    
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    node_info->lsp_fragment_gen_task = NULL;

    while ((curr = dequeue_glthread_first(&node_info->pending_lsp_gen_queue))) {

        fragment = isis_frag_regen_glue_to_fragment (curr);
        isis_regenerate_lsp_fragment (node, fragment, fragment->regen_flags);
        //isis_install_lsp (node, NULL, fragment->lsp_pkt);
        isis_fragment_unlock (node_info, fragment);
    }
}

void
isis_schedule_regen_fragment (node_t *node, isis_fragment_t *fragment) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    if (isis_is_protocol_shutdown_in_progress(node)) {
        /* No Op : We would still allow fragment regen, as when we are in the process
        of shutting down the protocol, we still need to regen purge LSPs*/
    }

    /* Fragment is already Queued up for regen*/
    if (IS_QUEUED_UP_IN_THREAD(&fragment->frag_regen_glue)) {
        return;
    }

    /* Queue the fragment for LSP regen */
    glthread_add_last (&node_info->pending_lsp_gen_queue, &fragment->frag_regen_glue);
    isis_fragment_lock (fragment);

    /* If the LSP gen job is already scheduled, then we are done */
    if (node_info->lsp_fragment_gen_task) {
        return;
    }

    node_info->lsp_fragment_gen_task = task_create_new_job (EV(node),
                                                        (void *)node,
                                                        isis_lsp_fragment_regen_cbk,
                                                        TASK_ONE_SHOT,
                                                        TASK_PRIORITY_COMPUTE);
}

/* This is Top level fn to insert a new TLV in ADVT-DB. Inserting a new TLV in ADVT-DB
    requires finding the fragment which can accomodate the TLV, regen the fragment's LSP pkt
    and flood it.*/
isis_tlv_record_advt_return_code_t
isis_record_tlv_advertisement (node_t *node, 
                                    uint8_t pn_no,
                                    isis_adv_data_t *adv_data,
                                    isis_adv_data_t **back_linkage,
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

    pkt_size_t tlv_size = isis_get_adv_data_size(adv_data);

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
        init_glthread(&fragment->frag_regen_glue);
        advt_db->fragments[frag_no] = fragment;
        isis_fragment_lock(fragment);
    }

    assert(IS_GLTHREAD_LIST_EMPTY(&adv_data->glue));
    glthread_add_last(&fragment->tlv_list_head, &adv_data->glue);
    adv_data->fragment = fragment;
    isis_fragment_lock(fragment);
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
    adv_data->holder = back_linkage;
    fragment->regen_flags = ISIS_LSP_DEF_REGEN_FLAGS;
    isis_schedule_regen_fragment(node, fragment);
    return ISIS_TLV_RECORD_ADVT_SUCCESS;
}

/* This fn regenerate fragment;s LSP pkt from scratch. regen_ctrl_flags controls as to what content
    will go in LSP pkt.*/
void
isis_regenerate_lsp_fragment (node_t *node, isis_fragment_t *fragment, uint32_t regen_ctrl_flags) {

    glthread_t *curr;
    pkt_size_t tlv_size;
    pkt_size_t bytes_filled;
    bool create_purge_lsp;
    ethernet_hdr_t *eth_hdr;
    pkt_size_t eth_payload_size;
    isis_node_info_t *node_info;
    isis_pkt_hdr_t *lsp_pkt_hdr;

    node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    bytes_filled = 0;
    eth_payload_size = 0;

    /* When protocol shut is in progress, then only zero fragment
        is allowed to be regenerated and advertised */
    if (isis_is_protocol_shutdown_in_progress(node) &&
            (fragment->pn_no || fragment->fr_no)) {
        return;
    }

    if (!fragment->lsp_pkt) {
        isis_fragment_alloc_new_lsp_pkt (node_info, fragment);
    }
    else {
        isis_fragment_dealloc_lsp_pkt (node_info, fragment);
        isis_fragment_alloc_new_lsp_pkt (node_info, fragment);
    }

    /* Drain the older pkt contents */
    eth_hdr = (ethernet_hdr_t *)(fragment->lsp_pkt->pkt);

    /* Re-manufacture ethernet hdr */
    if (IS_BIT_SET (regen_ctrl_flags, ISIS_SHOULD_REWRITE_ETH_HDR)) {
        memset((byte *)eth_hdr, 0, fragment->bytes_filled);
        memset (eth_hdr->src_mac.mac, 0, sizeof(mac_addr_t));
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
    eth_payload_size +=  sizeof (isis_pkt_hdr_t);

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
        tlv_size =  advt_data->tlv_size;

        lsp_tlv_buffer = tlv_buffer_insert_tlv(
                                        lsp_tlv_buffer,
                                        (uint8_t)advt_data->tlv_no,
                                        tlv_size - TLV_OVERHEAD_SIZE,
                                        isis_get_adv_data_tlv_content(advt_data,  tlv_content));

        bytes_filled += tlv_size;
        eth_payload_size += tlv_size;

    } ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr) ;

    SET_COMMON_ETH_FCS (eth_hdr, eth_payload_size, 0 );
    bytes_filled +=  ETH_FCS_SIZE;
    fragment->lsp_pkt->pkt_size = bytes_filled ;
}

isis_tlv_wd_return_code_t
isis_withdraw_tlv_advertisement (node_t *node,
                                    isis_adv_data_t *adv_data){

    
    isis_fragment_t *fragment;
    isis_advt_db_t *advt_db;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return ISIS_TLV_WD_SUCCESS;

    if (!adv_data->advt_id) return ISIS_TLV_WD_FAILED;

    fragment = adv_data->fragment;

    assert (fragment) ;
    isis_fragment_prevent_premature_deletion(fragment);

    advt_db = node_info->advt_db[fragment->pn_no];
    assert(advt_db);
    
    remove_glthread (&adv_data->glue);
    fragment->bytes_filled -= adv_data->tlv_size;
    remove_glthread(&fragment->priority_list_glue);
    glthread_priority_insert(&advt_db->fragment_priority_list,
                             &fragment->priority_list_glue,
                             isis_fragment_size_comp_fn,
                             (int)&((isis_fragment_t *)0)->priority_list_glue);


    if (IS_GLTHREAD_LIST_EMPTY(&fragment->tlv_list_head)) {
        /* Empty fragment, remove it if it is non-zero fragment */
        if (fragment->pn_no || fragment->fr_no) {
            isis_discard_fragment (node, fragment);
        }
    }
    else {
        isis_schedule_regen_fragment(node, fragment);
    }
    adv_data->fragment = NULL;
    isis_fragment_unlock(node_info, fragment);
    if (adv_data->holder) {
        *(adv_data->holder) = NULL;
    }
    XFREE(adv_data);
    isis_fragment_relieve_premature_deletion(node_info, fragment);
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
isis_destroy_advt_db (node_t *node, uint8_t pn_no) {

    int i;
    isis_advt_db_t *advt_db;
    isis_fragment_t *fragment;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;
     
     advt_db = node_info->advt_db[pn_no];
    
    if (!advt_db) return;

    for (i = 0; i < ISIS_MAX_FRAGMENT_SUPPORTED; i++) {

        fragment = advt_db->fragments[i];
        if (!fragment) continue;
        isis_discard_fragment (node, fragment);
    }

    XFREE(advt_db);
    node_info->advt_db[pn_no] = NULL;
}

void
isis_discard_fragment (node_t *node, isis_fragment_t *fragment) {

    glthread_t *curr;
    pkt_size_t pkt_size;
    isis_lsp_pkt_t *lsp_pkt;
    pkt_block_t *pkt_block;
    isis_adv_data_t *advt_data;
    isis_advt_db_t *advt_db;
    isis_node_info_t *node_info;

    isis_fragment_prevent_premature_deletion (fragment);
    node_info = ISIS_NODE_INFO(node);

    ITERATE_GLTHREAD_BEGIN(&fragment->tlv_list_head, curr) {

        advt_data = glue_to_isis_advt_data(curr);
        remove_glthread(&advt_data->glue);
        assert(advt_data->fragment);
        advt_data->fragment = NULL;
        isis_fragment_unlock(node_info, fragment);
        assert(advt_data->holder && *(advt_data->holder));
        *(advt_data->holder) = NULL;
        fragment->bytes_filled -=advt_data->tlv_size;
        XFREE(advt_data);
    }
    ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr);

    remove_glthread(&fragment->priority_list_glue);
    isis_fragment_unlock(node_info, fragment);

    advt_db = node_info->advt_db[fragment->pn_no];
    assert(advt_db->fragments[fragment->fr_no]);
    advt_db->fragments[fragment->fr_no] = NULL;
    isis_fragment_unlock(node_info, fragment);

    isis_remove_lsp_pkt_from_lspdb(node, fragment->lsp_pkt);

    if (IS_QUEUED_UP_IN_THREAD(&fragment->frag_regen_glue)) {
        remove_glthread(&fragment->frag_regen_glue);
        isis_fragment_unlock(node_info, fragment);
    }

    isis_fragment_dealloc_lsp_pkt(node_info, fragment);
    isis_fragment_relieve_premature_deletion(node_info, fragment);
}

void
isis_assert_check_all_advt_db_cleanedup (isis_node_info_t *node_info) {

    int i;

    for (i = 0; i < ISIS_MAX_PN_SUPPORTED; i++) {
        if (!node_info->advt_db[i]) continue;
        assert(0);
    }
}

#if 1
uint32_t 
isis_fragment_print (node_t *node, isis_fragment_t *fragment, byte *buff) {

    uint32_t rc = 0;
    glthread_t *curr;
    byte system_id_str[32];
    isis_adv_data_t *advt_data;

    rc = printf ("fragment : [%hu][%hu]  , seq_no : %u\n",
                fragment->pn_no, fragment->fr_no, fragment->seq_no);

    rc += printf ("  bytes filled : %hu, ref_count : %u   \n  lsp pkt bytes filled : %hu , ref_count : %u\n",
                fragment->bytes_filled, fragment->ref_count,
                fragment->lsp_pkt->pkt_size, fragment->lsp_pkt->ref_count);

    rc += printf ("    TLVs:\n");

    ITERATE_GLTHREAD_BEGIN(&fragment->tlv_list_head, curr) {

        advt_data = glue_to_isis_advt_data (curr);
        rc += printf ("     TLV %hu (%huB)\n", advt_data->tlv_no, advt_data->tlv_size);

        switch (advt_data->tlv_no) {
            case ISIS_IS_REACH_TLV:
                rc += printf ("       nbr sys id : %s\n", 
                    isis_system_id_tostring (&advt_data->u.adj_data.nbr_sys_id, system_id_str));
                rc +=  printf ("       metric : %u\n", advt_data->u.adj_data.metric);
                rc +=  printf ("       local ifindex : %u\n", advt_data->u.adj_data.local_ifindex);
                rc +=  printf ("       remote ifindex : %u\n", advt_data->u.adj_data.remote_ifindex);
                rc +=  printf ("       local ip : %s\n", tcp_ip_covert_ip_n_to_p (advt_data->u.adj_data.local_intf_ip, system_id_str));
                rc +=  printf ("       remote ip : %s\n", tcp_ip_covert_ip_n_to_p (advt_data->u.adj_data.remote_intf_ip, system_id_str)); 
                break;
            case ISIS_TLV_IP_REACH:
                rc += printf ("       Prefix : %s/%d   metric : %u\n",
                tcp_ip_covert_ip_n_to_p (advt_data->u.pfx.prefix, system_id_str),
                advt_data->u.pfx.mask, advt_data->u.pfx.metric);
                break;
        }
    } ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr);

    return 0;
}
#else
uint32_t 
isis_fragment_print (node_t *node, isis_fragment_t *fragment, byte *buff) {

    uint32_t rc = 0;
    glthread_t *curr;
    byte system_id_str[32];
    isis_adv_data_t *advt_data;

    rc = sprintf (buff + rc, "fragment : [%hu][%hu]  , seq_no : %u\n",
                fragment->pn_no, fragment->fr_no, fragment->seq_no);
                
    rc += printf ("  bytes filled : %hu, ref_count : %u   \n  lsp pkt bytes filled : %hu , ref_count : %u\n",
                fragment->bytes_filled, fragment->ref_count,
                fragment->lsp_pkt->pkt_size, fragment->lsp_pkt->ref_count);

    rc += sprintf (buff + rc, "    TLVs:\n");

    ITERATE_GLTHREAD_BEGIN(&fragment->tlv_list_head, curr) {

        advt_data = glue_to_isis_advt_data (curr);
        rc += sprintf (buff + rc, "     TLV %hu (%huB)\n", advt_data->tlv_no, advt_data->tlv_size);

        switch (advt_data->tlv_no) {
            case ISIS_IS_REACH_TLV:
                rc += sprintf (buff + rc, "       nbr sys id : %s\n", 
                    isis_system_id_tostring (&advt_data->u.adj_data.nbr_sys_id, system_id_str));
                rc +=  sprintf (buff + rc, "       metric : %u\n", advt_data->u.adj_data.metric);
                rc +=  sprintf (buff + rc, "       local ifindex : %u\n", advt_data->u.adj_data.local_ifindex);
                rc +=  sprintf (buff + rc, "       remote ifindex : %u\n", advt_data->u.adj_data.remote_ifindex);
                rc +=  sprintf (buff + rc, "       local ip : %s\n", tcp_ip_covert_ip_n_to_p (advt_data->u.adj_data.local_intf_ip, system_id_str));
                rc +=  sprintf (buff + rc, "       remote ip : %s\n", tcp_ip_covert_ip_n_to_p (advt_data->u.adj_data.remote_intf_ip, system_id_str)); 
                break;
            case ISIS_TLV_IP_REACH:
                rc += sprintf (buff + rc, "       Prefix : %s/%d   metric : %u\n",
                tcp_ip_covert_ip_n_to_p (advt_data->u.pfx.prefix, system_id_str),
                advt_data->u.pfx.mask, advt_data->u.pfx.metric);
                break;
        }
    } ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr);

    return rc;
}
#endif

uint32_t 
isis_show_advt_db (node_t *node) {

    int i, j;
    uint32_t rc = 0;
    isis_advt_db_t *advt_db;
    isis_fragment_t *fragment;

    byte *buff = node->print_buff;
    memset(buff, 0, NODE_PRINT_BUFF_LEN);
    
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return 0;

    for (i = 0; i < ISIS_MAX_PN_SUPPORTED; i++) {

        advt_db =      node_info->advt_db[i];
        if (!advt_db) continue;

        for (j = 0 ; j < ISIS_MAX_FRAGMENT_SUPPORTED; j++) {
            fragment = advt_db->fragments[j];
            if (!fragment) continue;
            rc += isis_fragment_print (node, fragment, buff + rc);
        }
    }
    return rc;
}

/* This fn handles when lsp pkt do not reference back the fragment */
void
isis_fragment_dealloc_lsp_pkt (isis_node_info_t *node_info, isis_fragment_t *fragment) {

    isis_lsp_pkt_t *lsp_pkt;

    if (!fragment->lsp_pkt) return;
    
    lsp_pkt = fragment->lsp_pkt;

    isis_fragment_prevent_premature_deletion (fragment);
    isis_lsp_pkt_prevent_premature_deletion(fragment->lsp_pkt);

    fragment->lsp_pkt = NULL;
    isis_deref_isis_pkt(node_info, lsp_pkt);

    if (lsp_pkt->fragment == fragment) {
        lsp_pkt->fragment = NULL;
        isis_fragment_unlock(node_info, fragment);
    }

    isis_lsp_pkt_relieve_premature_deletion(node_info, lsp_pkt);    //isis_fragment_relieve_premature_deletion(node_info, fragment); 
    fragment->ref_count--; // make this API work even if fragment has initial ref_count = 1
}

void
isis_fragment_alloc_new_lsp_pkt (isis_node_info_t *node_info, isis_fragment_t *fragment) {

    assert(!fragment->lsp_pkt);
    fragment->lsp_pkt = (isis_lsp_pkt_t *)XCALLOC(0, 1, isis_lsp_pkt_t);
    isis_ref_isis_pkt(fragment->lsp_pkt);
    fragment->lsp_pkt->fragment = fragment;
    isis_fragment_lock(fragment);
    fragment->lsp_pkt->flood_eligibility = true;
    fragment->lsp_pkt->pkt = (byte *)tcp_ip_get_new_pkt_buffer(fragment->bytes_filled);
    fragment->lsp_pkt->pkt_size = 0;
}

void
isis_fragment_lock (isis_fragment_t *fragment) {
    
    fragment->ref_count++;
}

static void
isis_fragment_delete (isis_fragment_t *fragment) {
    XFREE(fragment);
}

u_int8_t
isis_fragment_unlock (isis_node_info_t *node_info, isis_fragment_t *fragment) {

    fragment->ref_count--;
    if (fragment->ref_count) return (fragment->ref_count);

    /* Should not leak any memory*/
    assert(IS_GLTHREAD_LIST_EMPTY(&fragment->tlv_list_head));

    /* Fragment and LSP pkt have their own life time a.ka. reference count.
        It is possible that ref_count of fragment is reduced to 0, but lsp pkt yet is in use*/
    if (fragment->lsp_pkt) {
        isis_fragment_dealloc_lsp_pkt(node_info, fragment);
    }

    /* Fragment must not be Queued for regeneration */
    assert(!IS_QUEUED_UP_IN_THREAD(&fragment->frag_regen_glue));
    /*should not leave dangling pointers by referenced objects*/
    assert(!node_info->advt_db[fragment->pn_no]->fragments[fragment->fr_no]);
    assert(!IS_QUEUED_UP_IN_THREAD(&fragment->priority_list_glue));
    isis_fragment_delete (fragment);
    return 0;
}
