#include <assert.h>
#include <arpa/inet.h>
#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_advt.h"
#include "isis_flood.h"
#include "isis_lspdb.h"
#include "isis_tlv_struct.h"
#include "isis_struct.h"
#include "isis_utils.h"
#include "isis_adjacency.h"
#include"isis_policy.h"
#include "isis_dis.h"
#include "isis_ted.h"
#include "isis_cmdcodes.h"
#include "isis_srv6.h"

extern void
isis_ipv4_rt_notif_cbk (
        event_dispatcher_t *ev_dis,
        void *rt_notif_data, unsigned int arg_size) ;

static int 
isis_get_new_fragment_no (isis_advt_db_t *advt_db) {

    int i;

    for (i = 0; i < ISIS_MAX_FRAGMENT_SUPPORTED; i++) {
        if (!advt_db->fragments[i]) return i;
    }
    return -1;
}

static int
 isis_fragment_size_comp_fn (void *data1, void *data2){

    isis_fragment_t  *frag_info1 = (isis_fragment_t  *)data1;
    isis_fragment_t  *frag_info2 = (isis_fragment_t  *)data2;

    if (frag_info1->bytes_filled < frag_info2->bytes_filled) return CMP_PREFERRED;
    if (frag_info1->bytes_filled > frag_info2->bytes_filled) return CMP_NOT_PREFERRED;
    return CMP_PREF_EQUAL;
 }

static void
isis_fragment_bind_advt_data (
            node_t *node,
            isis_fragment_t *fragment,
            isis_adv_data_t *advt_data) {

    assert (!advt_data->fragment);
    assert (!IS_QUEUED_UP_IN_THREAD (&advt_data->glue));
    assert (!IS_BIT_SET(advt_data->flags, ISIS_ADVT_DATA_F_ADVERTISED));
    assert ((ISIS_LSP_MAX_PKT_SIZE - fragment->bytes_filled) >= advt_data->tlv_size);
    glthread_add_next (&fragment->tlv_list_head, &advt_data->glue);
    SET_BIT(advt_data->flags, ISIS_ADVT_DATA_F_ADVERTISED);
    advt_data->fragment = fragment;
    isis_fragment_lock (fragment);
    fragment->bytes_filled += advt_data->tlv_size;
    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[isis_event_tlv_added]);
}

static void
isis_fragment_unbind_advt_data (node_t *node,
            isis_fragment_t *fragment,
            isis_adv_data_t *advt_data) {

    assert (advt_data->fragment && advt_data->fragment == fragment );
    assert (IS_QUEUED_UP_IN_THREAD (&advt_data->glue));
    assert (advt_data->flags & ISIS_ADVT_DATA_F_ADVERTISED);
    remove_glthread (&advt_data->glue);
    UNSET_BIT16(advt_data->flags, ISIS_ADVT_DATA_F_ADVERTISED);
    fragment->bytes_filled -= advt_data->tlv_size;
    advt_data->fragment = NULL;
    isis_fragment_unlock (node, fragment);
    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[isis_event_tlv_removed]);
}

static void
isis_fragment_set_regen_flags (node_t *node, isis_fragment_t *fragment) {

    if (isis_is_overloaded (node, NULL)) {
            fragment->regen_flags |= ISIS_SHOULD_INCL_OL_BIT;
    }

    fragment->regen_flags |= ISIS_LSP_DEF_REGEN_FLAGS;
}

static void
isis_try_accomodate_wait_list_data (node_t *node, isis_fragment_t *fragment);

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
        isis_fragment_unlock (node, fragment);
    }
}

void
isis_cancel_all_fragment_regen_job (node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info->regen_all_fragment_task) return;

    task_cancel_job (EV(node), node_info->regen_all_fragment_task);
    node_info->regen_all_fragment_task = NULL;
}

void
isis_schedule_all_fragment_regen_job (node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (node_info->regen_all_fragment_task) return;

    if (!isis_validate_job_schedule  (node, ISIS_ALL_FRAG_REGEN_JOB)) return;
    isis_cancel_redundant_jobs (node, ISIS_ALL_FRAG_REGEN_JOB);

    node_info->regen_all_fragment_task =
        task_create_new_job(
            EV(node),
            (void *)node,
            isis_regen_all_fragments_from_scratch,
            TASK_ONE_SHOT,
            TASK_PRIORITY_LOW);
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
        isis_install_lsp (node, NULL, fragment->lsp_pkt);
        isis_fragment_unlock (node, fragment);
    }
}

void
isis_wait_list_advt_data_add (node_t *node, uint8_t pn_no, isis_adv_data_t *adv_data) {

    assert (!adv_data->fragment);
    assert (!(adv_data->flags & ISIS_ADVT_DATA_F_WAIT_LISTED));
    isis_advt_db_t *advt_db = ISIS_NODE_INFO(node)->advt_db[pn_no];
    glthread_add_next (&advt_db->advt_data_wait_list_head, &adv_data->glue);
    adv_data->flags |= ISIS_ADVT_DATA_F_WAIT_LISTED;
    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[isis_event_tlv_wait_listed]);
    isis_set_overload (node, 0, CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD);
    SET_BIT (ISIS_NODE_INFO(node)->event_control_flags, ISIS_EVENT_DEVICE_DYNAMIC_OVERLOAD_BIT);
    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[isis_event_device_dynamic_overload]);
}

void 
isis_wait_list_advt_data_remove (node_t *node, isis_adv_data_t *adv_data) {

    isis_node_info_t *node_info;
    node_info = ISIS_NODE_INFO(node);
    assert (IS_QUEUED_UP_IN_THREAD (&adv_data->glue));
    assert (adv_data->flags & ISIS_ADVT_DATA_F_WAIT_LISTED);
    remove_glthread (&adv_data->glue);
    UNSET_BIT16(adv_data->flags, ISIS_ADVT_DATA_F_WAIT_LISTED);
    ISIS_DECREMENT_NODE_STATS(node, isis_event_count[isis_event_tlv_wait_listed]);
    if (isis_is_protocol_admin_shutdown (node)) return;
    if (isis_get_waitlisted_advt_data_count (node)) return; 
    UNSET_BIT64(node_info->event_control_flags, ISIS_EVENT_DEVICE_DYNAMIC_OVERLOAD_BIT);
    if (!IS_BIT_SET (node_info->event_control_flags, ISIS_EVENT_DEVICE_OVERLOAD_BY_ADMIN_BIT)) {
        isis_unset_overload (node, 0, CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD);
    }
}   

void
isis_schedule_regen_fragment (node_t *node,
                                                    isis_fragment_t *fragment,
                                                    isis_event_type_t event_type) {

    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    if (isis_is_protocol_shutdown_in_progress(node)) {
        /* No Op : We would still allow fragment regen, as when we are in the process
        of shutting down the protocol, we still need to regen purge LSPs*/
    }

    /* No more work if shutdown apriori work has been completed */
    if (isis_is_protocol_shutdown_pending_work_completed (node)) {
        return;
    }

    /* Fragment is already Queued up for regen*/
    if (IS_QUEUED_UP_IN_THREAD(&fragment->frag_regen_glue)) {
        return;
    }

    /* Queue the fragment for LSP regen */
    glthread_add_next (&node_info->pending_lsp_gen_queue, &fragment->frag_regen_glue);
    isis_fragment_lock (fragment);

    /* If the LSP gen job is already scheduled, then we are done */
    if (node_info->lsp_fragment_gen_task) {
        return;
    }

    if (!isis_validate_job_schedule  (node, ISIS_FRAG_REGEN_JOB)) return;
    isis_cancel_redundant_jobs (node, ISIS_FRAG_REGEN_JOB);

    node_info->lsp_fragment_gen_task = task_create_new_job (EV(node),
                                                        (void *)node,
                                                        isis_lsp_fragment_regen_cbk,
                                                        TASK_ONE_SHOT,
                                                        TASK_PRIORITY_COMPUTE);
}

void
isis_free_advt_data (isis_adv_data_t *adv_data) {

    assert (!IS_QUEUED_UP_IN_THREAD (&adv_data->glue));
    assert (!(adv_data->flags & ISIS_ADVT_DATA_F_WAIT_LISTED)) ;
    assert (!(adv_data->flags & ISIS_ADVT_DATA_F_ADVERTISED)) ;
    assert (!adv_data->fragment);
    assert (!adv_data->src.holder);

    /* check and delete Subtlvs*/
    switch (adv_data->tlv_no) {

        case ISIS_TLV_LOCATOR:
        {
            glthread_t *curr;
            isis_adv_data_t *pfxsid_adv_data;
            while ((curr = dequeue_glthread_first (&adv_data->u.srv6_loc.pfxsid_list_head))) {
                pfxsid_adv_data = srv6_pfxsid_sibling_glue_to_pfxsid_adv_data(curr);
                remove_glthread (&pfxsid_adv_data->u.srv6_pfxsid.sibling_glue);
                adv_data->tlv_size -= pfxsid_adv_data->tlv_size;
                adv_data->u.srv6_loc.subtlv_len -= pfxsid_adv_data->tlv_size;
                isis_free_advt_data(pfxsid_adv_data);
            }
            assert (!adv_data->u.srv6_loc.subtlv_len);
        }
        break;
    }
    XFREE(adv_data);
}

void
isis_advt_data_clear_backlinkage( isis_node_info_t *node_info, isis_adv_data_t * adv_data) {

    switch (adv_data->tlv_no) {
        case ISIS_TLV_HOSTNAME:
            break;
        case ISIS_IS_REACH_TLV:
        case ISIS_TLV_RTR_CAP:
        case ISIS_TLV_IPV6_REACH:
        case ISIS_TLV_IPV6_MT_REACH:
        case ISIS_LOCATOR_PFX_SID_SUBTLV:
            if (adv_data->src.holder && *adv_data->src.holder)
                    *(adv_data->src.holder) = NULL;
            adv_data->src.holder = NULL;
            break;
        case ISIS_TLV_IP_REACH:
        /* To Do : Make linkage of exported prefixes same as other
            TLVs*/
        {
            void *app_data;
            mtrie_ops_result_code_t rc;
            uint32_t bin_ip, bin_mask;
            bitmap_t prefix_bm, mask_bm;
            bin_ip = adv_data->u.pfx.prefix;
            bin_mask = tcp_ip_convert_dmask_to_bin_mask(adv_data->u.pfx.mask);
            bin_mask = ~bin_mask;
            bin_mask = htonl(bin_mask);
            bitmap_init(&prefix_bm, 32);
            bitmap_init(&mask_bm, 32);
            prefix_bm.bits[0] = bin_ip;
            mask_bm.bits[0] = bin_mask;
            rc = mtrie_delete_prefix (&node_info->exported_routes,
                                                 &prefix_bm, &mask_bm,
                                                 &app_data);
            if (rc == MTRIE_DELETE_SUCCESS) {
                assert (adv_data == (isis_adv_data_t *)app_data);
            }
            bitmap_free_internal(&prefix_bm);
            bitmap_free_internal(&mask_bm);            
        }
        break;
        case ISIS_TLV_LOCATOR:
        {
            remove_glthread(&adv_data->u.srv6_loc.sibling_glue);
            /* Clear back linkage of SUBTLVs*/
            glthread_t *curr;
            isis_adv_data_t *pfxsid_adv_data;
            ITERATE_GLTHREAD_BEGIN (&adv_data->u.srv6_loc.pfxsid_list_head, curr) {

                pfxsid_adv_data = srv6_pfxsid_sibling_glue_to_pfxsid_adv_data(curr);
                isis_advt_data_clear_backlinkage(node_info, pfxsid_adv_data);

            } ITERATE_GLTHREAD_END (&adv_data->u.srv6_loc.pfxsid_list_head, curr);
        }
        break;
        default: ;
    }
}

/* This is Top level fn to insert a new TLV in ADVT-DB. Inserting a new TLV in ADVT-DB
    requires finding the fragment which can accomodate the TLV, regen the fragment's LSP pkt
    and flood it.*/
isis_advt_tlv_return_code_t
isis_advertise_tlv (node_t *node, 
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

    pkt_size_t tlv_size = isis_get_adv_data_size(adv_data);

    isis_advt_db_t *advt_db = node_info->advt_db[pn_no];

    if (!advt_db) {
        isis_create_advt_db (node_info, pn_no);
        advt_db =  node_info->advt_db[pn_no];
        new_advt_db = true;
    }

    curr = glthread_get_next (&advt_db->fragment_priority_list);

    if (curr) {
        fragment = isis_priority_list_glue_to_fragment(curr);
    }

    if (!curr || (fragment && 
            (ISIS_LSP_MAX_PKT_SIZE - fragment->bytes_filled) < tlv_size)) {

        frag_no = isis_get_new_fragment_no(advt_db);
        
        if (frag_no < 0) {

            if (new_advt_db) {
                XFREE(node_info->advt_db[pn_no]);
                node_info->advt_db[pn_no] = NULL;
            }

            isis_wait_list_advt_data_add (node, pn_no, adv_data);
            return ISIS_TLV_RECORD_ADVT_NO_FRAG;
        }

        fragment = isis_alloc_new_fragment();
        new_frag = true;
        fragment->fr_no = frag_no;
        fragment->pn_no = pn_no;
        advt_db->fragments[frag_no] = fragment;
        isis_fragment_lock(fragment);
    }
    
    isis_fragment_bind_advt_data (node, fragment, adv_data);

    remove_glthread(&fragment->priority_list_glue);
    glthread_priority_insert(&advt_db->fragment_priority_list,
                             &fragment->priority_list_glue,
                             isis_fragment_size_comp_fn,
                             (int)&((isis_fragment_t *)0)->priority_list_glue);
    if (new_frag) {
        isis_fragment_lock(fragment);
    }
    
    advt_info_out->pn_no = pn_no;
    advt_info_out->fr_no = frag_no;
    isis_fragment_set_regen_flags (node, fragment);
    isis_schedule_regen_fragment(node, fragment, isis_event_tlv_added);
    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[isis_event_tlv_added]);
    return ISIS_TLV_RECORD_ADVT_SUCCESS;
}

isis_tlv_wd_return_code_t
isis_withdraw_tlv_advertisement (node_t *node,
                                    isis_adv_data_t *adv_data){
    
    isis_fragment_t *fragment;
    isis_advt_db_t *advt_db;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    fragment = adv_data->fragment;

    /* Due to space exhaustion, some advt data may not have assigned fragment,
        Simply delete the advt data*/
    if (!fragment) {
        return ISIS_TLV_WD_FRAG_NOT_FOUND;
    }

    isis_fragment_prevent_premature_deletion(fragment);

    advt_db = node_info->advt_db[fragment->pn_no];
    assert(advt_db);
    isis_fragment_unbind_advt_data (node, fragment, adv_data);
    remove_glthread(&fragment->priority_list_glue);
    glthread_priority_insert(&advt_db->fragment_priority_list,
                             &fragment->priority_list_glue,
                             isis_fragment_size_comp_fn,
                             (int)&((isis_fragment_t *)0)->priority_list_glue);

    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[isis_event_tlv_removed]);

    isis_try_accomodate_wait_list_data (node, fragment);

    if (IS_GLTHREAD_LIST_EMPTY(&fragment->tlv_list_head)) {
        /* Empty fragment, remove it if it is not massiah fragment */
        if (fragment->pn_no || fragment->fr_no) {
            fragment->regen_flags = ISIS_SHOULD_INCL_PURGE_BIT;
            isis_regenerate_lsp_fragment (node, fragment, fragment->regen_flags);
            isis_schedule_lsp_flood (node, fragment->lsp_pkt, NULL);
            isis_discard_fragment (node, fragment);
        }
        else {
            fragment->regen_flags = ISIS_LSP_DEF_REGEN_FLAGS;
            isis_schedule_regen_fragment(node, fragment, isis_event_tlv_removed);
        }
    }
    else {
        isis_schedule_regen_fragment(node, fragment, isis_event_tlv_removed);
    }
    isis_fragment_relieve_premature_deletion(node, fragment);
    return ISIS_TLV_WD_SUCCESS;
}

/* This fn regenerate fragment;s LSP pkt from scratch. regen_ctrl_flags controls as to what content
    will go in LSP pkt.*/
void
isis_regenerate_lsp_fragment (node_t *node, isis_fragment_t *fragment, uint32_t regen_ctrl_flags) {

    glthread_t *curr;
    pkt_size_t tlv_size;
    pkt_size_t bytes_filled;
    ethernet_hdr_t *eth_hdr;
    pkt_size_t eth_payload_size;
    isis_node_info_t *node_info;
    isis_pkt_hdr_t *lsp_pkt_hdr;

    node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    bytes_filled = 0;
    eth_payload_size = 0;

    if (!fragment->lsp_pkt) {
        isis_fragment_alloc_new_lsp_pkt (fragment);
    }
    else {
        isis_fragment_dealloc_lsp_pkt (node, fragment);
        isis_fragment_alloc_new_lsp_pkt (fragment);
    }

    /* Drain the older pkt contents */
    eth_hdr = (ethernet_hdr_t *)(fragment->lsp_pkt->pkt);

    /* Re-manufacture ethernet hdr */
    memset((byte *)eth_hdr, 0, fragment->bytes_filled);
    memset(eth_hdr->src_mac.mac, 0, sizeof(mac_addr_t));
    layer2_fill_with_broadcast_mac(eth_hdr->dst_mac.mac);
    eth_hdr->type = htons(ISIS_LSP_ETH_PKT_TYPE);

    bytes_filled += (ETH_HDR_SIZE_EXCL_PAYLOAD - ETH_FCS_SIZE);

    /* Re-manufactue LSP Pkt Hdr */
    lsp_pkt_hdr = (isis_pkt_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr);

    lsp_pkt_hdr->isis_pkt_type = ISIS_L1_LSP_PKT_TYPE;
    lsp_pkt_hdr->seq_no = (++fragment->seq_no);
    lsp_pkt_hdr->rtr_id = tcp_ip_convert_ip_p_to_n(NODE_RTRID_ADDR(node));
    lsp_pkt_hdr->pn_no = fragment->pn_no;
    lsp_pkt_hdr->fr_no = fragment->fr_no;

    bytes_filled += sizeof (isis_pkt_hdr_t);
    eth_payload_size +=  sizeof (isis_pkt_hdr_t);

    if (IS_BIT_SET(regen_ctrl_flags, ISIS_SHOULD_INCL_PURGE_BIT) ) {
        SET_BIT(lsp_pkt_hdr->flags, ISIS_LSP_PKT_F_PURGE_BIT);
    }

    if (IS_BIT_SET(regen_ctrl_flags, ISIS_SHOULD_INCL_OL_BIT) ) {
        SET_BIT(lsp_pkt_hdr->flags, ISIS_LSP_PKT_F_OVERLOAD_BIT);
    }

    byte tlv_content[255];
    isis_adv_data_t *advt_data;
    byte *lsp_tlv_buffer = (byte *)(lsp_pkt_hdr + 1);

    /* Fill other TLVs*/
    ITERATE_GLTHREAD_BEGIN(&fragment->tlv_list_head, curr) {

        advt_data = glue_to_isis_advt_data(curr);
        if (advt_data->tlv_no == ISIS_IS_REACH_TLV) continue;
        if (advt_data->tlv_no == ISIS_TLV_IP_REACH) continue;
        if (advt_data->tlv_no == ISIS_TLV_IPV6_REACH) continue;
        if (advt_data->tlv_no == ISIS_TLV_LOCATOR) continue;
        
        tlv_size = advt_data->tlv_size;

        lsp_tlv_buffer = tlv_buffer_insert_tlv(
            lsp_tlv_buffer,
            (uint8_t)advt_data->tlv_no,
            tlv_size - TLV_OVERHEAD_SIZE,
            isis_get_adv_data_tlv_content(advt_data, tlv_content));

        bytes_filled += tlv_size;
        eth_payload_size += tlv_size;
        
    } ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr) ;


    if (IS_BIT_SET(regen_ctrl_flags, ISIS_SHOULD_INCL_IS_REACH_TLVS)) {

        ITERATE_GLTHREAD_BEGIN(&fragment->tlv_list_head, curr) {

            advt_data = glue_to_isis_advt_data(curr);

            if (advt_data->tlv_no != ISIS_IS_REACH_TLV) continue;

            tlv_size =  advt_data->tlv_size;

            lsp_tlv_buffer = tlv_buffer_insert_tlv(
                                        lsp_tlv_buffer,
                                        (uint8_t)advt_data->tlv_no,
                                        tlv_size - TLV_OVERHEAD_SIZE,
                                        isis_get_adv_data_tlv_content(advt_data,  tlv_content));

            bytes_filled += tlv_size;
            eth_payload_size += tlv_size;

        } ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr) ;
    }

    if (IS_BIT_SET(regen_ctrl_flags, ISIS_SHOULD_INCL_IP_REACH_TLVS)) {

        ITERATE_GLTHREAD_BEGIN(&fragment->tlv_list_head, curr) {

            advt_data = glue_to_isis_advt_data(curr);

            if (advt_data->tlv_no != ISIS_TLV_IP_REACH) continue;
            
            tlv_size =  advt_data->tlv_size;

            lsp_tlv_buffer = tlv_buffer_insert_tlv(
                                        lsp_tlv_buffer,
                                        (uint8_t)advt_data->tlv_no,
                                        tlv_size - TLV_OVERHEAD_SIZE,
                                        isis_get_adv_data_tlv_content(advt_data,  tlv_content));

            bytes_filled += tlv_size;
            eth_payload_size += tlv_size;

        } ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr) ;
    }

    if (IS_BIT_SET(regen_ctrl_flags, ISIS_SHOULD_INCL_IPV6_REACH_TLVS)) {

        ITERATE_GLTHREAD_BEGIN(&fragment->tlv_list_head, curr) {

            advt_data = glue_to_isis_advt_data(curr);

            if (advt_data->tlv_no != ISIS_TLV_IPV6_REACH) continue;
            
            tlv_size =  advt_data->tlv_size;

            lsp_tlv_buffer = tlv_buffer_insert_tlv(
                                        lsp_tlv_buffer,
                                        (uint8_t)advt_data->tlv_no,
                                        tlv_size - TLV_OVERHEAD_SIZE,
                                        isis_get_adv_data_tlv_content(advt_data,  tlv_content));

            bytes_filled += tlv_size;
            eth_payload_size += tlv_size;

        } ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr) ;
    }

    if (IS_BIT_SET(regen_ctrl_flags, ISIS_SHOULD_INCL_SRV6_TLVS)) {

        ITERATE_GLTHREAD_BEGIN(&fragment->tlv_list_head, curr) {

            advt_data = glue_to_isis_advt_data(curr);

            if (advt_data->tlv_no != ISIS_TLV_LOCATOR) continue;

            tlv_size =  advt_data->tlv_size;

            lsp_tlv_buffer = tlv_buffer_insert_tlv(
                                        lsp_tlv_buffer,
                                        (uint8_t)advt_data->tlv_no,
                                        tlv_size - TLV_OVERHEAD_SIZE,
                                        isis_get_adv_data_tlv_content(advt_data,  tlv_content));

            bytes_filled += tlv_size;
            eth_payload_size += tlv_size;

        } ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr) ;
    }

    SET_COMMON_ETH_FCS (eth_hdr, eth_payload_size, 0 );
    bytes_filled +=  ETH_FCS_SIZE;
    fragment->lsp_pkt->pkt_size = bytes_filled ;
    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[ isis_event_fragment_regen]);
}

void 
isis_create_advt_db(isis_node_info_t *node_info, uint8_t pn_no) {

    isis_advt_db_t *advt_db = node_info->advt_db[pn_no];
    assert(!advt_db);
    advt_db = (isis_advt_db_t *)XCALLOC2(0, 1, isis_advt_db_t );
    node_info->advt_db[pn_no] = advt_db;
    init_glthread(&advt_db->fragment_priority_list);
    init_glthread (&advt_db->advt_data_wait_list_head);
}

isis_fragment_t *
isis_alloc_new_fragment () {

    isis_fragment_t *fragment =  (isis_fragment_t  *)XCALLOC2(0, 1, isis_fragment_t);
    fragment->seq_no = 0;
    fragment->fr_no = 0;
    fragment->pn_no = 0;
    fragment->ref_count = 0;
    fragment->bytes_filled = ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(isis_pkt_hdr_t);
    init_glthread(&fragment->priority_list_glue);
    init_glthread(&fragment->tlv_list_head);
    init_glthread(&fragment->frag_regen_glue);
    return fragment;
}

void
isis_destroy_advt_db (node_t *node, uint8_t pn_no) {

    int i;
    glthread_t *curr;
    isis_advt_db_t *advt_db;
    isis_adv_data_t *adv_data;
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

    while ((curr = dequeue_glthread_first (&advt_db->advt_data_wait_list_head))) {

        adv_data = glue_to_isis_advt_data(curr);
        assert (!adv_data->fragment);
        assert (IS_BIT_SET(adv_data->flags, ISIS_ADVT_DATA_F_WAIT_LISTED));

        isis_advt_data_clear_backlinkage(node_info, adv_data);
        isis_free_advt_data(adv_data);
        ISIS_DECREMENT_NODE_STATS(node, isis_event_count[isis_event_tlv_wait_listed]);
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
    isis_advt_db_t *advt_db;
    isis_adv_data_t *advt_data;
    isis_node_info_t *node_info;

    isis_fragment_prevent_premature_deletion (fragment);
    node_info = ISIS_NODE_INFO(node);

    ITERATE_GLTHREAD_BEGIN(&fragment->tlv_list_head, curr) {

        advt_data = glue_to_isis_advt_data(curr);
        isis_fragment_unbind_advt_data  (node, fragment, advt_data);
        isis_advt_data_clear_backlinkage (node_info, advt_data);
        isis_free_advt_data (advt_data);
        
    } ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr);

    remove_glthread(&fragment->priority_list_glue);
    isis_fragment_unlock(node, fragment);

    advt_db = node_info->advt_db[fragment->pn_no];
    assert(advt_db->fragments[fragment->fr_no]);
    advt_db->fragments[fragment->fr_no] = NULL;
    isis_fragment_unlock(node, fragment);

    isis_remove_lsp_pkt_from_lspdb(node, fragment->lsp_pkt);
    isis_ted_uninstall_lsp(node, ISIS_TED_DB(node), fragment->lsp_pkt);

    /* Cancel fragment regeneration if scheduled*/
    if (IS_QUEUED_UP_IN_THREAD(&fragment->frag_regen_glue)) {
        remove_glthread(&fragment->frag_regen_glue);
        isis_fragment_unlock(node, fragment);
    }

    isis_fragment_dealloc_lsp_pkt(node, fragment);
    isis_fragment_relieve_premature_deletion(node, fragment);
    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[ isis_event_discard_fragment]);
}

void
isis_try_accomodate_wait_list_data (node_t *node, isis_fragment_t *fragment) {

    uint16_t N = 0;
    glthread_t *curr;
    isis_advt_db_t *advt_db;
    isis_adv_data_t *adv_data;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    advt_db = node_info->advt_db[fragment->pn_no];

    if (IS_GLTHREAD_LIST_EMPTY (&advt_db->advt_data_wait_list_head)) return;

    while ((curr = dequeue_glthread_first (&advt_db->advt_data_wait_list_head))) {

        adv_data = glue_to_isis_advt_data (curr);
        assert (!adv_data->fragment);
        assert (IS_BIT_SET(adv_data->flags, ISIS_ADVT_DATA_F_WAIT_LISTED));

        if (isis_advertise_advt_data_in_this_fragment (node, adv_data, fragment, false)) {
            N++;
            ISIS_DECREMENT_NODE_STATS(node, isis_event_count[isis_event_tlv_wait_listed]);
            ISIS_INCREMENT_NODE_STATS(node, isis_event_count[ isis_event_wait_list_tlv_advertised]);
            UNSET_BIT16(adv_data->flags, ISIS_ADVT_DATA_F_WAIT_LISTED);
            continue;
        }
        /* Add back if we have failed gracefully*/
         glthread_add_next (&advt_db->advt_data_wait_list_head, &adv_data->glue);
         break;
    }

    if (N) {
        isis_schedule_regen_fragment (node, fragment,  isis_event_wait_list_tlv_advertised);
    }

    if (isis_is_protocol_admin_shutdown (node)) return;
    if (isis_get_waitlisted_advt_data_count (node)) return;

    UNSET_BIT64(node_info->event_control_flags, ISIS_EVENT_DEVICE_DYNAMIC_OVERLOAD_BIT);
    if (!IS_BIT_SET(node_info->event_control_flags, ISIS_EVENT_DEVICE_OVERLOAD_BY_ADMIN_BIT)) {
        isis_unset_overload(node, 0, CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD);
    }
 }

/* This will be Used when TLV is generated which need to compulsorily need
    to go in this fragment only*/
bool
isis_advertise_advt_data_in_this_fragment (node_t *node,
                                         isis_adv_data_t *advt_data,
                                         isis_fragment_t *fragment,
                                         bool force) {

    glthread_t *curr;
    isis_advt_db_t *advt_db;
    pkt_size_t available_space;
    isis_node_info_t *node_info;
    isis_adv_data_t *old_advt_data;
    isis_advt_info_t advt_info_out;
    isis_advt_tlv_return_code_t rc;

    assert(!advt_data->fragment);
    assert (!IS_QUEUED_UP_IN_THREAD (&advt_data->glue));

    node_info = ISIS_NODE_INFO(node);
    
    advt_db = node_info->advt_db[fragment->pn_no];

    available_space = ISIS_LSP_MAX_PKT_SIZE - fragment->bytes_filled;

    if (available_space >= advt_data->tlv_size) {

        isis_fragment_bind_advt_data (node, fragment, advt_data);
        return true;
    }

    if (!force) return false;

    isis_fragment_prevent_premature_deletion (fragment);

    /* If available space is not sufficient, then move IS REACH TLVs Or IP REACH TLVs
        from this fragment to another fragment*/
    pkt_size_t required_space = advt_data->tlv_size - available_space;
    pkt_size_t size_freed = 0;

    remove_glthread(&fragment->priority_list_glue); // 0

    ITERATE_GLTHREAD_BEGIN(&fragment->tlv_list_head, curr) {

        old_advt_data = glue_to_isis_advt_data(curr);

        /* Dont remove TLVs which can be advertised only in this fragment*/
        if (fragment->pn_no == 0 && fragment->fr_no == 0 &&
            isis_is_zero_fragment_tlv(old_advt_data->tlv_no)) {
            continue;
        }

        isis_fragment_unbind_advt_data (node, fragment, advt_data);       

        size_freed += old_advt_data->tlv_size;

        isis_advertise_tlv(node,
                           fragment->pn_no, old_advt_data,
                           &advt_info_out);

        if (size_freed >= required_space) break;
    }
    ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr);

    if (size_freed < required_space) {

        isis_wait_list_advt_data_add(node, fragment->pn_no, advt_data);
        glthread_priority_insert(&advt_db->fragment_priority_list,
                                 &fragment->priority_list_glue,
                                 isis_fragment_size_comp_fn,
                                 (int)&((isis_fragment_t *)0)->priority_list_glue);
        isis_fragment_relieve_premature_deletion(node, fragment);
        return false;
    }

    isis_fragment_bind_advt_data (node, fragment, advt_data);

   glthread_priority_insert(&advt_db->fragment_priority_list,
                             &fragment->priority_list_glue,
                             isis_fragment_size_comp_fn,
                             (int)&((isis_fragment_t *)0)->priority_list_glue);

    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[isis_event_tlv_added]);
    isis_fragment_relieve_premature_deletion(node, fragment);
    return true;
}

static void
isis_insert_zero_fragment_tlvs (node_t *node) {

    isis_fragment_t *fragment0;
    isis_advt_info_t advt_info_out;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    isis_advt_db_t *advt_db = node_info->advt_db[0];

    fragment0 = advt_db->fragments[0];

    /* Insert zero fragment TLVs here i.e. TLVs which mandatorily goes in
        fragment zero . . . */
    isis_adv_data_t *advt_data = (isis_adv_data_t *)XCALLOC2(0, 1, isis_adv_data_t);
    advt_data->tlv_no = ISIS_TLV_HOSTNAME;
    strncpy (advt_data->u.host_name, node->node_name, NODE_NAME_SIZE);
    advt_data->tlv_size = isis_get_adv_data_size (advt_data);
    isis_advertise_advt_data_in_this_fragment (node, advt_data, fragment0, true);
}

void
isis_regen_zeroth_fragment (node_t *node) {

    glthread_t *curr;
    pkt_size_t advt_data_size;
    uint16_t advt_data_count;
    glthread_t advt_tlv_head;
    isis_fragment_t *fragment0;
    isis_adv_data_t *advt_data;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    isis_advt_db_t *advt_db = node_info->advt_db[0];
    init_glthread (&advt_tlv_head);

    if (!advt_db) {
        isis_create_advt_db (node_info, 0);
    }

    advt_db = node_info->advt_db[0];
    fragment0 = advt_db->fragments[0];
    advt_data_size = 0;
    advt_data_count = 0;

    if (fragment0) {
        if (fragment0->lsp_pkt) isis_fragment_dealloc_lsp_pkt (node, fragment0);
    }
    else {
        fragment0 = isis_alloc_new_fragment ();
        advt_db->fragments[0] = fragment0;
        isis_fragment_lock(fragment0);
        glthread_priority_insert(&advt_db->fragment_priority_list,
                             &fragment0->priority_list_glue,
                             isis_fragment_size_comp_fn,
                             (int)&((isis_fragment_t *)0)->priority_list_glue);
        isis_fragment_lock(fragment0);
    }

    if (isis_is_protocol_shutdown_in_progress (node)) {
        fragment0->regen_flags = ISIS_SHOULD_INCL_PURGE_BIT;
    }
    else {
        fragment0->regen_flags = ISIS_LSP_DEF_REGEN_FLAGS;
        if (isis_is_overloaded (node, NULL)) {
            fragment0->regen_flags |= ISIS_SHOULD_INCL_OL_BIT;
        }        
    }

    isis_insert_zero_fragment_tlvs (node);
    isis_schedule_regen_fragment (node, fragment0, isis_event_admin_config_changed);
}

void
isis_assert_check_all_advt_db_cleanedup (isis_node_info_t *node_info) {

    int i;

    for (i = 0; i < ISIS_MAX_PN_SUPPORTED; i++) {
        if (!node_info->advt_db[i]) continue;
        assert(0);
    }
}

uint32_t 
isis_fragment_print (node_t *node, isis_fragment_t *fragment, byte *buff) {

    uint32_t rc = 0;
    glthread_t *curr;
    char ipv6_addr_str[48];
    byte system_id_str[32];
    isis_adv_data_t *advt_data;

    rc += cprintf ("fragment : [%hu][%hu]  , seq_no : %u %p\n",
                fragment->pn_no, fragment->fr_no, fragment->seq_no, fragment);
                
    rc += cprintf ("  bytes filled : %hu, ref_count : %u   \n  lsp pkt bytes filled : %hu , ref_count : %u\n",
                fragment->bytes_filled, fragment->ref_count,
                (pkt_size_t)fragment->lsp_pkt->pkt_size, fragment->lsp_pkt->ref_count);

    rc += cprintf ("    TLVs:\n");

    ITERATE_GLTHREAD_BEGIN(&fragment->tlv_list_head, curr) {

        advt_data = glue_to_isis_advt_data (curr);
        rc += cprintf ("     TLV %hu (%huB)  flags:0x%x\n", 
            advt_data->tlv_no, advt_data->tlv_size, advt_data->flags);

        switch (advt_data->tlv_no) {
            case ISIS_IS_REACH_TLV:
                rc += cprintf ("       nbr sys id : %s\n", 
                            isis_system_id_tostring (&advt_data->u.adj_data.nbr_sys_id, system_id_str));
                rc +=  cprintf ("       metric : %u\n", advt_data->u.adj_data.metric);
                rc +=  cprintf ("       local ifindex : %u\n", advt_data->u.adj_data.local_ifindex);
                rc +=  cprintf ("       remote ifindex : %u\n", advt_data->u.adj_data.remote_ifindex);
                rc +=  cprintf ("       local ip : %s\n",
                             tcp_ip_covert_ip_n_to_p (advt_data->u.adj_data.local_intf_ip, system_id_str));
                rc +=  cprintf ("       remote ip : %s\n",
                             tcp_ip_covert_ip_n_to_p (advt_data->u.adj_data.remote_intf_ip, system_id_str)); 
                break;
            case ISIS_TLV_IP_REACH:
                rc += cprintf ("       Prefix : %s/%d   metric : %u\n",
                            tcp_ip_covert_ip_n_to_p (advt_data->u.pfx.prefix, system_id_str),
                advt_data->u.pfx.mask, advt_data->u.pfx.metric);
                break;
            case ISIS_TLV_IPV6_REACH:
            {
                char buffer[48];
                inet_ntop(AF_INET6, advt_data->u.v6pfx.prefix, buffer, 16);
                rc += cprintf ("       Prefix : %s/%d   metric : %u\n",
                    buffer, advt_data->u.v6pfx.mask, advt_data->u.v6pfx.metric);
            }
            break;
            case ISIS_TLV_HOSTNAME:
                rc += cprintf ("       Hostname : %s\n", advt_data->u.host_name);
            break;
            case ISIS_TLV_LOCATOR:
            {
                inet_ntop(AF_INET6, advt_data->u.srv6_loc.prefix.addr, ipv6_addr_str, 16);
                rc += cprintf ("       Locator : %s/%d  Metric : %u    Algorithm: %d   Flags : 0x%x  SubTLV len:%d\n",
                    ipv6_addr_str, advt_data->u.srv6_loc.prefix_len, 
                    advt_data->u.srv6_loc.metric, 
                    advt_data->u.srv6_loc.algorithm, 
                    advt_data->u.srv6_loc.flags,
                    advt_data->u.srv6_loc.subtlv_len);

                glthread_t *curr2;
                isis_adv_data_t *pfxsid_subtlv_advt_data;

                ITERATE_GLTHREAD_BEGIN(&advt_data->u.srv6_loc.pfxsid_list_head, curr2) {

                    pfxsid_subtlv_advt_data = srv6_pfxsid_sibling_glue_to_pfxsid_adv_data(curr2);
                    
                    inet_ntop(AF_INET6, pfxsid_subtlv_advt_data->u.srv6_pfxsid.prefix.addr,
                             ipv6_addr_str, 16);

                    rc += cprintf ("         SubTLV:%d  len:%d  Prefix-SID : %s  Endfn : %s    Flags : 0x%x\n",
                        pfxsid_subtlv_advt_data->tlv_no,
                        pfxsid_subtlv_advt_data->tlv_size,
                        ipv6_addr_str, 
                        srv6_end_fn_str( pfxsid_subtlv_advt_data->u.srv6_pfxsid.endfn),
                        pfxsid_subtlv_advt_data->u.srv6_pfxsid.flags);

                } ITERATE_GLTHREAD_END(&advt_data->u.srv6_loc.pfxsid_list_head, curr2);
            }
            break;
	    case ISIS_TLV_RTR_CAP:
                rc += cprintf("       Rtr ID : %s  Flags : 0x%x\n",
                    tcp_ip_covert_ip_n_to_p(advt_data->u.rtr_cap.rtr_cap.rtr_id, system_id_str),
                    advt_data->u.rtr_cap.rtr_cap.flags);

                if (advt_data->u.rtr_cap.is_rtr_cap_algo_subtlv19_present) {

                    rc += cprintf("         SubTLV%d  Algorithm Subtlv  len:%d\n", 
                                    advt_data->tlv_no,
                                    advt_data->u.rtr_cap.rtr_cap.rtr_cap_algorithm_subtlv19->length);

                    int n_algo = advt_data->u.rtr_cap.rtr_cap.rtr_cap_algorithm_subtlv19->length / 8;

                    for (int i = 0; i < n_algo; i++) {

                        rc += cprintf("          Algorithm : %d\n", 
                            advt_data->u.rtr_cap.rtr_cap_algorithm_subtlv19.algorithms[i]);
                    }
                }

                if (advt_data->u.rtr_cap.is_rtr_cap_srv6_subtlv2_present)
                {
                    isis_rtr_cap_srv6_subtlv2_t *srv6_subtlv = (isis_rtr_cap_srv6_subtlv2_t *)&advt_data->u.rtr_cap.rtr_cap_srv6_subtlv2;
                    rc += cprintf("\t  SubTLV%d  Algorithm Subtlv  len:%d\n", srv6_subtlv->type, srv6_subtlv->length);
                    rc += cprintf("\t    flags : 0x%x\n", srv6_subtlv->flags);
                    rc += cprintf("\t    Max # of SL in SRH supported by platform                : %d\n", srv6_subtlv->max_sl_msd);
                    rc += cprintf("\t    Max # of SIDs when applying PSP or USP flavors          : %d\n", srv6_subtlv->max_end_pop_srh_msd);
                    rc += cprintf("\t    Max # of T-INSERT SIDs supported by platform            : %d\n", srv6_subtlv->max_t_ins_srh_msd);
                    rc += cprintf("\t    Max # of T-ENCAP SIDs supported by platform             : %d\n", srv6_subtlv->max_t_encap_srh_msd);
                    rc += cprintf("\t    Max # of END.DX6 or END.DT6 SIDs supported by platform  : %d\n", srv6_subtlv->max_end_D_srh_msd);
                }

            break;
            default: 
                cprintf ("        Error : Unsupported TLV : %d\n", advt_data->tlv_no);
                break;
        }
    } ITERATE_GLTHREAD_END(&fragment->tlv_list_head, curr);

    return rc;
}

uint32_t 
isis_show_advt_db (node_t *node) {

    int i, j;
    uint32_t rc = 0;
    isis_advt_db_t *advt_db;
    isis_fragment_t *fragment;

    byte *buff = node->print_buff;
    
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return 0;

    for (i = 0; i < ISIS_MAX_PN_SUPPORTED; i++) {

        advt_db =      node_info->advt_db[i];
        if (!advt_db) continue;

        for (j = 0 ; j < ISIS_MAX_FRAGMENT_SUPPORTED; j++) {
            fragment = advt_db->fragments[j];
            if (!fragment) continue;
            rc += isis_fragment_print (node, fragment, buff + rc);
            rc += isis_show_one_lsp_pkt_detail_info (buff + rc, fragment->lsp_pkt);
        }
    }
    return rc;
}

/* This fn handles when lsp pkt do not reference back the fragment */
void
isis_fragment_dealloc_lsp_pkt (node_t *node, isis_fragment_t *fragment) {

    isis_lsp_pkt_t *lsp_pkt;

    if (!fragment->lsp_pkt) return;
    
    lsp_pkt = fragment->lsp_pkt;

    isis_fragment_prevent_premature_deletion (fragment);
    isis_lsp_pkt_prevent_premature_deletion(fragment->lsp_pkt);

    fragment->lsp_pkt = NULL;
    isis_deref_isis_pkt(node, lsp_pkt);
    isis_lsp_pkt_flood_timer_stop (lsp_pkt);
    isis_remove_lsp_pkt_from_lspdb(node, lsp_pkt);
    isis_ted_uninstall_lsp (node, ISIS_TED_DB(node), lsp_pkt);

    if (lsp_pkt->fragment == fragment) {
        lsp_pkt->fragment = NULL;
        isis_fragment_unlock(node, fragment);
    }

    isis_lsp_pkt_relieve_premature_deletion(node, lsp_pkt); 
    isis_fragment_relieve_premature_deletion (node, fragment);
}

void
isis_fragment_alloc_new_lsp_pkt (isis_fragment_t *fragment) {

    assert(!fragment->lsp_pkt);
    fragment->lsp_pkt = (isis_lsp_pkt_t *)XCALLOC2(0, 1, isis_lsp_pkt_t);
    isis_ref_isis_pkt(fragment->lsp_pkt);
    fragment->lsp_pkt->fragment = fragment;
    isis_fragment_lock(fragment);
    fragment->lsp_pkt->flood_eligibility = true;
    fragment->lsp_pkt->pkt = (byte *)tcp_ip_get_new_pkt_buffer(fragment->bytes_filled);
    fragment->lsp_pkt->alloc_size = fragment->bytes_filled;
    fragment->lsp_pkt->pkt_size = 0;
}

void
isis_fragment_lock (isis_fragment_t *fragment) {
    
    fragment->ref_count++;
}

uint32_t
isis_get_waitlisted_advt_data_count (node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    return node_info->isis_event_count [isis_event_tlv_wait_listed];
}

u_int8_t
isis_fragment_unlock (node_t *node, isis_fragment_t *fragment) {

    isis_node_info_t *node_info = ISIS_NODE_INFO (node);

    fragment->ref_count--;
    if (fragment->ref_count) return (fragment->ref_count);

    /* No Object Should hold a reference to this fragment. Let us examing
        one bye one 
    */
    assert(IS_GLTHREAD_LIST_EMPTY(&fragment->tlv_list_head));

    /* Fragment must not be Queued for regeneration */
    assert(!IS_QUEUED_UP_IN_THREAD(&fragment->frag_regen_glue));

    /*should not be pointed to by Advt_db */
    assert(!node_info->advt_db[fragment->pn_no]->fragments[fragment->fr_no]);

    /* Should be already dettached from priority list*/
    assert(!IS_QUEUED_UP_IN_THREAD(&fragment->priority_list_glue));

    /* Now release resources held by this fragment */
    if (fragment->lsp_pkt) {
        isis_deref_isis_pkt(node, fragment->lsp_pkt);
        fragment->lsp_pkt = NULL;
    }

    XFREE(fragment);
    return 0;
}

void
isis_regen_all_fragments_from_scratch (event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    int i;
    Interface *intf;
    glthread_t *curr;
    ipv6_addr_t v6_addr;
    isis_advt_db_t *advt_db;
    isis_adv_data_t *v6lo_advt;
    isis_advt_info_t advt_info;
    isis_adjacency_t *adjacency;

    node_t *node = (node_t *)arg;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    node_info->regen_all_fragment_task = NULL;

    if (isis_is_protocol_shutdown_in_progress (node)) return;

    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[ isis_event_full_lsp_regen]);
    
    SET_BIT (node_info->event_control_flags, ISIS_EVENT_FULL_LSP_REGEN_BIT);

    /* Cleanup all existing fragments and local LSP pkts*/
    for (i = 0; i < ISIS_MAX_PN_SUPPORTED; i++) {

        advt_db = node_info->advt_db[i];
        if (!advt_db) continue;
        isis_destroy_advt_db(node, i);
    }
    
    /* Now Regen all fragments by advertising all TLVs*/
    isis_regen_zeroth_fragment (node);
    
    /* Advertise IS REACH TLVs*/
    ITERATE_NODE_INTERFACES_BEGIN (node, intf) {

        if (!isis_node_intf_is_enable (intf)) continue;

        /* For P2P ineterface, simply advertise adjacency on a interface*/
        if (isis_intf_is_p2p(intf)) {

            ITERATE_GLTHREAD_BEGIN(ISIS_INTF_ADJ_LST_HEAD(intf), curr) {

                adjacency = glthread_to_isis_adjacency(curr);
                isis_adjacency_advertise_is_reach(adjacency);

            } ITERATE_GLTHREAD_END(ISIS_INTF_ADJ_LST_HEAD(intf), curr);

        } else {

            /* For LAN interface, Doing the DIS election will do all required advertisement
            for us i.e. advertise IS REACH info : self --> PN And if self is DIS, then advertise
            on behalf of PN also */
            isis_intf_resign_dis(intf);
            isis_intf_assign_new_dis (intf, isis_intf_reelect_dis(intf));
        }

    } ITERATE_NODE_INTERFACES_END (node, intf);

    /* Advertise v6loop back as  IPV6 REACH TLV*/
    assert (!node_info->tlv_global_advt.v6lo_adv_data_tlv236);
    if (!is_ipv6_addr_unspecified (&node->node_nw_prop.ipv6_rtr_id)) {
        memcpy (v6_addr.addr, node->node_nw_prop.ipv6_rtr_id, 16);
        v6lo_advt = isis_advertise_ipv6_reach (node, &v6_addr, 128, 0, 0);
        node_info->tlv_global_advt.v6lo_adv_data_tlv236 = v6lo_advt;
        v6lo_advt->src.holder = &node_info->tlv_global_advt.v6lo_adv_data_tlv236;
    }

    /* Advertise SRv6 Data*/
    if (isis_srv6_get_config(node)) {
        isis_srv6_locator_t *loc = ISIS_SRV6_LOC(node);
        isis_advertise_rtr_capability_tlv(node);
        isis_advertise_locator_ipv6_reachability_tlv236 (node, loc);
        isis_advertise_locator_ipv6_reachability_mt_tlv237(node, loc);
        isis_advertise_locator_tlv27_instance (node, loc, true);
        isis_srv6_advertise_all_prefix_sids (node);
    }

    /* Advertise IP REACH TLVs : Exported Routes*/
    if (node_info->export_policy) {
        isis_free_all_exported_rt_advt_data (node);
        nfc_ipv4_rt_request_flash (node, isis_ipv4_rt_notif_cbk);
    }

    UNSET_BIT64 (node_info->event_control_flags, ISIS_EVENT_FULL_LSP_REGEN_BIT);
   
    if (isis_get_waitlisted_advt_data_count (node)) return;
    if (!isis_is_overloaded (node, NULL)) return;

    UNSET_BIT64(node_info->event_control_flags, ISIS_EVENT_DEVICE_DYNAMIC_OVERLOAD_BIT);
    if (!IS_BIT_SET(node_info->event_control_flags, ISIS_EVENT_DEVICE_OVERLOAD_BY_ADMIN_BIT)) {
        isis_unset_overload(node, 0, CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD);
    }
}

isis_adv_data_t *
isis_advertise_ipv6_reach (node_t *node, 
                                ipv6_addr_t *ipv6_addr, 
                                uint8_t prefix_len, 
                                uint32_t metric, 
                                uint8_t flags) {

    isis_advt_info_t advt_info;

    isis_adv_data_t *adv_data = (isis_adv_data_t *)XCALLOC2(0, 1, isis_adv_data_t);
    adv_data->tlv_no = ISIS_TLV_IPV6_REACH;
    /* Fix: Copy from ipv6_addr->addr (the actual address data), not the pointer itself */
    memcpy (adv_data->u.v6pfx.prefix, ipv6_addr->addr, 16);
    adv_data->u.v6pfx.mask = prefix_len;
    adv_data->u.v6pfx.metric = metric;
    adv_data->u.v6pfx.flags = flags;
    init_glthread (&adv_data->glue);
    adv_data->tlv_size = isis_get_adv_data_size (adv_data);
    isis_advertise_tlv (node, 0, adv_data, &advt_info);
    return adv_data;
}
