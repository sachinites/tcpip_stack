#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_events.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_flood.h"
#include "isis_adjacency.h"
#include "isis_lspdb.h"
#include "isis_intf_group.h"
#include "isis_spf.h"

extern void
isis_parse_lsp_tlvs_internal(isis_lsp_pkt_t *new_lsp_pkt, 
                             bool *on_demand_tlv);

static void
isis_assign_lsp_src_mac_addr(Interface *intf,
                             isis_lsp_pkt_t *lsp_pkt) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)(lsp_pkt->pkt);
    memcpy(eth_hdr->src_mac.mac, IF_MAC(intf), sizeof(mac_addr_t));
}

void
isis_lsp_pkt_flood_complete(node_t *node, isis_lsp_pkt_t *lsp_pkt ){

    assert(!lsp_pkt->flood_queue_count);
    
    /* If this is purge pkt, dessociate it with fragment because fragment leaked object now*/
    isis_pkt_hdr_t *lsp_pkt_hdr = 
        (isis_pkt_hdr_t *)GET_ETHERNET_HDR_PAYLOAD((ethernet_hdr_t *)lsp_pkt->pkt);

    if (IS_BIT_SET (lsp_pkt_hdr->flags, ISIS_LSP_PKT_F_PURGE_BIT)) {
        if (lsp_pkt->fragment) { // remove this check later
            isis_fragment_dealloc_lsp_pkt (ISIS_NODE_INFO(node), lsp_pkt->fragment);
        }
        if (isis_is_lsp_pkt_installed_in_lspdb (lsp_pkt)) {
            isis_remove_lsp_pkt_from_lspdb(node, lsp_pkt);
        }
    }

}

void
isis_mark_isis_lsp_pkt_flood_ineligible(
        node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    lsp_pkt->flood_eligibility = false;
}


static void
isis_check_xmit_lsp_sanity_before_transmission(
        node_t *node,
        isis_lsp_pkt_t *lsp_pkt) {

    bool on_demand_tlv_present; 
    isis_node_info_t *node_info;

    node_info = ISIS_NODE_INFO(node);

    on_demand_tlv_present = false;

    isis_parse_lsp_tlvs_internal(lsp_pkt, &on_demand_tlv_present);

    if (isis_is_reconciliation_in_progress(node) &&
            isis_our_lsp(node, lsp_pkt)) {
        
        assert(on_demand_tlv_present);
    }
}

static void
isis_lsp_xmit_job(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    glthread_t *curr;
    Interface *intf;
    pkt_block_t *pkt_block;
    isis_lsp_pkt_t *lsp_pkt;
    bool has_up_adjacency;
    isis_lsp_xmit_elem_t *lsp_xmit_elem;
    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];
    
    intf = (Interface *)arg;
    isis_node_info_t *node_info = ISIS_NODE_INFO(intf->att_node);
    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);

    intf_info->lsp_xmit_job = NULL;

    sprintf(tlb, "%s : lsp xmit job triggered\n", ISIS_LSPDB_MGMT);
    tcp_trace(intf->att_node, intf, tlb);

    if (!isis_node_intf_is_enable(intf)) return;

    has_up_adjacency = isis_any_adjacency_up_on_interface(intf);

    pkt_block = pkt_block_get_new(NULL, 0);

    ITERATE_GLTHREAD_BEGIN(&intf_info->lsp_xmit_list_head, curr) {

        lsp_xmit_elem = glue_to_lsp_xmit_elem(curr);
        remove_glthread(curr);
        lsp_pkt = lsp_xmit_elem->lsp_pkt;
        assert(lsp_pkt->flood_queue_count);       
        XFREE(lsp_xmit_elem);
        
        if (has_up_adjacency && lsp_pkt->flood_eligibility){
    
            isis_assign_lsp_src_mac_addr(intf, lsp_pkt);
            pkt_block_set_new_pkt(pkt_block, (uint8_t *)lsp_pkt->pkt, lsp_pkt->pkt_size);
            pkt_block_set_starting_hdr_type(pkt_block, ETH_HDR);
            intf->SendPacketOut(pkt_block);
            ISIS_INTF_INCREMENT_STATS(intf, lsp_pkt_sent);

            sprintf(tlb, "%s : LSP %s pushed out of interface %s\n",
                ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt, lsp_id_str), intf->if_name.c_str());
            tcp_trace(intf->att_node, intf, tlb);
        } else {
            sprintf(tlb, "%s : LSP %s discarded from output flood Queue of interface %s\n",
                ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt, lsp_id_str), intf->if_name.c_str());
            tcp_trace(intf->att_node, intf, tlb);
        }

        lsp_pkt->flood_queue_count--;
        node_info->pending_lsp_flood_count--;

        if (!lsp_pkt->flood_queue_count) {
            isis_lsp_pkt_flood_complete(intf->att_node, lsp_pkt);
        }

        isis_deref_isis_pkt(node_info, lsp_pkt);

    } ITERATE_GLTHREAD_END(&intf_info->lsp_xmit_list_head, curr);

    /* If there are no more LSPs to be pushed out for flooding, and
        we are shutting down and no more LSP generation is scheduled,
        then, check and delete protocol configuration
    */
    if ( node_info->pending_lsp_flood_count ==0                &&
         isis_is_protocol_shutdown_in_progress(intf->att_node)   &&
         !node_info->lsp_pkt_gen_task                                    &&
        IS_BIT_SET (node_info->misc_flags, ISIS_F_DISABLE_LSP_GEN)) {
        
        isis_check_and_shutdown_protocol_now(intf->att_node,
            ISIS_PRO_SHUTDOWN_GEN_PURGE_LSP_WORK);
    }
    XFREE(pkt_block);
}

void
isis_queue_lsp_pkt_for_transmission(
        Interface *intf,
        isis_lsp_pkt_t *lsp_pkt) {

    isis_node_info_t *node_info;
    isis_intf_info_t *intf_info;
    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];

    if (!isis_node_intf_is_enable(intf)) return;

    if (!lsp_pkt->flood_eligibility) return;

    intf_info = ISIS_INTF_INFO(intf);
    node_info = ISIS_NODE_INFO(intf->att_node);

    isis_lsp_xmit_elem_t *lsp_xmit_elem =
        XCALLOC(0, 1, isis_lsp_xmit_elem_t);
    
    init_glthread(&lsp_xmit_elem->glue);
    lsp_xmit_elem->lsp_pkt = lsp_pkt;
    isis_ref_isis_pkt(lsp_pkt);

    glthread_add_last(&intf_info->lsp_xmit_list_head,
                      &lsp_xmit_elem->glue);

    sprintf(tlb, "%s : LSP %s scheduled to flood out of %s\n",
            ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt, lsp_id_str),
            intf->if_name.c_str());
    tcp_trace(intf->att_node, intf, tlb);

    lsp_pkt->flood_queue_count++;
    node_info->pending_lsp_flood_count++;

    if (!intf_info->lsp_xmit_job) {

       intf_info->lsp_xmit_job =
            task_create_new_job(EV(intf->att_node), 
                    intf, isis_lsp_xmit_job, TASK_ONE_SHOT,
                    TASK_PRIORITY_COMPUTE);
    }
}


void
isis_intf_purge_lsp_xmit_queue(Interface *intf) {

    glthread_t *curr;
    isis_lsp_pkt_t *lsp_pkt;
    isis_intf_info_t *intf_info;
    isis_lsp_xmit_elem_t *lsp_xmit_elem;

    if (!isis_node_intf_is_enable(intf)) return;
    
    intf_info = ISIS_INTF_INFO(intf);

    ITERATE_GLTHREAD_BEGIN(&intf_info->lsp_xmit_list_head, curr) {

        lsp_xmit_elem = glue_to_lsp_xmit_elem(curr);
        remove_glthread(curr);
        lsp_pkt = lsp_xmit_elem->lsp_pkt;
        XFREE(lsp_xmit_elem);
        lsp_pkt->flood_queue_count--;
        isis_deref_isis_pkt(ISIS_NODE_INFO(intf->att_node), lsp_pkt);

    } ITERATE_GLTHREAD_END(&intf_info->lsp_xmit_list_head, curr);

    if (intf_info->lsp_xmit_job) {
        task_cancel_job(EV(intf->att_node), intf_info->lsp_xmit_job);
        intf_info->lsp_xmit_job = NULL;
    }
}

void
isis_schedule_lsp_flood(node_t *node, 
                        isis_lsp_pkt_t *lsp_pkt,
                        Interface *exempt_iif) {

    Interface *intf;
    glthread_t *curr;
    avltree_node_t *avl_node;
    bool is_lsp_queued = false;
    isis_intf_group_t *intf_grp;
    isis_node_info_t *node_info;
    byte lsp_id_str[ISIS_LSP_ID_STR_SIZE];

    node_info  = ISIS_NODE_INFO(node);

    if (!lsp_pkt->flood_eligibility) return;

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if (!isis_node_intf_is_enable(intf)) continue;

        if (intf == exempt_iif) {
            sprintf(tlb, "%s : LSP %s flood skip out of intf %s, Reason :reciepient intf\n",
                        ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt, lsp_id_str), intf->if_name.c_str());
            tcp_trace(node, 0, tlb);
            continue;
        }

        if (ISIS_INTF_INFO(intf)->intf_grp) continue;

        sprintf(tlb, "%s : LSP %s scheduled for flood out of intf %s\n",
            ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt, lsp_id_str), intf->if_name.c_str());
        tcp_trace(node, 0, tlb);
        isis_queue_lsp_pkt_for_transmission(intf, lsp_pkt);
        is_lsp_queued = true;

    } ITERATE_NODE_INTERFACES_END(node, intf);

    /* Now iterate over all interface grps */
    ITERATE_AVL_TREE_BEGIN(&node_info->intf_grp_avl_root, avl_node) {

        intf_grp = avltree_container_of(avl_node, isis_intf_group_t, avl_glue);

        if (exempt_iif && ISIS_INTF_INFO(exempt_iif)->intf_grp == intf_grp) { 
        
            sprintf(tlb, "%s : LSP %s flood skip out of intf %s, Reason : reciepient intf grp %s\n",
                        ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt, lsp_id_str), exempt_iif->if_name.c_str(),
                        ISIS_INTF_INFO(exempt_iif)->intf_grp->name);
            tcp_trace(node, 0, tlb);
            continue;
        }
        
        intf = isis_intf_grp_get_first_active_intf_grp_member(node, intf_grp);
        if (!intf || !isis_any_adjacency_up_on_interface(intf)) continue;
        
        sprintf(tlb, "%s : LSP %s scheduled for flood out of intf %s intf-grp %s\n",
                    ISIS_LSPDB_MGMT,
                    isis_print_lsp_id(lsp_pkt, lsp_id_str),
                    intf->if_name.c_str(),
                    ISIS_INTF_INFO(intf)->intf_grp ? ISIS_INTF_INFO(intf)->intf_grp->name : "None");
        tcp_trace(node, 0, tlb);
        isis_queue_lsp_pkt_for_transmission(intf, lsp_pkt);
        is_lsp_queued = true;

    }  ITERATE_AVL_TREE_END;

    if (is_lsp_queued) {
        ISIS_INCREMENT_NODE_STATS(node, lsp_flood_count);
    }
}

/* Reconciliation APIs */
bool
isis_is_reconciliation_in_progress(node_t *node) {

    isis_reconc_data_t *recon;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return false;
    }
    
    recon = &node_info->reconc;
    return recon->reconciliation_in_progress;
}

static void
isis_lsp_pkt_flood_cbk (node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    isis_schedule_lsp_flood (node, lsp_pkt, NULL);
}

void
isis_enter_reconciliation_phase(node_t *node) {

    isis_reconc_data_t *recon;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return;
    }

    if (!node_info->on_demand_flooding) return;
    recon = &node_info->reconc;
    if (recon->reconciliation_in_progress) return;
    isis_cancel_spf_job(node) ;
    
    recon->reconciliation_in_progress = true;

    isis_start_reconciliation_timer(node);
    isis_walk_all_self_lsp_pkt (node, isis_lsp_pkt_flood_cbk);

    ISIS_INCREMENT_NODE_STATS(node,
        isis_event_count[isis_event_reconciliation_triggered]);
}

void
isis_exit_reconciliation_phase(node_t *node) {

    isis_reconc_data_t *recon;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return;
    }

    recon = &node_info->reconc;

    if (!recon->reconciliation_in_progress) return;

    recon->reconciliation_in_progress = false;

    isis_stop_reconciliation_timer(node);
    isis_schedule_lsp_pkt_generation(node, isis_event_reconciliation_exit);
    
    isis_schedule_spf_job(node, isis_event_reconciliation_exit);

    ISIS_INCREMENT_NODE_STATS(node,
        isis_event_count[isis_event_reconciliation_exit]);
}

void
isis_restart_reconciliation_timer(node_t *node) {

    isis_reconc_data_t *recon;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return;
    }
    
    recon = &node_info->reconc;

    if (!recon->reconciliation_in_progress) return;

    assert(recon->reconciliation_timer);

    timer_reschedule(recon->reconciliation_timer,
                     ISIS_DEFAULT_RECONCILIATION_THRESHOLD_TIME);

    ISIS_INCREMENT_NODE_STATS(node,
        isis_event_count[isis_event_reconciliation_restarted]);
}

static void
isis_timer_wrapper_exit_reconciliation_phase(
        event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    if (!arg) return;

    node_t *node = (node_t *)arg;

    isis_exit_reconciliation_phase(node);
}

void
isis_start_reconciliation_timer(node_t *node) {

    isis_reconc_data_t *recon;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return;
    }
    
    recon = &node_info->reconc;

    assert(recon->reconciliation_in_progress); 

    if(recon->reconciliation_timer) return;

    recon->reconciliation_timer = timer_register_app_event(
                                    CP_TIMER(node),
                                    isis_timer_wrapper_exit_reconciliation_phase,
                                    (void *)node, sizeof(node),
                                    ISIS_DEFAULT_RECONCILIATION_THRESHOLD_TIME,
                                    0);
}

void
isis_stop_reconciliation_timer(node_t *node) {

    isis_reconc_data_t *recon;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return;
    }

    recon = &node_info->reconc;

    if(!recon->reconciliation_timer) return;

    timer_de_register_app_event(recon->reconciliation_timer);
    recon->reconciliation_timer = NULL;
}

void
isis_walk_all_self_lsp_pkt (node_t *node, void (*fn_ptr)(node_t *, isis_lsp_pkt_t *)) {


}