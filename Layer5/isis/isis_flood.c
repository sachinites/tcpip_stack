#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_events.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_flood.h"
#include "isis_adjacency.h"
#include "isis_lspdb.h"

extern void
isis_parse_lsp_tlvs_internal(isis_pkt_t *new_lsp_pkt, 
                             bool *on_demand_tlv);

typedef struct isis_lsp_xmit_elem_ {

    isis_pkt_t *lsp_pkt;
    glthread_t glue;
} isis_lsp_xmit_elem_t;
GLTHREAD_TO_STRUCT(glue_to_lsp_xmit_elem, 
    isis_lsp_xmit_elem_t, glue);


static void
isis_assign_lsp_src_mac_addr(interface_t *intf,
                             isis_pkt_t *lsp_pkt) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)(lsp_pkt->pkt);
    memcpy(eth_hdr->src_mac.mac, IF_MAC(intf), sizeof(mac_add_t));                           
}

void
isis_lsp_pkt_flood_complete(node_t *node, isis_pkt_t *lsp_pkt ){

    assert(!lsp_pkt->flood_queue_count);
}

void
isis_mark_isis_lsp_pkt_flood_ineligible(
        node_t *node, isis_pkt_t *lsp_pkt) {

    lsp_pkt->flood_eligibility = false;
}


static void
isis_check_xmit_lsp_sanity_before_transmission(
        node_t *node,
        isis_pkt_t *lsp_pkt) {

    bool on_demand_tlv_present; 
    isis_node_info_t *isis_node_info;

    isis_node_info = ISIS_NODE_INFO(node);

    on_demand_tlv_present = false;

    isis_parse_lsp_tlvs_internal(lsp_pkt, &on_demand_tlv_present);

    if (isis_is_reconciliation_in_progress(node) &&
            isis_our_lsp(node, lsp_pkt)) {
        
        assert(on_demand_tlv_present);
    }
}

static void
isis_lsp_xmit_job(void *arg, uint32_t arg_size) {

    glthread_t *curr;
    interface_t *intf;
    isis_pkt_t *lsp_pkt;
    bool has_up_adjacency;
    isis_lsp_xmit_elem_t *lsp_xmit_elem;
    
    intf = (interface_t *)arg;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(intf->att_node);
    isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(intf);

    isis_intf_info->lsp_xmit_job = NULL;

    sprintf(tlb, "%s : lsp xmit job triggered\n", ISIS_LSPDB_MGMT);
    tcp_trace(intf->att_node, intf, tlb);

    if (!isis_node_intf_is_enable(intf)) return;

    has_up_adjacency = isis_any_adjacency_up_on_interface(intf);

    ITERATE_GLTHREAD_BEGIN(&isis_intf_info->lsp_xmit_list_head, curr) {

        lsp_xmit_elem = glue_to_lsp_xmit_elem(curr);
        remove_glthread(curr);
        lsp_pkt = lsp_xmit_elem->lsp_pkt;
        assert(lsp_pkt->flood_queue_count);
        lsp_pkt->flood_queue_count--;
        isis_node_info->pending_lsp_flood_count--;
        
        free(lsp_xmit_elem);
        
        if (has_up_adjacency && lsp_pkt->flood_eligibility){
    
            isis_assign_lsp_src_mac_addr(intf, lsp_pkt);
            send_pkt_out(lsp_pkt->pkt, lsp_pkt->pkt_size, intf);
            ISIS_INCREMENT_STATS(intf, lsp_pkt_sent);

            sprintf(tlb, "%s : LSP %s pushed out of interface %s\n",
                ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt), intf->if_name);
            tcp_trace(intf->att_node, intf, tlb);
        } else {
            sprintf(tlb, "%s : LSP %s discarded from output flood Queue of interface %s\n",
                ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt), intf->if_name);
            tcp_trace(intf->att_node, intf, tlb);
        }

        if (!lsp_pkt->flood_queue_count) {
            isis_lsp_pkt_flood_complete(intf->att_node, lsp_pkt);
        }

        isis_deref_isis_pkt(lsp_pkt);

    } ITERATE_GLTHREAD_END(&isis_intf_info->lsp_xmit_list_head, curr);

    if (isis_node_info->pending_lsp_flood_count ==0) {
        
        isis_check_and_shutdown_protocol_now(intf->att_node,
            ISIS_PRO_SHUTDOWN_GEN_PURGE_LSP_WORK);
    }

}

void
isis_queue_lsp_pkt_for_transmission(
        interface_t *intf,
        isis_pkt_t *lsp_pkt) {

    isis_node_info_t *isis_node_info;
    isis_intf_info_t *isis_intf_info;
    
    if (!isis_node_intf_is_enable(intf)) return;

    if (!lsp_pkt->flood_eligibility) return;

    isis_intf_info = ISIS_INTF_INFO(intf);
    isis_node_info = ISIS_NODE_INFO(intf->att_node);

    isis_lsp_xmit_elem_t *lsp_xmit_elem =
        calloc(1, sizeof(isis_lsp_xmit_elem_t));
    
    init_glthread(&lsp_xmit_elem->glue);
    lsp_xmit_elem->lsp_pkt = lsp_pkt;
    isis_ref_isis_pkt(lsp_pkt);

    glthread_add_last(&isis_intf_info->lsp_xmit_list_head,
                      &lsp_xmit_elem->glue);

    sprintf(tlb, "%s : LSP %s scheduled to flood out of %s\n",
            ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt),
            intf->if_name);
    tcp_trace(intf->att_node, intf, tlb);

    lsp_pkt->flood_queue_count++;
    isis_node_info->pending_lsp_flood_count++;

    if (!isis_intf_info->lsp_xmit_job) {

        isis_intf_info->lsp_xmit_job =
            task_create_new_job(intf, isis_lsp_xmit_job, TASK_ONE_SHOT);
    }
}

void
isis_intf_purge_lsp_xmit_queue(interface_t *intf) {

    glthread_t *curr;
    isis_pkt_t *lsp_pkt;
    isis_intf_info_t *isis_intf_info;
    isis_lsp_xmit_elem_t *lsp_xmit_elem;

    if (!isis_node_intf_is_enable(intf)) return;
    
    isis_intf_info = ISIS_INTF_INFO(intf);

    ITERATE_GLTHREAD_BEGIN(&isis_intf_info->lsp_xmit_list_head, curr) {

        lsp_xmit_elem = glue_to_lsp_xmit_elem(curr);
        remove_glthread(curr);
        lsp_pkt = lsp_xmit_elem->lsp_pkt;
        free(lsp_xmit_elem);
        lsp_pkt->flood_queue_count--;
        isis_deref_isis_pkt(lsp_pkt);

    } ITERATE_GLTHREAD_END(&isis_intf_info->lsp_xmit_list_head, curr);

    if (isis_intf_info->lsp_xmit_job) {
        task_cancel_job(isis_intf_info->lsp_xmit_job);
        isis_intf_info->lsp_xmit_job = NULL;
    }
}

void
isis_schedule_lsp_flood(node_t *node, 
                        isis_pkt_t *lsp_pkt,
                        interface_t *exempt_iif,
                        isis_event_type_t event_type) {

    interface_t *intf;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if (!lsp_pkt->flood_eligibility) return;

    sprintf(tlb, "%s : LSP %s scheduled for flood\n",
        ISIS_LSPDB_MGMT, isis_print_lsp_id(lsp_pkt));
    tcp_trace(node, exempt_iif, tlb);

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if (!isis_node_intf_is_enable(intf) ||
                intf == exempt_iif) continue;

        isis_queue_lsp_pkt_for_transmission(intf, lsp_pkt);

    } ITERATE_NODE_INTERFACES_END(node, intf);

    ISIS_INCREMENT_NODE_STATS(node, lsp_flood_count);
}

void
isis_update_lsp_flood_timer_with_new_lsp_pkt(
        node_t *node,
        isis_pkt_t *new_lsp_pkt) { /* Could be NULL */

    isis_pkt_t *old_lsp_pkt;
    isis_timer_data_t *old_isis_timer_data = NULL;
    isis_timer_data_t *new_isis_timer_data = NULL;
    
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
    
    timer_event_handle *wt_elem = isis_node_info->periodic_lsp_flood_timer;

    if(!wt_elem) return;

    old_isis_timer_data = wt_elem_get_and_set_app_data(wt_elem, 0);

    /* case 1 : */
    if (!old_isis_timer_data && !new_lsp_pkt) goto done;

    /* case 2 : */
    else if (!old_isis_timer_data && new_lsp_pkt) {

        new_isis_timer_data =
            calloc(1, sizeof(isis_timer_data_t));

        new_isis_timer_data->node = node;
        new_isis_timer_data->intf = NULL;
        new_isis_timer_data->data = (char *)new_lsp_pkt;
        isis_ref_isis_pkt(new_lsp_pkt);
        new_isis_timer_data->data_size = sizeof(isis_pkt_t);
        wt_elem_get_and_set_app_data(wt_elem, new_isis_timer_data);
        goto done;
    }

    /* case 3 : */
    else if (old_isis_timer_data && !new_lsp_pkt) {

        isis_deref_isis_pkt((isis_pkt_t *)old_isis_timer_data->data);
        free(old_isis_timer_data);
        assert(0);
        goto done;
    }

    /* case 4 : Both are non null*/
    else {

        isis_deref_isis_pkt((isis_pkt_t *)old_isis_timer_data->data);
        isis_ref_isis_pkt(new_lsp_pkt);
        old_isis_timer_data->data = (char *)new_lsp_pkt;
        wt_elem_get_and_set_app_data(wt_elem, old_isis_timer_data);
        goto done;
    }

    done:
        ;
}

static void
isis_timer_wrapper_lsp_flood(void *arg, uint32_t arg_size) {

    if (!arg) return;
    
    isis_timer_data_t *isis_timer_data = 
        (isis_timer_data_t *)arg;

    ISIS_INCREMENT_NODE_STATS((isis_timer_data->node), seq_no);

    uint32_t *seq_no = isis_get_lsp_pkt_seq_no(
                        (isis_pkt_t *)isis_timer_data->data);
    
    *seq_no = (ISIS_NODE_INFO(isis_timer_data->node))->seq_no;

    isis_schedule_lsp_pkt_generation(
            isis_timer_data->node,
            isis_event_periodic_lsp_generation);
}

void
isis_start_lsp_pkt_periodic_flooding(node_t *node) {

    wheel_timer_t *wt;
    isis_pkt_t *self_lsp_pkt;
    isis_node_info_t *isis_node_info;

    wt = node_get_timer_instance(node);
    isis_node_info = ISIS_NODE_INFO(node);
    self_lsp_pkt = isis_node_info->self_lsp_pkt;

    isis_timer_data_t *isis_timer_data = NULL;

    /* Even if there is no LSP pkt to flood, start the
        timer any way */
    if (isis_node_info->self_lsp_pkt) {
        
        isis_timer_data = calloc(1, sizeof(isis_timer_data_t));
        isis_timer_data->node = node;
        isis_timer_data->intf = NULL;
        isis_timer_data->data =
            (char *)(isis_node_info->self_lsp_pkt);
        isis_ref_isis_pkt(isis_node_info->self_lsp_pkt);
        isis_timer_data->data_size = sizeof(isis_pkt_t);
    }
       
    isis_node_info->periodic_lsp_flood_timer = 
                timer_register_app_event(wt,
                isis_timer_wrapper_lsp_flood,
                (void *)isis_timer_data,
                isis_timer_data ? sizeof(isis_timer_data_t) : 0,
                isis_node_info->lsp_flood_interval * 1000,
                1);
}

void
isis_stop_lsp_pkt_periodic_flooding(node_t *node){

    isis_timer_data_t *isis_timer_data = NULL;
    timer_event_handle *periodic_lsp_flood_timer;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    periodic_lsp_flood_timer = isis_node_info->periodic_lsp_flood_timer;

    if (!periodic_lsp_flood_timer) return;

    isis_timer_data = wt_elem_get_and_set_app_data(
                            periodic_lsp_flood_timer, 0);

    timer_de_register_app_event(periodic_lsp_flood_timer);

    if (isis_timer_data) {

        isis_deref_isis_pkt((isis_pkt_t *)isis_timer_data->data);
        free(isis_timer_data);
    }
    
    isis_node_info->periodic_lsp_flood_timer = NULL;
}

/* Reconciliation APIs */
bool
isis_is_reconciliation_in_progress(node_t *node) {

    isis_reconc_data_t *recon;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return false;
    }
    
    recon = &isis_node_info->reconc;
    return recon->reconciliation_in_progress;
}

void
isis_enter_reconciliation_phase(node_t *node) {

    isis_reconc_data_t *recon;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return;
    }

    if (!isis_node_info->on_demand_flooding) return;

    recon = &isis_node_info->reconc;

    if (recon->reconciliation_in_progress) return;

    recon->reconciliation_in_progress = true;

    timer_reschedule(isis_node_info->periodic_lsp_flood_timer,
                      ISIS_DEFAULT_RECONCILIATION_FLOOD_INTERVAL);

    isis_start_reconciliation_timer(node);
    isis_schedule_lsp_pkt_generation(node, isis_event_reconciliation_triggered);

    ISIS_INCREMENT_NODE_STATS(node,
        isis_event_count[isis_event_reconciliation_triggered]);
}

void
isis_exit_reconciliation_phase(node_t *node) {

    isis_reconc_data_t *recon;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return;
    }

    recon = &isis_node_info->reconc;

    if (!recon->reconciliation_in_progress) return;

    recon->reconciliation_in_progress = false;

    timer_reschedule(isis_node_info->periodic_lsp_flood_timer,
                      isis_node_info->lsp_flood_interval * 1000);

    isis_stop_reconciliation_timer(node);
    isis_schedule_lsp_pkt_generation(node, isis_event_reconciliation_exit);

    ISIS_INCREMENT_NODE_STATS(node,
        isis_event_count[isis_event_reconciliation_exit]);
}

void
isis_restart_reconciliation_timer(node_t *node) {

    isis_reconc_data_t *recon;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return;
    }
    
    recon = &isis_node_info->reconc;

    if (!recon->reconciliation_in_progress) return;

    assert(recon->reconciliation_timer);

    timer_reschedule(recon->reconciliation_timer,
                     ISIS_DEFAULT_RECONCILIATION_THRESHOLD_TIME);

    ISIS_INCREMENT_NODE_STATS(node,
        isis_event_count[isis_event_reconciliation_restarted]);
}

static void
isis_timer_wrapper_exit_reconciliation_phase(
        void *arg, uint32_t arg_size) {

    if (!arg) return;

    node_t *node = (node_t *)arg;

    isis_exit_reconciliation_phase(node);
}

void
isis_start_reconciliation_timer(node_t *node) {

    isis_reconc_data_t *recon;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return;
    }
    
    recon = &isis_node_info->reconc;

    assert(recon->reconciliation_in_progress); 

    if(recon->reconciliation_timer) return;

    recon->reconciliation_timer = timer_register_app_event(
                                    node_get_timer_instance(node),
                                    isis_timer_wrapper_exit_reconciliation_phase,
                                    (void *)node, sizeof(node),
                                    ISIS_DEFAULT_RECONCILIATION_THRESHOLD_TIME,
                                    0);

}

void
isis_stop_reconciliation_timer(node_t *node) {

    isis_reconc_data_t *recon;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return;
    }

    recon = &isis_node_info->reconc;

    if(!recon->reconciliation_timer) return;

    timer_de_register_app_event(recon->reconciliation_timer);
    recon->reconciliation_timer = NULL;
}
