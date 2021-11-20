#include "../../tcp_public.h"
#include "isis_const.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_lsdb.h"
#include "isis_flood.h"
#include "isis_adjacency.h"

static void
isis_timer_wrapper_lsp_flood(void *arg, uint32_t arg_size) {

    if (!arg) return;

    node_t *node = (node_t *)arg;

    isis_schedule_lsp_pkt_generation(node);
}

void
isis_start_lsp_pkt_periodic_flooding(node_t *node)  {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    if ( node_info->periodic_lsp_flood_timer)  return;

    node_info->periodic_lsp_flood_timer = 
        timer_register_app_event(node_get_timer_instance(node),
                            isis_timer_wrapper_lsp_flood,
                            (void *)node,
                            sizeof(node_t),
                            ISIS_LSP_DEFAULT_FLOOD_INTERVAL * 1000,
                            1);
}

void
isis_stop_lsp_pkt_periodic_flooding(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return;

    if (!node_info->periodic_lsp_flood_timer) return;

    timer_de_register_app_event(node_info->periodic_lsp_flood_timer);
    node_info->periodic_lsp_flood_timer = NULL;
}

static void
isis_lsp_xmit_job(void *arg, uint32_t arg_size) {

    glthread_t *curr;
    isis_intf_info_t *intf_info;
    isis_lsp_pkt_t *lsp_pkt;
    isis_lsp_xmit_elem_t *lsp_xmit_elem;
    interface_t *intf = (interface_t *)arg;

    intf_info = ISIS_INTF_INFO(intf);
    
    intf_info->lsp_xmit_job = NULL;

    if ( !isis_node_intf_is_enable(intf)) return;

    sprintf(tlb, "%s : lsp xmit job triggered\n", ISIS_LSPDB_TRACE);
    tcp_trace(intf->att_node, intf, tlb);

    ITERATE_GLTHREAD_BEGIN(&intf_info->lsp_xmit_list_head, curr) {

        lsp_xmit_elem = glue_to_lsp_xmit_elem(curr);
        remove_glthread(&lsp_xmit_elem->glue);
        lsp_pkt = lsp_xmit_elem->lsp_pkt;
        free(lsp_xmit_elem);
       
        send_pkt_out(lsp_pkt->pkt, lsp_pkt->pkt_size, intf);
        ISIS_INTF_INCREMENT_STATS(intf, lsp_pkt_sent);
        isis_deref_isis_pkt(lsp_pkt);

    } ITERATE_GLTHREAD_END(&intf_info->lsp_xmit_list_head, curr);
}

void
isis_queue_lsp_pkt_for_transmission(interface_t *intf, isis_lsp_pkt_t *lsp_pkt) {

    isis_node_info_t *node_info;
    isis_intf_info_t *intf_info;

    if (!isis_node_intf_is_enable(intf)) return;

    intf_info = ISIS_INTF_INFO (intf);

     if (!(intf_info->adjacency &&
            intf_info->adjacency->adj_state == ISIS_ADJ_STATE_UP)) {
                return;
    }

    isis_lsp_xmit_elem_t *lsp_xmit_elem = calloc(1, sizeof(isis_lsp_xmit_elem_t));

    init_glthread(&lsp_xmit_elem->glue);
    lsp_xmit_elem->lsp_pkt = lsp_pkt;
    isis_ref_isis_pkt(lsp_xmit_elem->lsp_pkt);
    glthread_add_last (&intf_info->lsp_xmit_list_head, &lsp_xmit_elem->glue);

    sprintf(tlb, "%s : LSP %s scheduled to flood out of %s\n",
            ISIS_LSPDB_TRACE, isis_print_lsp_id(lsp_pkt),
            intf->if_name);
    tcp_trace(intf->att_node, intf, tlb);

    if ( ! intf_info->lsp_xmit_job) {
        intf_info->lsp_xmit_job = task_create_new_job(intf, isis_lsp_xmit_job, TASK_ONE_SHOT);
    }
}

void
isis_schedule_lsp_flood (node_t *node, isis_lsp_pkt_t *lsp_pkt, interface_t *exempt_iif) {

    interface_t *intf;
    isis_intf_info_t *intf_info;

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

            if ( !isis_node_intf_is_enable(intf)) continue;

            if (intf == exempt_iif) continue;

            intf_info = ISIS_INTF_INFO(intf);

             if (!(intf_info->adjacency &&
                     intf_info->adjacency->adj_state == ISIS_ADJ_STATE_UP)) {
                continue;
             }

             sprintf(tlb, "%s : LSP %s scheduled for flood out of intf %s\n",
                     ISIS_LSPDB_TRACE, isis_print_lsp_id(lsp_pkt), intf->if_name);

            isis_queue_lsp_pkt_for_transmission(intf, lsp_pkt);

    } ITERATE_NODE_INTERFACES_END(node, intf);
}

void
isis_intf_purge_lsp_xmit_queue(interface_t *intf)  {

    glthread_t *curr;
    isis_lsp_pkt_t *lsp_pkt;
    isis_intf_info_t *intf_info;
    isis_lsp_xmit_elem_t *lsp_xmit_elem;

    if ( !isis_node_intf_is_enable(intf)) return;

    intf_info = ISIS_INTF_INFO(intf);

    ITERATE_GLTHREAD_BEGIN(&intf_info->lsp_xmit_list_head, curr) {

            lsp_xmit_elem = glue_to_lsp_xmit_elem(curr);
            remove_glthread(curr);
            lsp_pkt = lsp_xmit_elem->lsp_pkt;
            free(lsp_xmit_elem);
            isis_deref_isis_pkt(lsp_pkt);
    } ITERATE_GLTHREAD_END(&intf_info->lsp_xmit_list_head, curr) ;

    if (intf_info->lsp_xmit_job) {
        task_cancel_job(intf_info->lsp_xmit_job);
        intf_info->lsp_xmit_job = NULL;
    }
}

void
isis_flood_lsp_synchronously (node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    interface_t *intf;
    isis_intf_info_t *intf_info ;

    ITERATE_NODE_INTERFACES_BEGIN (node, intf) {

        if (!isis_node_intf_is_enable((intf))) continue;

        intf_info = ISIS_INTF_INFO(intf);
        
        if (intf_info->adjacency &&
             intf_info->adjacency->adj_state == ISIS_ADJ_STATE_UP) {

                send_pkt_out (lsp_pkt->pkt, lsp_pkt->pkt_size, intf);
        }

    } ITERATE_NODE_INTERFACES_END (node, intf);
} 

void
isis_create_and_flood_purge_lsp_pkt_synchronously (node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if (!node_info) return;
    SET_BIT(node_info->lsp_gen_flags, ISIS_LSP_PKT_CREATE_PURGE_LSP);
    isis_create_fresh_lsp_pkt(node);
    UNSET_BIT8(node_info->lsp_gen_flags, ISIS_LSP_PKT_CREATE_PURGE_LSP);
    isis_flood_lsp_synchronously(node, node_info->self_lsp_pkt);
}