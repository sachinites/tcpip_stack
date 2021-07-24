#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_pkt.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_events.h"

/* Checkig if protocol enable at node & intf level */
bool
isis_is_protocol_enable_on_node(node_t *node) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if (!isis_node_info || isis_node_info->is_shutting_down) {
        return false;
    }

    return true;
}

static void
isis_node_cancel_all_queued_jobs(node_t *node) {

    isis_cancel_lsp_pkt_generation_task(node);
}

static void
isis_node_cancel_all_timers(node_t *node){

}

void
isis_protocol_shut_down(node_t *node) {

    interface_t *intf;
    isis_intf_info_t *isis_intf_info;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if(!isis_node_info) return;

    isis_node_info->is_shutting_down = true;

    isis_node_cancel_all_queued_jobs(node);
    isis_node_cancel_all_timers(node);

    if(isis_node_info->isis_self_lsp_pkt){
        isis_deref_isis_pkt(isis_node_info->isis_self_lsp_pkt);
        isis_node_info->isis_self_lsp_pkt = NULL;
    }

    /* Queue All interfaces for Purge */
    ITERATE_NODE_INTERFACES_BEGIN(node, intf) { 

        isis_disable_protocol_on_interface(intf);

    } ITERATE_NODE_INTERFACES_END(node, intf);
    
    isis_check_delete_node_info(node);
}

static void
isis_free_node_info(node_t *node) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
    if(!isis_node_info) return;

    assert(!isis_node_info->isis_self_lsp_pkt);
    assert(!isis_node_info->isis_lsp_pkt_gen_task);
    assert(isis_node_info->is_shutting_down);
    assert(IS_GLTHREAD_LIST_EMPTY(&isis_node_info->purge_intf_list));

    free(isis_node_info);
    node->node_nw_prop.isis_node_info = NULL;
}

void
isis_check_delete_node_info(node_t *node) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
    if(!isis_node_info) return;

    if (isis_node_info->is_shutting_down == false) return;

    if (isis_node_info->isis_self_lsp_pkt) {
        return;
    }

    if (isis_node_info->isis_lsp_pkt_gen_task) {
        return;
    }

    if (!IS_GLTHREAD_LIST_EMPTY(&isis_node_info->purge_intf_list)) return;

    isis_free_node_info(node);
}

void
isis_show_node_protocol_state(node_t *node) {

    bool is_enabled ;
    interface_t *intf;

    is_enabled = isis_is_protocol_enable_on_node(node);

    printf("ISIS Protocol : %sabled\n", is_enabled ? "En" : "Dis");

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {    

        if (!isis_node_intf_is_enable(intf)) continue;
        isis_show_interface_protocol_state(intf);
    } ITERATE_NODE_INTERFACES_END(node, intf);
}

void
isis_init(node_t *node ) {

    size_t lsp_pkt_size = 0;

    if (isis_is_protocol_enable_on_node(node)) return;

    /* Register for interested pkts */
    tcp_stack_register_l2_pkt_trap_rule(
			node, isis_pkt_trap_rule, isis_pkt_recieve);

    isis_node_info_t *isis_node_info = calloc(1, sizeof(isis_node_info_t));
    node->node_nw_prop.isis_node_info = isis_node_info;
    init_glthread(&isis_node_info->purge_intf_list);
    isis_node_info->seq_no = 1;

    isis_schedule_lsp_pkt_generation(node, isis_event_protocol_enable);
}

void
isis_de_init(node_t *node) {

    if (!isis_is_protocol_enable_on_node(node)) return;

    /* De-Register for interested pkts */
    tcp_stack_de_register_l2_pkt_trap_rule(
			node, isis_pkt_trap_rule, isis_pkt_recieve);

    isis_protocol_shut_down(node);
}

void
isis_one_time_registration() {

    nfc_intf_register_for_events(isis_interface_updates);
    nfc_register_for_pkt_tracing(ISIS_ETH_PKT_TYPE, isis_print_pkt);
}

void
isis_schedule_job(node_t *node,
                  task_t **task,
                  event_cbk cbk,
                  void *data,
                  const char *job_name,
                  isis_events_t event_type) {

    if (*task) {
        printf("Node : %s : %s Already Scheduled. Reason : %s\n",
            node->node_name, job_name, isis_event(event_type));
        return;
    }
    
    if (!isis_is_protocol_enable_on_node(node)) {
        printf("Node : %s : Protocol not Enable. %s Will not be Scheduled."
                " Reason : %s\n", node->node_name, job_name,
                isis_event(event_type));
        return;
    }

    *task = task_create_new_job(data, cbk, TASK_ONE_SHOT);

    if(*task) {
        printf("Node : %s : %s Scheduled. Reason : %s\n",
            node->node_name, job_name, isis_event(event_type));        
    }
}
