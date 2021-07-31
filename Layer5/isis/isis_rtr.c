#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_pkt.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_events.h"
#include "isis_flood.h"
#include "isis_lspdb.h"

extern void isis_free_dummy_lsp_pkt(void);

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

    isis_stop_lsp_pkt_periodic_flooding(node);
    isis_stop_reconciliation_timer(node);
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
    isis_free_dummy_lsp_pkt();

    if(isis_node_info->isis_self_lsp_pkt){
        isis_deref_isis_pkt(isis_node_info->isis_self_lsp_pkt);
        isis_node_info->isis_self_lsp_pkt = NULL;
    }

    isis_cleanup_lsdb(node);

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

#if 0
    if (isis_node_info->isis_self_lsp_pkt) {
        return;
    }

    if (isis_node_info->isis_lsp_pkt_gen_task) {
        return;
    }

    if (!IS_GLTHREAD_LIST_EMPTY(&isis_node_info->purge_intf_list)) return;
#endif
    isis_free_node_info(node);
}

void
isis_show_node_protocol_state(node_t *node) {

    bool is_enabled ;
    interface_t *intf;
    isis_node_info_t *isis_node_info;
    is_enabled = isis_is_protocol_enable_on_node(node);

    printf("ISIS Protocol : %sabled\n", is_enabled ? "En" : "Dis");

    if(!is_enabled) return;

    isis_node_info = ISIS_NODE_INFO(node);

    printf("LSP flood count : %u\n", isis_node_info->lsp_flood_count);
    printf("SPF runs : %u\n", isis_node_info->spf_runs);
    printf("Seq # : %u\n", isis_node_info->seq_no);
    printf("adjacencu up : %u\n", isis_node_info->adjacency_up_count);

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {    

        if (!isis_node_intf_is_enable(intf)) continue;
        isis_show_interface_protocol_state(intf);
    } ITERATE_NODE_INTERFACES_END(node, intf);
    
    ISIS_INCREMENT_NODE_STATS(node,
            isis_event_count[isis_event_protocol_disable]);
}

static int
isis_compare_lspdb_lsp_pkt(const avltree_node_t *n1, const avltree_node_t *n2) {

    isis_pkt_t *lsp_pkt1 = avltree_container_of(n1, isis_pkt_t, avl_node_glue);
    isis_pkt_t *lsp_pkt2 = avltree_container_of(n2, isis_pkt_t, avl_node_glue);

    uint32_t *rtr_id1 = isis_get_lsp_pkt_rtr_id(lsp_pkt1);
    uint32_t *rtr_id2 = isis_get_lsp_pkt_rtr_id(lsp_pkt2);

    if (*rtr_id1 < *rtr_id2) return -1;
    if (*rtr_id1 > *rtr_id2) return 1;
    return 0;
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
    isis_node_info->seq_no = 0;
    isis_node_info->lsp_flood_interval    = ISIS_LSP_DEFAULT_FLOOD_INTERVAL;
    isis_node_info->lsp_lifetime_interval = ISIS_LSP_DEFAULT_LIFE_TIME_INTERVAL;
    avltree_init(&isis_node_info->lspdb_avl_root, isis_compare_lspdb_lsp_pkt);
    isis_node_info->on_demand_flooding    = ISIS_DEFAULT_ON_DEMAND_FLOODING_STATUS;

    isis_start_lsp_pkt_periodic_flooding(node);

    ISIS_INCREMENT_NODE_STATS(node,
            isis_event_count[isis_event_protocol_enable]);

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
                  isis_event_type_t event_type) {

    if (*task) {
        printf("Node : %s : %s Already Scheduled. Reason : %s\n",
            node->node_name, job_name, isis_event_str(event_type));
        return;
    }
    
    if (!isis_is_protocol_enable_on_node(node)) {
        printf("Node : %s : Protocol not Enable. %s Will not be Scheduled."
                " Reason : %s\n", node->node_name, job_name,
                isis_event_str(event_type));
        return;
    }

    *task = task_create_new_job(data, cbk, TASK_ONE_SHOT);

    if(*task) {
        printf("Node : %s : %s Scheduled. Reason : %s\n",
            node->node_name, job_name, isis_event_str(event_type));        
    }
}

void
isis_show_event_counters(node_t *node) {

    isis_event_type_t event_type;

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) return;

    printf("Event Counters :\n");
    for(event_type = isis_event_none + 1; 
        event_type < isis_event_max;
        event_type++){
        
        printf(" %s : %u\n", isis_event_str(event_type), 
                isis_node_info->isis_event_count[event_type]);
    }
}

void
isis_proto_enable_disable_on_demand_flooding(
        node_t *node,
        bool enable) {

    avltree_t *lsdb;
    avltree_node_t *curr;
    isis_pkt_t *lsp_pkt;
    isis_node_info_t *isis_node_info;

    isis_node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) return;
    lsdb = isis_get_lspdb_root(node);

    if (enable) {
        if (isis_node_info->on_demand_flooding) return;
            isis_node_info->on_demand_flooding = true;
            isis_stop_lsp_pkt_periodic_flooding(node);
            ITERATE_AVL_TREE_BEGIN(lsdb, curr) {

                lsp_pkt = avltree_container_of(curr, isis_pkt_t, avl_node_glue);
                isis_stop_lsp_pkt_installation_timer(lsp_pkt);
            } ITERATE_AVL_TREE_END;
    }
    else {
        if (!isis_node_info->on_demand_flooding) return;
        isis_node_info->on_demand_flooding = false;
        isis_start_lsp_pkt_periodic_flooding(node);
        ITERATE_AVL_TREE_BEGIN(lsdb, curr) {

                lsp_pkt = avltree_container_of(curr, isis_pkt_t, avl_node_glue);
                isis_start_lsp_pkt_installation_timer(node, lsp_pkt);
        } ITERATE_AVL_TREE_END;
    }
}
