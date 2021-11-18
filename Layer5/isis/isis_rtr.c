#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_pkt.h"
#include "isis_const.h"
#include "isis_lsdb.h"
#include "isis_flood.h"

bool
isis_is_protocol_enable_on_node(node_t *node) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
    if (!isis_node_info) {

        return false;
    }
    return true;
}

static int
isis_compare_lsdb_lsp_pkt (const avltree_node_t *n1, const avltree_node_t *n2) {

    isis_lsp_pkt_t *lsp_pkt1 = avltree_container_of(n1, isis_lsp_pkt_t, avl_node_glue);
    isis_lsp_pkt_t *lsp_pkt2 = avltree_container_of(n2, isis_lsp_pkt_t, avl_node_glue);

    uint32_t *rtr_id1 = isis_get_lsp_pkt_rtr_id(lsp_pkt1);
    uint32_t *rtr_id2 = isis_get_lsp_pkt_rtr_id(lsp_pkt2);

    if (*rtr_id1 < *rtr_id2) return -1;
    if (*rtr_id1 > *rtr_id2) return 1;
    return 0;
}

void
 isis_init (node_t *node) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node); 

    if (isis_node_info) return;

    isis_node_info = calloc(1, sizeof(isis_node_info_t));
    node->node_nw_prop.isis_node_info = isis_node_info;
    isis_node_info->seq_no = 0;
    isis_node_info->lsp_lifetime_interval = ISIS_LSP_DEFAULT_LIFE_TIME_INTERVAL;
    avltree_init(&isis_node_info->lspdb_avl_root, isis_compare_lsdb_lsp_pkt);
    tcp_stack_register_l2_pkt_trap_rule(node, 
            isis_pkt_trap_rule, isis_pkt_receive);
    isis_schedule_lsp_pkt_generation(node);
    isis_start_lsp_pkt_periodic_flooding(node);
 }

static void
isis_check_delete_node_info(node_t *node) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if ( !isis_node_info ) return;

    /* Place Assert checks here */
    assert(isis_node_info->lsp_pkt_gen_task == NULL);
    assert(isis_node_info->periodic_lsp_flood_timer == NULL);
    
    free(isis_node_info);
    node->node_nw_prop.isis_node_info = NULL;
}

static void
isis_node_cancel_all_queued_jobs (node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (node_info->lsp_pkt_gen_task) {
        task_cancel_job(node_info->lsp_pkt_gen_task);
        node_info->lsp_pkt_gen_task = NULL;
    }
}

void
 isis_de_init (node_t *node) {

     interface_t *intf;
     isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node); 

    if (!isis_node_info) return;

    isis_create_and_flood_purge_lsp_pkt_synchronously(node);
    
    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

            isis_disable_protocol_on_interface(intf);
            
    } ITERATE_NODE_INTERFACES_END(node, intf);

    if (isis_node_info->self_lsp_pkt) {
        isis_deref_isis_pkt(isis_node_info->self_lsp_pkt);
    }
    isis_cleanup_lsdb(node);
    isis_free_dummy_lsp_pkt();
    isis_node_cancel_all_queued_jobs(node);
    isis_stop_lsp_pkt_periodic_flooding(node);
    isis_check_delete_node_info(node);
    node->node_nw_prop.isis_node_info = NULL;

     tcp_stack_de_register_l2_pkt_trap_rule(node, 
            isis_pkt_trap_rule, isis_pkt_receive);
 }

 void
 isis_show_node_protocol_state(node_t *node) {

     interface_t *intf;
    isis_node_info_t *isis_node_info;

     printf("ISIS Protocol : %s\n", 
        isis_is_protocol_enable_on_node(node) ? "Enable" : "Disable");

    if (!isis_is_protocol_enable_on_node(node) ) return;

    isis_node_info =  ISIS_NODE_INFO(node);
    
    printf("Adjacency up Count: %u\n", isis_node_info->adj_up_count);

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {    

        if (!isis_node_intf_is_enable(intf)) continue;
        isis_show_interface_protocol_state(intf);
    } ITERATE_NODE_INTERFACES_END(node, intf);
 }

 void
isis_one_time_registration() {
    nfc_intf_register_for_events(isis_interface_updates);
    nfc_register_for_pkt_tracing (ISIS_ETH_PKT_TYPE, isis_print_pkt);
}
