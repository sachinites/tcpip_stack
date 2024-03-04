#include <errno.h>
#include <unistd.h>
#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_pkt.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_events.h"
#include "isis_flood.h"
#include "isis_lspdb.h"
#include "isis_spf.h"
#include "isis_cmdcodes.h"
#include "isis_intf_group.h"
#include "isis_layer2map.h"
#include "isis_ted.h"
#include "isis_policy.h"
#include "isis_advt.h"

extern void isis_mem_init();
void isis_ipv4_rt_notif_cbk (
        event_dispatcher_t *ev_dis,
        void *rt_notif_data, unsigned int arg_size);

/* Checking if protocol enable at node & intf level */
bool
isis_is_protocol_enable_on_node(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info ) {
        return false;
    }

    return true;
}

static void
isis_node_cancel_all_queued_jobs(node_t *node) {

    isis_cancel_spf_job(node);
    isis_cancel_lsp_fragment_regen_job(node);
    isis_cancel_all_fragment_regen_job (node);
}

static void
isis_node_cancel_all_timers(node_t *node){

    isis_stop_overload_timer(node);
}

static void
isis_free_node_info(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    XFREE(node_info);
    node->node_nw_prop.isis_node_info = NULL;
    cprintf ("%s: ISIS Protocol successfully shutdown\n", node->node_name);
}

static void
isis_check_delete_node_info(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if ( !node_info ) return;

    /* Scheduled jobs */
    assert (!node_info->lsp_fragment_gen_task);
    assert (!node_info->regen_all_fragment_task);
    assert (!node_info->spf_job_task);

    /*Hooked up Data Structures should be empty */
    assert (avltree_is_empty(&node_info->intf_grp_avl_root));
    assert(!node_info->ted_db);
    assert(!node_info->exported_routes.root);
    assert (!node_info->isis_event_count [isis_event_tlv_wait_listed]);

    /* Must not be any pending LSP for regeneration*/
    assert (IS_GLTHREAD_LIST_EMPTY (&node_info->pending_lsp_gen_queue));
    isis_assert_check_all_advt_db_cleanedup(node_info);

    /* Timers */
    assert (!node_info->ovl_data.ovl_timer);

    /* Should not have any pending work to do */
    assert (!node_info->shutdown_pending_work_flags);
    /* ensure tracing objects is cleaned up*/
    assert (!node_info->tr);
    isis_free_node_info (node);
}

static void
isis_protocol_shutdown_now (node_t *node) {

    Interface *intf;

    isis_intf_grp_cleanup(node);
    isis_node_cancel_all_queued_jobs(node);
    isis_node_cancel_all_timers(node);
    isis_free_dummy_lsp_pkt(node);
    isis_cleanup_spf_logc(node);
    isis_unconfig_import_policy(node, NULL);
    isis_unconfig_export_policy(node, NULL);

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) { 
        isis_disable_protocol_on_interface(intf);
    } ITERATE_NODE_INTERFACES_END(node, intf);
    
    /* Destroy all Major DBs in the end*/
    isis_destroy_advt_db(node, 0);
    /* This should be No-Op, buts lets do*/
    isis_cleanup_lsdb(node, true);
    /*This would cleanup fake nodes, if any*/
    isis_cleanup_teddb (node);
    tracer_deinit (ISIS_NODE_INFO(node)->tr);
    ISIS_NODE_INFO(node)->tr = NULL;
    isis_check_delete_node_info(node); 
}

void
isis_check_and_shutdown_protocol_now(
        node_t *node, 
        uint16_t work_completed_flag) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if(!node_info) return;

    if (!isis_is_protocol_admin_shutdown(node)) return;

    /* Flag must be set */
    assert (node_info->shutdown_pending_work_flags & 
                work_completed_flag);
    
    /* clean the bit*/
    UNSET_BIT16(node_info->shutdown_pending_work_flags,
                                    work_completed_flag);

    if (isis_is_protocol_shutdown_in_progress(node)) return;

    isis_protocol_shutdown_now(node);
}

bool
isis_is_protocol_shutdown_in_progress(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info) return false;

    if (IS_BIT_SET(node_info->shutdown_pending_work_flags ,
                            ISIS_PRO_SHUTDOWN_ALL_PENDING_WORK)) {
        return true;
    }

    return false;
}

bool
isis_is_protocol_admin_shutdown(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if ( !node_info ) return false;

    if ( IS_BIT_SET(node_info->event_control_flags,
                ISIS_EVENT_ADMIN_ACTION_SHUTDOWN_PENDING_BIT)) {

        return true;
    }
    return false;
}

static void
isis_schedule_route_delete_task(node_t *node,
        isis_event_type_t event_type){

    clear_rt_table(NODE_RT_TABLE(node), PROTO_ISIS);

    isis_check_and_shutdown_protocol_now(node,
            ISIS_PRO_SHUTDOWN_DEL_ROUTES_WORK);
}

static void
isis_launch_prior_shutdown_tasks(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    node_info->shutdown_pending_work_flags = 0;

    /* Set the flags to track what work needs to be done before we die out */
    if (node_info->adjacency_up_count) {

        trace (ISIS_TR(node), TR_ISIS_EVENTS, 
            "%s : Generating Pre-shutdown work - Purging Zero LSPs\n", node->node_name);

        SET_BIT(node_info->shutdown_pending_work_flags,
                            ISIS_PRO_SHUTDOWN_GEN_PURGE_LSP_WORK);

        isis_walk_all_self_zero_lsps (node, isis_schedule_purge_lsp_flood_cbk);
    }
    
    if (isis_has_routes(node)) {

        trace (ISIS_TR(node), TR_ISIS_EVENTS, 
            "%s : Generating Pre-shutdown work - Route deletion\n", node->node_name);

        SET_BIT(node_info->shutdown_pending_work_flags,
                            ISIS_PRO_SHUTDOWN_DEL_ROUTES_WORK);
        
        isis_schedule_route_delete_task(node,
                isis_event_admin_action_shutdown_pending);
    }
}

bool
isis_is_protocol_shutdown_pending_work_completed (node_t *node) {

    if (isis_is_protocol_admin_shutdown(node) &&
            !isis_is_protocol_shutdown_in_progress(node)) {

        return true;
    }

    return false;
}

void
isis_protocol_shut_down(node_t *node) {

    Interface *intf;
    isis_intf_info_t *intf_info;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if(!node_info) return;

    if (isis_is_protocol_shutdown_in_progress(node)) {
        cprintf("Protocol Busy shutting down... Please Wait.\n");
        return;
    }

    if (isis_is_protocol_admin_shutdown(node)){
        cprintf("Protocol Already In ShutDown State\n");
        return;
    }
      
    SET_BIT( node_info->event_control_flags, 
        ISIS_EVENT_ADMIN_ACTION_SHUTDOWN_PENDING_BIT);

    isis_launch_prior_shutdown_tasks(node);
}

void
isis_show_node_protocol_state(node_t *node) {

    bool is_enabled ;
    Interface *intf;
    isis_node_info_t *node_info;
    is_enabled = isis_is_protocol_enable_on_node(node);

    cprintf("ISIS Protocol : %sabled\n", is_enabled ? "En" : "Dis");

    if(!is_enabled) return;

    node_info = ISIS_NODE_INFO(node);

    cprintf("LSP flood count : %u\n", node_info->lsp_flood_count);
    cprintf("SPF runs : %u\n", node_info->spf_runs);
    cprintf("Adjacency up Count: %u\n", node_info->adjacency_up_count);

    if (node_info->import_policy) {
        cprintf("Import Policy : %s\n", node_info->import_policy->name);
    }
    if (node_info->export_policy) {
        cprintf("Export Policy : %s\n", node_info->export_policy->name);
    }

    cprintf("Overload Status : %s   ", node_info->ovl_data.ovl_status ? "On" : "Off");
    if (node_info->ovl_data.ovl_status &&
            node_info->ovl_data.ovl_timer) {
        cprintf("Timer : %usec left\n", wt_get_remaining_time(node_info->ovl_data.ovl_timer)/1000);
    }
    else {
        cprintf("Timer : Not Running\n");
    }

    cprintf("Layer2-Mapping : %sabled\n", isis_is_layer2_mapping_enabled(node) ? "En" : "Dis");

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {    

        if (!isis_node_intf_is_enable(intf)) continue;
        isis_show_interface_protocol_state(intf);
    } ITERATE_NODE_INTERFACES_END(node, intf);
    
    ISIS_INCREMENT_NODE_STATS(node,
            isis_event_count[isis_event_admin_config_changed]);
}

static int
isis_compare_lspdb_lsp_pkt(const avltree_node_t *n1, const avltree_node_t *n2) {

    isis_lsp_pkt_t *lsp_pkt1 = avltree_container_of(n1, isis_lsp_pkt_t, avl_node_glue);
    isis_lsp_pkt_t *lsp_pkt2 = avltree_container_of(n2, isis_lsp_pkt_t, avl_node_glue);

    uint32_t *rtr_id1 = isis_get_lsp_pkt_rtr_id(lsp_pkt1);
    uint32_t *rtr_id2 = isis_get_lsp_pkt_rtr_id(lsp_pkt2);

    if (*rtr_id1 < *rtr_id2) return CMP_PREFERRED;
    if (*rtr_id1 > *rtr_id2) return CMP_NOT_PREFERRED;

    pn_id_t pn1 = isis_get_lsp_pkt_pn_id(lsp_pkt1);
    pn_id_t pn2 = isis_get_lsp_pkt_pn_id(lsp_pkt2);

    if (pn1 < pn2) return CMP_PREFERRED;
    if (pn1 > pn2) return CMP_NOT_PREFERRED;

    uint8_t fr1 = isis_get_lsp_pkt_fr_no (lsp_pkt1);
    uint8_t fr2 = isis_get_lsp_pkt_fr_no (lsp_pkt2);

    if (fr1 < fr2) return CMP_PREFERRED;
    if (fr1 > fr2) return CMP_NOT_PREFERRED;

    return CMP_PREF_EQUAL;
}

void
isis_de_init(node_t *node) {

    if (!isis_is_protocol_enable_on_node(node)) return;

    /* De-Register for interested pkts */
    tcp_stack_de_register_l2_pkt_trap_rule(
			node, isis_lsp_pkt_trap_rule, isis_lsp_pkt_recieve_cbk);
    tcp_stack_register_l2_pkt_trap_rule(
			node, isis_hello_pkt_trap_rule, isis_hello_pkt_recieve_cbk);

    nfc_ipv4_rt_un_subscribe(node, isis_ipv4_rt_notif_cbk);
    isis_protocol_shut_down(node);
}

void
isis_init (node_t *node ) {

    char log_file_name[NODE_NAME_SIZE + 16] = {0};
     if (isis_is_protocol_enable_on_node(node)) return;

    /* Register for interested pkts */
    tcp_stack_register_l2_pkt_trap_rule(
			node, isis_lsp_pkt_trap_rule, isis_lsp_pkt_recieve_cbk);
    tcp_stack_register_l2_pkt_trap_rule(
			node, isis_hello_pkt_trap_rule, isis_hello_pkt_recieve_cbk);

    isis_node_info_t *node_info = XCALLOC(0, 1, isis_node_info_t);
    node->node_nw_prop.isis_node_info = node_info;
    node_info->sys_id = {NODE_LO_ADDR_INT(node), 0};
    node_info->lsp_flood_interval    = ISIS_LSP_DEFAULT_FLOOD_INTERVAL;
    node_info->lsp_lifetime_interval = ISIS_LSP_DEFAULT_LIFE_TIME_INTERVAL;
    avltree_init(&node_info->lspdb_avl_root, isis_compare_lspdb_lsp_pkt);
    isis_init_intf_group_avl_tree(&node_info->intf_grp_avl_root);
    node_info->dyn_intf_grp = true;  /* True By Default */
    node_info->layer2_mapping = true;   /* True By Default */
    node_info->ted_db = XCALLOC(0, 1, ted_db_t);
    ted_init_teddb(node_info->ted_db, NULL, isis_spf_cleanup_spf_data);
    nfc_ipv4_rt_subscribe(node, isis_ipv4_rt_notif_cbk);
    isis_init_spf_logc(node);
    init_mtrie(&node_info->exported_routes, 32, NULL);
    isis_create_advt_db(node_info, 0);
    init_glthread (&node_info->pending_lsp_gen_queue);
    snprintf (log_file_name, sizeof (log_file_name), "logs/%s-isis-log.txt", node->node_name);
    node_info->tr = tracer_init ("isis", log_file_name, node->node_name, STDOUT_FILENO, 0);
    isis_regen_zeroth_fragment(node);
    ISIS_INCREMENT_NODE_STATS(node,
            isis_event_count[isis_event_admin_config_changed]);
    node_info->lsdb_advt_block = false;
}

void
isis_one_time_registration() {

    nfc_intf_register_for_events(isis_interface_updates);
    nfc_register_for_pkt_tracing(ISIS_LSP_ETH_PKT_TYPE, isis_print_lsp_pkt_cbk);
    nfc_register_for_pkt_tracing(ISIS_HELLO_ETH_PKT_TYPE, isis_print_hello_pkt_cbk);
}

void
isis_schedule_job(node_t *node,
                  task_t **task,
                  event_cbk cbk,
                  void *data,
                  const char *job_name,
                  isis_event_type_t event_type) {

    if (*task) {
        trace (ISIS_TR(node), TR_ISIS_SPF, "%s Already Scheduled. Reason : %s\n",
            job_name, isis_event_str(event_type));
        return;
    }
    
    if (!isis_is_protocol_enable_on_node(node)) {
        trace (ISIS_TR(node), TR_ISIS_SPF, "Protocol not Enable. %s Will not be Scheduled."
                " Reason : %s\n", job_name, isis_event_str(event_type));
        return;
    }

    *task = task_create_new_job(EV(node), data, cbk, TASK_ONE_SHOT, TASK_PRIORITY_COMPUTE);

    if(*task) {
        trace (ISIS_TR(node), TR_ISIS_SPF, "%s Scheduled. Reason : %s\n",
            job_name, isis_event_str(event_type));        
    }
}

void
isis_show_event_counters(node_t *node) {

    int rc = 0;
    int enum_int;
    isis_event_type_t event_type;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) return;

    cprintf ("\nEvent Counters :\n");

    for(enum_int = (int)(isis_event_none + 1); 
        enum_int < (int)isis_event_max;
        enum_int++){
        
        event_type = static_cast <isis_event_type_t> (enum_int);

        cprintf (" %s : %u\n", isis_event_str(event_type), 
                node_info->isis_event_count[event_type]);
    }
}

bool
isis_is_overloaded (node_t *node, bool *ovl_timer_running) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    
    if (ovl_timer_running) *ovl_timer_running = false;

    if  (!isis_is_protocol_enable_on_node(node)) return false;

    if  (node_info->ovl_data.ovl_timer && ovl_timer_running) {
        *ovl_timer_running = true;
    }

    return node_info->ovl_data.ovl_status;
}

static void
isis_overload_timer_expire(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    node_t *node = (node_t *)arg;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    isis_overload_data_t *ovl_data = &node_info->ovl_data;

    timer_de_register_app_event(ovl_data->ovl_timer);
    ovl_data->ovl_timer = NULL;
    ovl_data->timeout_val = 0;

    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[isis_event_overload_timeout]);

    if (IS_BIT_SET (node_info->event_control_flags, 
        ISIS_EVENT_DEVICE_DYNAMIC_OVERLOAD_BIT)) {
        return;
    }

    ovl_data->ovl_status = false;
    isis_regen_zeroth_fragment (node);
}

static void
isis_start_overload_timer(node_t *node, uint32_t timeout_val) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    isis_overload_data_t *ovl_data = &node_info->ovl_data;

    if (ovl_data->ovl_timer) return;

    ovl_data->ovl_timer = timer_register_app_event(CP_TIMER(node),
                                            isis_overload_timer_expire,
                                            (void *)node, 
                                            sizeof(node_t),
                                            timeout_val * 1000, 0);
}

void
isis_stop_overload_timer(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if ( !isis_is_protocol_enable_on_node(node)) {
        return;
    }

    isis_overload_data_t *ovl_data = &node_info->ovl_data;

    if (!ovl_data->ovl_timer) return;

    timer_de_register_app_event(ovl_data->ovl_timer);
    ovl_data->ovl_timer = NULL;
}

int
isis_set_overload (node_t *node, uint32_t timeout_val, int cmdcode) {

    int rc = 0;
    bool regen_lsp = false;
    isis_overload_data_t *ovl_data;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        cprintf( ISIS_ERROR_PROTO_NOT_ENABLE "\n");  
        return -1;
    }

    ovl_data = &node_info->ovl_data;

    if (!ovl_data->ovl_status) {
        ovl_data->ovl_status = true;
        regen_lsp = true;

        rc = 0;
    }

    /* case 1 : user has fired : ...isis overload
            case 1.1 : timer is not running -> no action on timer
            case 1.2 : timer is running -> no action on timer
    */

   /* case 1: ser has fired : ...isis overload */
   if (cmdcode ==
            CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD) {

            if (ovl_data->ovl_timer) {
                /* case 1.1 : : timer is not running -> no action on timer */
            }
            else {
                /* case 1.2 : timer is running -> no action on timer*/
            }
        goto done;
   }

   /* case 2 : user has fired : ...isis overload timeout <value>
            case 2.1 : timer is not running
                case 2.1.1 : <value is non-zero> -> trigger the timer
                case 2.1.2 : <value is zero> -> no action on timer
            case 2.2 : timer is running
                case 2.1.1 : <value is non-zero>
                    case 2.1.1.1 : timeout val is not changed -> no action on timer
                    case 2.1.1.2 : timeout val is changed -> reschedule timer
                case 2.1.2 : <value is zero> -> switch off the timer
    */

   /* case 2 : user has fired : ...isis overload timeout <value> */
   if (cmdcode ==
            CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD_TIMEOUT) {

        if (!ovl_data->ovl_timer) {
            /* case 2.1 : timer is not running */
            if (timeout_val) {
                /* case 2.1.1 : <value is non-zero> -> trigger the timer */
                ovl_data->timeout_val = timeout_val;
                isis_start_overload_timer(node, timeout_val);
                rc = 0;                                    
            }
            else {
                /* case 2.1.2 : <value is zero> -> no action on timer */
            }
        }
        else {
            /* case 2.2 : timer is running*/
                if (timeout_val) {
                     /*case 2.1.1 : <value is non-zero> */
                     if (timeout_val == ovl_data->timeout_val) {
                         /* case 2.1.1.1 : timeout val is not changed -> no action on timer */
                     }
                     else {
                         /* case 2.1.1.2 : timeout val is changed -> reschedule timer */
                         ovl_data->timeout_val = timeout_val;
                         timer_reschedule(ovl_data->ovl_timer, timeout_val * 1000);
                         rc = 0;
                     }
                }
                else {
                    /* case 2.1.2 : <value is zero> -> switch off the timer */
                    isis_stop_overload_timer(node);
                    rc  = 0;
                }
        }
     }

     done:
        if (regen_lsp) {
            isis_fragment_t *fragment0 = node_info->advt_db[0]->fragments[0];
            fragment0->regen_flags = ISIS_SHOULD_INCL_OL_BIT | ISIS_LSP_DEF_REGEN_FLAGS;
            isis_schedule_regen_fragment (node, fragment0, isis_event_device_overload_config);
            return 0;
        }
        
        return rc;
}

int
isis_unset_overload(node_t *node, uint32_t timeout_val, int cmdcode) {
    
    bool regen_lsp = false;
    isis_overload_data_t *ovl_data;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) return -1;

    ovl_data = &node_info->ovl_data;

    if (cmdcode == CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD) {

        /* user triggered : ...no protocol isis overload */
        if (!ovl_data->ovl_status)  return -1;

        ovl_data->ovl_status = false;
        regen_lsp = true;

        if (ovl_data->ovl_timer) {
            isis_stop_overload_timer(node);
        }
        goto done;
    }

    if (cmdcode == CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD_TIMEOUT) {

         /* user triggered : ...no protocol isis overload timeout <value >*/

         if (!ovl_data->ovl_timer) {
             goto done;
         }

         isis_stop_overload_timer(node);
    }

    done:

        if (regen_lsp) {
            isis_fragment_t *fragment0 = node_info->advt_db[0]->fragments[0];
            fragment0->regen_flags &= ~ISIS_SHOULD_INCL_OL_BIT;            
            isis_schedule_regen_fragment (node, fragment0, isis_event_device_overload_config);
            return 0;
        }

        return -1;
}

bool
isis_has_routes(node_t *node) {

    return true;
}

extern void
 isis_process_ipv4_route_notif (node_t *node, l3_route_t *l3route) ;
 
void
isis_ipv4_rt_notif_cbk (
        event_dispatcher_t *ev_dis,
        void *rt_notif_data, unsigned int arg_size) {

    node_t *node;
    l3_route_t *l3route;

    rt_route_notif_data_t *route_notif_data = 
        (rt_route_notif_data_t *)rt_notif_data;

    node = route_notif_data->node;

    if (isis_is_protocol_shutdown_in_progress(node) ||
         !isis_is_protocol_enable_on_node(node) ) {
             return;
    }

    l3route = route_notif_data->l3route;
    isis_process_ipv4_route_notif(node, l3route);
}
