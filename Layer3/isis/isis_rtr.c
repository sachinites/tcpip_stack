#include <errno.h>
#include <unistd.h>
#include "../../tcp_public.h"
#include "isis_utils.h"
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
#include "isis_srv6.h"
#include "../../RTM/rtm_nb_integ.h"
#include "../../datapath/dp_uapi.h"

extern void isis_recv_ipc_updates(isis_node_info_t *node_info,
                                  ips_major_code_t major_code,
                                  uint32_t minor_code,
                                  void *msg,
                                  uint32_t msg_size);

extern void isis_rtm_test(isis_node_info_t *node_info) ;

/* Checking if protocol enable at node & intf level */
bool
isis_is_protocol_enable_on_node(vrf_t *vrf) {

    if (vrf->isis_node_info) return true;
    return false;
}

static void
isis_node_cancel_all_queued_jobs(isis_node_info_t *node_info) {

    isis_cancel_spf_job(node_info);
    isis_cancel_lsp_fragment_regen_job(node_info);
    isis_cancel_all_fragment_regen_job (node_info);
}

static void
isis_node_cancel_all_timers(isis_node_info_t *node_info){

    isis_stop_overload_timer(node_info);
}

static void
isis_free_node_info(isis_node_info_t *node_info) {

    vrf_t *vrf = node_info->vrf;
    XFREE(node_info);
    vrf->isis_node_info = NULL;
    cprintf ("%s: ISIS Protocol successfully shutdown\n", vrf->node->node_name);
}

static void
isis_check_delete_node_info(isis_node_info_t *node_info) {

    /* Scheduled jobs */
    assert (!node_info->lsp_fragment_gen_task);
    assert (!node_info->regen_all_fragment_task);
    assert (!node_info->spf_job_task);

    /*Hooked up Data Structures should be empty */
    assert (avltree_is_empty(&node_info->intf_grp_avl_root));
    assert (!node_info->ted_db);
    assert (!node_info->exported_routes.root);
    assert (!node_info->isis_event_count [isis_event_tlv_wait_listed]);
    assert (!node_info->tlv_global_advt.v6lo_adv_data_tlv236);
    assert (!node_info->tlv_global_advt.v6lo_adv_data_tlv237);
    assert (!node_info->srv6_config ); 

    /* Must not be any pending LSP for regeneration*/
    assert (IS_GLTHREAD_LIST_EMPTY (&node_info->pending_lsp_gen_queue));
    isis_assert_check_all_advt_db_cleanedup(node_info);

    /* Timers */
    assert (!node_info->ovl_data.ovl_timer);

    /* Should not have any pending work to do */
    assert (!node_info->shutdown_pending_work_flags);
    /* ensure tracing objects is cleaned up*/
    assert (!node_info->tr);
    isis_free_node_info (node_info);
}

static void
isis_protocol_shutdown_now (isis_node_info_t *node_info) {

    Interface *intf;

    isis_intf_grp_cleanup(node_info);
    isis_node_cancel_all_queued_jobs(node_info);
    isis_node_cancel_all_timers(node_info);
    isis_free_dummy_lsp_pkt(node_info);
    isis_cleanup_spf_logc(node_info);
    isis_unconfig_import_policy(node_info, NULL);
    isis_unconfig_export_policy(node_info, NULL);

    ITERATE_NODE_ISIS_INTERFACES_BEGIN(node_info, intf) { 
        
        isis_disable_protocol_on_interface(intf);

    } ITERATE_NODE_ISIS_INTERFACES_END;
    
    isis_disable_srv6(node_info);
    /* Destroy all Major DBs in the end*/
    isis_destroy_advt_db(node_info, 0);
    /* This should be No-Op, buts lets do*/
    isis_cleanup_lsdb(node_info, true);
    /*This would cleanup fake nodes, if any*/
    isis_cleanup_teddb (node_info);
    tracer_deinit (node_info->tr);
    node_info->tr = NULL;
    #if 0
    cp_ips_unjoin (node, IPC_INTERFACE, isis_recv_ipc_updates);
    cp_ips_unjoin (node, IPC_GRE_TUNNEL, isis_recv_ipc_updates);
    cp_ips_unjoin (node, IPC_ACCESS_LIST, isis_recv_ipc_updates);
    #endif
    isis_check_delete_node_info(node_info); 
}

void
isis_check_and_shutdown_protocol_now(
        isis_node_info_t *node_info, 
        uint16_t work_completed_flag) {

    if (!isis_is_protocol_admin_shutdown(node_info)) return;

    /* Flag must be set */
    assert (node_info->shutdown_pending_work_flags & 
                work_completed_flag);
    
    /* clean the bit*/
    UNSET_BIT16(node_info->shutdown_pending_work_flags,
                                    work_completed_flag);

    if (isis_is_protocol_shutdown_in_progress(node_info)) return;

    isis_protocol_shutdown_now(node_info);
}

bool
isis_is_protocol_shutdown_in_progress(isis_node_info_t *node_info) {

    if (IS_BIT_SET(node_info->shutdown_pending_work_flags ,
                            ISIS_PRO_SHUTDOWN_ALL_PENDING_WORK)) {
        return true;
    }

    return false;
}

bool
isis_is_protocol_admin_shutdown(isis_node_info_t *node_info) {

    if ( IS_BIT_SET(node_info->event_control_flags,
                ISIS_EVENT_ADMIN_ACTION_SHUTDOWN_PENDING_BIT)) {

        return true;
    }
    return false;
}

static void
isis_schedule_route_delete_task(isis_node_info_t *node_info,
        isis_event_type_t event_type){

    bool del_static = isis_is_protocol_shutdown_in_progress(node_info);
    vrf_t *vrf = node_info->vrf;

    cp_rtm_uninstall_routes_by_proto  (
            vrf->inet0,
            RTM_PROTO_ISIS, RTM_PROTO_L1_ISIS_INT, 0);
    cp_rtm_uninstall_routes_by_proto  (
            vrf->inet6,
            RTM_PROTO_ISIS, RTM_PROTO_L1_ISIS_INT, 0);

    isis_check_and_shutdown_protocol_now(node_info,
            ISIS_PRO_SHUTDOWN_DEL_ROUTES_WORK);
}

static void
isis_launch_prior_shutdown_tasks(isis_node_info_t *node_info) {

    node_info->shutdown_pending_work_flags = 0;

    /* Set the flags to track what work needs to be done before we die out */
    if (node_info->adjacency_up_count) {

        tracer (ISIS_TR(node_info), TR_ISIS_EVENTS, 
            "Generating Pre-shutdown work - Purging Zero LSPs\n");

        SET_BIT(node_info->shutdown_pending_work_flags,
                            ISIS_PRO_SHUTDOWN_GEN_PURGE_LSP_WORK);

        isis_walk_all_self_zero_lsps (node_info, isis_schedule_purge_lsp_flood_cbk);
    }
    
    if (isis_has_routes(node_info)) {

        tracer (ISIS_TR(node_info), TR_ISIS_EVENTS, 
            "Generating Pre-shutdown work - Route deletion\n");

        SET_BIT(node_info->shutdown_pending_work_flags,
                            ISIS_PRO_SHUTDOWN_DEL_ROUTES_WORK);
        
        isis_schedule_route_delete_task(node_info,
                isis_event_admin_action_shutdown_pending);
    }
}

bool
isis_is_protocol_shutdown_pending_work_completed (isis_node_info_t *node_info) {

    if (isis_is_protocol_admin_shutdown(node_info) &&
        !isis_is_protocol_shutdown_in_progress(node_info)) {

        return true;
    }

    return false;
}

void
isis_protocol_shut_down(isis_node_info_t *node_info) {

    Interface *intf;
    isis_intf_info_t *intf_info;

    if (isis_is_protocol_shutdown_in_progress(node_info)) {
        cprintf("Protocol Busy shutting down... Please Wait.\n");
        return;
    }

    if (isis_is_protocol_admin_shutdown(node_info)){
        cprintf("Protocol Already In ShutDown State\n");
        return;
    }
      
    SET_BIT( node_info->event_control_flags, 
        ISIS_EVENT_ADMIN_ACTION_SHUTDOWN_PENDING_BIT);

    isis_ips_send_lsp_update (node_info, 0, false);
    isis_launch_prior_shutdown_tasks(node_info);
}

void
isis_show_node_protocol_state(vrf_t *vrf) {

    bool is_enabled ;
    Interface *intf;
    is_enabled = isis_is_protocol_enable_on_node(vrf);

    cprintf("ISIS Protocol : %sabled %p\n", 
        is_enabled ? "En" : "Dis", vrf->isis_node_info);

    if(!is_enabled) return;

    isis_node_info_t *node_info = vrf->isis_node_info;

    cprintf("LSP flood count : %u\n", node_info->lsp_flood_count);
    cprintf("SPF runs : %u\n", node_info->spf_runs);
    cprintf("Adjacency up Count: %u\n", node_info->adjacency_up_count);

    if (node_info->import_policy) {
        cprintf("Import Policy : %s\n", node_info->import_policy->name);
    }
    if (node_info->export_policy) {
        cprintf("Export Policy : %s\n", node_info->export_policy->name);
    }

    cprintf("Overload Status : %s\n", node_info->ovl_data.ovl_status ? "On" : "Off");

    if (node_info->ovl_data.ovl_status &&
            node_info->ovl_data.ovl_timer) {
        cprintf("Overload Timer : %usec left\n", 
            wt_get_remaining_time(node_info->ovl_data.ovl_timer)/1000);
    }
    else {
        cprintf("Overload Timer : Not Running\n");
    }

    cprintf("Layer2-Mapping : %sabled\n", 
        isis_is_layer2_mapping_enabled(node_info) ? "En" : "Dis");

    if (isis_srv6_get_config (node_info)) {
        cprintf("Segment Routing : SRv6\n");
    }

    ITERATE_NODE_ISIS_INTERFACES_BEGIN(node_info, intf) {    

        if (!isis_is_protocol_enable_on_intf(intf)) continue;
        isis_show_interface_protocol_state(intf);

    } ITERATE_NODE_ISIS_INTERFACES_END;
    
    ISIS_INCREMENT_NODE_STATS(node_info,
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
isis_de_init(vrf_t *vrf) {

    if (!isis_is_protocol_enable_on_node(vrf)) return;

    /* De-Register for interested pkts */
    dp_de_register_l2_pkt_trap_rule(
			vrf->node->dp_ctx,
            isis_lsp_pkt_trap_rule, isis_lsp_pkt_recieve_cbk);

    dp_de_register_l2_pkt_trap_rule(
			vrf->node->dp_ctx,
            isis_hello_pkt_trap_rule, isis_hello_pkt_recieve_cbk);

    tracer (ISIS_TR(vrf->isis_node_info), TR_ISIS_EVENTS, 
            "ISIS pkt trap disabled\n");

    //nfc_ipv4_rt_un_subscribe(node, isis_ipv4_rt_notif_cbk);
    isis_protocol_shut_down(vrf->isis_node_info);
}

void
isis_init (vrf_t *vrf) {

    node_t *node = vrf->node;
    char log_file_name[128] = {0};

    if (vrf->isis_node_info) return;

    /* Register for interested pkts */
    dp_register_l2_pkt_trap_rule(
			node->dp_ctx,
            isis_lsp_pkt_trap_rule, isis_lsp_pkt_recieve_cbk);

    dp_register_l2_pkt_trap_rule(
			node->dp_ctx,
            isis_hello_pkt_trap_rule, isis_hello_pkt_recieve_cbk);

    isis_node_info_t *node_info = XCALLOC2(0, 1, isis_node_info_t);
    vrf->isis_node_info = node_info;
    node_info->vrf = vrf;

    node_info->sys_id = {NODE_LO_ADDR_INT(node), 0};
    node_info->lsp_flood_interval    = ISIS_LSP_DEFAULT_FLOOD_INTERVAL;
    node_info->lsp_lifetime_interval = ISIS_LSP_DEFAULT_LIFE_TIME_INTERVAL;

    avltree_init(&node_info->lspdb_avl_root, isis_compare_lspdb_lsp_pkt);

    isis_init_intf_group_avl_tree(&node_info->intf_grp_avl_root);

    node_info->dyn_intf_grp = true;  /* True By Default */

    node_info->layer2_mapping = true;   /* True By Default */

    node_info->ted_db = XCALLOC2(0, 1, ted_db_t);
    ted_init_teddb(node_info->ted_db, NULL, isis_spf_cleanup_spf_data);

    //nfc_ipv4_rt_subscribe(node, isis_ipv4_rt_notif_cbk);

    isis_init_spf_logc(node_info);

    init_mtrie(&node_info->exported_routes, 32, NULL);

    isis_create_advt_db(node_info, 0);

    init_glthread (&node_info->pending_lsp_gen_queue);
    
    snprintf (log_file_name, sizeof (log_file_name), 
        "logs/%s-%s-isis-log.txt", 
        node->node_name, vrf->vrf_name);
    node_info->tr = tracer_init ("isis", log_file_name, node->node_name, STDOUT_FILENO, 0);

    isis_schedule_all_fragment_regen_job (node_info);

    ISIS_INCREMENT_NODE_STATS(node_info,
        isis_event_count[isis_event_admin_config_changed]);
    node_info->lsdb_advt_block = false;
}

void
isis_one_time_registration() {

    nfc_register_for_pkt_tracing(ISIS_LSP_ETH_PKT_TYPE, isis_print_lsp_pkt_cbk);
    nfc_register_for_pkt_tracing(ISIS_HELLO_ETH_PKT_TYPE, isis_print_hello_pkt_cbk);
}

void
isis_schedule_job(isis_node_info_t *node_info,
                  task_t **task,
                  event_cbk cbk,
                  void *data,
                  isis_job_type_t job_type,
                  isis_event_type_t event_type,
                  int job_priority) {

    if (*task) {
        tracer (ISIS_TR(node_info), TR_ISIS_SPF, 
            "%s Already Scheduled. Reason : %s\n",
            isis_job_type_str (job_type), isis_event_str(event_type));
        return;
    }

    switch (job_type) {

        case ISIS_JOB_NONE:
            assert(0);
        case ISIS_FRAG_REGEN_JOB:
            break;
        case ISIS_ALL_FRAG_REGEN_JOB:
            break;
        case ISIS_SPF_JOB:
            break;
        case ISIS_LSP_XMIT_INTF_JOB:
            break;
        case ISIS_ROUTE_CAL_JOB:
            break;
        case ISIS_JOB_MAX:
            assert(0);
    }

    *task = task_create_new_job(EV(node_info->vrf->node), data, cbk, TASK_ONE_SHOT, job_priority);

    if(*task) {
        tracer (ISIS_TR(node_info), TR_ISIS_SPF, "%s Scheduled. Reason : %s\n",
            isis_job_type_str (job_type), isis_event_str(event_type));        
    }
}

void
isis_show_event_counters(isis_node_info_t *node_info) {

    int rc = 0;
    int enum_int;
    isis_event_type_t event_type;

    cprintf ("Event Counters :\n");

    for(enum_int = (int)(isis_event_none + 1); 
        enum_int < (int)isis_event_max;
        enum_int++){
        
        event_type = static_cast <isis_event_type_t> (enum_int);

        cprintf (" %s : %u\n", isis_event_str(event_type), 
                node_info->isis_event_count[event_type]);
    }
}

bool
isis_is_overloaded (isis_node_info_t *node_info, bool *ovl_timer_running) {
    
    if (ovl_timer_running) *ovl_timer_running = false;

    if  (node_info->ovl_data.ovl_timer && ovl_timer_running) {
        *ovl_timer_running = true;
    }

    return node_info->ovl_data.ovl_status;
}

static void
isis_overload_timer_expire(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    isis_node_info_t *node_info = (isis_node_info_t *)arg;
    isis_overload_data_t *ovl_data = &node_info->ovl_data;

    timer_de_register_app_event(ovl_data->ovl_timer);
    ovl_data->ovl_timer = NULL;
    ovl_data->timeout_val = 0;

    ISIS_INCREMENT_NODE_STATS(node_info, isis_event_count[isis_event_overload_timeout]);

    if (IS_BIT_SET (node_info->event_control_flags, 
        ISIS_EVENT_DEVICE_DYNAMIC_OVERLOAD_BIT)) {
        return;
    }

    ovl_data->ovl_status = false;
    isis_regen_zeroth_fragment (node_info);
}

static void
isis_start_overload_timer(isis_node_info_t *node_info, uint32_t timeout_val) {

    isis_overload_data_t *ovl_data = &node_info->ovl_data;

    if (ovl_data->ovl_timer) return;

    ovl_data->ovl_timer = timer_register_app_event(CP_TIMER(node_info->vrf->node),
                                            isis_overload_timer_expire,
                                            (void *)node_info, 
                                            sizeof(isis_node_info_t),
                                            timeout_val * 1000, 0);
}

void
isis_stop_overload_timer(isis_node_info_t *node_info) {

    isis_overload_data_t *ovl_data = &node_info->ovl_data;

    if (!ovl_data->ovl_timer) return;

    timer_de_register_app_event(ovl_data->ovl_timer);
    ovl_data->ovl_timer = NULL;
}

int
isis_set_overload (isis_node_info_t *node_info, uint32_t timeout_val, int cmdcode) {

    int rc = 0;
    bool regen_lsp = false;
    isis_overload_data_t *ovl_data;

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
                isis_start_overload_timer(node_info, timeout_val);
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
                    isis_stop_overload_timer(node_info);
                    rc  = 0;
                }
        }
     }

     done:
        if (regen_lsp) {
            isis_fragment_t *fragment0 = node_info->advt_db[0]->fragments[0];
            fragment0->regen_flags = ISIS_SHOULD_INCL_OL_BIT | ISIS_LSP_DEF_REGEN_FLAGS;
            isis_schedule_regen_fragment (node_info, fragment0, isis_event_device_overload_config);
            return 0;
        }
        
        return rc;
}

int
isis_unset_overload(isis_node_info_t *node_info, uint32_t timeout_val, int cmdcode) {
    
    bool regen_lsp = false;
    isis_overload_data_t *ovl_data;

    ovl_data = &node_info->ovl_data;

    if (cmdcode == CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD) {

        /* user triggered : ...no protocol isis overload */
        if (!ovl_data->ovl_status)  return -1;

        ovl_data->ovl_status = false;
        regen_lsp = true;

        if (ovl_data->ovl_timer) {
            isis_stop_overload_timer(node_info);
        }
        goto done;
    }

    if (cmdcode == CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD_TIMEOUT) {

         /* user triggered : ...no protocol isis overload timeout <value >*/

         if (!ovl_data->ovl_timer) {
             goto done;
         }

         isis_stop_overload_timer(node_info);
    }

    done:

        if (regen_lsp) {
            isis_fragment_t *fragment0 = node_info->advt_db[0]->fragments[0];
            fragment0->regen_flags &= ~ISIS_SHOULD_INCL_OL_BIT;            
            isis_schedule_regen_fragment (node_info, fragment0, isis_event_device_overload_config);
            return 0;
        }

        return -1;
}

bool
isis_has_routes(isis_node_info_t *node_info) {

    return true;
}

#if 0
extern void
 isis_process_ipv4_route_notif (isis_node_info_t *node_info, l3_route_t *l3route) ;
 
void
isis_ipv4_rt_notif_cbk (
        event_dispatcher_t *ev_dis,
        void *rt_notif_data, unsigned int arg_size) {

    isis_node_info_t *node_info;
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
#endif

void 
isis_cancel_redundant_jobs (isis_node_info_t *node_info, isis_job_type_t job_type) {

    Interface *intf;
    isis_intf_info_t *intf_info;

    switch (job_type) {

    case ISIS_JOB_NONE:
    break;
    case ISIS_FRAG_REGEN_JOB:
        /* No Redundant job */
    break;
    case ISIS_ALL_FRAG_REGEN_JOB:

        isis_cancel_lsp_fragment_regen_job(node_info);
        isis_cancel_spf_job(node_info);

        ITERATE_NODE_ISIS_INTERFACES_BEGIN(node_info, intf) {
             
             if (!isis_is_protocol_enable_on_intf(intf)) continue;
             isis_cancel_lsp_xmit_job (intf);

        }ITERATE_NODE_ISIS_INTERFACES_END;

    break;

    case ISIS_SPF_JOB:
         /* Should cancel Route calculation job. But at this point of time, Route cal is not a different job. 
         No Redundant job */
    break;
    case ISIS_LSP_XMIT_INTF_JOB:
        /* No Redundant job */
    break;
    case ISIS_ROUTE_CAL_JOB:
        /* No Redundant job */
    break;
    case ISIS_JOB_MAX:
    break;
    }
}

bool 
isis_validate_job_schedule (isis_node_info_t *node_info, isis_job_type_t job_type) {
    
    if (isis_is_protocol_shutdown_pending_work_completed (node_info)) {
        return false;
    }

 switch (job_type) {

    case ISIS_JOB_NONE:
    break;
    case ISIS_FRAG_REGEN_JOB:
        if (node_info->regen_all_fragment_task) return false;
    break;
    case ISIS_ALL_FRAG_REGEN_JOB:
    break;
    case ISIS_SPF_JOB:
        if (node_info->regen_all_fragment_task) return false;
    break;
    case ISIS_LSP_XMIT_INTF_JOB:
    break;
    case ISIS_ROUTE_CAL_JOB:
        if (node_info->regen_all_fragment_task) return false;
        if (node_info->spf_job_task) return false;
    break;
    case ISIS_JOB_MAX:
    break;
    }    
    return true;
}
