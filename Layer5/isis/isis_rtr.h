#ifndef __ISIS_RTR__
#define __ISIS_RTR__

#include "isis_events.h"
#include "isis_pkt.h"
#include "isis_spf.h"

typedef struct isis_adv_data_ isis_adv_data_t;
typedef struct ted_db_ ted_db_t;
typedef struct prefix_lst_ prefix_list_t;
typedef struct isis_advt_db_ isis_advt_db_t;

typedef struct isis_timer_data_ {

    node_t *node;
    Interface *intf;
    void *data;
    size_t data_size;
} isis_timer_data_t;

typedef struct isis_reconc_data_ {

   /* is reconciliation going on */
    bool reconciliation_in_progress;
    /* reconciliation timer */
    timer_event_handle *reconciliation_timer;
} isis_reconc_data_t;

typedef struct isis_overload_data_ {

    bool ovl_status;
    uint32_t timeout_val;
    timer_event_handle *ovl_timer;
} isis_overload_data_t;

typedef struct node_info_ {
    /* self system id -> <rtrid-0>*/
    isis_system_id_t sys_id;
    /* self LSP flood time interval */
    uint32_t lsp_flood_interval; // in sec
    /* lsp pkt life time interval in lspdb */
    uint32_t lsp_lifetime_interval;
    /* No of times LSP is flooded by this node */
    uint32_t lsp_flood_count;
    /* LSPs Queued but not dispatched out of interfaces */
    uint32_t pending_lsp_flood_count;
    /* LSP DB */
    avltree_t lspdb_avl_root;
    /* no of SPF runs*/
    uint32_t spf_runs;
    /*event counts*/
    uint32_t isis_event_count[isis_event_max];
    /*Adjacency up count */
    uint16_t adjacency_up_count;
    /* event flags */
    uint64_t event_control_flags;
    /*flag to control protocol shutdown procedure*/
    uint16_t shutdown_pending_work_flags;
    /* overload object */
    isis_overload_data_t ovl_data;
    /* Tree of interface Groups configured by User */
    avltree_t intf_grp_avl_root;
    /* Dynamic intf grp */
    bool dyn_intf_grp;
    /* Layer 2 Mapping */
    bool layer2_mapping;
    /* Ted DB */
    ted_db_t *ted_db;
    /* SPF log list */
    isis_spf_log_container_t spf_logc;
    /* import policy */
    prefix_list_t *import_policy;
    /* export policy */
    prefix_list_t *export_policy;
    /* Dummy LSP PKT for lookup */
    isis_lsp_pkt_t *lsp_dummy_pkt; 
    /* Exported Route Tree */
    mtrie_t exported_routes;
    /* Advertisement DB per PN*/
    isis_advt_db_t* advt_db[ISIS_MAX_PN_SUPPORTED];
    /* Queue holding fragments to be regenerated*/
    glthread_t pending_lsp_gen_queue;
    /* Task for generating the LSP fragments*/
    task_t *lsp_fragment_gen_task;
    /* Task to regenrate all fragments from scratch*/
    task_t *regen_all_fragment_task;
    /*Task to schedule spf job*/
    task_t *spf_job_task;
    /* ISIS specific logging */
    tracer_t *tr;
    /* LSDB advt block/unblock, used for debugging*/
    bool lsdb_advt_block;
} isis_node_info_t;

#define ISIS_NODE_INFO(node_ptr)    \
    ((isis_node_info_t *)(node_ptr->node_nw_prop.isis_node_info))

#define ISIS_INCREMENT_NODE_STATS(node_ptr, field)  \
    (ISIS_NODE_INFO(node_ptr))->field++;

#define ISIS_DECREMENT_NODE_STATS(node_ptr, field)  \
    (ISIS_NODE_INFO(node_ptr))->field--;

#define ISIS_TR(node_ptr)  \
    ((ISIS_NODE_INFO(node_ptr))->tr)

bool
isis_is_protocol_enable_on_node(node_t *node) ;

void
isis_init(node_t *node );

void
isis_de_init(node_t *node) ;

void
isis_protocol_shut_down(node_t *node);

void
isis_show_node_protocol_state(node_t *node);

void
isis_schedule_job(node_t *node,
                  task_t **task,
                  event_cbk cbk,
                  void *data,
                  const char *job_name,
                  isis_event_type_t event_type);

void
isis_show_event_counters(node_t *node);

/* Protocol Shutdown related APIs and Constants */
#define ISIS_PRO_SHUTDOWN_GEN_PURGE_LSP_WORK    (1 << 0)
#define ISIS_PRO_SHUTDOWN_DEL_ROUTES_WORK       (1 << 1)
#define ISIS_PRO_SHUTDOWN_ALL_PENDING_WORK  \
    (ISIS_PRO_SHUTDOWN_GEN_PURGE_LSP_WORK | \
     ISIS_PRO_SHUTDOWN_DEL_ROUTES_WORK)
#define ISIS_PRO_SHUTDOWN_COMPLETED              (1 << 15) /*upto 15th bit only*/

bool
isis_is_protocol_shutdown_in_progress(node_t *node);

bool
isis_is_protocol_admin_shutdown(node_t *node);

void
isis_protocol_shut_down(node_t *node);

bool
isis_is_protocol_shutdown_pending_work_completed (node_t *node);

void
isis_check_and_shutdown_protocol_now(
        node_t *node, uint16_t work_completed_flag);

int
isis_set_overload(node_t *node, uint32_t timeout_val, int cmdcode) ;

int
isis_unset_overload(node_t *node, uint32_t timeout_val, int cmdcode) ;

bool
isis_is_overloaded(node_t *node, bool *ovl_timer_running);

void
isis_stop_overload_timer(node_t *node);

bool
isis_has_routes(node_t *node) ;

#endif
