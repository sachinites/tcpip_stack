#ifndef __ISIS_RTR__
#define __ISIS_RTR__

#include "isis_events.h"
#include "isis_pkt.h"

typedef struct isis_adv_data_ isis_adv_data_t;
typedef struct ted_db_ ted_db_t;

typedef struct isis_timer_data_ {

    node_t *node;
    interface_t *intf;
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
    /* pointer to self LSP pkt */
    isis_lsp_pkt_t *self_lsp_pkt;
    /* Task to schedule self LSP pkt generation */
    task_t *lsp_pkt_gen_task;
    /*Task to schedule spf job*/
    task_t *spf_job_task;
    /* Boolean to track if node is shutting down */
    bool is_shutting_down;
    /* LSP sequence no */
    uint32_t seq_no;
    /*Timer to flood self LSP periodically */
    timer_event_handle *periodic_lsp_flood_timer;
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
    /* on demand flooding */
    bool on_demand_flooding;
    /* Reconciliation data */
    isis_reconc_data_t reconc;
    /*Adjacency up count */
    uint16_t adjacency_up_count;
    /* event flags */
    unsigned long event_control_flags;
    /*flag to control protocol shutdown procedure*/
    uint16_t shutdown_pending_work_flags;
    /* overload object */
    isis_overload_data_t ovl_data;
    /* Miscellaneous flags */
    uint64_t misc_flags;
    /* Tree of interface Groups configured by User */
    avltree_t intf_grp_avl_root;
    /* Dynamic intf grp */
    bool dyn_intf_grp;
    /* Layer 2 Mapping */
    bool layer2_mapping;
    /* Rtr ID to be advertised */
     isis_adv_data_t *adv_data_rtr_id;
    /* List of Data to be advertised in local LSP pkt */
    glthread_t adv_data_list_head;
    /* Ted DB */
    ted_db_t *ted_db;
} isis_node_info_t;

#define ISIS_NODE_INFO(node_ptr)    \
    ((isis_node_info_t *)(node_ptr->node_nw_prop.isis_node_info))

#define ISIS_INCREMENT_NODE_STATS(node_ptr, field)  \
    (ISIS_NODE_INFO(node_ptr))->field++;

#define ISIS_DECREMENT_NODE_STATS(node_ptr, field)  \
    (ISIS_NODE_INFO(node_ptr))->field--;


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

void
isis_proto_enable_disable_on_demand_flooding(
        node_t *node,
        bool enable);

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

void
isis_check_and_shutdown_protocol_now(
        node_t *node, uint16_t work_completed_flag);

void
isis_set_overload(node_t *node, uint32_t timeout_val, int cmdcode) ;

void
isis_unset_overload(node_t *node, uint32_t timeout_val, int cmdcode) ;

bool
isis_is_overloaded(node_t *node, bool *ovl_timer_running);

void
isis_stop_overload_timer(node_t *node);

bool
isis_has_routes(node_t *node) ;

#endif
