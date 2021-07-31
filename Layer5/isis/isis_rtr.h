#ifndef __ISIS_RTR__
#define __ISIS_RTR__

#include "isis_events.h"
#include "isis_pkt.h"

typedef struct isis_timer_data_ {

    node_t *node;
    interface_t *intf;
    void *data;
    size_t data_size;
} isis_timer_data_t;

typedef struct isis_node_info_ {
    /* pointer to self LSP pkt */
    isis_pkt_t *isis_self_lsp_pkt;
    /* Task to schedule self LSP pkt generation */
    task_t *isis_lsp_pkt_gen_task;
    /* Boolean to track if node is shutting down */
    bool is_shutting_down;
    /* LSP sequence no */
    uint32_t seq_no;
    /* List of interfaces to be proto disabled */
    glthread_t purge_intf_list;
    /*Timer to flood self LSP periodically */
    timer_event_handle *periodic_lsp_flood_timer;
    /* self LSP flood time interval */
    uint32_t lsp_flood_interval; // in sec
    /* lsp pkt life time interval in lspdb */
    uint32_t lsp_lifetime_interval;
    /* No of times LSP is flooded by this node */
    uint32_t lsp_flood_count;
    /* LSP DB */
    avltree_t lspdb_avl_root;
    /* no of SPF runs*/
    uint32_t spf_runs;
    /*event counts*/
    uint32_t isis_event_count[isis_event_max];
    /* on demand flooding */
    bool on_demand_flooding;
    /* lsp regenerate reason cached */
    isis_event_type_t gen_lsp_with_on_demand_tlv;
} isis_node_info_t;

#define ISIS_NODE_INFO(node_ptr)    \
    ((isis_node_info_t *)(node_ptr->node_nw_prop.isis_node_info))

#define ISIS_INCREMENT_NODE_STATS(node_ptr, field)  \
    (ISIS_NODE_INFO(node_ptr))->field++;

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
isis_check_delete_node_info(node_t *node) ;

void
isis_show_event_counters(node_t *node);

void
isis_proto_enable_disable_on_demand_flooding(
        node_t *node,
        bool enable);

#endif
