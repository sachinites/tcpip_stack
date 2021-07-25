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
    wheel_timer_elem_t *periodic_lsp_flood_timer;
    /* self LSP flood time interval */
    uint32_t lsp_flood_interval; // in sec
    /* No of times LSP is flooded by this node */
    uint32_t lsp_flood_count;
} isis_node_info_t;

#define ISIS_NODE_INFO(node_ptr)    \
    (isis_node_info_t *)(node_ptr->node_nw_prop.isis_node_info)

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
                  isis_events_t event_type);

void
isis_check_delete_node_info(node_t *node) ;

#endif