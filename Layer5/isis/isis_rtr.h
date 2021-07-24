#ifndef __ISIS_RTR__
#define __ISIS_RTR__

#include "isis_pkt.h"
#include "isis_events.h"

typedef struct isis_node_info_ {

    isis_pkt_t *isis_self_lsp_pkt;  /* defiend in isis_pkt.h */
    task_t *isis_lsp_pkt_gen_task;
    bool is_shutting_down;
    uint32_t seq_no;
    glthread_t purge_intf_list;
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