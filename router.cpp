#include "router.h"
#include "router_init.h"

#include <inttypes.h>

#include "CLIBuilder/cmdtlv.h"
#include "CLIBuilder/libcli.h"

#include "libs/pkt-block/cp_pkt_block.h"
#include "LabelMgr/label_mgr.h"

extern graph_t *topo;
extern int cprintf (const char * format, ...);

static const char *
ev_dis_state_str(EV_DISPATCHER_STATE state) {

    switch (state) {
        case EV_DIS_IDLE:
            return "IDLE";
        case EV_DIS_TASK_FIN_WAIT:
            return "TASK_FIN_WAIT";
        default:
            return "UNKNOWN";
    }
}

static const char *
task_type_str(task_type_t type) {

    switch (type) {
        case TASK_ONE_SHOT:
            return "ONE_SHOT";
        case TASK_PKT_Q_JOB:
            return "PKT_Q_JOB";
        case TASK_BG:
            return "BG";
        default:
            return "UNKNOWN";
    }
}

static const char *
task_priority_str(task_priority_t priority) {

    switch (priority) {
        case TASK_PRIORITY_CRITICAL:
            return "CRITICAL";
        case TASK_PRIORITY_HIGH:
            return "HIGH";
        case TASK_PRIORITY_MEDIUM:
            return "MEDIUM";
        case TASK_PRIORITY_LOW_MEDIUM:
            return "LOW_MEDIUM";
        case TASK_PRIORITY_LOW:
            return "LOW";
        case TASK_PRIORITY_VERY_LOW:
            return "VERY_LOW";
        default:
            return "UNKNOWN";
    }
}

void
show_event_dispatcher(event_dispatcher_t *ev_dis) {

    glthread_t *curr;
    task_t *task;
    pkt_q_t *pkt_q;
    int pri;
    int task_idx;

    EV_DIS_LOCK(ev_dis);

    cprintf("\nEvent Dispatcher: %s (%p)\n", ev_dis->name, ev_dis);
    cprintf("========================================\n");
    cprintf("  State              : %s\n",
            ev_dis_state_str(ev_dis->ev_dis_state));
    cprintf("  Pending Tasks      : %u\n", ev_dis->pending_task_count);
    cprintf("  Tasks Executed     : %" PRIu64 "\n", ev_dis->n_task_exec);
    cprintf("  Signal Sent        : %s (sent=%u, recv=%u)\n",
            ev_dis->signal_sent ? "true" : "false",
            ev_dis->signal_sent_cnt, ev_dis->signal_recv_cnt);
    cprintf("  Thread             : %p\n", (void *)ev_dis->thread);

    if (ev_dis->current_task) {
        task = ev_dis->current_task;
        cprintf("  Current Task       : %p cbk=%p type=%s priority=%s invocations=%u\n",
                task, (void *)task->ev_cbk,
                task_type_str(task->task_type),
                task_priority_str(task->priority),
                task->no_of_invocations);
    } else {
        cprintf("  Current Task       : None\n");
    }

    cprintf("\n  Pending Task Queues:\n");
    for (pri = TASK_PRIORITY_FIRST; pri < TASK_PRIORITY_MAX; pri++) {

        if (IS_GLTHREAD_LIST_EMPTY(&ev_dis->task_array_head[pri]))
            continue;

        cprintf("    Priority %s (%d):\n",
                task_priority_str((task_priority_t)pri), pri);
        task_idx = 0;
        ITERATE_GLTHREAD_BEGIN(&ev_dis->task_array_head[pri], curr) {

            task = glue_to_task(curr);
            cprintf("      [%d] task=%p cbk=%p data=%p data_size=%u type=%s "
                    "re_schedule=%s invocations=%u\n",
                    task_idx++, task, (void *)task->ev_cbk, task->data,
                    task->data_size, task_type_str(task->task_type),
                    task->re_schedule ? "true" : "false",
                    task->no_of_invocations);
        } ITERATE_GLTHREAD_END(&ev_dis->task_array_head[pri], curr);
    }

    if (!IS_GLTHREAD_LIST_EMPTY(&ev_dis->pkt_queue_head)) {

        cprintf("\n  Packet Queues:\n");
        ITERATE_GLTHREAD_BEGIN(&ev_dis->pkt_queue_head, curr) {

            pkt_q = glue_to_pkt_q(curr);
            cprintf("    pkt_q=%p task=%p pkt_count=%u drop_count=%u queued=%s\n",
                    pkt_q, pkt_q->task, pkt_q->pkt_count, pkt_q->drop_count,
                    IS_QUEUED_UP_IN_THREAD(&pkt_q->task->glue) ? "yes" : "no");
        } ITERATE_GLTHREAD_END(&ev_dis->pkt_queue_head, curr);
    }

    EV_DIS_UNLOCK(ev_dis);
}

bool
rtr_eligible_to_remove_rtr_id(node_t *node) {

    for (int i = 0; i < MAX_VRF_PER_NODE; i++) {
        if (node->vrf[i] &&
            node->vrf[i]->isis_node_info) {
            return false;
        }
    }
    return true;
}

int
show_scheduler(int64_t cmdcode, 
               Stack_t *tlv_stack,
               op_mode enable_or_disable)
{
   node_t *node;
   c_string node_name;
   tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){
        
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    show_event_dispatcher(&node->ev_dis);

   return 0;
}

int
cp_punted_pkt_recv_job_cbk(event_dispatcher_t *ev_dis, void *arg, size_t arg_size) {

    node_t *node = (node_t *)ev_dis->app_data;

    cp_pkt_block_t *cp_pkt_block = (cp_pkt_block_t *)arg;

    /* Now distribute the packet to the appropriate handler based on info 
        stored in auxullary data*/



    /* Free the pkt after use */
    cp_pkt_block_dereference(cp_pkt_block);
    return 0;
}

int 
mpls_label_mgr_show_handler(int64_t cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable) {

    node_t *node;
    c_string node_name;
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    label_mgr_show_all(node->lbl_mgr);

    return 0;
}