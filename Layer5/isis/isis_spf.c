#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_spf.h"

static void
isis_run_spf(void *arg, uint32_t arg_size){

    node_t *node = (node_t *)arg;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    node_info->spf_job_task = NULL;
    
    ISIS_INCREMENT_NODE_STATS(node, spf_runs);
    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[isis_event_spf_runs]);
}

void
isis_schedule_spf_job(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return;
    }
    
    ISIS_INCREMENT_NODE_STATS(node,
        isis_event_count[isis_event_spf_job_scheduled]);

    if (node_info->spf_job_task) {
        
        sprintf(tlb, "%s : spf job already scheduled\n", ISIS_SPF);
        tcp_trace(node, 0, tlb);
        return;
    }
    
    node_info->spf_job_task =
        task_create_new_job(node, isis_run_spf, TASK_ONE_SHOT);
}

void
isis_cancel_spf_job(node_t *node) {

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    if (!node_info ||
        !node_info->spf_job_task) return;

    task_cancel_job(node_info->spf_job_task);
    node_info->spf_job_task = NULL;
}
