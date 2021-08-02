#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_spf.h"

static void
isis_run_spf(void *arg, uint32_t arg_size){

    node_t *node = (node_t *)arg;
    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    isis_node_info->spf_job_task = NULL;
    
    ISIS_INCREMENT_NODE_STATS(node, spf_runs);
    ISIS_INCREMENT_NODE_STATS(node, isis_event_count[isis_event_spf_runs]);
}

void
isis_schedule_spf_job(node_t *node) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if (!isis_is_protocol_enable_on_node(node)) {
        return;
    }
    
    ISIS_INCREMENT_NODE_STATS(node,
        isis_event_count[isis_event_spf_job_scheduled]);

    if (isis_node_info->spf_job_task) {
        
        sprintf(tlb, "%s : spf job already scheduled\n", ISIS_SPF);
        tcp_trace(node, 0, tlb);
        return;
    }
    
    isis_node_info->spf_job_task =
        task_create_new_job(node, isis_run_spf, TASK_ONE_SHOT);
}

void
isis_cancel_spf_job(node_t *node) {

    isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);

    if (!isis_node_info ||
        !isis_node_info->spf_job_task) return;

    task_cancel_job(isis_node_info->spf_job_task);
    isis_node_info->spf_job_task = NULL;
}