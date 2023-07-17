#ifndef __ISIS_SPF__
#define __ISIS_SPF__

/* SPF run */
#define ISIS_INFINITE_METRIC     0xFFFFFFFF
#define ISIS_NODE_SPF_DATA(tednodeptr)  (tednodeptr->proto_data[TED_ISIS_PROTO])
#define ISIS_NODE_SPF_METRIC ((tednodeptr)  \
     (((isis_spf_data_t *)(ISIS_NODE_SPF_DATA(tednodeptr)))->spf_metric)
#define ISIS_NODE_SPF_NXTHOPS ((tednodeptr)  \
     (((isis_spf_data_t *)(ISIS_NODE_SPF_DATA(tednodeptr)))->nexthops)

typedef struct isis_spf_data_{

    /*Final spf result stored in this list*/
    ted_node_t *node; /*back pointer to owning node*/
    glthread_t spf_result_head;

    /*Temp fields used for calculations*/
    uint32_t spf_metric;
    glthread_t priority_thread_glue;
    bool is_spf_processed;
    nexthop_t *nexthops[MAX_NXT_HOPS];
} isis_spf_data_t;
GLTHREAD_TO_STRUCT(isis_priority_thread_glue_to_spf_data, 
    isis_spf_data_t, priority_thread_glue);

#define isis_spf_data_offset_from_priority_thread_glue \
    ((size_t)&(((isis_spf_data_t *)0)->priority_thread_glue))

typedef struct isis_spf_result_{

    ted_node_t *node;
    uint32_t spf_metric;
    nexthop_t *nexthops[MAX_NXT_HOPS];
    glthread_t spf_res_glue;
} isis_spf_result_t;
GLTHREAD_TO_STRUCT(isis_spf_res_glue_to_spf_result, 
    isis_spf_result_t, spf_res_glue);

void
isis_schedule_spf_job(node_t *node, isis_event_type_t event_type);

void
isis_cancel_spf_job(node_t *node);

/* SPF Logging */
#define ISIS_MAX_SPF_LOG_COUNT  20

typedef struct isis_spf_log_ {

    time_t timestamp;
    isis_event_type_t event;
    glthread_t glue;
} isis_spf_log_t;
GLTHREAD_TO_STRUCT(isis_glue_spf_log, 
    isis_spf_log_t, glue);

typedef struct isis_spf_log_container_ {

    uint8_t count;
    glthread_t head;
} isis_spf_log_container_t;

void
isis_add_new_spf_log(node_t *node, isis_event_type_t event);

void
isis_show_spf_logs(node_t *node);

void
isis_init_spf_logc(node_t *node);

void
isis_cleanup_spf_logc(node_t *node);

void
isis_spf_cleanup_spf_data(ted_node_t *ted_node);

void
isis_show_spf_results (node_t *node);

#endif 