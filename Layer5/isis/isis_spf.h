#ifndef __ISIS_SPF__
#define __ISIS_SPF__

void
isis_schedule_spf_job(node_t *node);

void
isis_cancel_spf_job(node_t *node);

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



#endif 