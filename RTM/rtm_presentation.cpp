#include "../graph.h"
#include "rtm.h"
#include "rtm_route.h"
#include "rtm_presentation.h"
#include "rtm_proto.h"
#include "../prefix-list/prefixlst.h"
#include "../EventDispatcher/event_dispatcher.h"

#define RTM_ADVT_COUNT_PREEMPTION_LIMIT 100

static void 
rtm_schedule_presentation_job (rtm_t *rtm) ;

#pragma pack(push, 8)
typedef struct rtm_presentation_data_ {

    rtm_nh *nh;
    prefix_list_t *prefix_list;
    void (*cbk)(rtm_t *,  rtm_nh *);
    glthread_t glue;

} rtm_presentation_data_t;
#pragma pack(pop)
GLTHREAD_TO_STRUCT(rtm_presentation_data_to_glue, rtm_presentation_data_t, glue);


static void
rtm_advt_job_cbk(event_dispatcher_t *ev, void *arg, uint32_t arg_size) {

    glthread_t *curr;
    uint32_t count = 0;

    rtm_t *rtm = (rtm_t *)arg;
    rtm->advt_job = NULL;
    rtm_presentation_data_t *presentation_data = NULL;

    while ((curr = dequeue_glthread_first(&rtm->advt_queue.head))) {

        presentation_data =
            (rtm_presentation_data_t *)rtm_presentation_data_to_glue(curr);

        /* Evaluate against prefix list */
        if (!presentation_data->prefix_list) {
            
            presentation_data->cbk(rtm, presentation_data->nh);   
        }
        else if (((prefix_list_evaluate(presentation_data->nh->owner_route->prefix.u.v4_addr,
                            presentation_data->nh->owner_route->prefix.prefix_len, 
                            presentation_data->prefix_list) == PFX_LST_PERMIT))) {

            presentation_data->cbk(rtm, presentation_data->nh);
        }

        rtm_nh_dereference(rtm, presentation_data->nh);
        if (presentation_data->prefix_list)
            prefix_list_dereference(presentation_data->prefix_list);
        free(presentation_data);
        count++;

        if (count == RTM_ADVT_COUNT_PREEMPTION_LIMIT)
        {
            rtm_schedule_presentation_job(rtm);
            return;
        }
    }
}

void 
rtm_schedule_presentation_job (rtm_t *rtm) {

    if (rtm->advt_job) return;

    rtm->advt_job = task_create_new_job ( EV(rtm->node),
             (void *)rtm,
             rtm_advt_job_cbk,
             TASK_ONE_SHOT, TASK_PRIORITY_COMPUTE );
}

/* This fn to be enhanced to be asynchronous */
void 
rtm_presentation_layer_route_add (rtm_t *rtm, rtm_nh *nh) {

    /* Iteratve over Advt DB of each protocol */
    avltree_t *proto_info_tree;
    rtm_proto_info_t *proto_info;
    rtm_rt_subscription_t *sub_info;
    avltree_node_t *proto_info_node;
    avltree_node_t *sub_proto_advt_db_node;
    rtm_presentation_data_t *presentation_data;

    for (int proto = 0; proto < RTM_PROTO_MAX; proto++) {

        proto_info_tree = &rtm->proto_info_tree[proto];

        if (avltree_is_empty(proto_info_tree)) continue;
        
        ITERATE_AVL_TREE_BEGIN(proto_info_tree, proto_info_node) {
            
            proto_info = avltree_container_of(proto_info_node, rtm_proto_info_t, proto_glue);

            if (proto_info->proto != proto) continue;

            if (avltree_is_empty(&proto_info->sub_db)) continue;

            /* Iterate over Advt DB of each instance*/
            ITERATE_AVL_TREE_BEGIN(&proto_info->sub_db, sub_proto_advt_db_node) {
                
                sub_info = avltree_container_of(sub_proto_advt_db_node, rtm_rt_subscription_t, avl_glue);
                
                if ( !sub_info->cbk ) continue;

                if (sub_info->target_proto != nh->proto) continue;
                if (sub_info->target_sub_proto != RTM_SUB_PROTO_NA &&
                         sub_info->target_sub_proto != nh->sub_proto ) continue;
                if (sub_info->target_instance_no != nh->rtm_nh_proto->instance_no) continue;

                presentation_data = (rtm_presentation_data_t *)calloc(1, sizeof(rtm_presentation_data_t));
                presentation_data->nh = nh;
                rtm_nh_reference (nh);
                presentation_data->prefix_list = sub_info->prefix_list;
                if (presentation_data->prefix_list) prefix_list_reference (presentation_data->prefix_list);
                presentation_data->cbk = sub_info->cbk;
                Fglthread_add_last(&rtm->advt_queue, &presentation_data->glue);

            } ITERATE_AVL_TREE_END;

        } ITERATE_AVL_TREE_END;

        rtm_schedule_presentation_job (rtm);
    }
}

void 
rtm_on_demand_route_request (rtm_t *rtm, uint8_t vrf_id, uint8_t instance_no, RTM_PROTO_T proto) {

    rtm_nh *nh;
    rtm_route *route;
    glthread_t *path_node;
    avltree_t *proto_info_tree;
    avltree_node_t *route_node;
    rtm_proto_info_t *proto_info;
    rtm_rt_subscription_t *sub_info;
    avltree_node_t *proto_info_node;
    rtm_proto_info_t proto_info_template;
    avltree_node_t *sub_proto_advt_db_node;
    rtm_presentation_data_t *presentation_data;

    proto_info_tree = &rtm->proto_info_tree[proto];

    if (avltree_is_empty(proto_info_tree)) return;

    memset (&proto_info_template, 0, sizeof(avltree_node_t));
    proto_info_template.vrf_id = vrf_id;
    proto_info_template.instance_no = instance_no;
    proto_info_template.proto = proto;
    avltree_node_init (&proto_info_template.proto_glue);
    proto_info_node = avltree_lookup(&proto_info_template.proto_glue, proto_info_tree);
    if (!proto_info_node) return;

    proto_info = avltree_container_of(proto_info_node, rtm_proto_info_t, proto_glue);

    /* Iterate over all the paths in rtm->route_tree*/
    ITERATE_AVL_TREE_BEGIN(&rtm->route_tree, route_node) {

        route = avltree_container_of(route_node, rtm_route, route_glue);

        if (route->nh_count == 0) continue;

        /* Iterate over all the nexthops in route->path_list*/
        ITERATE_GLTHREAD_BEGIN(&route->path_list, path_node) {

            nh = route_glue_to_rtm_nh(path_node);

            /* All front nexthops are active */
            if (!nh->is_active) break;

            /* Iteratae over all subscriptions by this protocols */
            ITERATE_AVL_TREE_BEGIN(&proto_info->sub_db, sub_proto_advt_db_node) {
                
                sub_info = avltree_container_of(sub_proto_advt_db_node, rtm_rt_subscription_t, avl_glue);
                
                if ( !sub_info->cbk ) continue;

                if (sub_info->target_proto != nh->proto) continue;
                if (sub_info->target_sub_proto != RTM_SUB_PROTO_NA &&
                         sub_info->target_sub_proto != nh->sub_proto ) continue;
                if (sub_info->target_instance_no != nh->rtm_nh_proto->instance_no) continue;                
                
                presentation_data = (rtm_presentation_data_t *)calloc(1, sizeof(rtm_presentation_data_t));
                presentation_data->nh = nh;
                rtm_nh_reference (nh);
                presentation_data->prefix_list = sub_info->prefix_list;
                if (presentation_data->prefix_list) prefix_list_reference (presentation_data->prefix_list);
                presentation_data->cbk = sub_info->cbk;
                Fglthread_add_last(&rtm->advt_queue, &presentation_data->glue);
                rtm_schedule_presentation_job (rtm);

            } ITERATE_AVL_TREE_END;        
            
        } ITERATE_GLTHREAD_END(&route->path_list, path_node);

    } ITERATE_AVL_TREE_END;

    rtm_schedule_presentation_job (rtm);
}