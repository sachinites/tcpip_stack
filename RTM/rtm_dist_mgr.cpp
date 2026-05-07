#include <assert.h>

#include "../libs/Tracer/tracer.h"
#include "../libs/LinuxMemoryManager/uapi_mm.h"

#include "../router_init.h"
#include "../libs/prefix-list/prefixlst.h"
#include "rtm_dist_mgr.h"
#include "rtm_presentation.h"
#include "rtm_priv_api.h"
#include "rtm_nh.h"
#include "rtm_proto.h"

extern int cprintf (const char *format, ...);

extern inline void 
fib_set_nh_idx(
    uint64_t *p, 
    uint32_t inhidx, 
    uint32_t nhidx);

static void 
dist_mgr_schedule_route_advertise(dist_mgr_t *dist_mgr, rt_redist_route_t *dist_route);

static void 
rtm_dist_mgr_distribute_route_to_target_clients 
    (dist_mgr_t *dist_mgr, rt_redist_route_t *dist_rt);

static int
nhidx_tree_comp_fn(
    const avltree_node_t *node1,
    const avltree_node_t *node2)
{
    rt_redist_route_t *rt1 = avltree_container_of(
            node1, rt_redist_route_t, nhidx_glue);

    rt_redist_route_t *rt2 = avltree_container_of(
            node2, rt_redist_route_t, nhidx_glue);    

    if (rt1->Cnhidx < rt2->Cnhidx) return 1;
    if (rt1->Cnhidx > rt2->Cnhidx) return -1;
    return 0;
}

static int
prefix_tree_comp_fn(
    const avltree_node_t *node1,
    const avltree_node_t *node2)
{
    avl_prefix_node_t *pfx1 = avltree_container_of(
            node1, avl_prefix_node_t, glue);

    avl_prefix_node_t *pfx2 = avltree_container_of(
            node2, avl_prefix_node_t, glue);  

    return (cmn_prefix_compare (&pfx1->prefix, &pfx2->prefix));
}

static int
vrf_instance_tree_comp_fn(
    const avltree_node_t *node1,
    const avltree_node_t *node2)
{

    avl_vrf_node_t *vrf1 = avltree_container_of(
        node1, avl_vrf_node_t, glue);

    avl_vrf_node_t *vrf2 = avltree_container_of(
        node2, avl_vrf_node_t, glue);

    if (vrf1->vrf_no < vrf2->vrf_no)
        return 1;
    if (vrf1->vrf_no > vrf2->vrf_no)
        return -1;

    if (vrf1->instance_no < vrf2->instance_no)
        return 1;
    if (vrf1->instance_no > vrf2->instance_no)
        return -1;

    return 0;
}

void 
rtm_dist_mgr_init (node_t *node) {

    uint32_t i;

    dist_mgr_t *dist_mgr = (dist_mgr_t *)XCALLOC2(0, 1, dist_mgr_t);
    dist_mgr->node = node;
    dist_mgr->gc_task = NULL;
    dist_mgr->redis_task = NULL;

    dist_mgr->target_lst = NULL;

    avltree_init(&dist_mgr->nhidx_tree, nhidx_tree_comp_fn);
    avltree_init(&dist_mgr->route_tree_by_prefix, prefix_tree_comp_fn);

    for (i = 0; i < (uint32_t)RTM_SUB_PROTO_MAX; i++) {

        avltree_init(&dist_mgr->route_tree[AF_IPV4][i],  vrf_instance_tree_comp_fn);
        avltree_init(&dist_mgr->route_tree[AF_IPV6][i],  vrf_instance_tree_comp_fn);
        avltree_init(&dist_mgr->route_tree[AF_LABEL][i], vrf_instance_tree_comp_fn);
        avltree_init(&dist_mgr->route_tree[AF_MAC][i],   vrf_instance_tree_comp_fn);
    }

    init_Fglthread(&dist_mgr->redis_queue);
    init_Fglthread(&dist_mgr->gc_queue);

    node->dist_mgr = dist_mgr;
}

static void 
rt_redist_route_reference (rt_redist_route_t *redis_rt) {

    redis_rt->ref_count++;
}

static void 
rtm_dist_mgr_check_and_delete (rt_redist_route_t *redis_rt) {

    /* Check all linkages */
    XFREE(redis_rt);
}

static uint32_t
rt_redist_route_dereference (dist_mgr_t *dist_mgr, rt_redist_route_t *redis_rt) {

    redis_rt->ref_count--;
    
    if (redis_rt->ref_count) return redis_rt->ref_count;

    rtm_t *rtm = rtm_get_route_target_rtm(
                vrf_get_by_id (dist_mgr->node, redis_rt->nh_proto->vrf_id),
                redis_rt->prefix.afi,
                redis_rt->nh_proto->proto,
                redis_rt->nh_proto->sub_proto);

    rtm_nh_proto_dereference(rtm, redis_rt->nh_proto);
    redis_rt->nh_proto = NULL;
    rtm_dist_mgr_check_and_delete (redis_rt);    

    return 0;
}   

void 
rtm_distribution_manager_update (dist_mgr_t *dist_mgr,
                                 rtm_presentation_data_t *presentation_data) {

    int i, j;
    uint64_t Cnhidx;
    char rt_str[48];
    char nh_str[128];
    avltree_node_t *avl_node;
    rt_redist_route_t rt_tmplate;
    
    tracer (dist_mgr->node->cptr, DREDIS_DET,
        "REDIS-MGR : Route %s, NH %s(%u), Operation %s\n",
        rtm_format_prefix(&presentation_data->route, rt_str, sizeof(rt_str)),
        presentation_data->operation == RTM_PPT_OP_ADD ? \
        rtm_nh_one_liner_trace(presentation_data->nh, nh_str, sizeof(nh_str)) : "deleted",
        presentation_data->nh_idx,
        presentation_data->operation == RTM_PPT_OP_ADD ? "Add" : 
        presentation_data->operation == RTM_PPT_OP_UPDATE ? "Update" : "Delete");

    switch (presentation_data->operation) {

        case RTM_PPT_OP_ADD:
        {
            rt_redist_route_t *redis_rt = (rt_redist_route_t *)XCALLOC2(0, 1, rt_redist_route_t);

            fib_set_nh_idx(&Cnhidx, 
                presentation_data->inh_idx, 
                presentation_data->nh_idx);

            redis_rt->Cnhidx = Cnhidx;
            avltree_node_init (&redis_rt->nhidx_glue);

            memcpy(&redis_rt->prefix, &presentation_data->route, sizeof (redis_rt->prefix));
            init_glthread (&redis_rt->rt_pfx_lst_glue);
            init_glthread (&redis_rt->rt_src_lst_glue);

            redis_rt->nh_proto = presentation_data->rtm_nh_proto;
            rtm_nh_proto_reference(redis_rt->nh_proto);

            redis_rt->ref_count = 0;

            init_glthread (&redis_rt->redis_glue);

            avl_node = avltree_insert (&redis_rt->nhidx_glue, &dist_mgr->nhidx_tree);

            /* Insertion must succeed */
            assert(!avl_node);
            rt_redist_route_reference(redis_rt);


            avl_prefix_node_t pfx_node_tmplate;
            memcpy(&pfx_node_tmplate.prefix, 
                &presentation_data->route, sizeof (pfx_node_tmplate.prefix));
            avltree_node_init (&pfx_node_tmplate.glue);

            avl_node = avltree_lookup (&pfx_node_tmplate.glue, &dist_mgr->route_tree_by_prefix);
          
            avl_prefix_node_t *pfx_node = NULL;

            if (!avl_node) {

                pfx_node = (avl_prefix_node_t *)XCALLOC2(0, 1, avl_prefix_node_t);
                memcpy(&pfx_node->prefix, &presentation_data->route, sizeof (pfx_node->prefix));
                avltree_node_init (&pfx_node->glue);
                init_Fglthread(&pfx_node->rt_pfx_lst);                
                assert(!avltree_insert (&pfx_node->glue, &dist_mgr->route_tree_by_prefix));
            }
            else {

                pfx_node = avltree_container_of (avl_node, avl_prefix_node_t, glue);
            }

            Fglthread_add_next (&pfx_node->rt_pfx_lst, &pfx_node->rt_pfx_lst.head, &redis_rt->rt_pfx_lst_glue);
            rt_redist_route_reference(redis_rt);

            avl_vrf_node_t avl_vrf_node_tmplate;
            avl_vrf_node_tmplate.vrf_no = presentation_data->rtm_nh_proto->vrf_id;
            avl_vrf_node_tmplate.instance_no = presentation_data->rtm_nh_proto->instance_no;
            avltree_node_init (&avl_vrf_node_tmplate.glue);

            avl_node = avltree_lookup (&avl_vrf_node_tmplate.glue, 
                        &dist_mgr->route_tree[presentation_data->route.afi]
                                             [presentation_data->rtm_nh_proto->proto]);

            
            avl_vrf_node_t *avl_vrf_node = NULL;

            if (!avl_node) {

                avl_vrf_node = (avl_vrf_node_t *)XCALLOC2(0, 1, avl_vrf_node_t);
                avl_vrf_node->vrf_no = avl_vrf_node_tmplate.vrf_no;
                avl_vrf_node->instance_no = avl_vrf_node_tmplate.instance_no;
                avltree_node_init (&avl_vrf_node->glue);
                init_Fglthread(&avl_vrf_node->rt_src_lst); 
                assert(!avltree_insert (&avl_vrf_node->glue, 
                    &dist_mgr->route_tree[presentation_data->route.afi]
                                         [presentation_data->rtm_nh_proto->proto]));
            }
            else {

                avl_vrf_node = avltree_container_of (avl_node, avl_vrf_node_t, glue);
            }

            Fglthread_add_next (&avl_vrf_node->rt_src_lst, &avl_vrf_node->rt_src_lst.head, &redis_rt->rt_src_lst_glue);
            rt_redist_route_reference(redis_rt);

            dist_mgr_schedule_route_advertise (dist_mgr, redis_rt);
        }
        break;
        case RTM_PPT_OP_DELETE:
        {

            fib_set_nh_idx(&Cnhidx,
                presentation_data->inh_idx,
                presentation_data->nh_idx);

            rt_tmplate.Cnhidx = Cnhidx;
            avltree_node_init(&rt_tmplate.nhidx_glue);

            avl_node = avltree_lookup(&rt_tmplate.nhidx_glue, &dist_mgr->nhidx_tree);
            if (!avl_node) break;

            rt_redist_route_t *redis_rt = avltree_container_of(
                    avl_node, rt_redist_route_t, nhidx_glue);
            
            /* Get the extra lock to prevent premature deletion */
            rt_redist_route_reference(redis_rt);

            avltree_remove(&redis_rt->nhidx_glue, &dist_mgr->nhidx_tree);
            rt_redist_route_dereference(dist_mgr, redis_rt);

            /* Remove from prefix-keyed tree; prune the prefix node when empty */
            avl_prefix_node_t pfx_node_tmplate;
            memcpy(&pfx_node_tmplate.prefix, &redis_rt->prefix, sizeof(pfx_node_tmplate.prefix));
            avltree_node_init(&pfx_node_tmplate.glue);

            avl_node = avltree_lookup(&pfx_node_tmplate.glue, &dist_mgr->route_tree_by_prefix);
            assert(avl_node);
            avl_prefix_node_t *pfx_node = avltree_container_of(avl_node, avl_prefix_node_t, glue);
            remove_Fglthread(&pfx_node->rt_pfx_lst, &redis_rt->rt_pfx_lst_glue);
            rt_redist_route_dereference(dist_mgr, redis_rt);

            if (Fglthread_list_is_empty(&pfx_node->rt_pfx_lst)) {
                avltree_remove(&pfx_node->glue, &dist_mgr->route_tree_by_prefix);
                XFREE(pfx_node);
            }

            /* Remove from vrf/proto-keyed tree; prune the vrf node when empty */
            avl_vrf_node_t avl_vrf_node_tmplate;
            avl_vrf_node_tmplate.vrf_no     = redis_rt->nh_proto->vrf_id;
            avl_vrf_node_tmplate.instance_no = redis_rt->nh_proto->instance_no;
            avltree_node_init(&avl_vrf_node_tmplate.glue);

            avl_node = avltree_lookup(&avl_vrf_node_tmplate.glue,
                        &dist_mgr->route_tree[presentation_data->route.afi]
                                             [redis_rt->nh_proto->proto]);
            assert(avl_node);
            avl_vrf_node_t *avl_vrf_node = avltree_container_of(avl_node, avl_vrf_node_t, glue);
            remove_Fglthread(&avl_vrf_node->rt_src_lst, &redis_rt->rt_src_lst_glue);
            rt_redist_route_dereference(dist_mgr, redis_rt);

            if (Fglthread_list_is_empty(&avl_vrf_node->rt_src_lst)) {
                avltree_remove(&avl_vrf_node->glue,
                    &dist_mgr->route_tree[presentation_data->route.afi]
                                         [redis_rt->nh_proto->proto]);
                XFREE(avl_vrf_node);
            }

            redis_rt->is_deleted = true;
            dist_mgr_schedule_route_advertise(dist_mgr, redis_rt);

            /* Unlock the extra lock */
            rt_redist_route_dereference(dist_mgr, redis_rt);
        }
        break;
        case RTM_PPT_OP_UPDATE:
            assert(0);
    }
}

static void 
dist_mgr_redistrbution_job_cbk(
        event_dispatcher_t *ev_dis, 
        void *arg, uint32_t arg_size) {

    glthread_t *curr;
    dist_mgr_t *dist_mgr = (dist_mgr_t *)arg;
    rt_redist_route_t *dist_rt = NULL;

    dist_mgr->redis_task = NULL;

    while ((curr = dequeue_glthread_first(&dist_mgr->redis_queue.head))) {

        dist_rt = rt_redist_route_redis_glue_to_rt(curr);

        rtm_dist_mgr_distribute_route_to_target_clients (dist_mgr, dist_rt);
        remove_Fglthread(&dist_mgr->redis_queue, curr);
        rt_redist_route_dereference(dist_mgr, dist_rt);
    }
}

void 
dist_mgr_schedule_route_advertise(dist_mgr_t *dist_mgr, rt_redist_route_t *dist_rt) {

    if (!IS_GLTHREAD_LIST_EMPTY(&dist_rt->redis_glue)) return;

    Fglthread_add_last (&dist_mgr->redis_queue, &dist_rt->redis_glue);
    rt_redist_route_reference(dist_rt);

    if (dist_mgr->redis_task) return;

    dist_mgr->redis_task = task_create_new_job (EV(dist_mgr->node), 
                                    (void *)dist_mgr, 
                                    dist_mgr_redistrbution_job_cbk,
                                    TASK_ONE_SHOT, 
                                    TASK_PRIORITY_COMPUTE);
}

/* CLIENT Redistribution of Routes */

/* Algorithm : 

1. For all Target clients TC
2.   For all Rules in TC
3.     For all Filters in Rule
4.       If Filter matches dist_rt
5.         Add dist_rt to TC's client_redis_queue as rt_advert_info_t
6.           invoke clients Callback to notify of this route
7.     End For
8.   End For
9. End For

*/
static bool
rtm_dist_mgr_rule_source_matches (dist_rule_t *rule, rtm_nh_proto_t *nh_proto) {

    if (rule->src_proto != nh_proto->proto) return false;

    /* RTM_SUB_PROTO_NA on the rule acts as a wildcard for sub-protocol */
    if (rule->src_sub_proto != RTM_SUB_PROTO_NA &&
        rule->src_sub_proto != nh_proto->sub_proto) return false;

    if ((uint32_t)rule->src_instance_no != nh_proto->instance_no) return false;

    return true;
}

static bool
rtm_dist_mgr_rule_filter_permits (dist_rule_t *rule, cmn_prefix_t *prefix) {

    /* No filter configured => permit by default */
    if (!rule->pfx_lst) return true;

    /* prefix-list library currently supports IPv4 only.
       For non-IPv4 routes with a configured filter, deny to be safe. */
    if (prefix->afi != AF_IPV4) return false;

    return prefix_list_evaluate (prefix->u.v4_addr,
                                 prefix->prefix_len,
                                 rule->pfx_lst) == PFX_LST_PERMIT;
}

void 
rtm_dist_mgr_distribute_route_to_target_clients 
    (dist_mgr_t *dist_mgr, rt_redist_route_t *dist_rt) {

    redist_target_t *target;
    dist_rule_t *rule;
    char rt_str[48];

    /* 1. For all Target clients TC */
    for (target = dist_mgr->target_lst; target; target = target->next) {

        /* Honor the target's VRF scope: only advertise routes from the
           same VRF the client registered for */
        if (target->dst_vrf != dist_rt->nh_proto->vrf_id) continue;

        /* 2. For all Rules in TC */
        for (rule = target->rule_list; rule; rule = rule->next) {

            /* 3/4. Filter check : source protocol + prefix-list */
            if (!rtm_dist_mgr_rule_source_matches (rule, dist_rt->nh_proto)) continue;

            if (!rtm_dist_mgr_rule_filter_permits (rule, &dist_rt->prefix)) continue;

            /* 5. Build advertisement and queue it for the target */
            rt_advert_info_t *advert_info =
                (rt_advert_info_t *)XCALLOC2(0, 1, rt_advert_info_t);

            memcpy (&advert_info->route, &dist_rt->prefix, sizeof (advert_info->route));
            advert_info->src_proto    = dist_rt->nh_proto->proto;
            advert_info->out_cost     = rule->out_cost;
            advert_info->out_tag      = rule->out_tag;
            advert_info->out_community = rule->out_community;
            advert_info->Cnhidx       = dist_rt->Cnhidx;
            advert_info->is_delete    = dist_rt->is_deleted;
            init_glthread (&advert_info->redis_glue);

            if (!advert_info->is_delete) {
                Fglthread_add_last (&target->client_redis_queue,
                                &advert_info->redis_glue);
            }
            
            tracer (dist_mgr->node->cptr, DREDIS_DET,
                "REDIS-MGR : Advertise %s (%s) to target proto %s instance %u vrf %u\n",
                rtm_format_prefix (&dist_rt->prefix, rt_str, sizeof (rt_str)),
                advert_info->is_delete ? "delete" : "add",
                rtm_proto_to_string (target->dst_proto),
                target->dst_instance_no,
                target->dst_vrf);

            /* 6. Notify the client */
            if (target->redis_cbk) {
                target->redis_cbk (dist_mgr->node, advert_info);
            }

            /* One advertisement per target is enough; further matching rules
               for the same target would only generate duplicates */
            break;
        }
    }
}
