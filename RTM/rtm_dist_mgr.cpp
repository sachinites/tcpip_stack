#include <assert.h>

#include "../libs/Tracer/tracer.h"
#include "../libs/LinuxMemoryManager/uapi_mm.h"

#include "../router_init.h"
#include "../libs/prefix-list/prefixlst.h"
#include "../net.h"
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

    bitmap_free_internal (&redis_rt->client_advert_tracker.proto_bitmap);
    bitmap_free_internal (&redis_rt->client_advert_tracker.vrf_id);
    bitmap_free_internal (&redis_rt->client_advert_tracker.instance_no);
    
    rtm_dist_mgr_check_and_delete (redis_rt);    

    return 0;
}   

void 
rtm_redist_target_record_rt_advertisement 
    (dist_mgr_t *dist_mgr, 
    redist_target_t *target, 
    rt_redist_route_t *dist_rt, bool add) {

    rt_advertised_node_t *node;

    if (add) {    
        node = (rt_advertised_node_t *)XCALLOC2(0, 1, rt_advertised_node_t);
        avltree_node_init (&node->glue);
        node->dist_rt = dist_rt;
        rt_redist_route_reference(dist_rt);
        assert(!avltree_insert(&node->glue, &target->rt_advertised));
        bitmap_set_bit_at (&dist_rt->client_advert_tracker.proto_bitmap, target->proto);
        bitmap_set_bit_at (&dist_rt->client_advert_tracker.vrf_id, target->vrf);
        bitmap_set_bit_at (&dist_rt->client_advert_tracker.instance_no, target->instance_no);
        return;
    }

    rt_advertised_node_t tmplate;
    avltree_node_init (&tmplate.glue);
    tmplate.dist_rt = dist_rt;

    avltree_node_t *avl_node = avltree_lookup (&tmplate.glue, &target->rt_advertised);
    assert (avl_node);

    node = avltree_container_of(avl_node, rt_advertised_node_t, glue);
    assert(avltree_remove (&node->glue, &target->rt_advertised));
    assert(node->dist_rt == dist_rt);

    node->dist_rt = NULL;
    bitmap_unset_bit_at (&dist_rt->client_advert_tracker.proto_bitmap, target->proto);
    bitmap_unset_bit_at (&dist_rt->client_advert_tracker.vrf_id, target->vrf);
    bitmap_unset_bit_at (&dist_rt->client_advert_tracker.instance_no, target->instance_no);
    rt_redist_route_dereference(dist_mgr, dist_rt);
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

            init_glthread (&redis_rt->redis_glue);
            redis_rt->is_deleted = false;
            redis_rt->ref_count = 0;

            bitmap_init(&redis_rt->client_advert_tracker.proto_bitmap, bitmap_next_32_divisible_integer((uint16_t)RTM_PROTO_MAX));
            bitmap_init(&redis_rt->client_advert_tracker.vrf_id, bitmap_next_32_divisible_integer((uint16_t)MAX_VRF_PER_NODE));
            bitmap_init(&redis_rt->client_advert_tracker.instance_no, bitmap_next_32_divisible_integer(32));
            
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

    if (rule->src_vrf_id != nh_proto->vrf_id) return false;
    
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

/* First rule on this target that permits redistribution of dist_rt (VRF + policy). */
static bool
rtm_dist_mgr_target_first_permitting_rule(
    redist_target_t *target,
    rt_redist_route_t *dist_rt,
    dist_rule_t **rule_out)
{
    dist_rule_t *rule;

    if (rule_out)
        *rule_out = NULL;

    if (dist_rt->is_deleted)
        return false;

    for (rule = target->rule_list; rule; rule = rule->next) {

        if (!rtm_dist_mgr_rule_source_matches(rule, dist_rt->nh_proto))
            continue;
        if (!rtm_dist_mgr_rule_filter_permits(rule, &dist_rt->prefix))
            continue;
        if (rule_out)
            *rule_out = rule;
        return true;
    }
    return false;
}

static inline void
rtm_dist_mgr_advert_fill_from_route(
    rt_advert_info_t *advert_info,
    rt_redist_route_t *dist_rt)
{
    memset(advert_info, 0, sizeof(*advert_info));
    memcpy(&advert_info->route, &dist_rt->prefix, sizeof(advert_info->route));
    advert_info->src_proto = dist_rt->nh_proto->proto;
    advert_info->src_vrf_id = dist_rt->nh_proto->vrf_id;
    advert_info->Cnhidx = dist_rt->Cnhidx;
}

extern void (*RT_DIST_HANDLERS[])(node_t *, rt_advert_info_t  *);

static void 
target_redis_cbk (
        event_dispatcher_t *ev_dis, 
        void *arg, uint32_t arg_size) {

    redist_target_t *target = (redist_target_t *)arg;
    glthread_t *curr;
    rt_advert_info_t *advert_info;

    target->client_flash_job = NULL;
    node_t *node = (node_t *)ev_dis->app_data;

    while ((curr = dequeue_glthread_first(&target->client_redis_queue.head))) {

        advert_info = redis_glue_to_rt_advert_info(curr);
        RT_DIST_HANDLERS[target->proto](node, advert_info);
        XFREE(advert_info);
    }
}

static inline void
rtm_dist_mgr_schedule_rt_advert_info_to_target (
                dist_mgr_t *dist_mgr, 
                redist_target_t *target, 
                rt_advert_info_t *advert_info) {

    Fglthread_add_last (&target->client_redis_queue,
                        &advert_info->redis_glue);

    if (target->client_flash_job) return;

    target->client_flash_job = task_create_new_job (EV(dist_mgr->node), 
                                    (void *)target, 
                                    target_redis_cbk,
                                    TASK_ONE_SHOT, 
                                    TASK_PRIORITY_COMPUTE);
}

void rtm_dist_mgr_distribute_route_to_target_clients(
            dist_mgr_t *dist_mgr, 
            rt_redist_route_t *dist_rt)
{
    char rt_str[48];
    dist_rule_t *rule;
    redist_target_t *target;
    rt_advert_info_t advert_tmplate;
    rt_advert_info_t *advert_info;

    /* Build route-derived advertisement template once; per-rule action fields
       are applied on cloned objects before queuing to targets. */
    rtm_dist_mgr_advert_fill_from_route(&advert_tmplate, dist_rt);

    /* This route has been deleted , withdraw it from all targets */
    if (dist_rt->is_deleted)
    {
        /* IF the route is deleted, withdraw it from all clientd we advertised it before */
        for (target = dist_mgr->target_lst; target; target = target->next)
        {
            if (redist_route_is_advertised_to_client(dist_rt, target))
            {
                advert_info = (rt_advert_info_t *)XCALLOC2(0, 1, rt_advert_info_t);
                memcpy(advert_info, &advert_tmplate, sizeof(*advert_info));
                init_glthread(&advert_info->redis_glue);
                advert_info->code = RTM_CLIENT_RT_DEL;

                tracer(dist_mgr->node->cptr, DREDIS_DET,
                       "REDIS-MGR : Withdraw %s from target proto %s instance %u vrf %u\n",
                       rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                       rtm_proto_to_string(target->proto),
                       target->instance_no,
                       target->vrf);

                rtm_dist_mgr_schedule_rt_advert_info_to_target(dist_mgr, target, advert_info);
                rtm_redist_target_record_rt_advertisement (dist_mgr, target, dist_rt, false);
            }
        }

        return;
    }

    /* 1. For all Target clients TC */
    for (target = dist_mgr->target_lst; target; target = target->next)
    {
        
        bool policy_permits = false;

        /* 2. For all Rules in TC */
        for (rule = target->rule_list; rule; rule = rule->next)
        {

            /* 3/4. Filter check : source protocol + prefix-list */
            if (!rtm_dist_mgr_rule_source_matches(rule, dist_rt->nh_proto)) continue;

            /* Policy permits this Route*/
            if (rtm_dist_mgr_rule_filter_permits(rule, &dist_rt->prefix))
            {

                policy_permits = true;

                /* Skip if this route already advertised */
                if (redist_route_is_advertised_to_client(dist_rt, target)) {

                    tracer(dist_mgr->node->cptr, DREDIS_DET,
                           "REDIS-MGR : Route %s already advertised to target proto %s instance %u vrf %u, skip re-advertisement\n",
                           rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                           rtm_proto_to_string(target->proto),
                           target->instance_no,
                           target->vrf);
                    break;
                }

                /* 5. Clone base advertisement, apply rule action and queue by pointer */
                advert_info = (rt_advert_info_t *)XCALLOC2(0, 1, rt_advert_info_t);
                memcpy(advert_info, &advert_tmplate, sizeof(*advert_info));
                advert_info->out_cost = rule->out_cost;
                advert_info->out_tag = rule->out_tag;
                advert_info->out_community = rule->out_community;
                advert_info->code = RTM_CLIENT_RT_ADD;
                init_glthread(&advert_info->redis_glue);

                tracer(dist_mgr->node->cptr, DREDIS_DET,
                       "REDIS-MGR : Advertise %s to target proto %s instance %u vrf %u\n",
                       rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                       rtm_proto_to_string(target->proto),
                       target->instance_no,
                       target->vrf);

                rtm_dist_mgr_schedule_rt_advert_info_to_target(dist_mgr, target, advert_info);
                rtm_redist_target_record_rt_advertisement(dist_mgr, target, dist_rt, true);
                break;
            }

            else
            {

                // goto next rule without breaking out of the loop to check if any other rule permits this route for this target
                continue;
            }
        } // rule loop ends

        /* If none of the rule permits, and if the route is already advertised, withdraw it */
        if (!policy_permits &&
            (redist_route_is_advertised_to_client(dist_rt, target)))
        {
            advert_info = (rt_advert_info_t *)XCALLOC2(0, 1, rt_advert_info_t);
            memcpy(advert_info, &advert_tmplate, sizeof(*advert_info));
            init_glthread(&advert_info->redis_glue);
            advert_info->code = RTM_CLIENT_RT_DEL;

            tracer(dist_mgr->node->cptr, DREDIS_DET,
                   "REDIS-MGR : Withdraw %s from target proto %s instance %u vrf %u\n",
                   rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                   rtm_proto_to_string(target->proto),
                   target->instance_no,
                   target->vrf);

            rtm_dist_mgr_schedule_rt_advert_info_to_target(dist_mgr, target, advert_info);
            rtm_redist_target_record_rt_advertisement(dist_mgr, target, dist_rt, false);
        }

    } // target loop ends 
}

/* This fn is called when route distribution Rule is added/deleted 
    under a protocol */
void
rtm_dist_mgr_refresh_dist_routes_to_target(
                        dist_mgr_t *dist_mgr,
                        redist_target_t *target)
{
    avltree_node_t *avl_node;
    rt_redist_route_t *dist_rt;
    dist_rule_t *rule;
    rt_advert_info_t advert_tmplate;
    rt_advert_info_t *advert_info;
    char rt_str[48];
    bool should_advert;
    bool is_advertised;

    ITERATE_AVL_TREE_BEGIN(&dist_mgr->nhidx_tree, avl_node)
    {
        dist_rt = avltree_container_of(avl_node, rt_redist_route_t, nhidx_glue);
        should_advert =
            rtm_dist_mgr_target_first_permitting_rule(target, dist_rt, &rule);
        is_advertised = redist_route_is_advertised_to_client(dist_rt, target);

        if (is_advertised && !should_advert) {

            rtm_dist_mgr_advert_fill_from_route(&advert_tmplate, dist_rt);
            advert_info = (rt_advert_info_t *)XCALLOC2(0, 1, rt_advert_info_t);
            memcpy(advert_info, &advert_tmplate, sizeof(*advert_info));
            init_glthread(&advert_info->redis_glue);
            advert_info->code = RTM_CLIENT_RT_DEL;

            tracer(dist_mgr->node->cptr, DREDIS_DET,
                   "REDIS-MGR : Policy flash withdraw %s from target proto %s instance %u vrf %u\n",
                   rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                   rtm_proto_to_string(target->proto),
                   target->instance_no,
                   target->vrf);

            rtm_dist_mgr_schedule_rt_advert_info_to_target(dist_mgr, target, advert_info);
            rtm_redist_target_record_rt_advertisement (dist_mgr, target, dist_rt, false);
        }
        else if (!is_advertised && should_advert) {

            rtm_dist_mgr_advert_fill_from_route(&advert_tmplate, dist_rt);
            advert_info = (rt_advert_info_t *)XCALLOC2(0, 1, rt_advert_info_t);
            memcpy(advert_info, &advert_tmplate, sizeof(*advert_info));
            advert_info->out_cost = rule->out_cost;
            advert_info->out_tag = rule->out_tag;
            advert_info->out_community = rule->out_community;
            advert_info->code = RTM_CLIENT_RT_ADD;
            init_glthread(&advert_info->redis_glue);

            tracer(dist_mgr->node->cptr, DREDIS_DET,
                   "REDIS-MGR : Policy flash advertise %s to target proto %s instance %u vrf %u\n",
                   rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                   rtm_proto_to_string(target->proto),
                   target->instance_no,
                   target->vrf);

            rtm_dist_mgr_schedule_rt_advert_info_to_target(dist_mgr, target, advert_info);
            rtm_redist_target_record_rt_advertisement (dist_mgr, target, dist_rt, true);
        }
    }
    ITERATE_AVL_TREE_END;
}



typedef struct dist_mgr_gc_container_ {

    DIST_MGR_GC_TYPE_T type;
    void *object;
    glthread_t glue;

} dist_mgr_gc_container_t;
GLTHREAD_TO_STRUCT(dist_mgr_gc_container_object, dist_mgr_gc_container_t, glue);


static void 
dist_mgr_check_and_delete (redist_target_t *target) {

    assert (!target->rule_list);
    assert (Fglthread_list_is_empty (&target->client_redis_queue));
    assert (!target->client_flash_job);
    assert (!target->next);
    assert (avltree_is_empty (&target->rt_advertised));
    XFREE  (target);
}

static void 
dist_mgr_release_all_target_resources (dist_mgr_t *dist_mgr, redist_target_t *target) {

    /* Free the Rule list. Each rule may hold a reference on its filter
       prefix-list which must be released before the rule itself is freed. */
    dist_rule_t *rule;

    while ((rule = target->rule_list)) {

        target->rule_list = rule->next;
        rule->next = NULL;
        if (rule->pfx_lst) prefix_list_dereference(rule->pfx_lst);
        XFREE(rule);
    }

    /* Release the routes advertised to this target i.e. target->rt_advertised.
       At GC time the client has already drained client_redis_queue, so we just
       tear down the bookkeeping: drop the per-target advertisement bit on each
       dist_rt, dereference the dist_rt, and free the avl entry. */
    avltree_node_t *avl_node;
    rt_advertised_node_t *adv_node;
    rt_redist_route_t *dist_rt;

    ITERATE_AVL_TREE_BEGIN(&target->rt_advertised, avl_node)
    {
        adv_node = avltree_container_of(avl_node, rt_advertised_node_t, glue);
        dist_rt = adv_node->dist_rt;

        avltree_remove(&adv_node->glue, &target->rt_advertised);
        adv_node->dist_rt = NULL;
        XFREE(adv_node);

        bitmap_unset_bit_at (&dist_rt->client_advert_tracker.proto_bitmap, target->proto);
        bitmap_unset_bit_at (&dist_rt->client_advert_tracker.vrf_id, target->vrf);
        bitmap_unset_bit_at (&dist_rt->client_advert_tracker.instance_no, target->instance_no);
        rt_redist_route_dereference(dist_mgr, dist_rt);

    } ITERATE_AVL_TREE_END;
}

static void 
dist_mgr_gc_job_cbk(
        event_dispatcher_t *ev_dis, 
        void *arg, uint32_t arg_size) {

    glthread_t *curr;
    dist_mgr_t *dist_mgr = (dist_mgr_t *)arg;
    dist_mgr_gc_container_t *container = NULL;

    dist_mgr->gc_task = NULL;

    while ((curr = dequeue_glthread_first(&dist_mgr->gc_queue.head))) {

        container = dist_mgr_gc_container_object(curr);
        
        switch (container->type) {

            case DIST_MGR_GC_TYPE_TARGET:
                dist_mgr_release_all_target_resources (dist_mgr, (redist_target_t *)container->object);
                dist_mgr_check_and_delete((redist_target_t *)container->object);
                break;
            default: ;
                break;
        }
        XFREE(container);
    }
}

void 
rtm_dis_mgr_gc (dist_mgr_t *dist_mgr, void *object, DIST_MGR_GC_TYPE_T type) {

    dist_mgr_gc_container_t *container = 
        (dist_mgr_gc_container_t *)XCALLOC2(0, 1, dist_mgr_gc_container_t);

    container->type = type;
    container->object = object;
    init_glthread(&container->glue);
    Fglthread_add_last (&dist_mgr->gc_queue, &container->glue);

    if (dist_mgr->gc_task) return;

    dist_mgr->gc_task = task_create_new_job (EV_PURGER(dist_mgr->node), 
                                    (void *)dist_mgr, 
                                    dist_mgr_gc_job_cbk,
                                    TASK_ONE_SHOT, 
                                    TASK_PRIORITY_GARBAGE_COLLECTOR);

}