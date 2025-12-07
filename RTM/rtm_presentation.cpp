#include <string.h>
#include <stddef.h>
#include "../graph.h"
#include "rtm.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_presentation.h"
#include "rtm_proto.h"
#include "rtm_common.h"
#include "rtm_priv_api.h"
#include "../prefix-list/prefixlst.h"
#include "../EventDispatcher/event_dispatcher.h"
#include "../Tracer/tracer.h"

#define RTM_ADVT_COUNT_PREEMPTION_LIMIT 100

static void 
rtm_schedule_presentation_job (rtm_t *rtm) ;

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
                presentation_data->nh_idx = nh->idx;
                rtm_nh_reference (nh);
                presentation_data->prefix_list = sub_info->prefix_list;
                if (presentation_data->prefix_list) prefix_list_reference (presentation_data->prefix_list);
                presentation_data->operation = RTM_PPT_OP_ADD;  /* This is an ADD operation */
                presentation_data->cbk = sub_info->cbk;
                Fglthread_add_last(&rtm->advt_nhs[nh->proto], &presentation_data->glue);

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
                presentation_data->nh_idx = nh->idx;
                rtm_nh_reference (nh);
                presentation_data->prefix_list = sub_info->prefix_list;
                if (presentation_data->prefix_list) prefix_list_reference (presentation_data->prefix_list);
                presentation_data->operation = RTM_PPT_OP_ADD;  /* On-demand requests are ADDs */
                presentation_data->cbk = sub_info->cbk;
                Fglthread_add_last(&rtm->advt_nhs[nh->proto], &presentation_data->glue);
                rtm_schedule_presentation_job (rtm);

            } ITERATE_AVL_TREE_END;        
            
        } ITERATE_GLTHREAD_END(&route->path_list, path_node);

    } ITERATE_AVL_TREE_END;

    rtm_schedule_presentation_job (rtm);
}


/* APIs over RTM PPT DB */

/* Comparison function for rtm_ppt_route_t AVL tree */
static int
rtm_ppt_route_compare(const avltree_node_t *node1, const avltree_node_t *node2) {
    
    rtm_ppt_route_t *route1 = avltree_container_of(node1, rtm_ppt_route_t, route_glue);
    rtm_ppt_route_t *route2 = avltree_container_of(node2, rtm_ppt_route_t, route_glue);
    
    rtm_prefix_t *p1 = &route1->prefix;
    rtm_prefix_t *p2 = &route2->prefix;
    
    return rtm_prefix_compare(p1, p2);
}

void 
rtm_ppt_db_initialize(rtm_t *rtm) {
    
    avltree_init (&rtm->ppt_db_route_tree, rtm_ppt_route_compare);
}

static int
rtm_ppt_nhidx_compare(const void *_nh1, const void *_nh2) {
    rtm_ppt_nhidx_t *nh1 = (rtm_ppt_nhidx_t *)_nh1;
    rtm_ppt_nhidx_t *nh2 = (rtm_ppt_nhidx_t *)_nh2;
    
    if (nh1->nh_pidx < nh2->nh_pidx) return -1;
    if (nh1->nh_pidx > nh2->nh_pidx) return 1;
    return 0;
}

static int
rtm_uint32_compare(const void *_n1, const void *_n2) {
    uint32_t *n1 = (uint32_t *)_n1;
    uint32_t *n2 = (uint32_t *)_n2;
    
    if (*n1 < *n2) return -1;
    if (*n1 > *n2) return 1;
    return 0;
}

/* Helper function to calculate dnh_list pointer for flexible arrays */
/* For nhidx_list[i], dnh_list starts after all nhidx entries, then after dnhs of previous entries */
static uint32_t* get_dnh_ptr_for_nhidx(rtm_ppt_nhidx_t *nhidx_list, int idx, int total_nh_count) {
    char *base = (char *)nhidx_list;
    /* Skip all nhidx entries */
    char *ptr = base + (total_nh_count * sizeof(rtm_ppt_nhidx_t));
    /* Skip dnhs from previous entries */
    for (int i = 0; i < idx; i++) {
        ptr += nhidx_list[i].dnh_list_count * sizeof(uint32_t);
    }
    return (uint32_t *)ptr;
}

/* Helper function to get allocated route pointer from stack structure */
/* The allocated pointer is stored in route_glue field */
static rtm_ppt_route_t* get_allocated_route(rtm_ppt_route_t *stack_route) {
    if (!stack_route || stack_route->nhidx_list_count == 0) {
        return NULL;
    }
    return *(rtm_ppt_route_t **)((char *)stack_route + offsetof(rtm_ppt_route_t, route_glue));
}

rtm_ppt_route_t *
rtm_ppt_db_get_route (
        rtm_t *rtm, 
        rtm_route *route) {
        
    /* Create template for route lookup */
    rtm_ppt_route_t route_template;
    memset(&route_template, 0, sizeof(rtm_ppt_route_t));
    route_template.prefix = route->prefix;
    avltree_node_init(&route_template.route_glue);
    
    /* Look up the route entry */
    avltree_node_t *route_node = avltree_lookup(&route_template.route_glue, &rtm->ppt_db_route_tree);
    rtm_ppt_route_t *ppt_route = NULL;
    
    if (route_node) {
        ppt_route = avltree_container_of(route_node, rtm_ppt_route_t, route_glue);
        return ppt_route;
    }

    /* Create new EMPTY route entry - will be populated by rtm_ppt_route_update */
    ppt_route = (rtm_ppt_route_t *)calloc(1, sizeof(rtm_ppt_route_t));

    ppt_route->prefix = route->prefix;
    avltree_node_init(&ppt_route->route_glue);
    avltree_insert(&ppt_route->route_glue, &rtm->ppt_db_route_tree);
    ppt_route->nhidx_list_count = 0;

    return ppt_route;
}

/* Implement this function, This function Implements the diff logic.
    Compare the rtm_route *route with rtm_ppt_route_t *ppt_route and
    find which Nexthops are added new in rtm_route and which are deleted
    from rtm_route ( i.e present in ppt_route but not in rtm_route). Emit out
    Results : 
    rtm_ppt_route_t *out_add -- Contains all NHs and DNHs which are added
    rtm_ppt_route_t *out_del -- Contains all NHs and DNHs which are deleted
*/
void
rtm_ppt_route_diff (
    rtm_route *route, rtm_ppt_route_t *ppt_route,
    rtm_ppt_route_t *out_add,
    rtm_ppt_route_t *out_del) {
    
    if (!route || !ppt_route || !out_add || !out_del) return;
    
    /* Initialize output structures */
    memset(out_add, 0, sizeof(rtm_ppt_route_t));
    memset(out_del, 0, sizeof(rtm_ppt_route_t));
    out_add->prefix = route->prefix;
    out_del->prefix = route->prefix;
    
    /* Build current state from rtm_route - count active NHs and DNHs */
    rtm_nh *nh, *dnh;
    glthread_t *nh_glue, *dnh_glue;
    glthread_data_node_t *data_node;
    int active_nh_count = 0;
    int total_dnh_count = 0;
    
    ITERATE_GLTHREAD_BEGIN(&route->path_list, nh_glue) {
        nh = route_glue_to_rtm_nh(nh_glue);
        if (!nh->is_active) break;
        active_nh_count++;
        
        if (nh->is_indirect && rtm_nh_is_resolved(nh)) {
            ITERATE_GLTHREAD_BEGIN(&nh->direct_nh_list.head, dnh_glue) {
                total_dnh_count++;
            } ITERATE_GLTHREAD_END(&nh->direct_nh_list.head, dnh_glue);
        }
    } ITERATE_GLTHREAD_END(&route->path_list, nh_glue);
    
    /* Allocate memory for current state */
    rtm_ppt_nhidx_t *current_list = (rtm_ppt_nhidx_t *)malloc(
        (active_nh_count * sizeof(rtm_ppt_nhidx_t)) +
        (total_dnh_count * sizeof(uint32_t)));
    
    if (!current_list) return;
    
    memset(current_list, 0, 
           (active_nh_count * sizeof(rtm_ppt_nhidx_t)) +
           (total_dnh_count * sizeof(uint32_t)));
    
    /* Build current nexthop list */
    uint16_t current_count = 0;
    uint32_t *dnh_data_ptr = (uint32_t *)(current_list + active_nh_count);
    
    ITERATE_GLTHREAD_BEGIN(&route->path_list, nh_glue) {
        nh = route_glue_to_rtm_nh(nh_glue);
        if (!nh->is_active) break;
        
        current_list[current_count].nh_pidx = nh->idx;
        current_list[current_count].dnh_list_count = 0;
        
        if (nh->is_indirect && rtm_nh_is_resolved(nh)) {
            uint16_t dnh_idx = 0;
            uint32_t *dnh_list_ptr = get_dnh_ptr_for_nhidx(current_list, current_count, active_nh_count);
            
            ITERATE_GLTHREAD_BEGIN(&nh->direct_nh_list.head, dnh_glue) {
                data_node = glue_to_glthread_data_node(dnh_glue);
                dnh = (rtm_nh *)data_node->data;
                dnh_list_ptr[dnh_idx++] = dnh->idx;
                current_list[current_count].dnh_list_count++;
            } ITERATE_GLTHREAD_END(&nh->direct_nh_list.head, dnh_glue);
            
            /* Sort direct nexthops */
            if (current_list[current_count].dnh_list_count > 1) {
                qsort(dnh_list_ptr, 
                      current_list[current_count].dnh_list_count,
                      sizeof(uint32_t), rtm_uint32_compare);
            }
        }
        
        current_count++;
    } ITERATE_GLTHREAD_END(&route->path_list, nh_glue);
    
    /* Sort current list by nh_pidx */
    qsort(current_list, current_count, sizeof(rtm_ppt_nhidx_t), rtm_ppt_nhidx_compare);
    
    /* Now perform the diff using two-pointer technique */
    /* We need to track DNH additions/deletions separately for granular diff */
    int curr_idx = 0;
    int old_idx = 0;
    int add_count = 0;
    int del_count = 0;
    int add_dnh_count = 0;
    int del_dnh_count = 0;
    
    /* Count additions and deletions - granular DNH tracking */
    while (curr_idx < current_count && old_idx < ppt_route->nhidx_list_count) {
        if (current_list[curr_idx].nh_pidx < ppt_route->nhidx_list[old_idx].nh_pidx) {
            /* Current NH is new - it's an addition */
            add_count++;
            add_dnh_count += current_list[curr_idx].dnh_list_count;
            curr_idx++;
        } else if (current_list[curr_idx].nh_pidx > ppt_route->nhidx_list[old_idx].nh_pidx) {
            /* Old NH is missing - it's a deletion */
            del_count++;
            del_dnh_count += ppt_route->nhidx_list[old_idx].dnh_list_count;
            old_idx++;
        } else {
            /* Same NH - check if DNHs changed granularly */
            rtm_ppt_nhidx_t *curr_nh = &current_list[curr_idx];
            rtm_ppt_nhidx_t *old_nh = &ppt_route->nhidx_list[old_idx];
            
            /* Track DNH changes for this specific NH */
            int nh_add_dnh_count = 0;
            int nh_del_dnh_count = 0;
            
            /* Granular DNH diff: count only new and removed DNHs */
            if (curr_nh->dnh_list_count > 0 || old_nh->dnh_list_count > 0) {
                uint32_t *curr_dnh_list = get_dnh_ptr_for_nhidx(current_list, curr_idx, current_count);
                uint32_t *old_dnh_list = get_dnh_ptr_for_nhidx(ppt_route->nhidx_list, old_idx, ppt_route->nhidx_list_count);
                
                int curr_dnh = 0, old_dnh = 0;
                
                /* Count new DNHs (in current but not in old) */
                while (curr_dnh < curr_nh->dnh_list_count && old_dnh < old_nh->dnh_list_count) {
                    if (curr_dnh_list[curr_dnh] < old_dnh_list[old_dnh]) {
                        /* New DNH found */
                        nh_add_dnh_count++;
                        curr_dnh++;
                    } else if (curr_dnh_list[curr_dnh] > old_dnh_list[old_dnh]) {
                        /* Old DNH removed */
                        nh_del_dnh_count++;
                        old_dnh++;
                    } else {
                        /* Same DNH - skip both */
                        curr_dnh++;
                        old_dnh++;
                    }
                }
                
                /* Remaining current DNHs are additions */
                nh_add_dnh_count += (curr_nh->dnh_list_count - curr_dnh);
                
                /* Remaining old DNHs are deletions */
                nh_del_dnh_count += (old_nh->dnh_list_count - old_dnh);
            }
            
            /* If there are any DNH changes, we need to add entries for the indirect NH */
            if (nh_add_dnh_count > 0) {
                add_count++;
                add_dnh_count += nh_add_dnh_count;
            }
            if (nh_del_dnh_count > 0) {
                del_count++;
                del_dnh_count += nh_del_dnh_count;
            }
            
            curr_idx++;
            old_idx++;
        }
    }
    
    /* Remaining current items are additions */
    while (curr_idx < current_count) {
        add_count++;
        add_dnh_count += current_list[curr_idx].dnh_list_count;
        curr_idx++;
    }
    
    /* Remaining old items are deletions */
    while (old_idx < ppt_route->nhidx_list_count) {
        del_count++;
        del_dnh_count += ppt_route->nhidx_list[old_idx].dnh_list_count;
        old_idx++;
    }
    
    
    /* Free any existing allocations in out_add and out_del */
    /* Note: With flexible arrays, we need to free the entire structure, not just nhidx_list */
    /* But since out_add/out_del are stack variables, we can't free them here */
    /* The caller will handle freeing */
    
    /* Allocate memory for additions - use flexible array */
    rtm_ppt_route_t *add_route_alloc = NULL;
    if (add_count > 0) {
        add_route_alloc = (rtm_ppt_route_t *)calloc(1,
            sizeof(rtm_ppt_route_t) +
            add_count * sizeof(rtm_ppt_nhidx_t) +
            add_dnh_count * sizeof(uint32_t));
        
        if (add_route_alloc) {
            add_route_alloc->prefix = route->prefix;
            add_route_alloc->nhidx_list_count = 0;
            /* Copy base structure fields to out_add */
            out_add->prefix = add_route_alloc->prefix;
            out_add->nhidx_list_count = 0;
            /* Store allocated pointer in route_glue (temporary storage for cleanup) */
            *(rtm_ppt_route_t **)((char *)out_add + offsetof(rtm_ppt_route_t, route_glue)) = add_route_alloc;
        } else {
            memset(out_add, 0, sizeof(rtm_ppt_route_t));
        }
    } else {
        memset(out_add, 0, sizeof(rtm_ppt_route_t));
    }
    
    /* Allocate memory for deletions - use flexible array */
    rtm_ppt_route_t *del_route_alloc = NULL;
    if (del_count > 0) {
        del_route_alloc = (rtm_ppt_route_t *)calloc(1,
            sizeof(rtm_ppt_route_t) +
            del_count * sizeof(rtm_ppt_nhidx_t) +
            del_dnh_count * sizeof(uint32_t));
        
        if (del_route_alloc) {
            del_route_alloc->prefix = route->prefix;
            del_route_alloc->nhidx_list_count = 0;
            /* Copy base structure fields to out_del */
            out_del->prefix = del_route_alloc->prefix;
            out_del->nhidx_list_count = 0;
            /* Store allocated pointer in route_glue (temporary storage for cleanup) */
            *(rtm_ppt_route_t **)((char *)out_del + offsetof(rtm_ppt_route_t, route_glue)) = del_route_alloc;
        } else {
            memset(out_del, 0, sizeof(rtm_ppt_route_t));
        }
    } else {
        memset(out_del, 0, sizeof(rtm_ppt_route_t));
    }
    
    /* Fill in additions and deletions */
    curr_idx = 0;
    old_idx = 0;
    uint16_t add_idx = 0;
    uint16_t del_idx = 0;
    /* Calculate dnh pointers - they start after all nhidx entries */
    /* Use the allocated structures directly since we can't access flexible arrays from stack structures */
    uint32_t *add_dnh_ptr = NULL;
    uint32_t *del_dnh_ptr = NULL;
    if (add_count > 0 && add_route_alloc) {
        add_dnh_ptr = get_dnh_ptr_for_nhidx(add_route_alloc->nhidx_list, 0, add_count);
    }
    if (del_count > 0 && del_route_alloc) {
        del_dnh_ptr = get_dnh_ptr_for_nhidx(del_route_alloc->nhidx_list, 0, del_count);
    }
    
    while (curr_idx < current_count && old_idx < ppt_route->nhidx_list_count) {
        if (current_list[curr_idx].nh_pidx < ppt_route->nhidx_list[old_idx].nh_pidx) {
            /* Addition */
            if (add_route_alloc) {
                add_route_alloc->nhidx_list[add_idx].nh_pidx = current_list[curr_idx].nh_pidx;
                add_route_alloc->nhidx_list[add_idx].dnh_list_count = current_list[curr_idx].dnh_list_count;
                
                if (current_list[curr_idx].dnh_list_count > 0) {
                    uint32_t *src_dnh = get_dnh_ptr_for_nhidx(current_list, curr_idx, current_count);
                    uint32_t *dst_dnh = get_dnh_ptr_for_nhidx(add_route_alloc->nhidx_list, add_idx, add_count);
                    memcpy(dst_dnh, src_dnh,
                           current_list[curr_idx].dnh_list_count * sizeof(uint32_t));
                    add_dnh_ptr += current_list[curr_idx].dnh_list_count;
                }
                add_idx++;
            }
            curr_idx++;
        } else if (current_list[curr_idx].nh_pidx > ppt_route->nhidx_list[old_idx].nh_pidx) {
            /* Deletion */
            if (del_route_alloc) {
                del_route_alloc->nhidx_list[del_idx].nh_pidx = ppt_route->nhidx_list[old_idx].nh_pidx;
                del_route_alloc->nhidx_list[del_idx].dnh_list_count = ppt_route->nhidx_list[old_idx].dnh_list_count;
                
                if (ppt_route->nhidx_list[old_idx].dnh_list_count > 0) {
                    /* Get dnh_list pointer for this entry */
                    uint32_t *dnh_list_ptr = get_dnh_ptr_for_nhidx(del_route_alloc->nhidx_list, del_idx, del_count);
                    memcpy(dnh_list_ptr, 
                           get_dnh_ptr_for_nhidx(ppt_route->nhidx_list, old_idx, ppt_route->nhidx_list_count),
                           ppt_route->nhidx_list[old_idx].dnh_list_count * sizeof(uint32_t));
                    del_dnh_ptr += ppt_route->nhidx_list[old_idx].dnh_list_count;
                }
                del_idx++;
            }
            old_idx++;
        } else {
            /* Same NH - perform granular DNH diff */
            rtm_ppt_nhidx_t *curr_nh = &current_list[curr_idx];
            rtm_ppt_nhidx_t *old_nh = &ppt_route->nhidx_list[old_idx];
            
            /* Track new and removed DNHs separately - same logic as counting phase */
            uint16_t add_dnh_idx = 0;
            uint16_t del_dnh_idx = 0;
            
            if (curr_nh->dnh_list_count > 0 || old_nh->dnh_list_count > 0) {
                uint32_t *curr_dnh_list = get_dnh_ptr_for_nhidx(current_list, curr_idx, current_count);
                uint32_t *old_dnh_list = get_dnh_ptr_for_nhidx(ppt_route->nhidx_list, old_idx, ppt_route->nhidx_list_count);
                
                int curr_dnh = 0, old_dnh = 0;
                
                /* Find new and removed DNHs - same logic as counting phase */
                while (curr_dnh < curr_nh->dnh_list_count && old_dnh < old_nh->dnh_list_count) {
                    if (curr_dnh_list[curr_dnh] < old_dnh_list[old_dnh]) {
                        /* New DNH - add to additions */
                        if (add_route_alloc) {
                            if (add_dnh_idx == 0) {
                                /* First new DNH for this indirect NH - create entry */
                                add_route_alloc->nhidx_list[add_idx].nh_pidx = curr_nh->nh_pidx;
                                add_route_alloc->nhidx_list[add_idx].dnh_list_count = 0;
                            }
                            uint32_t *dst_dnh = get_dnh_ptr_for_nhidx(add_route_alloc->nhidx_list, add_idx, add_count);
                            dst_dnh[add_dnh_idx++] = curr_dnh_list[curr_dnh];
                            add_route_alloc->nhidx_list[add_idx].dnh_list_count++;
                        }
                        curr_dnh++;
                    } else if (curr_dnh_list[curr_dnh] > old_dnh_list[old_dnh]) {
                        /* Old DNH removed - add to deletions */
                        if (del_route_alloc) {
                            if (del_dnh_idx == 0) {
                                /* First removed DNH for this indirect NH - create entry */
                                del_route_alloc->nhidx_list[del_idx].nh_pidx = old_nh->nh_pidx;
                                del_route_alloc->nhidx_list[del_idx].dnh_list_count = 0;
                            }
                            uint32_t *dst_dnh = get_dnh_ptr_for_nhidx(del_route_alloc->nhidx_list, del_idx, del_count);
                            dst_dnh[del_dnh_idx++] = old_dnh_list[old_dnh];
                            del_route_alloc->nhidx_list[del_idx].dnh_list_count++;
                        }
                        old_dnh++;
                    } else {
                        /* Same DNH - skip both (don't add to add/del) */
                        curr_dnh++;
                        old_dnh++;
                    }
                }
                
                /* Remaining current DNHs are additions */
                while (curr_dnh < curr_nh->dnh_list_count) {
                    if (add_route_alloc) {
                        if (add_dnh_idx == 0) {
                            add_route_alloc->nhidx_list[add_idx].nh_pidx = curr_nh->nh_pidx;
                            add_route_alloc->nhidx_list[add_idx].dnh_list_count = 0;
                        }
                        uint32_t *dst_dnh = get_dnh_ptr_for_nhidx(add_route_alloc->nhidx_list, add_idx, add_count);
                        dst_dnh[add_dnh_idx++] = curr_dnh_list[curr_dnh];
                        add_route_alloc->nhidx_list[add_idx].dnh_list_count++;
                    }
                    curr_dnh++;
                }
                
                /* Remaining old DNHs are deletions */
                while (old_dnh < old_nh->dnh_list_count) {
                    if (del_route_alloc) {
                        if (del_dnh_idx == 0) {
                            del_route_alloc->nhidx_list[del_idx].nh_pidx = old_nh->nh_pidx;
                            del_route_alloc->nhidx_list[del_idx].dnh_list_count = 0;
                        }
                        uint32_t *dst_dnh = get_dnh_ptr_for_nhidx(del_route_alloc->nhidx_list, del_idx, del_count);
                        dst_dnh[del_dnh_idx++] = old_dnh_list[old_dnh];
                        del_route_alloc->nhidx_list[del_idx].dnh_list_count++;
                    }
                    old_dnh++;
                }
            }
            
            /* Update indices only if we created entries */
            if (add_dnh_idx > 0 && add_route_alloc) {
                add_idx++;
            }
            if (del_dnh_idx > 0 && del_route_alloc) {
                del_idx++;
            }
            
            curr_idx++;
            old_idx++;
        }
    }
    
    /* Process remaining additions */
    while (curr_idx < current_count) {
        if (add_route_alloc) {
            add_route_alloc->nhidx_list[add_idx].nh_pidx = current_list[curr_idx].nh_pidx;
            add_route_alloc->nhidx_list[add_idx].dnh_list_count = current_list[curr_idx].dnh_list_count;
            
            if (current_list[curr_idx].dnh_list_count > 0) {
                uint32_t *src_dnh = get_dnh_ptr_for_nhidx(current_list, curr_idx, current_count);
                uint32_t *dst_dnh = get_dnh_ptr_for_nhidx(add_route_alloc->nhidx_list, add_idx, add_count);
                memcpy(dst_dnh, src_dnh,
                       current_list[curr_idx].dnh_list_count * sizeof(uint32_t));
                add_dnh_ptr += current_list[curr_idx].dnh_list_count;
            }
            add_idx++;
        }
        curr_idx++;
    }
    
    /* Process remaining deletions */
    while (old_idx < ppt_route->nhidx_list_count) {
        if (del_route_alloc) {
            del_route_alloc->nhidx_list[del_idx].nh_pidx = ppt_route->nhidx_list[old_idx].nh_pidx;
            del_route_alloc->nhidx_list[del_idx].dnh_list_count = ppt_route->nhidx_list[old_idx].dnh_list_count;
            
            if (ppt_route->nhidx_list[old_idx].dnh_list_count > 0) {
                uint32_t *dnh_list_ptr = get_dnh_ptr_for_nhidx(del_route_alloc->nhidx_list, del_idx, del_count);
                memcpy(dnh_list_ptr,
                       get_dnh_ptr_for_nhidx(ppt_route->nhidx_list, old_idx, ppt_route->nhidx_list_count),
                       ppt_route->nhidx_list[old_idx].dnh_list_count * sizeof(uint32_t));
                del_dnh_ptr += ppt_route->nhidx_list[old_idx].dnh_list_count;
            }
            del_idx++;
        }
        old_idx++;
    }
    
    /* Update counts in output structures */
    if (add_route_alloc) {
        add_route_alloc->nhidx_list_count = add_idx;
        out_add->nhidx_list_count = add_idx;
    }
    if (del_route_alloc) {
        del_route_alloc->nhidx_list_count = del_idx;
        out_del->nhidx_list_count = del_idx;
    }
    
    /* Clean up */
    free(current_list);
}


void 
rtm_ppt_route_update (rtm_t *rtm, rtm_ppt_route_t **ppt_route_ptr,
    rtm_ppt_route_t *out_add,
    rtm_ppt_route_t *out_del) {
    
    if (!rtm || !ppt_route_ptr || !*ppt_route_ptr) return;
    
    rtm_ppt_route_t *ppt_route = *ppt_route_ptr;
    
    /* Handle the case where there are no changes */
    if ((!out_add || out_add->nhidx_list_count == 0) && 
        (!out_del || out_del->nhidx_list_count == 0)) {
        return;
    }
    
    /* Step 1: Get counts */
    int current_count = ppt_route->nhidx_list_count;
    int add_count = out_add ? out_add->nhidx_list_count : 0;
    int del_count = out_del ? out_del->nhidx_list_count : 0;
    
    rtm_ppt_route_t *add_alloc = out_add ? get_allocated_route(out_add) : NULL;
    rtm_ppt_route_t *del_alloc = out_del ? get_allocated_route(out_del) : NULL;
    
    /* Step 2: Calculate OLD total DNH count BEFORE any modifications */
    int old_total_dnh_count = 0;
    if (ppt_route->nhidx_list_count > 0) {
        for (int i = 0; i < current_count; i++) {
            old_total_dnh_count += ppt_route->nhidx_list[i].dnh_list_count;
        }
    }
    
    /* Step 3: Build a temporary working structure to calculate what the new state should be */
    /* We'll track: which INHs to keep, their final DNH counts */
    typedef struct {
        uint32_t nh_pidx;
        uint16_t dnh_count;
        uint32_t dnh_list[256]; /* Max DNHs per INH */
    } temp_nh_t;
    
    temp_nh_t *temp_list = (temp_nh_t *)calloc(current_count + add_count, sizeof(temp_nh_t));
    if (!temp_list) return;
    
    int temp_count = 0;
    
    /* Copy existing NHs to temp list */
    for (int i = 0; i < current_count; i++) {
        temp_list[temp_count].nh_pidx = ppt_route->nhidx_list[i].nh_pidx;
        temp_list[temp_count].dnh_count = ppt_route->nhidx_list[i].dnh_list_count;
        
        /* Copy DNHs */
        uint32_t *src_dnh = get_dnh_ptr_for_nhidx(ppt_route->nhidx_list, i, current_count);
        for (int d = 0; d < ppt_route->nhidx_list[i].dnh_list_count; d++) {
            temp_list[temp_count].dnh_list[d] = src_dnh[d];
        }
        temp_count++;
    }
    
    /* Step 4: Apply deletions to temp list */
    if (del_alloc && del_count > 0) {
        for (int d = 0; d < del_count; d++) {
            uint32_t del_nh_pidx = del_alloc->nhidx_list[d].nh_pidx;
            uint16_t del_dnh_count = del_alloc->nhidx_list[d].dnh_list_count;
            uint32_t *del_dnh = get_dnh_ptr_for_nhidx(del_alloc->nhidx_list, d, del_count);
            
            /* Find this NH in temp list */
            for (int t = 0; t < temp_count; t++) {
                if (temp_list[t].nh_pidx == del_nh_pidx) {
                    if (del_dnh_count == 0) {
                        /* Delete entire INH - shift array */
                        for (int s = t; s < temp_count - 1; s++) {
                            temp_list[s] = temp_list[s + 1];
                        }
                        temp_count--;
                    } else {
                        /* Delete specific DNHs */
                        uint16_t new_dnh_count = 0;
                        for (int e = 0; e < temp_list[t].dnh_count; e++) {
                            bool should_delete = false;
                            for (int dd = 0; dd < del_dnh_count; dd++) {
                                if (temp_list[t].dnh_list[e] == del_dnh[dd]) {
                                    should_delete = true;
                                    break;
                                }
                            }
                            if (!should_delete) {
                                temp_list[t].dnh_list[new_dnh_count++] = temp_list[t].dnh_list[e];
                            }
                        }
                        temp_list[t].dnh_count = new_dnh_count;
                        
                        /* If all DNHs deleted, remove the INH */
                        if (new_dnh_count == 0) {
                            for (int s = t; s < temp_count - 1; s++) {
                                temp_list[s] = temp_list[s + 1];
                            }
                            temp_count--;
                        }
                    }
                    break;
                }
            }
        }
    }
    
    /* Step 5: Apply additions to temp list */
    if (add_alloc && add_count > 0) {
        for (int a = 0; a < add_count; a++) {
            uint32_t add_nh_pidx = add_alloc->nhidx_list[a].nh_pidx;
            uint16_t add_dnh_count = add_alloc->nhidx_list[a].dnh_list_count;
            uint32_t *add_dnh = get_dnh_ptr_for_nhidx(add_alloc->nhidx_list, a, add_count);
            
            /* Check if this NH already exists */
            bool found = false;
            for (int t = 0; t < temp_count; t++) {
                if (temp_list[t].nh_pidx == add_nh_pidx) {
                    /* Merge DNHs */
                    if (add_dnh_count > 0) {
                        uint32_t merged[512];
                        int e = 0, n = 0, m = 0;
                        
                        /* Two-pointer merge */
                        while (e < temp_list[t].dnh_count && n < add_dnh_count) {
                            if (temp_list[t].dnh_list[e] < add_dnh[n]) {
                                merged[m++] = temp_list[t].dnh_list[e++];
                            } else if (temp_list[t].dnh_list[e] > add_dnh[n]) {
                                merged[m++] = add_dnh[n++];
                            } else {
                                merged[m++] = temp_list[t].dnh_list[e++];
                                n++;
                            }
                        }
                        while (e < temp_list[t].dnh_count) merged[m++] = temp_list[t].dnh_list[e++];
                        while (n < add_dnh_count) merged[m++] = add_dnh[n++];
                        
                        /* Update temp list */
                        temp_list[t].dnh_count = m;
                        memcpy(temp_list[t].dnh_list, merged, m * sizeof(uint32_t));
                    }
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                /* Add new INH */
                temp_list[temp_count].nh_pidx = add_nh_pidx;
                temp_list[temp_count].dnh_count = add_dnh_count;
                for (int d = 0; d < add_dnh_count; d++) {
                    temp_list[temp_count].dnh_list[d] = add_dnh[d];
                }
                temp_count++;
            }
        }
    }
    
    /* Step 6: Calculate NEW total DNH count */
    int new_total_dnh_count = 0;
    for (int t = 0; t < temp_count; t++) {
        new_total_dnh_count += temp_list[t].dnh_count;
    }
    
    /* Step 7: Since rtm_ppt_route_t uses flexible arrays, ANY change requires reallocation */
    bool needs_realloc = (temp_count != current_count) || (new_total_dnh_count != old_total_dnh_count);
    
    if (!needs_realloc) {
        /* Sanity check - should not happen */
        free(temp_list);
        return;
    }
    
    /* Step 8: Allocate new structure */
    rtm_ppt_route_t *new_route = NULL;
    new_route = (rtm_ppt_route_t *)calloc(1,
        sizeof(rtm_ppt_route_t) +
        temp_count * sizeof(rtm_ppt_nhidx_t) +
        new_total_dnh_count * sizeof(uint32_t));
    
    if (!new_route) {
        free(temp_list);
        return;
    }
    
    /* Copy prefix and initialize */
    new_route->prefix = ppt_route->prefix;
    new_route->route_glue = ppt_route->route_glue;
    new_route->nhidx_list_count = temp_count;
    
    /* Step 9: Copy from temp list to new structure */
    uint32_t *dnh_write_ptr = get_dnh_ptr_for_nhidx(new_route->nhidx_list, 0, temp_count);
    
    for (int t = 0; t < temp_count; t++) {
        new_route->nhidx_list[t].nh_pidx = temp_list[t].nh_pidx;
        new_route->nhidx_list[t].dnh_list_count = temp_list[t].dnh_count;
        
        /* Copy DNH list */
        memcpy(dnh_write_ptr, temp_list[t].dnh_list, temp_list[t].dnh_count * sizeof(uint32_t));
        dnh_write_ptr += temp_list[t].dnh_count;
    }
    
    /* Step 10: Sort by nh_pidx */
    if (temp_count > 1) {
        qsort(new_route->nhidx_list, temp_count, sizeof(rtm_ppt_nhidx_t), rtm_ppt_nhidx_compare);
    }
    
    /* Step 11: Replace old structure with new one */
    /* Remove old route from tree */
    avltree_remove(&ppt_route->route_glue, &rtm->ppt_db_route_tree);
    avltree_node_init(&ppt_route->route_glue);
    
    /* Free old structure */
    free(ppt_route);
    
    /* Update caller's pointer to point to new structure */
    *ppt_route_ptr = new_route;
    avltree_node_init(&new_route->route_glue);
    
    /* Insert new route into tree */
    avltree_insert(&new_route->route_glue, &rtm->ppt_db_route_tree);
    
    /* Clean up */
    free(temp_list);
}

static void
rtm_ppt_route_release_resources(rtm_t *rtm, rtm_ppt_route_t *ppt_route) {

    /* With flexible arrays, the entire structure is allocated as one block */
    /* So we don't need to free nhidx_list separately - it's part of the structure */
    /* This function is called before freeing the structure, so we don't need to do anything here */
    (void)rtm;
    (void)ppt_route;
}

static void 
rtm_ppt_route_check_and_delete (rtm_t *rtm, rtm_ppt_route_t *ppt_route) {

    rtm_ppt_route_release_resources (rtm, ppt_route);
    assert (!avltree_node_is_inuse (&ppt_route->route_glue));
    free (ppt_route);
}

void 
rtm_ppt_db_destroy(rtm_t *rtm) {
    
    avltree_node_t *node;
    rtm_ppt_route_t *ppt_route;
    
    ITERATE_AVL_TREE_BEGIN(&rtm->ppt_db_route_tree, node) {

        ppt_route = avltree_container_of(node, rtm_ppt_route_t, route_glue);
        avltree_remove (&ppt_route->route_glue, &rtm->ppt_db_route_tree);
        avltree_node_init(&ppt_route->route_glue);
        rtm_ppt_route_check_and_delete (rtm, ppt_route);

    } ITERATE_AVL_TREE_END;
    
    /* Verify tree is empty */
    assert(avltree_is_empty(&rtm->ppt_db_route_tree));
}

/* Algorithm : 
1. create or get rtm_ppt_route_t using rtm_ppt_db_get_route( ) API.
2. Compute rtm_ppt_route_t *out_add and rtm_ppt_route_t *out_del using rtm_ppt_route_diff ( )
3. Update the rtm_ppt_route_t using rtm_ppt_route_update ( ) API.
4. use the results out_add and out_del to advertise the routes to the appropriate protocols.
*/
void 
rtm_ppt_route_advertise (rtm_t *rtm, rtm_route *route) {
    
    avltree_t *proto_info_tree;
    rtm_proto_info_t *proto_info;
    rtm_rt_subscription_t *sub_info;
    avltree_node_t *proto_info_node;
    rtm_ppt_route_t out_add, out_del;
    avltree_node_t *sub_proto_advt_db_node;
    rtm_presentation_data_t *presentation_data;

    /* Get the first active nexthop to determine source protocol */
    glthread_t *first_nh_glue = BASE(&route->path_list);

    if (!first_nh_glue) return;
    
    rtm_nh *first_nh = route_glue_to_rtm_nh(first_nh_glue);

    if (!first_nh || !first_nh->is_active) return;
    
    RTM_PROTO_T src_proto = first_nh->proto;
    RTM_SUB_PROTO_T src_sub_proto = first_nh->sub_proto;
    uint32_t src_instance = first_nh->rtm_nh_proto ? \
                        first_nh->rtm_nh_proto->instance_no : 0;
    
    /* Step 1: Get or create cached route for this subscribing protocol */
    rtm_ppt_route_t *cached_route = rtm_ppt_db_get_route(rtm, route);
    
    rtm_ppt_route_diff(route, cached_route, &out_add, &out_del);

    for (int proto = 0; proto < RTM_PROTO_MAX; proto++) {
        
        proto_info_tree = &rtm->proto_info_tree[proto];
        
        if (avltree_is_empty(proto_info_tree)) continue;
        
        /* Iterate over all instances of this protocol type */
        ITERATE_AVL_TREE_BEGIN(proto_info_tree, proto_info_node) {
            
            proto_info = avltree_container_of(proto_info_node, rtm_proto_info_t, proto_glue);
            
            if (proto_info->proto != proto) continue;
            
            if (avltree_is_empty(&proto_info->sub_db)) continue;
            
            /* Iterate over all subscriptions for this protocol instance */
            ITERATE_AVL_TREE_BEGIN(&proto_info->sub_db, sub_proto_advt_db_node) {
                
                sub_info = avltree_container_of(sub_proto_advt_db_node, rtm_rt_subscription_t, avl_glue);
                
                if (!sub_info->cbk) continue;
                
                /* Check if this subscription matches the route's source */
                if (sub_info->target_proto != src_proto) continue;
                if (sub_info->target_sub_proto != RTM_SUB_PROTO_NA &&
                    sub_info->target_sub_proto != src_sub_proto) continue;
                if (sub_info->target_instance_no != src_instance) continue;
                
                /* Check prefix list filter */
                if (sub_info->prefix_list) {
                    if (prefix_list_evaluate(route->prefix.u.v4_addr,
                                            route->prefix.prefix_len,
                                            sub_info->prefix_list) != PFX_LST_PERMIT) {
                        continue;
                    }
                }
                
                /* Step 4a: Advertise deletions first */
                rtm_ppt_route_t *del_alloc = get_allocated_route(&out_del);
                    if (del_alloc) {
                        for (int i = 0; i < out_del.nhidx_list_count; i++) {
                            rtm_ppt_nhidx_t *nh_entry = &del_alloc->nhidx_list[i];
                        
                            /* Try to find the actual rtm_nh by index (may be NULL if already deleted) */
                            rtm_nh *nh = rtm_nh_lookup_by_idx(rtm, nh_entry->nh_pidx);
                            
                            /* If indirect and has direct nexthops, advertise deletion for each direct nexthop */
                            if (nh_entry->dnh_list_count > 0) {
                                uint32_t *dnh_list = get_dnh_ptr_for_nhidx(del_alloc->nhidx_list, i, out_del.nhidx_list_count);
                                
                                for (uint16_t dnh_idx = 0; dnh_idx < nh_entry->dnh_list_count; dnh_idx++) {
                                    rtm_nh *dnh = rtm_nh_lookup_by_idx(rtm, dnh_list[dnh_idx]);
                                    
                                    presentation_data = (rtm_presentation_data_t *)calloc(1, sizeof(rtm_presentation_data_t));
                                    
                                    presentation_data->nh = dnh;  /* May be NULL for DELETE operations */
                                    presentation_data->nh_idx = dnh_list[dnh_idx];  /* Always valid */
                                    presentation_data->route = route->prefix;
                                    if (dnh) {
                                        rtm_nh_reference(dnh);
                                    }
                                    presentation_data->prefix_list = sub_info->prefix_list;
                                    if (presentation_data->prefix_list) 
                                        prefix_list_reference(presentation_data->prefix_list);
                                    presentation_data->operation = RTM_PPT_OP_DELETE;  /* This is a DELETE */
                                    presentation_data->cbk = sub_info->cbk;
                                    
                                    /* Determine protocol: use dnh->proto if available, else use src_proto as fallback */
                                    RTM_PROTO_T nh_proto = dnh ? dnh->proto : src_proto;
                                    Fglthread_add_last(&rtm->advt_nhs[nh_proto], &presentation_data->glue);
                                }
                            } else {
                                /* Direct nexthop or unresolved indirect - advertise deletion of the nexthop itself */
                                presentation_data = (rtm_presentation_data_t *)calloc(1, sizeof(rtm_presentation_data_t));
                                if (!presentation_data) continue;
                                
                                presentation_data->nh = nh;  /* May be NULL for DELETE operations */
                                presentation_data->nh_idx = nh_entry->nh_pidx;  /* Always valid */
                                presentation_data->route = route->prefix;
                                if (nh) {
                                    rtm_nh_reference(nh);
                                }
                                presentation_data->prefix_list = sub_info->prefix_list;
                                if (presentation_data->prefix_list) 
                                    prefix_list_reference(presentation_data->prefix_list);
                                presentation_data->operation = RTM_PPT_OP_DELETE;  /* This is a DELETE */
                                presentation_data->cbk = sub_info->cbk;
                                
                                /* Determine protocol: use nh->proto if available, else use src_proto as fallback */
                                RTM_PROTO_T nh_proto = nh ? nh->proto : src_proto;
                                Fglthread_add_last(&rtm->advt_nhs[nh_proto], &presentation_data->glue);
                            }
                        }
                    }
                    
                    /* Step 4b: Advertise additions */
                    rtm_ppt_route_t *add_alloc = get_allocated_route(&out_add);
                    if (add_alloc) {
                        for (int i = 0; i < out_add.nhidx_list_count; i++) {
                            rtm_ppt_nhidx_t *nh_entry = &add_alloc->nhidx_list[i];
                            
                            /* Find the actual rtm_nh by index */
                            rtm_nh *nh = rtm_nh_lookup_by_idx(rtm, nh_entry->nh_pidx);
                            if (!nh) continue;
                            
                            /* If indirect and resolved, advertise each direct nexthop */
                            if (nh->is_indirect && rtm_nh_is_resolved(nh) && nh_entry->dnh_list_count > 0) {
                                uint32_t *dnh_list = get_dnh_ptr_for_nhidx(add_alloc->nhidx_list, i, out_add.nhidx_list_count);
                                
                                for (uint16_t dnh_idx = 0; dnh_idx < nh_entry->dnh_list_count; dnh_idx++) {
                                    rtm_nh *dnh = rtm_nh_lookup_by_idx(rtm, dnh_list[dnh_idx]);
                                    if (!dnh) continue;
                                    
                                    presentation_data = (rtm_presentation_data_t *)calloc(1, sizeof(rtm_presentation_data_t));
                                    if (!presentation_data) continue;
                                    
                                    presentation_data->nh = dnh;  /* Wrap direct nexthop */
                                    presentation_data->nh_idx = dnh->idx;
                                    presentation_data->route = nh->owner_route->prefix;
                                    rtm_nh_reference(dnh);
                                    presentation_data->prefix_list = sub_info->prefix_list;
                                    if (presentation_data->prefix_list) 
                                        prefix_list_reference(presentation_data->prefix_list);
                                    presentation_data->operation = RTM_PPT_OP_ADD;  /* This is an ADD */
                                    presentation_data->cbk = sub_info->cbk;
                                    Fglthread_add_last(&rtm->advt_nhs[dnh->proto], &presentation_data->glue);
                                }
                            } else {
                                /* Direct nexthop or unresolved indirect - advertise the nexthop itself */
                                presentation_data = (rtm_presentation_data_t *)calloc(1, sizeof(rtm_presentation_data_t));
                                if (!presentation_data) continue;
                                
                                presentation_data->nh = nh;
                                presentation_data->nh_idx = nh_entry->nh_pidx;
                                presentation_data->route = nh->owner_route->prefix;
                                rtm_nh_reference(nh);
                                presentation_data->prefix_list = sub_info->prefix_list;
                                if (presentation_data->prefix_list) 
                                    prefix_list_reference(presentation_data->prefix_list);
                                presentation_data->operation = RTM_PPT_OP_ADD;  /* This is an ADD */
                                presentation_data->cbk = sub_info->cbk;
                                Fglthread_add_last(&rtm->advt_nhs[nh->proto], &presentation_data->glue);
                            }
                        }
                    }
                
            } ITERATE_AVL_TREE_END;
            
        } ITERATE_AVL_TREE_END;
    }
    /* Step 3: Update the cached route */
    rtm_ppt_route_update(rtm, &cached_route, &out_add, &out_del);
    assert (rtm_ppt_route_is_equal (route, cached_route));

    /* Clean up diff results - with flexible arrays, we need to free the entire structures */
    /* The allocated pointers are stored in route_glue field (temporary storage) */
    if (out_add.nhidx_list_count > 0) {
        rtm_ppt_route_t *allocated = *(rtm_ppt_route_t **)((char *)&out_add + offsetof(rtm_ppt_route_t, route_glue));
        if (allocated) {
            free(allocated);
        }
    }
    if (out_del.nhidx_list_count > 0) {
        rtm_ppt_route_t *allocated = *(rtm_ppt_route_t **)((char *)&out_del + offsetof(rtm_ppt_route_t, route_glue));
        if (allocated) {
            free(allocated);
        }
    }

    /* Schedule the presentation job to process the advertisement queue */
    rtm_schedule_presentation_job(rtm);
}

void 
rtm_ppt_route_db_delete (rtm_t *rtm, rtm_prefix_t *prefix) {

    rtm_ppt_route_t *ppt_route;
    rtm_ppt_route_t ppt_route_template = {0};

    ppt_route_template.prefix = *prefix;
    avltree_node_init (&ppt_route_template.route_glue);

    avltree_node_t *node = avltree_lookup(
            &ppt_route_template.route_glue, &rtm->ppt_db_route_tree);

    if (!node) return;

    ppt_route = avltree_container_of(node, rtm_ppt_route_t, route_glue);

    avltree_remove (&ppt_route->route_glue, &rtm->ppt_db_route_tree);
    avltree_node_init(&ppt_route->route_glue);
    rtm_ppt_route_check_and_delete (rtm, ppt_route);
}

bool 
rtm_ppt_route_is_equal (rtm_route *route, rtm_ppt_route_t *ppt_route) {
    
    if (!route || !ppt_route) return false;
    
    /* Step 1: Build current active nexthop list from rtm_route */
    rtm_nh *nh, *dnh;
    glthread_t *nh_glue, *dnh_glue;
    glthread_data_node_t *data_node;
    int active_nh_count = 0;
    int total_dnh_count = 0;
    
    /* Count active nexthops and DNHs */
    ITERATE_GLTHREAD_BEGIN(&route->path_list, nh_glue) {
        nh = route_glue_to_rtm_nh(nh_glue);
        if (!nh->is_active) break;
        
        active_nh_count++;
        
        if (nh->is_indirect && rtm_nh_is_resolved(nh)) {
            ITERATE_GLTHREAD_BEGIN(&nh->direct_nh_list.head, dnh_glue) {
                total_dnh_count++;
            } ITERATE_GLTHREAD_END(&nh->direct_nh_list.head, dnh_glue);
        }
    } ITERATE_GLTHREAD_END(&route->path_list, nh_glue);
    
    /* Quick count check */
    if (active_nh_count != ppt_route->nhidx_list_count) {
        return false;
    }
    
    /* If both are empty, they're equal */
    if (active_nh_count == 0) {
        return true;
    }
    
    /* Step 2: Build sorted list from current route state */
    rtm_ppt_nhidx_t *current_list = (rtm_ppt_nhidx_t *)malloc(
        (active_nh_count * sizeof(rtm_ppt_nhidx_t)) +
        (total_dnh_count * sizeof(uint32_t)));
    
    if (!current_list) return false;
    
    memset(current_list, 0, 
           (active_nh_count * sizeof(rtm_ppt_nhidx_t)) +
           (total_dnh_count * sizeof(uint32_t)));
    
    /* Build current nexthop list */
    uint16_t current_count = 0;
    
    ITERATE_GLTHREAD_BEGIN(&route->path_list, nh_glue) {
        nh = route_glue_to_rtm_nh(nh_glue);
        if (!nh->is_active) break;
        
        current_list[current_count].nh_pidx = nh->idx;
        current_list[current_count].dnh_list_count = 0;
        
        if (nh->is_indirect && rtm_nh_is_resolved(nh)) {
            uint16_t dnh_idx = 0;
            uint32_t *dnh_list_ptr = get_dnh_ptr_for_nhidx(current_list, current_count, active_nh_count);
            
            ITERATE_GLTHREAD_BEGIN(&nh->direct_nh_list.head, dnh_glue) {
                data_node = glue_to_glthread_data_node(dnh_glue);
                dnh = (rtm_nh *)data_node->data;
                dnh_list_ptr[dnh_idx++] = dnh->idx;
                current_list[current_count].dnh_list_count++;
            } ITERATE_GLTHREAD_END(&nh->direct_nh_list.head, dnh_glue);
            
            /* Sort direct nexthops */
            if (current_list[current_count].dnh_list_count > 1) {
                qsort(dnh_list_ptr, 
                      current_list[current_count].dnh_list_count,
                      sizeof(uint32_t), rtm_uint32_compare);
            }
        }
        
        current_count++;
    } ITERATE_GLTHREAD_END(&route->path_list, nh_glue);
    
    /* Sort current list by nh_pidx */
    if (current_count > 1) {
        qsort(current_list, current_count, sizeof(rtm_ppt_nhidx_t), rtm_ppt_nhidx_compare);
    }
    
    /* Step 3: Compare current list with ppt_route list */
    bool is_equal = true;
    
    /* Both lists should have same count (already checked above) */
    for (int i = 0; i < current_count && is_equal; i++) {
        /* Compare primary nexthop index */
        if (current_list[i].nh_pidx != ppt_route->nhidx_list[i].nh_pidx) {
            is_equal = false;
            break;
        }
        
        /* Compare DNH count */
        if (current_list[i].dnh_list_count != ppt_route->nhidx_list[i].dnh_list_count) {
            is_equal = false;
            break;
        }
        
        /* Compare each DNH index */
        if (current_list[i].dnh_list_count > 0) {
            uint32_t *curr_dnh = get_dnh_ptr_for_nhidx(current_list, i, current_count);
            uint32_t *ppt_dnh = get_dnh_ptr_for_nhidx(ppt_route->nhidx_list, i, ppt_route->nhidx_list_count);
            for (int j = 0; j < current_list[i].dnh_list_count; j++) {
                if (curr_dnh[j] != ppt_dnh[j]) {
                    is_equal = false;
                    break;
                }
            }
        }
    }
    
    /* Clean up */
    free(current_list);
    
    return is_equal;
}

static void
rtm_advt_dispatch_job_cbk(event_dispatcher_t *ev __attribute__((unused)), 
            void *arg, 
            uint32_t arg_size __attribute__((unused)))
{
    uint8_t proto;
    char nh_str[48];
    glthread_t *curr;
    char route_str[48];
    uint32_t count = 0;

    rtm_t *rtm = (rtm_t *)arg;
    rtm->advt_job = NULL;

    rtm_presentation_data_t *presentation_data = NULL;
    
    for (proto = RTM_PROTO_STATIC; proto < RTM_PROTO_MAX; proto++)
    {

        while ((curr = dequeue_glthread_first(&rtm->advt_nhs[proto].head)))
        {

            presentation_data =
                (rtm_presentation_data_t *)rtm_presentation_data_to_glue(curr);

            /* Evaluate against prefix list */
            if (!presentation_data->prefix_list)
            {

                presentation_data->cbk(rtm, presentation_data->nh_idx,
                                       presentation_data->nh,
                                       presentation_data->operation);
            }
            else if (presentation_data->nh &&
                     ((prefix_list_evaluate(presentation_data->nh->owner_route->prefix.u.v4_addr,
                                            presentation_data->nh->owner_route->prefix.prefix_len,
                                            presentation_data->prefix_list) == PFX_LST_PERMIT)))
            {

                presentation_data->cbk(rtm, presentation_data->nh_idx,
                                       presentation_data->nh,
                                       presentation_data->operation);
            }

            tracer (rtm->node->cptr, DRTM, 
                "RTM[%s] : PPT-DB : Route %s : Presentation data for NH %s(%u), operation %d\n",
                    rtm->name, 
                    rtm_format_prefix(&presentation_data->route, route_str, sizeof(route_str)),
                    presentation_data->nh ? \
                    rtm_format_nexthop(&presentation_data->nh->prefix, nh_str, sizeof(nh_str)):
                    "deleted",
                    presentation_data->nh_idx, presentation_data->operation);

            if (presentation_data->nh)
            {
                rtm_nh_dereference(rtm, presentation_data->nh);
            }

            if (presentation_data->prefix_list) {
                prefix_list_dereference(presentation_data->prefix_list);
            }

            free(presentation_data);
            
            count++;

            if (count == RTM_ADVT_COUNT_PREEMPTION_LIMIT)
            {
                rtm_schedule_presentation_job(rtm);
                return;
            }
        }
    }
}

void 
rtm_schedule_presentation_job (rtm_t *rtm) {

    if (rtm->advt_job) return;

    rtm->advt_job = task_create_new_job ( EV(rtm->node),
             (void *)rtm,
             rtm_advt_dispatch_job_cbk,
             TASK_ONE_SHOT, TASK_PRIORITY_COMPUTE );
}

static void
rtm_advt_route_advt_prep_job_cbk(
        event_dispatcher_t *ev, 
        void *arg, 
        uint32_t arg_size) {

    rtm_route *route;
    glthread_t *curr;
    rtm_t *rtm = (rtm_t *)arg;

    rtm->route_advt_prep_job = NULL;

    while ((curr = dequeue_glthread_first(&rtm->route_advt_queue.head))) {

        route = advt_glue_to_route(curr);
        rtm_ppt_route_advertise (rtm , route);        
        rtm_route_dereference(rtm, route);
    }

    rtm_schedule_presentation_job (rtm);
}

void 
rtm_schedule_route_advertisement (rtm_t *rtm, rtm_route *route) {

    if (IS_QUEUED_UP_IN_THREAD (&route->advt_glue)) return;

    /* Populate rtm PPT DB */
    rtm_ppt_db_get_route(rtm, route);

    rtm_route_Fglthread_add_last (route, &rtm->route_advt_queue, &route->advt_glue);

    if (rtm->route_advt_prep_job) return;

    rtm->route_advt_prep_job = task_create_new_job (
            EV(rtm->node),
            (void *)rtm,
            rtm_advt_route_advt_prep_job_cbk,
            TASK_ONE_SHOT, TASK_PRIORITY_COMPUTE );
}