/*
 * =====================================================================================
 *
 *       Filename:  rtm_presentation.cpp
 *
 *    Description:  RTM Presentation Layer - FIB Updates and Route Advertisement
 *
 *        This file implements the presentation layer that sits between RTM and FIB.
 *        It handles route advertisement, diff computation, and FIB updates when
 *        routes change.
 *
 *        Presentation Layer Architecture:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ RTM (Routing Table Manager)                                 │
 *        │   └─> Route Changes Detected                                │
 *        │       └─> Presentation Layer                                  │
 *        │           ├─> Compute Diff (old vs new)                    │
 *        │           ├─> Queue for Advertisement                        │
 *        │           └─> FIB Interface                                 │
 *        │               └─> Update FIB (Forwarding Information Base)  │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Diff Computation:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ Old State (PPT DB)        New State (RTM)                   │
 *        │   Route: 10.0.0.0/8        Route: 10.0.0.0/8              │
 *        │     NH: 1.1.1.1              NH: 1.1.1.1 (unchanged)       │
 *        │     NH: 2.2.2.2              NH: 3.3.3.3 (changed)         │
 *        │                              NH: 4.4.4.4 (new)              │
 *        │                                                              │
 *        │ Diff Result:                                               │
 *        │   ADD:  NH: 4.4.4.4                                        │
 *        │   DEL:  NH: 2.2.2.2                                        │
 *        │   MOD:  NH: 3.3.3.3 (replaces 2.2.2.2)                     │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Advertisement Flow:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ 1. Route changes in RTM                                     │
 *        │ 2. Route added to advertisement queue                       │
 *        │ 3. Advertisement prep job runs                               │
 *        │    - Compute diff between old and new state                 │
 *        │    - Create ADD/DEL operations                               │
 *        │ 4. Advertisement job runs                                   │
 *        │    - Process ADD/DEL operations                              │
 *        │    - Update FIB                                              │
 *        │    - Update PPT DB (Presentation DB)                         │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Version:  1.0
 *        Created:  [Original Date]
 *       Revision:  1.0
 *       Compiler:  gcc/g++
 *
 * =====================================================================================
 */

#include <string.h>
#include <stddef.h>
#include <assert.h>
#include "../router_init.h"
#include "rtm.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_presentation.h"
#include "rtm_proto.h"
#include "rtm_gc.h"
#include "rtm_priv_api.h"
#include "rtm_fib_interface.h"
#include "../libs/prefix-list/prefixlst.h"
#include "../libs/EventDispatcher/event_dispatcher.h"
#include "../libs/Tracer/tracer.h"
#include "../lmm_enums.h"
#include "../libs/LinuxMemoryManager/uapi_mm.h"

#define RTM_ADVT_COUNT_PREEMPTION_LIMIT 100

/* ========================================================================
 * Forward Declarations
 * ======================================================================== */

static void 
rtm_schedule_presentation_job (rtm_t *rtm) ;

/* ========================================================================
 * On-Demand Route Advertisement
 * ======================================================================== */

/**
 * @brief Handle on-demand route request from protocol
 * 
 * When a protocol requests routes (e.g., during protocol startup),
 * this function iterates through all routes in the RTM and creates
 * advertisement entries for all active, resolved nexthops.
 * 
 * This is used for:
 * - Protocol initialization (sending all existing routes)
 * - Route refresh requests
 * - Protocol reconnection scenarios
 * 
 * @param rtm Pointer to routing table
 * @param vrf_id VRF identifier
 * @param instance_no Protocol instance number
 * @param proto Protocol type requesting routes
 */
void rtm_on_demand_route_request(rtm_t *rtm, uint8_t vrf_id,
                                 uint8_t instance_no,
                                 RTM_PROTO_T proto)
{
    rtm_route *route;
    rtm_nh *nh, *dnh;
    glthread_t *path_node;
    avltree_node_t *route_node;
    glthread_t *data_node_thread;
    glthread_data_node_t *data_node;
    rtm_presentation_data_t *presentation_data;

    /* Iterate over all the paths in rtm->route_tree*/
    ITERATE_AVL_TREE_BEGIN(&rtm->route_tree, route_node)
    {
        route = avltree_container_of(route_node, rtm_route, route_glue);

        if (route->nh_count == 0) continue;

        /* Iterate over all the nexthops in route->path_list*/
        ITERATE_GLTHREAD_BEGIN(&route->path_list, path_node)
        {
            nh = route_glue_to_rtm_nh(path_node);

            /* All front nexthops are active */
            if (!nh->is_active) break;
            if (!rtm_nh_is_resolved(nh)) continue;

            if (nh->is_indirect)
            {
                ITERATE_GLTHREAD_BEGIN(&nh->direct_nh_list.head, data_node_thread)
                {
                    data_node = glue_to_glthread_data_node(data_node_thread);
                    dnh = (rtm_nh *)(data_node->data);
                    presentation_data = (rtm_presentation_data_t *)XCALLOC2(
                            0, 1, rtm_presentation_data_t);
                    presentation_data->nh = dnh;
                    rtm_nh_reference(dnh);
                    presentation_data->inh = nh;
                    rtm_nh_reference(nh);
                    presentation_data->nh_idx = dnh->idx;
                    presentation_data->route = route->prefix;
                    presentation_data->nh_addr = dnh->prefix;
                    presentation_data->rtm_nh_proto = dnh->rtm_nh_proto;
                    rtm_nh_proto_reference(dnh->rtm_nh_proto);

                    presentation_data->operation = RTM_PPT_OP_ADD; /* On-demand requests are ADDs */
                    Fglthread_add_last(&rtm->advt_nhs[nh->proto], &presentation_data->glue);
                    
                } ITERATE_GLTHREAD_END(&nh->direct_nh_list.head, data_node_thread);
            }
            else
            {
                presentation_data = (rtm_presentation_data_t *)XCALLOC2(
                        0, 1, rtm_presentation_data_t);
                dnh = nh;
                presentation_data->nh = dnh;
                rtm_nh_reference(dnh);
                presentation_data->inh = NULL;
                presentation_data->nh_idx = dnh->idx;
                presentation_data->route = route->prefix;
                presentation_data->nh_addr = dnh->prefix;
                presentation_data->rtm_nh_proto = dnh->rtm_nh_proto;
                rtm_nh_proto_reference(dnh->rtm_nh_proto);
                presentation_data->operation = RTM_PPT_OP_ADD; /* On-demand requests are ADDs */
                Fglthread_add_last(&rtm->advt_nhs[nh->proto], &presentation_data->glue);
            }
        }
        ITERATE_GLTHREAD_END(&route->path_list, path_node);

    } ITERATE_AVL_TREE_END;

    rtm_schedule_presentation_job(rtm);
}

/* ========================================================================
 * Presentation Database (PPT DB) Management
 * ======================================================================== */

/**
 * @brief Comparison function for PPT route AVL tree
 * 
 * Compares two routes in the presentation database by prefix.
 * Used for maintaining sorted route tree for efficient diff computation.
 * 
 * @param node1 First AVL tree node
 * @param node2 Second AVL tree node
 * 
 * @return -1 if route1 < route2, 0 if equal, 1 if route1 > route2
 */
static int
rtm_ppt_route_compare(const avltree_node_t *node1, const avltree_node_t *node2) {
    
    rtm_ppt_route_t *route1 = avltree_container_of(node1, rtm_ppt_route_t, route_glue);
    rtm_ppt_route_t *route2 = avltree_container_of(node2, rtm_ppt_route_t, route_glue);
    
    cmn_prefix_t *p1 = &route1->prefix;
    cmn_prefix_t *p2 = &route2->prefix;
    
    if (route1->ridx < route2->ridx) return -1;
    if (route1->ridx > route2->ridx) return  1;
    return cmn_prefix_compare(p1, p2);
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

/* Helper function no longer needed - dnh_list is now a direct pointer */

/* Helper function to get allocated route pointer from stack structure */
/* The allocated pointer is stored in route_glue field */
static rtm_ppt_route_t* get_allocated_route(rtm_ppt_route_t *stack_route) {
    if (!stack_route || stack_route->nhidx_list_count == 0) {
        return NULL;
    }
    return *(rtm_ppt_route_t **)((char *)stack_route + offsetof(rtm_ppt_route_t, route_glue));
}

static rtm_ppt_route_t *
rtm_ppt_db_lookup_route (
        rtm_t *rtm, 
        rtm_route *route) {
        
    /* Create template for route lookup */
    rtm_ppt_route_t route_template;

    memset(&route_template, 0, sizeof(rtm_ppt_route_t));
    route_template.ridx = route->ridx;
    route_template.prefix = route->prefix;
    avltree_node_init(&route_template.route_glue);
    
    /* Look up the route entry */
    avltree_node_t *route_node = avltree_lookup(
            &route_template.route_glue, &rtm->ppt_db_route_tree);

    assert (route_node);
    return (rtm_ppt_route_t *)avltree_container_of(route_node, rtm_ppt_route_t, route_glue);
}

static int compare_uint32(const void *a, const void *b) {
    uint32_t ua = *(const uint32_t*)a;
    uint32_t ub = *(const uint32_t*)b;
    if (ua < ub) return -1;
    if (ua > ub) return 1;
    return 0;
}

static void sort_uint32(uint32_t *arr, size_t n) {
    qsort(arr, n, sizeof(uint32_t), compare_uint32);
}

static rtm_ppt_route_t *
rtm_ppt_db_clone_route (
        rtm_t *rtm, 
        rtm_route *route) {

    rtm_nh *nh, *dnh;
    glthread_t *curr, *curr2;
    glthread_data_node_t *data_node;
    uint16_t nh_count;
    uint16_t *dnh_counts;  /* Track DNH count per NH */

    nh_count = 0;
    
    /* First pass: count NHs and DNHs per NH */
    ITERATE_GLTHREAD_BEGIN(&route->path_list, curr) {
        nh = route_glue_to_rtm_nh(curr);
        if (!nh->is_active) continue;
        if (!rtm_nh_is_resolved(nh)) continue;
        nh_count++;
    }ITERATE_GLTHREAD_END(&route->path_list, curr);

    if (nh_count == 0) {
        rtm_ppt_route_t *ppt_route = (rtm_ppt_route_t *)calloc(1, sizeof(rtm_ppt_route_t));
        avltree_node_init (&ppt_route->route_glue);
        ppt_route->ridx = route->ridx;
        ppt_route->prefix = route->prefix;
        ppt_route->nhidx_list_count = 0;
        return ppt_route;
    }

    /* Allocate array to track DNH counts per NH */
    dnh_counts = (uint16_t *)XCALLOC_BUFF(0, nh_count * sizeof(uint16_t));

    /* Second pass: count DNHs for each NH */
    int i = 0;
    ITERATE_GLTHREAD_BEGIN(&route->path_list, curr) {
        nh = route_glue_to_rtm_nh(curr);
        if (!nh->is_active) continue;
        if (!rtm_nh_is_resolved(nh)) continue;
        
        dnh_counts[i] = 0;
        ITERATE_GLTHREAD_BEGIN(&nh->direct_nh_list.head, curr2) {
            dnh_counts[i]++;
        } ITERATE_GLTHREAD_END(&nh->direct_nh_list.head, curr2);
        i++;
    }ITERATE_GLTHREAD_END(&route->path_list, curr);

    /* Allocate main structure (only nhidx_list, no DNH arrays) */
    rtm_ppt_route_t *ppt_route = (rtm_ppt_route_t *)calloc (1, 
        sizeof (rtm_ppt_route_t) + 
        (sizeof (rtm_ppt_nhidx_t) * nh_count) );

    /* Now copy data*/
    ppt_route->ridx = route->ridx;
    ppt_route->prefix = route->prefix;
    avltree_node_init (&ppt_route->route_glue);
    ppt_route->nhidx_list_count = nh_count;

    /* Third pass: populate NHs and allocate DNH arrays */
    i = 0;
    ITERATE_GLTHREAD_BEGIN(&route->path_list, curr) {
        nh = route_glue_to_rtm_nh(curr);
        if (!nh->is_active) continue;
        if (!rtm_nh_is_resolved(nh)) continue;
        
        ppt_route->nhidx_list[i].nh_pidx = nh->idx;
        ppt_route->nhidx_list[i].nh_pidx_rtm = nh->rtm;
        ppt_route->nhidx_list[i].dnh_list_count = dnh_counts[i];
        
        /* Allocate DNH array if needed */
        if (dnh_counts[i] > 0) {
            ppt_route->nhidx_list[i].dnh_list = (rtm_ppt_nhidx_t::dnh *)XCALLOC_BUFF(0, 
                dnh_counts[i] * sizeof(rtm_ppt_nhidx_t::dnh));
            
            int j = 0;
            ITERATE_GLTHREAD_BEGIN(&nh->direct_nh_list.head, curr2) {
                data_node = glue_to_glthread_data_node(curr2);
                dnh = (rtm_nh *)(data_node->data);
                ppt_route->nhidx_list[i].dnh_list[j].dnh_idx = dnh->idx;
                ppt_route->nhidx_list[i].dnh_list[j].dnh_idx_rtm = dnh->rtm;
                j++;
            } ITERATE_GLTHREAD_END(&nh->direct_nh_list.head, curr2);
            
            /* Sort DNH list (inner list) - comparator for struct dnh */
            auto compare_dnh = [](const void *a, const void *b) -> int {
                const rtm_ppt_nhidx_t::dnh *da = (const rtm_ppt_nhidx_t::dnh *)a;
                const rtm_ppt_nhidx_t::dnh *db = (const rtm_ppt_nhidx_t::dnh *)b;
                if (da->dnh_idx < db->dnh_idx) return -1;
                if (da->dnh_idx > db->dnh_idx) return 1;
                return 0;
            };
            qsort(ppt_route->nhidx_list[i].dnh_list, dnh_counts[i], sizeof(rtm_ppt_nhidx_t::dnh), compare_dnh);
        } else {
            ppt_route->nhidx_list[i].dnh_list = NULL;
        }
        
        i++;
    }ITERATE_GLTHREAD_END(&route->path_list, curr);

    assert (i == nh_count);
    
    /* Sort outer list by nh_pidx for efficient diffing */
    if (nh_count > 1) {
        /* IMPORTANT: Don't sort the flexible array in-place as it can corrupt adjacent memory.
           Instead, create a temporary array, sort it, then copy back. */
        
        /* Allocate temporary array for sorting */
        rtm_ppt_nhidx_t *temp_list = (rtm_ppt_nhidx_t *)XCALLOC_BUFF(0, 
            nh_count * sizeof(rtm_ppt_nhidx_t));
        
        /* Copy to temp array */
        memcpy(temp_list, ppt_route->nhidx_list, nh_count * sizeof(rtm_ppt_nhidx_t));
        
        /* Comparator for sorting by nh_pidx */
        auto compare_nhidx = [](const void *a, const void *b) -> int {
            const rtm_ppt_nhidx_t *na = (const rtm_ppt_nhidx_t *)a;
            const rtm_ppt_nhidx_t *nb = (const rtm_ppt_nhidx_t *)b;
            if (na->nh_pidx < nb->nh_pidx) return -1;
            if (na->nh_pidx > nb->nh_pidx) return 1;
            return 0;
        };
        
        /* Sort the temporary array (safe - no risk of corrupting ppt_route) */
        qsort(temp_list, nh_count, sizeof(rtm_ppt_nhidx_t), compare_nhidx);
        
        /* Copy sorted result back to the flexible array */
        memcpy(ppt_route->nhidx_list, temp_list, nh_count * sizeof(rtm_ppt_nhidx_t));
        
        /* Free temporary array */
        XFREE(temp_list);
    }
    
    XFREE(dnh_counts);
    return ppt_route;
}

/* ========================================================================
 * Diff Computation
 * ======================================================================== */

/**
 * @brief Compute diff between current route state and PPT DB state
 * 
 * This function implements the core diff algorithm that compares the
 * current route state in RTM with the previously advertised state
 * stored in the Presentation Database (PPT DB).
 * 
 * Diff Algorithm:
 * ┌─────────────────────────────────────────────────────────┐
 * │ 1. Sort both lists by nexthop ID                        │
 * │ 2. Use two-pointer technique to find differences        │
 * │ 3. Identify:                                            │
 * │    - Added nexthops (in route, not in ppt_route)         │
 * │    - Deleted nexthops (in ppt_route, not in route)      │
 * │    - Modified nexthops (same ID, different DNHs)        │
 * │ 4. For indirect nexthops, also diff direct NH lists     │
 * └─────────────────────────────────────────────────────────┘
 * 
 * Output:
 * - out_add: Contains all nexthops and direct NHs that were added
 * - out_del: Contains all nexthops and direct NHs that were deleted
 * 
 * @param route Current route state from RTM
 * @param ppt_route Previous route state from PPT DB
 * @param out_add Output structure for added nexthops
 * @param out_del Output structure for deleted nexthops
 */
static void
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
    
    /* Allocate memory for current state - only nhidx_list, DNH arrays allocated separately */
    rtm_ppt_nhidx_t *current_list = (rtm_ppt_nhidx_t *)XCALLOC_BUFF(0,
        active_nh_count * sizeof(rtm_ppt_nhidx_t));
    
    if (!current_list) return;
    
    memset(current_list, 0, active_nh_count * sizeof(rtm_ppt_nhidx_t));
    
    /* Build current nexthop list - use temp structure to avoid qsort issues with flexible arrays */
    typedef struct {
        uint32_t nh_pidx;
        rtm_t *nh_pidx_rtm;
        uint16_t dnh_count;
        rtm_ppt_nhidx_t::dnh dnh_list[16]; /* Max DNHs per INH */
    } temp_nh_build_t;
    
    temp_nh_build_t *temp_build = (temp_nh_build_t *)XCALLOC_BUFF(0, active_nh_count * sizeof(temp_nh_build_t));
    if (!temp_build) {
        XFREE(current_list);
        return;
    }
    
    uint16_t current_count = 0;
    
    ITERATE_GLTHREAD_BEGIN(&route->path_list, nh_glue) {
        nh = route_glue_to_rtm_nh(nh_glue);
        if (!nh->is_active) break;
        
        temp_build[current_count].nh_pidx = nh->idx;
        temp_build[current_count].nh_pidx_rtm = nh->rtm;
        temp_build[current_count].dnh_count = 0;
        
        if (nh->is_indirect && rtm_nh_is_resolved(nh)) {
            ITERATE_GLTHREAD_BEGIN(&nh->direct_nh_list.head, dnh_glue) {
                data_node = glue_to_glthread_data_node(dnh_glue);
                dnh = (rtm_nh *)data_node->data;
                temp_build[current_count].dnh_list[temp_build[current_count].dnh_count].dnh_idx = dnh->idx;
                temp_build[current_count].dnh_list[temp_build[current_count].dnh_count].dnh_idx_rtm = dnh->rtm;
                temp_build[current_count].dnh_count++;
            } ITERATE_GLTHREAD_END(&nh->direct_nh_list.head, dnh_glue);
            
            /* Sort direct nexthops */
            if (temp_build[current_count].dnh_count > 1) {
                auto compare_dnh = [](const void *a, const void *b) -> int {
                    const rtm_ppt_nhidx_t::dnh *da = (const rtm_ppt_nhidx_t::dnh *)a;
                    const rtm_ppt_nhidx_t::dnh *db = (const rtm_ppt_nhidx_t::dnh *)b;
                    if (da->dnh_idx < db->dnh_idx) return -1;
                    if (da->dnh_idx > db->dnh_idx) return 1;
                    return 0;
                };
                qsort(temp_build[current_count].dnh_list, 
                      temp_build[current_count].dnh_count,
                      sizeof(rtm_ppt_nhidx_t::dnh), compare_dnh);
            }
        }
        
        current_count++;
    } ITERATE_GLTHREAD_END(&route->path_list, nh_glue);
    
    /* Sort temp list by nh_pidx using qsort (safe because temp_build is regular struct) */
    if (current_count > 1) {
        /* Simple comparator for temp_build */
        auto compare_temp_build = [](const void *a, const void *b) -> int {
            const temp_nh_build_t *ta = (const temp_nh_build_t *)a;
            const temp_nh_build_t *tb = (const temp_nh_build_t *)b;
            if (ta->nh_pidx < tb->nh_pidx) return -1;
            if (ta->nh_pidx > tb->nh_pidx) return 1;
            return 0;
        };
        qsort(temp_build, current_count, sizeof(temp_nh_build_t), compare_temp_build);
    }
    
    /* Now copy sorted temp_build to current_list, allocating DNH arrays separately */
    for (int i = 0; i < current_count; i++) {
        current_list[i].nh_pidx = temp_build[i].nh_pidx;
        current_list[i].nh_pidx_rtm = temp_build[i].nh_pidx_rtm;
        current_list[i].dnh_list_count = temp_build[i].dnh_count;
        
        if (temp_build[i].dnh_count > 0) {
            current_list[i].dnh_list = (rtm_ppt_nhidx_t::dnh *)XCALLOC_BUFF(0, 
                temp_build[i].dnh_count * sizeof(rtm_ppt_nhidx_t::dnh));
            memcpy(current_list[i].dnh_list, temp_build[i].dnh_list, 
                   temp_build[i].dnh_count * sizeof(rtm_ppt_nhidx_t::dnh));
        } else {
            current_list[i].dnh_list = NULL;
        }
    }
    
    XFREE(temp_build);
    
    /* Now perform the diff using two-pointer merge technique */
    /* ASSUMPTION: Both current_list and ppt_route->nhidx_list are sorted by nh_pidx */
    /* ASSUMPTION: All DNH lists within each NH are sorted by DNH index */
    /* This allows efficient O(n+m) comparison instead of O(n*m) nested loops */
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
                rtm_ppt_nhidx_t::dnh *curr_dnh_list = curr_nh->dnh_list;
                rtm_ppt_nhidx_t::dnh *old_dnh_list = old_nh->dnh_list;
                
                int curr_dnh = 0, old_dnh = 0;
                
                /* Count new DNHs (in current but not in old) */
                while (curr_dnh < curr_nh->dnh_list_count && old_dnh < old_nh->dnh_list_count) {
                    if (curr_dnh_list[curr_dnh].dnh_idx < old_dnh_list[old_dnh].dnh_idx) {
                        /* New DNH found */
                        nh_add_dnh_count++;
                        curr_dnh++;
                    } else if (curr_dnh_list[curr_dnh].dnh_idx > old_dnh_list[old_dnh].dnh_idx) {
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
    
    
    /* XFREE any existing allocations in out_add and out_del */
    /* Note: With flexible arrays, we need to XFREE the entire structure, not just nhidx_list */
    /* But since out_add/out_del are stack variables, we can't XFREE them here */
    /* The caller will handle XFREEing */
    
    /* Allocate memory for additions - only nhidx_list, DNH arrays allocated separately */
    rtm_ppt_route_t *add_route_alloc = NULL;
    if (add_count > 0) {
        add_route_alloc = (rtm_ppt_route_t *)XCALLOC_BUFF(0,
            sizeof(rtm_ppt_route_t) +
            add_count * sizeof(rtm_ppt_nhidx_t));
        
        if (add_route_alloc) {
            add_route_alloc->prefix = route->prefix;
            add_route_alloc->nhidx_list_count = 0;
            /* Initialize all dnh_list pointers to NULL */
            for (int i = 0; i < add_count; i++) {
                add_route_alloc->nhidx_list[i].dnh_list = NULL;
            }
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
    
    /* Allocate memory for deletions - only nhidx_list, DNH arrays allocated separately */
    rtm_ppt_route_t *del_route_alloc = NULL;
    if (del_count > 0) {
        del_route_alloc = (rtm_ppt_route_t *)XCALLOC_BUFF(0,
            sizeof(rtm_ppt_route_t) +
            del_count * sizeof(rtm_ppt_nhidx_t));
        
        if (del_route_alloc) {
            del_route_alloc->prefix = route->prefix;
            del_route_alloc->nhidx_list_count = 0;
            /* Initialize all dnh_list pointers to NULL */
            for (int i = 0; i < del_count; i++) {
                del_route_alloc->nhidx_list[i].dnh_list = NULL;
            }
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
    
    while (curr_idx < current_count && old_idx < ppt_route->nhidx_list_count) {
        if (current_list[curr_idx].nh_pidx < ppt_route->nhidx_list[old_idx].nh_pidx) {
            /* Addition */
            if (add_route_alloc) {
                add_route_alloc->nhidx_list[add_idx].nh_pidx = current_list[curr_idx].nh_pidx;
                add_route_alloc->nhidx_list[add_idx].nh_pidx_rtm = current_list[curr_idx].nh_pidx_rtm;
                add_route_alloc->nhidx_list[add_idx].dnh_list_count = current_list[curr_idx].dnh_list_count;
                
                if (current_list[curr_idx].dnh_list_count > 0) {
                    add_route_alloc->nhidx_list[add_idx].dnh_list = (rtm_ppt_nhidx_t::dnh *)XCALLOC_BUFF(0,
                        current_list[curr_idx].dnh_list_count * sizeof(rtm_ppt_nhidx_t::dnh));
                    memcpy(add_route_alloc->nhidx_list[add_idx].dnh_list, 
                           current_list[curr_idx].dnh_list,
                           current_list[curr_idx].dnh_list_count * sizeof(rtm_ppt_nhidx_t::dnh));
                } else {
                    add_route_alloc->nhidx_list[add_idx].dnh_list = NULL;
                }
                add_idx++;
            }
            curr_idx++;
        } else if (current_list[curr_idx].nh_pidx > ppt_route->nhidx_list[old_idx].nh_pidx) {
            /* Deletion */
            if (del_route_alloc) {
                del_route_alloc->nhidx_list[del_idx].nh_pidx = ppt_route->nhidx_list[old_idx].nh_pidx;
                del_route_alloc->nhidx_list[del_idx].nh_pidx_rtm = ppt_route->nhidx_list[old_idx].nh_pidx_rtm;
                del_route_alloc->nhidx_list[del_idx].dnh_list_count = ppt_route->nhidx_list[old_idx].dnh_list_count;
                
                if (ppt_route->nhidx_list[old_idx].dnh_list_count > 0) {
                    del_route_alloc->nhidx_list[del_idx].dnh_list = (rtm_ppt_nhidx_t::dnh *)XCALLOC_BUFF(0,
                        ppt_route->nhidx_list[old_idx].dnh_list_count * sizeof(rtm_ppt_nhidx_t::dnh));
                    memcpy(del_route_alloc->nhidx_list[del_idx].dnh_list,
                           ppt_route->nhidx_list[old_idx].dnh_list,
                           ppt_route->nhidx_list[old_idx].dnh_list_count * sizeof(rtm_ppt_nhidx_t::dnh));
                } else {
                    del_route_alloc->nhidx_list[del_idx].dnh_list = NULL;
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
                rtm_ppt_nhidx_t::dnh *curr_dnh_list = curr_nh->dnh_list;
                rtm_ppt_nhidx_t::dnh *old_dnh_list = old_nh->dnh_list;
                
                int curr_dnh = 0, old_dnh = 0;
                
                /* Find new and removed DNHs - same logic as counting phase */
                while (curr_dnh < curr_nh->dnh_list_count && old_dnh < old_nh->dnh_list_count) {
                    if (curr_dnh_list[curr_dnh].dnh_idx < old_dnh_list[old_dnh].dnh_idx) {
                        /* New DNH - add to additions */
                        if (add_route_alloc) {
                            if (add_dnh_idx == 0) {
                                /* First new DNH for this indirect NH - create entry */
                                add_route_alloc->nhidx_list[add_idx].nh_pidx = curr_nh->nh_pidx;
                                add_route_alloc->nhidx_list[add_idx].nh_pidx_rtm = curr_nh->nh_pidx_rtm;
                                add_route_alloc->nhidx_list[add_idx].dnh_list_count = 0;
                            }
                            if (add_dnh_idx == 0) {
                                /* Allocate DNH array for this NH */
                                add_route_alloc->nhidx_list[add_idx].dnh_list = (rtm_ppt_nhidx_t::dnh *)XCALLOC_BUFF(0,
                                    curr_nh->dnh_list_count * sizeof(rtm_ppt_nhidx_t::dnh));
                            }
                            add_route_alloc->nhidx_list[add_idx].dnh_list[add_dnh_idx] = curr_dnh_list[curr_dnh];
                            add_dnh_idx++;
                            add_route_alloc->nhidx_list[add_idx].dnh_list_count++;
                        }
                        curr_dnh++;
                    } else if (curr_dnh_list[curr_dnh].dnh_idx > old_dnh_list[old_dnh].dnh_idx) {
                        /* Old DNH removed - add to deletions */
                        if (del_route_alloc) {
                            if (del_dnh_idx == 0) {
                                /* First removed DNH for this indirect NH - create entry */
                                del_route_alloc->nhidx_list[del_idx].nh_pidx = old_nh->nh_pidx;
                                del_route_alloc->nhidx_list[del_idx].nh_pidx_rtm = old_nh->nh_pidx_rtm;
                                del_route_alloc->nhidx_list[del_idx].dnh_list_count = 0;
                            }
                            if (del_dnh_idx == 0) {
                                /* Allocate DNH array for this NH */
                                del_route_alloc->nhidx_list[del_idx].dnh_list = (rtm_ppt_nhidx_t::dnh *)XCALLOC_BUFF(0,
                                    old_nh->dnh_list_count * sizeof(rtm_ppt_nhidx_t::dnh));
                            }
                            del_route_alloc->nhidx_list[del_idx].dnh_list[del_dnh_idx] = old_dnh_list[old_dnh];
                            del_dnh_idx++;
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
                            add_route_alloc->nhidx_list[add_idx].nh_pidx_rtm = curr_nh->nh_pidx_rtm;
                            add_route_alloc->nhidx_list[add_idx].dnh_list_count = 0;
                        }
                        if (add_dnh_idx == 0) {
                            /* Allocate DNH array for this NH */
                            add_route_alloc->nhidx_list[add_idx].dnh_list = (rtm_ppt_nhidx_t::dnh *)XCALLOC_BUFF(0,
                                curr_nh->dnh_list_count * sizeof(rtm_ppt_nhidx_t::dnh));
                        }
                        add_route_alloc->nhidx_list[add_idx].dnh_list[add_dnh_idx] = curr_dnh_list[curr_dnh];
                        add_dnh_idx++;
                        add_route_alloc->nhidx_list[add_idx].dnh_list_count++;
                    }
                    curr_dnh++;
                }
                
                /* Remaining old DNHs are deletions */
                while (old_dnh < old_nh->dnh_list_count) {
                    if (del_route_alloc) {
                        if (del_dnh_idx == 0) {
                            del_route_alloc->nhidx_list[del_idx].nh_pidx = old_nh->nh_pidx;
                            del_route_alloc->nhidx_list[del_idx].nh_pidx_rtm = old_nh->nh_pidx_rtm;
                            del_route_alloc->nhidx_list[del_idx].dnh_list_count = 0;
                        }
                        if (del_dnh_idx == 0) {
                            /* Allocate DNH array for this NH */
                            del_route_alloc->nhidx_list[del_idx].dnh_list = (rtm_ppt_nhidx_t::dnh *)XCALLOC_BUFF(0,
                                old_nh->dnh_list_count * sizeof(rtm_ppt_nhidx_t::dnh));
                        }
                        del_route_alloc->nhidx_list[del_idx].dnh_list[del_dnh_idx] = old_dnh_list[old_dnh];
                        del_dnh_idx++;
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
            add_route_alloc->nhidx_list[add_idx].nh_pidx_rtm = current_list[curr_idx].nh_pidx_rtm;
            add_route_alloc->nhidx_list[add_idx].dnh_list_count = current_list[curr_idx].dnh_list_count;
            
            if (current_list[curr_idx].dnh_list_count > 0) {
                add_route_alloc->nhidx_list[add_idx].dnh_list = (rtm_ppt_nhidx_t::dnh *)XCALLOC_BUFF(0,
                    current_list[curr_idx].dnh_list_count * sizeof(rtm_ppt_nhidx_t::dnh));
                memcpy(add_route_alloc->nhidx_list[add_idx].dnh_list,
                       current_list[curr_idx].dnh_list,
                       current_list[curr_idx].dnh_list_count * sizeof(rtm_ppt_nhidx_t::dnh));
            } else {
                add_route_alloc->nhidx_list[add_idx].dnh_list = NULL;
            }
            add_idx++;
        }
        curr_idx++;
    }
    
    /* Process remaining deletions */
    while (old_idx < ppt_route->nhidx_list_count) {
        if (del_route_alloc) {
            del_route_alloc->nhidx_list[del_idx].nh_pidx = ppt_route->nhidx_list[old_idx].nh_pidx;
            del_route_alloc->nhidx_list[del_idx].nh_pidx_rtm = ppt_route->nhidx_list[old_idx].nh_pidx_rtm;
            del_route_alloc->nhidx_list[del_idx].dnh_list_count = ppt_route->nhidx_list[old_idx].dnh_list_count;
            
            if (ppt_route->nhidx_list[old_idx].dnh_list_count > 0) {
                del_route_alloc->nhidx_list[del_idx].dnh_list = (rtm_ppt_nhidx_t::dnh *)XCALLOC_BUFF(0,
                    ppt_route->nhidx_list[old_idx].dnh_list_count * sizeof(rtm_ppt_nhidx_t::dnh));
                memcpy(del_route_alloc->nhidx_list[del_idx].dnh_list,
                       ppt_route->nhidx_list[old_idx].dnh_list,
                       ppt_route->nhidx_list[old_idx].dnh_list_count * sizeof(rtm_ppt_nhidx_t::dnh));
            } else {
                del_route_alloc->nhidx_list[del_idx].dnh_list = NULL;
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
    
    /* Clean up - free DNH arrays first, then main structure */
    if (current_list) {
        for (int i = 0; i < current_count; i++) {
            if (current_list[i].dnh_list) {
                XFREE(current_list[i].dnh_list);
            }
        }
        XFREE(current_list);
    }
}


static void
rtm_ppt_route_release_resources(rtm_t *rtm, rtm_ppt_route_t *ppt_route) {

    if (ppt_route && ppt_route->nhidx_list_count > 0) {
        
        for (int i = 0; i < ppt_route->nhidx_list_count; i++) {
            if (ppt_route->nhidx_list[i].dnh_list) {
                XFREE(ppt_route->nhidx_list[i].dnh_list);
            }
        }
    }
}

static void 
rtm_ppt_route_check_and_delete (rtm_t *rtm, rtm_ppt_route_t *ppt_route) {
    
    rtm_ppt_route_release_resources (rtm, ppt_route);
    assert (!avltree_node_is_inuse (&rtm->ppt_db_route_tree, 
        &ppt_route->route_glue));
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
1. create or get rtm_ppt_route_t using rtm_ppt_db_lookup_route( ) API.
2. Compute rtm_ppt_route_t *out_add and rtm_ppt_route_t *out_del using rtm_ppt_route_diff ( )
3. Update the rtm_ppt_route_t using rtm_ppt_route_update ( ) API.
4. use the results out_add and out_del to advertise the routes to the appropriate protocols.
*/
static void 
rtm_ppt_route_advertise (rtm_t *rtm, rtm_route *route) {
    
    char prefix_str[48];
    rtm_nh_proto_t *nh_proto;
    rtm_ppt_route_t out_add, out_del;
    avltree_node_t *sub_proto_advt_db_node;
    rtm_presentation_data_t *presentation_data;

    rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str));

    /* Step 1: Get or create cached route for this subscribing protocol */
    rtm_ppt_route_t *cached_route = rtm_ppt_db_lookup_route(rtm, route);

    tracer (rtm->node->cptr, DRTM, 
         "RTM[%s] : Computing Diff for Route %s\n", rtm->name, prefix_str);
    rtm_ppt_route_diff(route, cached_route, &out_add, &out_del);

    /* Step 4a: Advertise deletions first */
    rtm_ppt_route_t *del_alloc = get_allocated_route(&out_del);

    if (del_alloc)
    {
        for (int i = 0; i < out_del.nhidx_list_count; i++)
        {
            rtm_ppt_nhidx_t *nh_entry = &del_alloc->nhidx_list[i];

            /* Delete case, NH is deleted and breathing its last moments in
                Garbage collecter DB*/
            rtm_nh *inh = rtm_nh_lookup_by_idx(nh_entry->nh_pidx_rtm, nh_entry->nh_pidx);

            if (!inh) {
                inh = rtm_gc_lookup_nh(nh_entry->nh_pidx_rtm, nh_entry->nh_pidx);
            }

            nh_proto = inh->rtm_nh_proto;

            /* If indirect and has direct nexthops, advertise deletion for each direct nexthop */
            if (nh_entry->dnh_list_count > 0)
            {
                rtm_ppt_nhidx_t::dnh *dnh_list = del_alloc->nhidx_list[i].dnh_list;

                for (uint16_t dnh_idx = 0; dnh_idx < nh_entry->dnh_list_count; dnh_idx++)
                {
                    rtm_nh *dnh = rtm_nh_lookup_by_idx(dnh_list[dnh_idx].dnh_idx_rtm, dnh_list[dnh_idx].dnh_idx);
                    rtm_nh *dnh_gc = NULL;

                    presentation_data = (rtm_presentation_data_t *)XCALLOC2(0, 1, rtm_presentation_data_t);

                    presentation_data->nh = dnh; /* May be NULL for DELETE operations */
                    if (dnh)
                        rtm_nh_reference(dnh);
                    else
                        dnh_gc = rtm_gc_lookup_nh(dnh_list[dnh_idx].dnh_idx_rtm, dnh_list[dnh_idx].dnh_idx);

                    presentation_data->inh = NULL;
                    presentation_data->inh_idx = inh->idx;
                    presentation_data->nh_idx = dnh_list[dnh_idx].dnh_idx; /* Always valid */
                    presentation_data->route = route->prefix;
                    presentation_data->nh_addr = dnh ? dnh->prefix : dnh_gc->prefix;
                    presentation_data->rtm_nh_proto = dnh ? dnh->rtm_nh_proto : dnh_gc->rtm_nh_proto;
                    rtm_nh_proto_reference(presentation_data->rtm_nh_proto);
                    presentation_data->target_fib.vrf = dnh ? dnh->target_fib.vrf : dnh_gc->target_fib.vrf;
                    presentation_data->target_fib.afi = dnh ? dnh->target_fib.afi : dnh_gc->target_fib.afi;
                    presentation_data->operation = RTM_PPT_OP_DELETE; /* This is a DELETE */
                    /* Determine protocol: use dnh->proto if available, else use src_proto as fallback */
                    RTM_PROTO_T nh_proto = dnh ? dnh->proto : dnh_gc->proto;
                    Fglthread_add_last(&rtm->advt_nhs[nh_proto], &presentation_data->glue);
                }
            }
            else
            {
                /* Direct nexthop or unresolved indirect - advertise deletion of the nexthop itself */
                presentation_data = (rtm_presentation_data_t *)XCALLOC2(
                        0, 1, rtm_presentation_data_t);
                rtm_nh *dnh = rtm_nh_lookup_by_idx(nh_entry->nh_pidx_rtm, nh_entry->nh_pidx);
                rtm_nh *dnh_gc = NULL;
                presentation_data->nh = dnh; /* Must have deleted */
                if (dnh)
                    rtm_nh_reference(dnh);
                else
                    dnh_gc = rtm_gc_lookup_nh(nh_entry->nh_pidx_rtm, nh_entry->nh_pidx);

                presentation_data->inh = NULL;
                presentation_data->inh_idx = 0;
                presentation_data->nh_idx = nh_entry->nh_pidx; /* Always valid */
                presentation_data->route = route->prefix;
                presentation_data->nh_addr = dnh ? dnh->prefix : dnh_gc->prefix;
                presentation_data->rtm_nh_proto = dnh ? dnh->rtm_nh_proto : dnh_gc->rtm_nh_proto;
                rtm_nh_proto_reference(presentation_data->rtm_nh_proto);
                presentation_data->target_fib.vrf = dnh ? dnh->target_fib.vrf : dnh_gc->target_fib.vrf;
                presentation_data->target_fib.afi = dnh ? dnh->target_fib.afi : dnh_gc->target_fib.afi;
                presentation_data->operation = RTM_PPT_OP_DELETE; /* This is a DELETE */
                /* Determine protocol: use nh->proto if available, else use src_proto as fallback */
                RTM_PROTO_T nh_proto = dnh ? dnh->proto : dnh_gc->proto;
                Fglthread_add_last(&rtm->advt_nhs[nh_proto], &presentation_data->glue);
            }
        }
    }

    /* Step 4b: Advertise additions */
    rtm_ppt_route_t *add_alloc = get_allocated_route(&out_add);

    if (add_alloc)
    {

        for (int i = 0; i < out_add.nhidx_list_count; i++)
        {

            rtm_ppt_nhidx_t *nh_entry = &add_alloc->nhidx_list[i];

            /* Find the actual rtm_nh by index */
            rtm_nh *nh = rtm_nh_lookup_by_idx(nh_entry->nh_pidx_rtm, nh_entry->nh_pidx);

            /* If indirect and resolved, advertise each direct nexthop */
            if (nh->is_indirect && rtm_nh_is_resolved(nh) && nh_entry->dnh_list_count > 0)
            {
                rtm_ppt_nhidx_t::dnh *dnh_list = add_alloc->nhidx_list[i].dnh_list;

                for (uint16_t dnh_idx = 0; dnh_idx < nh_entry->dnh_list_count; dnh_idx++)
                {
                    rtm_nh *dnh = rtm_nh_lookup_by_idx(dnh_list[dnh_idx].dnh_idx_rtm, dnh_list[dnh_idx].dnh_idx);

                    presentation_data = (rtm_presentation_data_t *)XCALLOC2(
                        0, 1, rtm_presentation_data_t);
                    presentation_data->nh = dnh; /* Wrap direct nexthop */
                    rtm_nh_reference(dnh);
                    presentation_data->inh = nh;
                    rtm_nh_reference(nh);
                    presentation_data->inh_idx = nh->idx;
                    presentation_data->nh_idx = dnh->idx;
                    presentation_data->route = route->prefix;
                    presentation_data->nh_addr = dnh->prefix;
                    presentation_data->rtm_nh_proto = dnh->rtm_nh_proto;
                    rtm_nh_proto_reference(dnh->rtm_nh_proto);
                    presentation_data->operation = RTM_PPT_OP_ADD; /* This is an ADD */
                    Fglthread_add_last(&rtm->advt_nhs[dnh->proto], &presentation_data->glue);
                }
            }
            else
            {
                /* Direct nexthop or unresolved indirect - advertise the nexthop itself */
                presentation_data = (rtm_presentation_data_t *)XCALLOC2(
                        0, 1, rtm_presentation_data_t);
                presentation_data->nh = nh;
                rtm_nh_reference(nh);
                presentation_data->inh = NULL;
                presentation_data->inh_idx = 0;
                presentation_data->nh_idx = nh_entry->nh_pidx;
                presentation_data->route = route->prefix;
                presentation_data->nh_addr = nh->prefix;
                presentation_data->rtm_nh_proto = nh->rtm_nh_proto;
                rtm_nh_proto_reference(nh->rtm_nh_proto);
                presentation_data->operation = RTM_PPT_OP_ADD; /* This is an ADD */
                Fglthread_add_last(&rtm->advt_nhs[nh->proto], &presentation_data->glue);
            }
        }
    }
    /* Step 3: Update the cached route */
    
    /* Debug: Print what we're adding and deleting */
    if (out_add.nhidx_list_count > 0 || out_del.nhidx_list_count > 0) {
       
        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : Route %s: Updating PPT DB: add_count=%u, del_count=%u\n",
            rtm->name, prefix_str,
            out_add.nhidx_list_count,
            out_del.nhidx_list_count);
        
        rtm_ppt_route_t *add_alloc = *(rtm_ppt_route_t **)((char *)&out_add + offsetof(rtm_ppt_route_t, route_glue));
        if (add_alloc) {
            for (int i = 0; i < out_add.nhidx_list_count; i++) {
                tracer(rtm->node->cptr, DRTM_DET,
                    "RTM[%s] :   ADD NH[%d]: idx=%u, dnh_count=%u\n",
                    rtm->name, i,
                    add_alloc->nhidx_list[i].nh_pidx,
                    add_alloc->nhidx_list[i].dnh_list_count);
                
                if (add_alloc->nhidx_list[i].dnh_list_count > 0) {
                    rtm_ppt_nhidx_t::dnh *dnh_list = add_alloc->nhidx_list[i].dnh_list;
                    for (int j = 0; j < add_alloc->nhidx_list[i].dnh_list_count; j++) {
                        tracer(rtm->node->cptr, DRTM_DET,
                            "RTM[%s] :     DNH[%d]: idx=%u\n",
                            rtm->name, j, dnh_list[j].dnh_idx);
                    }
                }
            }
        }
        
        rtm_ppt_route_t *del_alloc = *(rtm_ppt_route_t **)((char *)&out_del + offsetof(rtm_ppt_route_t, route_glue));
        if (del_alloc) {
            for (int i = 0; i < out_del.nhidx_list_count; i++) {
                tracer(rtm->node->cptr, DRTM_DET,
                    "RTM[%s] :   DEL NH[%d]: idx=%u, dnh_count=%u\n",
                    rtm->name, i,
                    del_alloc->nhidx_list[i].nh_pidx,
                    del_alloc->nhidx_list[i].dnh_list_count);
                
                if (del_alloc->nhidx_list[i].dnh_list_count > 0) {
                    rtm_ppt_nhidx_t::dnh *dnh_list = del_alloc->nhidx_list[i].dnh_list;
                    for (int j = 0; j < del_alloc->nhidx_list[i].dnh_list_count; j++) {
                        tracer(rtm->node->cptr, DRTM_DET,
                            "RTM[%s] :     DNH[%d]: idx=%u\n",
                            rtm->name, j, dnh_list[j].dnh_idx);
                    }
                }
            }
        }
    }
    
    /* Clean up diff results - with flexible arrays, we need to XFREE the entire structures */
    /* The allocated pointers are stored in route_glue field (temporary storage) */
    if (out_add.nhidx_list_count > 0) {
        rtm_ppt_route_t *allocated = *(rtm_ppt_route_t **)((char *)&out_add + offsetof(rtm_ppt_route_t, route_glue));
        if (allocated) {
            XFREE(allocated);
        }
    }
    if (out_del.nhidx_list_count > 0) {
        rtm_ppt_route_t *allocated = *(rtm_ppt_route_t **)((char *)&out_del + offsetof(rtm_ppt_route_t, route_glue));
        if (allocated) {
            XFREE(allocated);
        }
    }

    /* Updated the PPT DB after diff */
    if (route->nh_count == 0) {
        // This route will going to be deleted and hence the ppt route also from
        // rtm_route_check_and_delete( ) . No need to do anything here.
    }
    else if ( !rtm_route_is_resolved (route)) {
        // If the route has INH and the route is unresolved, then we can delete  the route from
        // PPT-DB. The route will be added back to PPT-DB when the route is resolved.
        rtm_ppt_unregister_route(rtm, &route->prefix, route->ridx);
    }
    else {
        /* Update the cached route in PPT DB with the latest snapshot */
        assert(avltree_remove (&cached_route->route_glue, &rtm->ppt_db_route_tree));
        avltree_node_init(&cached_route->route_glue);
        rtm_ppt_route_check_and_delete (rtm, cached_route);
        rtm_ppt_route_t *updated_ppt_rt = rtm_ppt_db_clone_route(rtm, route);
        assert (!avltree_node_is_inuse (&rtm->ppt_db_route_tree, &updated_ppt_rt->route_glue));
        avltree_insert(&updated_ppt_rt->route_glue, &rtm->ppt_db_route_tree);
        tracer (rtm->node->cptr, DRTM, 
            "RTM[%s] : Route %s : Synchronized with PPT-DB\n",
            rtm->name, prefix_str);
    }

    /* Schedule the presentation job to process the advertisement queue */
    rtm_schedule_presentation_job(rtm);
}

static void 
rtm_check_and_delete_presentation_data (rtm_t *rtm,
        rtm_presentation_data_t *presentation_data) {

    if (presentation_data->nh) 
        rtm_nh_dereference(rtm, presentation_data->nh);

    if (presentation_data->inh) 
        rtm_nh_dereference(rtm, presentation_data->inh);

    rtm_nh_proto_dereference(rtm, presentation_data->rtm_nh_proto);
    presentation_data->rtm_nh_proto = NULL;
    
    if (presentation_data->prefix_list) 
        prefix_list_dereference(presentation_data->prefix_list);

    assert (!IS_QUEUED_UP_IN_THREAD(&presentation_data->glue));

    XFREE(presentation_data);
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
        ITERATE_GLTHREAD_BEGIN(&rtm->advt_nhs[proto].head, curr)
        {
            presentation_data =
                (rtm_presentation_data_t *)rtm_presentation_data_to_glue(curr);

            remove_Fglthread (&rtm->advt_nhs[proto], curr);

            tracer (rtm->node->cptr, DRTM, 
                "RTM[%s] : PPT-DB : Route %s : Presentation data for NH %s[%u|%u], operation %s\n",
                    rtm->name, 
                    rtm_format_prefix(&presentation_data->route, route_str, sizeof(route_str)),
                    rtm_format_nexthop(&presentation_data->nh_addr, nh_str, sizeof(nh_str)),
                    presentation_data->inh_idx, 
                    presentation_data->nh_idx, 
                    presentation_data->operation == RTM_PPT_OP_ADD ? "Add" : \
                    (presentation_data->operation == RTM_PPT_OP_UPDATE) ? "Update" : "Delete");
                    
            /* Update FIB */
            rtm_fib_update(rtm, presentation_data);

            /* Now Advertise it to Routing Protocols */

            if (!presentation_data->cbk) {
                rtm_check_and_delete_presentation_data (rtm, presentation_data);
                continue;
            }

            /* Evaluate against prefix list */
            if (!presentation_data->prefix_list)
            {

                presentation_data->cbk(rtm, presentation_data->nh_idx,
                                       presentation_data->nh,
                                       presentation_data->rtm_nh_proto,
                                       presentation_data->operation);
            }
            else if (presentation_data->nh &&
                     ((prefix_list_evaluate(presentation_data->nh->owner_route->prefix.u.v4_addr,
                                            presentation_data->nh->owner_route->prefix.prefix_len,
                                            presentation_data->prefix_list) == PFX_LST_PERMIT)))
            {

                presentation_data->cbk(rtm, presentation_data->nh_idx,
                                       presentation_data->nh,
                                       presentation_data->rtm_nh_proto,
                                       presentation_data->operation);
            }

            rtm_check_and_delete_presentation_data(rtm, presentation_data);
            
            count++;

            if (count == RTM_ADVT_COUNT_PREEMPTION_LIMIT)
            {
                rtm_schedule_presentation_job(rtm);
                return;
            }
        }ITERATE_GLTHREAD_END(&rtm->advt_nhs[proto].head, curr);
    }
}

void 
rtm_schedule_presentation_job (rtm_t *rtm) {

    if (rtm->advt_job) return;

    rtm->advt_job = task_create_new_job ( EV(rtm->node),
             (void *)rtm,
             rtm_advt_dispatch_job_cbk,
             TASK_ONE_SHOT, TASK_PRIORITY_COMPUTE_LOW );
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

    /* Log the stats */
    rtm_log_stats(rtm);
    rtm_clear_stats(rtm);

    while ((curr = dequeue_glthread_first(&rtm->route_advt_queue.head))) {

        route = advt_glue_to_route(curr);
        rtm_ppt_route_advertise (rtm , route);        
        rtm_route_dereference(rtm, route);
    }

    rtm_schedule_presentation_job (rtm);
}

void 
rtm_schedule_route_advertisement (rtm_t *rtm, rtm_route *route) {

    char prefix_str[48];

    if (IS_QUEUED_UP_IN_THREAD (&route->advt_glue)) {

        tracer (rtm->node->cptr, DRTM, "RTM[%s] : Route %s is already Queued for Advt\n",
            rtm->name,
            rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));
        return;
    }

    /* Populate rtm PPT DB */
    rtm_ppt_register_route(rtm, &route->prefix, route->ridx);

    rtm_route_Fglthread_add_last (route, &rtm->route_advt_queue, &route->advt_glue);
    
    tracer (rtm->node->cptr, DRTM, "RTM[%s] : Route %s is Queued for Advt\n",
            rtm->name,
            rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));

    if (rtm->route_advt_prep_job) {
        tracer (rtm->node->cptr, DRTM, "RTM[%s] : Advt job is already scheduled\n", rtm->name);  
        return;
    }

    rtm->route_advt_prep_job = task_create_new_job (
            EV(rtm->node),
            (void *)rtm,
            rtm_advt_route_advt_prep_job_cbk,
            TASK_ONE_SHOT, TASK_PRIORITY_COMPUTE_LOW );

    tracer (rtm->node->cptr, DRTM, "RTM[%s] : Advt job scheduled\n", rtm->name);  
}

/* Should be called by RTM core when route is malloc'd for the
    first time before invoking rtm_schedule_route_advertisement( )
    on this route 
*/
void 
rtm_ppt_register_route (rtm_t *rtm, cmn_prefix_t *prefix, uint32_t ridx) {

    char prefix_str[48];
    rtm_ppt_route_t *ppt_route;
    rtm_ppt_route_t ppt_route_template;

    /* Validate prefix before proceeding */
    if (!prefix) {
        tracer (rtm->node->cptr, DRTM|DERR, "RTM[%s] : PPT-DB Registration failed : NULL prefix\n",
            rtm->name);
        return;
    }

    /* Properly initialize the template structure to avoid uninitialized memory */
    memset(&ppt_route_template, 0, sizeof(rtm_ppt_route_t));

    ppt_route_template.ridx = ridx;
    ppt_route_template.prefix = *prefix;
    avltree_node_init (&ppt_route_template.route_glue);

    avltree_node_t *node = avltree_lookup(
            &ppt_route_template.route_glue, &rtm->ppt_db_route_tree);

    if (node) return;

    ppt_route = (rtm_ppt_route_t *)calloc(1, sizeof(rtm_ppt_route_t));

    ppt_route->ridx = ridx;
    ppt_route->prefix = *prefix;
    avltree_node_init(&ppt_route->route_glue);
    ppt_route->nhidx_list_count = 0;
    avltree_insert(&ppt_route->route_glue, &rtm->ppt_db_route_tree);

    tracer (rtm->node->cptr, DRTM, "RTM[%s] : Route %s : Successfully Registered with PPT-DB\n",
            rtm->name, rtm_format_prefix(prefix, prefix_str, sizeof (prefix_str)));
}

/* Should be called by RTM core when route is permanently deleted. 
    Should be called in the context of GC job only as per RTM design */
void 
rtm_ppt_unregister_route (rtm_t *rtm, cmn_prefix_t *prefix, uint32_t ridx) {

    char prefix_str[48];
    rtm_ppt_route_t *ppt_route;
    rtm_ppt_route_t ppt_route_template;

    /* Properly initialize the template structure to avoid uninitialized memory */
    memset(&ppt_route_template, 0, sizeof(rtm_ppt_route_t));
    ppt_route_template.ridx = ridx;
    ppt_route_template.prefix = *prefix;
    avltree_node_init (&ppt_route_template.route_glue);

    avltree_node_t *node = avltree_lookup(
            &ppt_route_template.route_glue, &rtm->ppt_db_route_tree);

    if (!node) {
        tracer (rtm->node->cptr, DRTM, 
            "RTM[%s] : Route %s : PPT-DB Unregistration failed : Route not found in PPT-DB. "
            "This is Expected for Unresolved routes\n",
            rtm->name, rtm_format_prefix(prefix, prefix_str, sizeof (prefix_str)));
        return;
    }

    ppt_route = avltree_container_of(node, rtm_ppt_route_t, route_glue);

    avltree_remove (&ppt_route->route_glue, &rtm->ppt_db_route_tree);
    avltree_node_init(&ppt_route->route_glue);
    rtm_ppt_route_check_and_delete (rtm, ppt_route);

    tracer (rtm->node->cptr, DRTM, "RTM[%s] : Route %s : Successfully UnRegistered with PPT-DB\n",
            rtm->name, rtm_format_prefix(prefix, prefix_str, sizeof (prefix_str)));
}
