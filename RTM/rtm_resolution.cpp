#include <assert.h>
#include <memory.h>
#include <stdlib.h>
#include "../Tree/libtree.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../EventDispatcher/event_dispatcher.h"
#include "../graph.h"
#include "rtm_resolution.h"
#include "rtm.h"
#include "rtm_nh.h"
#include "rtm_route.h"

void  
rtm_schedule_resolution_worker (rtm_t *rtm);

static bool 
rtm_inh_has_direct_nh (rtm_nh *indirect_nh, rtm_nh *nh) {

    glthread_t *direct_nh_glue;
    glthread_data_node_t *data_node;

    ITERATE_GLTHREAD_BEGIN(&indirect_nh->direct_nh_list.head, direct_nh_glue) {

        data_node = glue_to_glthread_data_node(direct_nh_glue);

        if (data_node->data == (void *)nh) {
            return true;
        
        }
    } ITERATE_GLTHREAD_END(&indirect_nh->direct_nh_list, direct_nh_glue);

    return false;
}

/* Route can have either all actie nexthops as Direct NHs Or
    INHs which are resolved */
static void 
rtm_copy_route_active_nhs_to_inh_direct_nh_set(
        rtm_t *rtm, rtm_route *route, rtm_nh *indirect_nh) {
    
    rtm_nh *nh;
    glthread_t *nh_glue;
    glthread_data_node_t *data_node;

    ITERATE_GLTHREAD_BEGIN(&route->path_list, nh_glue) {

        nh = route_glue_to_rtm_nh(nh_glue);
        if (!nh->is_active) continue;

        if (!nh->is_indirect) {

            if (rtm_inh_has_direct_nh(indirect_nh, nh)) continue;

            data_node = (glthread_data_node_t *)XCALLOC (0, 1, glthread_data_node_t);
            init_glthread(&data_node->glue);
            data_node->data = nh;
            Fglthread_add_last (&indirect_nh->direct_nh_list, &data_node->glue);
            rtm_nh_reference (nh);
        }
        else {

            /* Iterate over direct NH of this INH*/
            ITERATE_GLTHREAD_BEGIN(&nh->direct_nh_list.head, nh_glue) {

                data_node = glue_to_glthread_data_node(nh_glue);
                nh = (rtm_nh *)data_node->data;
                assert (!nh->is_indirect);
                if (!nh->is_active) continue;
                if (rtm_inh_has_direct_nh(indirect_nh, nh)) continue;
                data_node = (glthread_data_node_t *)XCALLOC (0, 1, glthread_data_node_t);
                init_glthread(&data_node->glue);
                data_node->data = nh;
                Fglthread_add_last (&indirect_nh->direct_nh_list, &data_node->glue);
                rtm_nh_reference (nh);

            } ITERATE_GLTHREAD_END(&nh->direct_nh_list, direct_nh_glue);
        }

    } ITERATE_GLTHREAD_END(&route->path_list, nh_glue);
}

static void
rtm_flush_inh_direct_nh_set(
    rtm_t *rtm, rtm_nh *indirect_nh) {
    
    glthread_t *curr_glue;
    glthread_t *next_glue;
    glthread_data_node_t *data_node;
    rtm_nh *nh;

    ITERATE_GLTHREAD_BEGIN(&indirect_nh->direct_nh_list.head, curr_glue) {

        data_node = glue_to_glthread_data_node(curr_glue);
        nh = (rtm_nh *)data_node->data;
        rtm_nh_remove_Fglthread (rtm, indirect_nh, 
            &indirect_nh->direct_nh_list, curr_glue);
        XFREE (data_node);

    } ITERATE_GLTHREAD_END(&indirect_nh->direct_nh_list.head, curr_glue);

}

/* Route has been resolved i.e. its INH has been resolbed by DNHs
    Now check what all INHs this route resolves recursively and update them 
    This fn works for Unresolution also.    
*/

void
rtm_resolve_routes_recursively (rtm_t *rtm, rtm_route *route) {

    glthread_t *curr_lnh_glue;
    rtm_nh *indirect_nh;

    ITERATE_GLTHREAD_BEGIN(&route->resolved_lnhs.head, curr_lnh_glue) {

        indirect_nh = resolution_list_glue_to_rtm_nh(curr_lnh_glue);

        /* Withdraw first*/
        rtm_flush_inh_direct_nh_set(rtm, indirect_nh);

        /* Copy Route's active NHs to INH direct NH set*/
        rtm_copy_route_active_nhs_to_inh_direct_nh_set(rtm, route, indirect_nh);

        /* This INH cannot have any active DNH, try to resolve it again */

        if (Fglthread_list_is_empty(&indirect_nh->direct_nh_list)) {
            
            /* INH is no longer resolvable, de-couple it from resolver route*/
            rtm_route_dereference (rtm, indirect_nh->resolved_via_route);
            indirect_nh->resolved_via_route = NULL;
            rtm_nh_remove_Fglthread(rtm, indirect_nh, 
                &route->resolved_lnhs, &indirect_nh->resolution_list_glue);
                
            /* And Queue it again for re-resolution*/
            rtm_nh_Fglthread_add_last (indirect_nh, &rtm->unresolvable_paths, 
                &indirect_nh->resolution_list_glue);
            rtm_schedule_resolution_worker (rtm);
        }

        /* Now Recursively update the routes INH upstream in Graph*/
        rtm_resolve_routes_recursively (rtm, indirect_nh->owner_route);

    } ITERATE_GLTHREAD_END(&route->resolved_lnhs.head, curr_lnh_glue);
}

void 
rtm_track_inh_for_resolution (rtm_t *rtm, rtm_nh *indirect_nh) {

    /* Sanity Checks */
    assert (!rtm_nh_is_resolved (indirect_nh));
    assert (indirect_nh->is_indirect);
    assert (indirect_nh->resolved_via_route == NULL);

    /* Indirect_nh may or may not be on RTM resolver Queue */
    //assert (!IS_QUEUED_UP_IN_THREAD(&indirect_nh->resolution_list_glue));

    assert (Fglthread_list_is_empty(&indirect_nh->direct_nh_list));
    assert (indirect_nh->is_active);

    /* Check if there exist a route to resolve this INH*/
    rtm_route *route = rtm_lpm_tree_lookup(rtm, &indirect_nh->prefix);

    if (!route) {

        /* No route to resolve this INH*/
       if (!IS_QUEUED_UP_IN_THREAD(&indirect_nh->resolution_list_glue)) {  

            rtm_nh_Fglthread_add_last (indirect_nh, 
                &rtm->unresolvable_paths, 
                &indirect_nh->resolution_list_glue);
       }
        return;
    }

    if (IS_QUEUED_UP_IN_THREAD(&indirect_nh->resolution_list_glue)) {

        rtm_nh_remove_Fglthread (rtm, indirect_nh, 
            &rtm->unresolvable_paths, &indirect_nh->resolution_list_glue);
    }
    
    rtm_nh_Fglthread_add_last(indirect_nh, &route->resolved_lnhs, 
        &indirect_nh->resolution_list_glue);
    
    /* There exist a route to resolve this INH - use wrapper */

    indirect_nh->resolved_via_route = route;
    rtm_route_reference (route);

    /* Copy Route's active NHs to INH direct NH set*/
    rtm_copy_route_active_nhs_to_inh_direct_nh_set(rtm, route, indirect_nh);
    
    /* Now Recursively update the routes INH upstream in Graph*/
    if (rtm_nh_is_resolved (indirect_nh)) {
        rtm_resolve_routes_recursively (rtm, indirect_nh->owner_route);
    }
}

/* Algorithm : 
    1. Withdraw all its DNHs from owning route's active NH set Recursively
    2. Drain its direct NH set
*/
void 
rtm_untrack_inh_for_resolution (rtm_t *rtm, rtm_nh *indirect_nh) {

    rtm_nh *nh;
    glthread_t *curr_glue;
    glthread_data_node_t *data_node;

    /* Sanity Checks */
    assert (indirect_nh->is_indirect);
    assert (indirect_nh->resolved_via_route);
    assert (IS_QUEUED_UP_IN_THREAD(&indirect_nh->resolution_list_glue));
    assert (!Fglthread_list_is_empty(&indirect_nh->direct_nh_list));
    assert (indirect_nh->is_active);

    /* Step 1: Drain its direct NH set - remove all direct nexthops */
    rtm_flush_inh_direct_nh_set(rtm, indirect_nh);

    /* Step 2: Clean up resolution linkages */
    rtm_nh_remove_Fglthread (rtm, indirect_nh, 
        &indirect_nh->resolved_via_route->resolved_lnhs, 
        &indirect_nh->resolution_list_glue);

    rtm_route_dereference (rtm, indirect_nh->resolved_via_route);
    indirect_nh->resolved_via_route = NULL;

    /* And Queue it again for re-resolution*/
    rtm_nh_Fglthread_add_last (indirect_nh, 
            &rtm->unresolvable_paths, &indirect_nh->resolution_list_glue);

    rtm_schedule_resolution_worker (rtm);
    
    /* Step 3 : Withdraw all its DNHs from owning route's active NH set Recursively */
    rtm_resolve_routes_recursively (rtm, indirect_nh->owner_route);
    
    assert (!rtm_nh_is_resolved (indirect_nh));
}

static void
rtm_resolver_job_cbk(event_dispatcher_t *ev, void *arg, uint32_t arg_size) {

    glthread_t *curr_glue;
    rtm_nh *indirect_nh;

    rtm_t *rtm = (rtm_t *)arg;

    rtm->resolution_job = NULL;

    ITERATE_GLTHREAD_BEGIN(&rtm->unresolvable_paths.head, curr_glue) {

        indirect_nh = resolution_list_glue_to_rtm_nh(curr_glue);

        /* If this is not Active, this INH should not be considered for resolution
           if its owning route has been deleted while it was queued up for resolution
           than also this INH should not be considered for resolution
        */
        if (!indirect_nh->is_active || 
             !indirect_nh->owner_route) {
            continue;
        } 

        rtm_track_inh_for_resolution (rtm, indirect_nh);

    } ITERATE_GLTHREAD_END(&rtm->unresolvable_paths.head, curr_glue);

}

void 
rtm_schedule_resolution_worker (rtm_t *rtm) {

    if (rtm->resolution_job) return;

    rtm->resolution_job =  task_create_new_job ( EV(rtm->node),
             (void *)rtm,
             rtm_resolver_job_cbk,
             TASK_ONE_SHOT, TASK_PRIORITY_COMPUTE );
}