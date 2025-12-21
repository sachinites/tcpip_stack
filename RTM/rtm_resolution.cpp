#include <assert.h>
#include <memory.h>
#include <stdlib.h>
#include "../Tree/libtree.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../EventDispatcher/event_dispatcher.h"
#include "../graph.h"
#include "../Tracer/tracer.h"
#include "rtm_resolution.h"
#include "rtm.h"
#include "rtm_nh.h"
#include "rtm_route.h"
#include "rtm_presentation.h"
#include "rtm_priv_api.h"

void  
rtm_schedule_nh_resolution_worker (rtm_t *rtm);

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
void 
rtm_copy_route_active_nhs_to_inh_direct_nh_set(
        rtm_t *rtm, rtm_route *route, rtm_nh *indirect_nh) {
    
    rtm_nh *nh;
    char inh_str[128];
    char route_str[48];
    int dnh_count = 0;
    glthread_t *nh_glue;
    glthread_data_node_t *data_node;
    
    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Copying active NHs from route %s to INH %s\n",
        rtm->name,
        rtm_format_prefix(&route->prefix, route_str, sizeof(route_str)),
        rtm_nh_one_liner_trace(indirect_nh, inh_str, sizeof(inh_str)));

    ITERATE_GLTHREAD_BEGIN(&route->path_list, nh_glue) {

        nh = route_glue_to_rtm_nh(nh_glue);

        if (!nh->is_active) continue;
        if (nh->rtm_flags & RTM_DNH_RTM_F_NO_PROPOGATE_UPSTREAM) continue;

        if (!nh->is_indirect) {

            if (rtm_inh_has_direct_nh(indirect_nh, nh)) continue;

            data_node = (glthread_data_node_t *)XCALLOC (0, 1, glthread_data_node_t);
            init_glthread(&data_node->glue);
            data_node->data = nh;
            rtm_nh_Fglthread_add_last (nh, &indirect_nh->direct_nh_list,
                &data_node->glue);
                
            tracer(rtm->node->cptr, DRTM_DET,
                "RTM[%s] : Copied direct NH %s to INH %s\n",
                rtm->name,
                rtm_nh_one_liner_trace(nh, route_str, sizeof(route_str)),
                rtm_nh_one_liner_trace(indirect_nh, inh_str, sizeof(inh_str)));
            dnh_count++;
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
                rtm_nh_Fglthread_add_last (nh, &indirect_nh->direct_nh_list,
                    &data_node->glue);
                tracer(rtm->node->cptr, DRTM_DET,
                    "RTM[%s] : Copied direct NH %s to INH %s\n",
                    rtm->name,
                    rtm_nh_one_liner_trace(nh, route_str, sizeof(route_str)),
                    rtm_nh_one_liner_trace(indirect_nh, inh_str, sizeof(inh_str)));
                dnh_count++;

            } ITERATE_GLTHREAD_END(&nh->direct_nh_list, direct_nh_glue);
        }

    } ITERATE_GLTHREAD_END(&route->path_list, nh_glue);
    
    rtm_schedule_route_advertisement (rtm, indirect_nh->owner_route);
    
    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Copied %d direct NHs from Route %s to INH %s\n",
        rtm->name, dnh_count, 
        rtm_format_prefix(&route->prefix, route_str, sizeof(route_str)),
        rtm_nh_one_liner_trace(indirect_nh, inh_str, sizeof(inh_str)));
}

/* Route has been resolved i.e. its INH has been resolbed by DNHs
    Now check what all INHs this route resolves recursively and update them 
    This fn works for Unresolution also.    
*/
void
rtm_resolve_routes_recursively (rtm_t *rtm, rtm_route *route) {

    char route_str[48];
    char inh_str[128];
    rtm_nh *indirect_nh;
    int resolved_count = 0;
    int unresolved_count = 0;
    glthread_t *curr_lnh_glue;

    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Route : %s : Route propogation starts\n",
        rtm->name,
        rtm_format_prefix(&route->prefix, route_str, sizeof(route_str)));

    ITERATE_GLTHREAD_BEGIN(&route->resolved_lnhs.head, curr_lnh_glue) {

        indirect_nh = resolution_list_glue_to_rtm_nh(curr_lnh_glue);

        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : Route : %s : Propogating resolution to INH %s\n",
            rtm->name, route_str,
            rtm_nh_one_liner_trace(indirect_nh, inh_str, sizeof(inh_str)));

        /* Withdraw first*/
        rtm_flush_inh_direct_nh_set(rtm, indirect_nh);

        /* Copy Route's active NHs to INH direct NH set*/
        rtm_copy_route_active_nhs_to_inh_direct_nh_set(rtm, route, indirect_nh);

        /* This INH cannot have any active DNH, try to resolve it again */
        bool was_resolved = rtm_route_is_resolved(indirect_nh->owner_route);

        if (Fglthread_list_is_empty(&indirect_nh->direct_nh_list)) {
            
            tracer(rtm->node->cptr, DRTM,
                "RTM[%s] : INH %s became unresolvable, withdrawing from Resolution\n",
                rtm->name, inh_str);
            
            rtm_resolution_nh_withdraw(rtm, indirect_nh);

            tracer(rtm->node->cptr, DRTM,
                "RTM[%s] : INH %s became unresolvable, moving to unresolvable queue\n",
                rtm->name, inh_str);

            /* And Queue it again for re-resolution*/
            rtm_nh_Fglthread_add_last (indirect_nh, &rtm->unresolvable_paths, 
                &indirect_nh->unresolvable_list_glue);

            unresolved_count++;

            rtm_schedule_nh_resolution_worker (rtm);
        }
        else {
            resolved_count++;
            tracer (rtm->node->cptr, DRTM,
                "RTM[%s] : Route %s resolved INH %s successfully\n",
                rtm->name, route_str, inh_str);

            if (!was_resolved && rtm_route_is_resolved (indirect_nh->owner_route)) {

                char resolved_route[48];
                tracer(rtm->node->cptr, DRTM,
                    "RTM[%s] : Route %s is freshly resolved, Will schedule Resolution Workder if not already.\n", 
                    rtm->name, 
                    rtm_format_prefix(&indirect_nh->owner_route->prefix, 
                        resolved_route, sizeof(resolved_route)));

                rtm_schedule_nh_resolution_worker (rtm);
            }
        }

        rtm_schedule_nh_resolution_worker (rtm);

        /* Now Recursively update the routes INH upstream in Graph*/
        rtm_resolve_routes_recursively (rtm, indirect_nh->owner_route);

    } ITERATE_GLTHREAD_END(&route->resolved_lnhs.head, curr_lnh_glue);
}

static void 
rtm_try_unresolvable_paths_resolution (rtm_t *rtm, int *resolved_count) {

    rtm_route *route;
    rtm_nh *indirect_nh;
    glthread_t *curr_glue;
    char inh_str[128];
    char route_str[48];
    char route_resolver_str[48];
    int initial_resolved_count = 0;

    ITERATE_GLTHREAD_BEGIN(&rtm->unresolvable_paths.head, curr_glue) {

        indirect_nh = unresolvable_list_glue_to_rtm_nh(curr_glue);

        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : Trying to resolve INH %s\n",
            rtm->name,
            rtm_nh_one_liner_trace(indirect_nh, inh_str, sizeof(inh_str)));

        /* Sanity Checks */
        assert ( indirect_nh->is_active && 
                    indirect_nh->is_indirect &&
                    !rtm_nh_is_resolved (indirect_nh) );

        assert (indirect_nh->resolved_via_route == NULL);
        assert (!IS_QUEUED_UP_IN_THREAD(&indirect_nh->route_resolved_list_glue));
        assert (Fglthread_list_is_empty (&indirect_nh->direct_nh_list));

        route = rtm_get_resolver_route(rtm, indirect_nh);

        if (!route) {

            tracer(rtm->node->cptr, DRTM_DET,
                "RTM[%s] : INH %s is still unresolvable, keeping it on unresolvable Queue\n",
                rtm->name,inh_str );
            continue;
        }

        rtm_nh_remove_Fglthread (rtm, indirect_nh,
            &rtm->unresolvable_paths, &indirect_nh->unresolvable_list_glue);

        rtm_copy_route_active_nhs_to_inh_direct_nh_set(rtm, route, indirect_nh);

        indirect_nh->resolved_via_route = route;
        rtm_route_reference (route);
        rtm_nh_Fglthread_add_last (indirect_nh, 
                &route->resolved_lnhs, 
                &indirect_nh->route_resolved_list_glue);     
        rtm_inh_moved_to_resolved_state(rtm, indirect_nh);

        if ( !IS_QUEUED_UP_IN_THREAD (&indirect_nh->owner_route->resolved_route_glue) ) {

            /* Queue the route to recursively update resolution graph upstream. We cant do
                it synchronously here because we want to do it only when all INHs of the route
                are resolved from downstream routes in RES Graph*/
                tracer(rtm->node->cptr, DRTM,
                    "RTM[%s] : Queuing route %s for recursive resolution upstream\n",
                    rtm->name, route_str);

                rtm_route_Fglthread_add_last (
                    indirect_nh->owner_route, 
                    &rtm->resolved_unpropogated_routes, 
                    &indirect_nh->owner_route->resolved_route_glue);
        }
        
        initial_resolved_count++;
        
    } ITERATE_GLTHREAD_END(&rtm->unresolvable_paths.head, curr_glue);

    if (initial_resolved_count) {
        *resolved_count += initial_resolved_count;
        rtm_try_unresolvable_paths_resolution (rtm, resolved_count);
    }
} 

static void
rtm_nh_resolver_job_cbk(event_dispatcher_t *ev, void *arg, uint32_t arg_size) {

    int resolved_count = 0;
    rtm_t *rtm = (rtm_t *)arg;

    rtm->nh_resolution_job = NULL;
    
    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : NH resolution worker started\n",
        rtm->name);

    if (IS_BIT_SET (rtm->flags, RTM_F_INHS_RE_RESOLVE)) {

         UNSET_BIT16(rtm->flags, RTM_F_INHS_RE_RESOLVE);

        rtm_all_inh_unresolve(rtm, NULL);
    }
    
    rtm_try_unresolvable_paths_resolution (rtm, &resolved_count);

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : NH resolution worker completed: resolved=%d\n",
        rtm->name, resolved_count);

    if (resolved_count) {
        rtm_schedule_route_propogation_worker (rtm);
    }
}

void 
rtm_schedule_nh_resolution_worker (rtm_t *rtm) {

    if (rtm->nh_resolution_job) {
        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : NH resolution worker already scheduled\n", rtm->name);
        return;
    }

    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Scheduling NH resolution worker\n", rtm->name);

    rtm->nh_resolution_job =  task_create_new_job ( EV(rtm->node),
             (void *)rtm,
             rtm_nh_resolver_job_cbk,
             TASK_ONE_SHOT, TASK_PRIORITY_COMPUTE );
}

/* This API is used to resolve unresolve routes Or re-resolve already resolved routes 
    of other dependent RTMs. For example, 
    if LDP installs the route in x.inet.3 then , an attempt should be made to resolve BGP 
    routes in x.inet.0 RTM for all VRFs  
    This API should be invoked when : 
    1. A new Route is added 
    2. A Route is Deleted
    3. An Existing Route moved from resolved to unresolved state
    4. An Existing Route moved from unresolved to resolved state
*/
void 
rtm_schedule_nh_resolution_worker_of_dependent_rtms (rtm_t *rtm) {

    /* If this is 0.inet.3 RTM, Schedule the NH resolution worker of x.inet.0 RTM*/

    // Since VRFs are not supported, we will handle Default VRF RTMs only for now

    if (rtm == rtm->node->node_nw_prop.inet3) {

        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : NH resolution worker already scheduled in RTM inet.0\n", rtm->name);        

        SET_BIT(rtm->node->node_nw_prop.inet0->flags, RTM_F_INHS_RE_RESOLVE);

        rtm_schedule_nh_resolution_worker (rtm->node->node_nw_prop.inet0);
    }

    /* If this is 0.inet.63 RTM, Schedule the NH resolution worked of 0.inet.6 RTM*/
     else if (rtm == rtm->node->node_nw_prop.inet63) {

        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : NH resolution worker already scheduled in RTM inet.6\n", rtm->name);        

        SET_BIT(rtm->node->node_nw_prop.inet6->flags, RTM_F_INHS_RE_RESOLVE);

        rtm_schedule_nh_resolution_worker (rtm->node->node_nw_prop.inet6);
    }

}


void 
rtm_schedule_route_propogation (rtm_t *rtm, rtm_route *route) {

    char route_str[48];

    if (IS_QUEUED_UP_IN_THREAD (&route->resolved_route_glue)) return;
    
    tracer(rtm->node->cptr, DRTM,
                    "RTM[%s] : Queuing route %s for recursive resolution upstream\n",
                    rtm->name,
                    rtm_format_prefix(&route->prefix, route_str, sizeof(route_str)));

                rtm_route_Fglthread_add_last (
                    route, 
                    &rtm->resolved_unpropogated_routes, 
                    &route->resolved_route_glue);

    rtm_schedule_route_propogation_worker (rtm);
}


static void 
rtm_rt_resolver_job_cbk (event_dispatcher_t *ev, void *arg, uint32_t arg_size) {

    glthread_t *curr;
    rtm_route *route;
    
    rtm_t *rtm = (rtm_t *)arg;

    rtm->nh_resolution_job = NULL;
    
    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Route Propogation Worker Started\n",
        rtm->name);

    ITERATE_GLTHREAD_BEGIN(&rtm->resolved_unpropogated_routes.head, curr) {

        route = resolved_route_glue_to_route (curr);

        rtm_resolve_routes_recursively (rtm , route);

        rtm_route_remove_Fglthread (rtm, route, 
            &rtm->resolved_unpropogated_routes,  
            &route->resolved_route_glue);

    } ITERATE_GLTHREAD_END(&rtm->resolved_unpropogated_routes.head, curr);
}

void 
rtm_schedule_route_propogation_worker (rtm_t *rtm) {

    if (rtm->rt_resolution_job) return;
   
    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Route Propogation Worker Scheduled\n",
        rtm->name);

    rtm->rt_resolution_job =  task_create_new_job ( EV(rtm->node),
             (void *)rtm,
             rtm_rt_resolver_job_cbk,
             TASK_ONE_SHOT, TASK_PRIORITY_COMPUTE );
}

/* Withdraw this NH from contribution to Resolution Graph. After this API
    INH/DNH do not contribute to the resolution of any route in RTM, also
    it is not even on rtm->unresolvable list. 
    This API is Fully synchronous and must be used when NHs are being
    deleted from RTM
*/
void
rtm_resolution_nh_withdraw (rtm_t *rtm, rtm_nh *nh) {

    /* Nexthop must stay intact with its owner route for calling this API */
    char inh_str[128];
    char route_str[48];

    tracer (rtm->node->cptr, DRTM, 
        "RTM[%s] : Nexthop %s Complete withdrawn from Resolution Graph\n", 
        rtm->name,
        rtm_nh_one_liner_trace(nh, inh_str, sizeof(inh_str)));
        
    assert (nh->owner_route);
    assert (IS_QUEUED_UP_IN_THREAD (&nh->route_glue));
   
    /* Eight Cases :  
        Active        Indirect           Resolved               Result
            0                0                        0                      Invalid
            0                0                        1                      Sanity Checks Only, No Action
            0                1                        0                      Sanity Checks Only, No Action
            0                1                        1                      Invalid
            1                0                        0                      Invalid
            1                0                        1                      Withdraw Upstream in RES Graph
            1                1                        0                      Remove from Unresolvable list
            1                1                        1                      Withdraw Upstream, Give up Down-stream DNHs
    */

   /* Case 1 :  */
    if (!nh->is_active && !nh->is_indirect && !rtm_nh_is_resolved (nh)) {

        /* Invalid State */
        assert (0);
    }

    /* Case 2 : */
    if (!nh->is_active && !nh->is_indirect && rtm_nh_is_resolved (nh)) {
        
        /* This us DNH do not contribute to resolution graph */

        /* Sanity checks to ensure this ... */
        assert (!IS_QUEUED_UP_IN_THREAD (&nh->unresolvable_list_glue));
        // Since it is DNH, it cannot be resolved by any other route
        assert (!IS_QUEUED_UP_IN_THREAD (&nh->route_resolved_list_glue));
        assert (!nh->resolved_via_route);
        // Since it is DNH, it need no borrowed DNHs
        assert (Fglthread_list_is_empty (&nh->direct_nh_list));
        // Action : No Action 
        return;
    }

    /* Case 3 : */
    if (!nh->is_active && nh->is_indirect && !rtm_nh_is_resolved (nh)) {
        
        /* This is INH with no resolution of self */

        // Since this is inactive, it must not be on unresolvable thread/list
        assert (!IS_QUEUED_UP_IN_THREAD (&nh->unresolvable_list_glue));
        // Since it is unresolved, it cannot be on route->resolved_lnhs list
        assert (!IS_QUEUED_UP_IN_THREAD (&nh->route_resolved_list_glue));
        assert (!nh->resolved_via_route);
        // Since it is unresolved, its borrowed DNH list must be empty
        assert (Fglthread_list_is_empty (&nh->direct_nh_list));
        // Action : No Action 
        return;
    }

   /* Case 4 :  */
    if (!nh->is_active && nh->is_indirect && rtm_nh_is_resolved (nh)) {

        /* Indirect NH which is Inactive state cannot be in resolved state */
        assert (0);
    }

   /* Case 5 :  */
    if (nh->is_active && !nh->is_indirect && !rtm_nh_is_resolved (nh)) {

        /* DNHs are always in resolved state  */
        assert (0);
    }

   /* Case 6 :  */
    if (nh->is_active && !nh->is_indirect && rtm_nh_is_resolved (nh)) {

        /* These Active DNHs contribute to resolution graph only Upstream Direction  */
        // Since it is DNH, it must not be on unresolvable thread/list
        assert (!IS_QUEUED_UP_IN_THREAD (&nh->unresolvable_list_glue));
        // Since it is DNH, it cannot be on route->resolved_lnhs list
        assert (!IS_QUEUED_UP_IN_THREAD (&nh->route_resolved_list_glue));
        // Dince it is DNH, no other route can resolve it
        assert (!nh->resolved_via_route);
        // Since it is DNH, it need no borrowed DNHs
        assert (Fglthread_list_is_empty (&nh->direct_nh_list));

        // Action 

        // if Upstream there is no route resolved by this DNH, no action
        if (Fglthread_list_is_empty (&nh->owner_route->resolved_lnhs)) return;

        /* We need to withdraw this NH from Resolution Graph upstream, 
            set the no propogation flag */
        nh->rtm_flags |= RTM_DNH_RTM_F_NO_PROPOGATE_UPSTREAM;

        rtm_resolve_routes_recursively (rtm, nh->owner_route);

        nh->rtm_flags &= ~RTM_DNH_RTM_F_NO_PROPOGATE_UPSTREAM;

        rtm_schedule_route_advertisement (rtm, nh->owner_route);
        return;
    }

    /* Case 7 :  */
    /* We cannot take any decision based on rtm_nh_is_resolved( ) API
        because, in NH delete case recursively upstream, INH could still
        be resolved by some route while at the same time has direct_nh_list
        empty. So, will process it based on status of nh->direct_nh_list( )
    */
    if (nh->is_active && nh->is_indirect && 
        Fglthread_list_is_empty(&nh->direct_nh_list))
    {
        /* IF this INH DNH list is empty*/
        if (IS_QUEUED_UP_IN_THREAD(&nh->unresolvable_list_glue))
        {
            assert(nh->resolved_via_route == NULL);
            return;
        }

        tracer(rtm->node->cptr, DRTM,
           "RTM[%s] : Route %s do not resolve INH %s anymore\n",
           rtm->name,
           rtm_format_prefix(&nh->resolved_via_route->prefix, 
            route_str, sizeof(route_str)), inh_str);

        rtm_nh_remove_Fglthread(rtm, nh,
                                &nh->resolved_via_route->resolved_lnhs,
                                &nh->route_resolved_list_glue);
        rtm_route_dereference(rtm, nh->resolved_via_route);
        nh->resolved_via_route = NULL;
        rtm_inh_moved_to_unresolved_state(rtm, nh);

        // if Upstream there is no route resolved by this DNH, no action
        if (Fglthread_list_is_empty (&nh->owner_route->resolved_lnhs)) return;

        rtm_resolve_routes_recursively (rtm, nh->owner_route);
        return;
    }

    /* Case 8 : */
    if (nh->is_active && nh->is_indirect && 
            !Fglthread_list_is_empty(&nh->direct_nh_list)) {

        // Such an INH contribute to reslution graph upstream and downstream,
        // we must withdraw its contribution in both directions
        // Sanity Checks
        // Must not be on unresolvable list since it is resolved already
        assert (!IS_QUEUED_UP_IN_THREAD (&nh->unresolvable_list_glue));
        // must be on route->resolved_lnhs since it is resolved
        assert (IS_QUEUED_UP_IN_THREAD (&nh->route_resolved_list_glue));
        // Must be resolved by some route
        assert (nh->resolved_via_route);
        // Since it is resolved, nust have DNHs borrowed list
        assert (!Fglthread_list_is_empty (&nh->direct_nh_list) );

        // Action 
        // 1 Withdraw DNHs pulled from Downstream Routes in resolution Graph
        rtm_flush_inh_direct_nh_set (rtm, nh);
        
        tracer(rtm->node->cptr, DRTM,
           "RTM[%s] : Route %s do not resolve INH %s anymore\n",
           rtm->name,
           rtm_format_prefix(&nh->resolved_via_route->prefix, route_str, sizeof(route_str)),
           inh_str);

        // Break linkage from route which resolves this INH
        rtm_nh_remove_Fglthread(rtm, nh, 
                &nh->resolved_via_route->resolved_lnhs, 
                &nh->route_resolved_list_glue);
        rtm_route_dereference(rtm,  nh->resolved_via_route);
        nh->resolved_via_route = NULL;
        rtm_inh_moved_to_unresolved_state(rtm, nh);

        // Action 
        // 2 Withdraw its contribution to resolution graph upstream 
        
         if (Fglthread_list_is_empty (&nh->owner_route->resolved_lnhs)) return;
        rtm_resolve_routes_recursively (rtm, nh->owner_route);

        /* We dont put INHs wbeing withdrawl on Unresolvable path*/
        return;
    }
}

static uint32_t 
rtm_re_resolve_inhs_per_protocol (rtm_t *rtm, cmn_prefix_t *route, RTM_PROTO_T proto) {

    rtm_nh *nh;
    glthread_t *curr;
    uint32_t count = 0;
    rtm_route *resolver_route;
    char nh_str[128], from_rt_str[48], to_rt_str[48];

    ITERATE_GLTHREAD_BEGIN (&rtm->nhs_by_src[proto], curr) {

        nh = src_glue_to_rtm_nh(curr);

        assert (nh->is_indirect);

        /* Skip those who are aready allotted resolver route */
        if (!nh->resolved_via_route) continue;

        /* Sanity Check : It has to be acitve INH if it is allotted resolver router */
        assert (nh->is_active);

        resolver_route = rtm_get_resolver_route (rtm, nh);
        assert (resolver_route);

        tracer(rtm->node->cptr, DRTM_DET, 
            "RTM[%s] : LPM lookup result for Look up : %s is Route %s\n",
            rtm->name, 
            rtm_nh_one_liner_trace(nh, nh_str, sizeof(nh_str)),
            rtm_format_prefix(&resolver_route->prefix, to_rt_str, sizeof(to_rt_str)));

        if (resolver_route == nh->resolved_via_route) {
            tracer(rtm->node->cptr, DRTM_DET,
                "RTM[%s] : INH %s remains resolved via same route %s\n", 
                rtm->name, 
                rtm_nh_one_liner_trace(nh, nh_str, sizeof(nh_str)),
                rtm_format_prefix(&resolver_route->prefix, to_rt_str, sizeof(to_rt_str)));
            continue;
        }

        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : Re-resolving INH %s from route %s to route %s\n", 
            rtm->name, 
            rtm_nh_one_liner_trace(nh, nh_str, sizeof(nh_str)),
            rtm_format_prefix(&nh->resolved_via_route->prefix, from_rt_str, sizeof(from_rt_str)),
            rtm_format_prefix(&resolver_route->prefix, to_rt_str, sizeof(to_rt_str)));

        rtm_resolution_nh_withdraw(rtm, nh);
        rtm_nh_Fglthread_add_last (nh, &rtm->unresolvable_paths, &nh->unresolvable_list_glue);

        count++;

    } ITERATE_GLTHREAD_END (rtm->nhs_by_src[proto], curr) ;

    if (!Fglthread_list_is_empty (&rtm->unresolvable_paths)) {
        rtm_schedule_nh_resolution_worker (rtm);
    }

    tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : Number of INHs Re-resolved to other route : %u\n", 
            rtm->name, count);

    return count;
}

void 
rtm_re_resolve_inhs (rtm_t *rtm, cmn_prefix_t *route) {

    /* BGP protocol */
    RTM_PROTO_T proto = RTM_PROTO_BGP;
    rtm_re_resolve_inhs_per_protocol (rtm, route, proto);
}

void 
rtm_all_inh_unresolve(rtm_t *rtm,  cmn_prefix_t *route) {

    rtm_nh *nh;
    avltree_node_t *avl_node;

    ITERATE_AVL_TREE_BEGIN(&rtm->nhs_by_idx, avl_node) {

       nh = (rtm_nh *)avltree_container_of(avl_node, rtm_nh, idx_glue);
       if (!nh->is_indirect)  continue;
       if (!rtm_nh_is_resolved(nh)) continue;
      if (route && cmn_prefix_compare(&nh->resolved_via_route->prefix, route) != 0) continue;
        rtm_resolution_nh_withdraw(rtm, nh);
        rtm_nh_Fglthread_add_last (nh, 
            &rtm->unresolvable_paths, &nh->unresolvable_list_glue);

    } ITERATE_AVL_TREE_END(&rtm->nhs_by_idx, avl_node);

}

rtm_route *
rtm_get_resolver_route (rtm_t *rtm, rtm_nh *inh) {

    cmn_prefix_t *prefix;
    rtm_route *resolver_route;
    rtm_t *lookup_rtm = rtm_get_resolver_rtm (rtm->node, inh);

    if (!lookup_rtm) return NULL;
    
    prefix = &inh->prefix;

    switch (prefix->afi) {

        case AF_IPV4:
        {
            switch (lookup_rtm->afi) {

                case AF_IPV4:
                {
                    resolver_route = rtm_lpm_tree_lookup(lookup_rtm, prefix);
                    if (!resolver_route) return NULL;
                    if (!rtm_route_is_resolved(resolver_route)) return NULL;
                    return resolver_route;
                }
                break;
            }
        }
        break;


        case AF_IPV6:
        {
            switch (lookup_rtm->afi) {

                case AF_IPV6:
                {
                    resolver_route = rtm_lpm_tree_lookup(lookup_rtm, prefix);
                    if (!resolver_route) return NULL;
                    if (!rtm_route_is_resolved(resolver_route)) return NULL;
                    return resolver_route;
                }
                break;
            }
        }
        break;        


        case AF_LABEL:
        {
            switch (lookup_rtm->afi) {

                case AF_LABEL:
                {
                    resolver_route = rtm_route_lookup(lookup_rtm, prefix);
                    if (!resolver_route) return NULL;
                    if (!rtm_route_is_resolved(resolver_route)) return NULL;
                    return resolver_route;
                }
                break;
            }
        }
        break;

    }

    return NULL;
}

/* feed the set of rules for route resolution */
rtm_t *
rtm_get_resolver_rtm (node_t *node, rtm_nh *indirect_nh) {

    /* Rule 1 : If the route is BGP VPNv4 route installed in Customer
        VRF inet.0 table <x.inet.0> , resolve it in default inet.3 table*/

    if (indirect_nh->proto == RTM_PROTO_BGP &&
            indirect_nh->sub_proto == RTM_PROTO_BGP_VPN) {
          //  indirect_nh->rtm->vrf != RTM_DEFAULT_VRF) {

        //A route installed in x.inet.0 should be resolved over 0.inet.3
        if (indirect_nh->prefix.afi == AF_IPV4 &&
                indirect_nh->rtm->afi == AF_IPV4) 
            return node->node_nw_prop.inet3;

        //x.inet63.0
        if (indirect_nh->prefix.afi == AF_IPV6 &&
                indirect_nh->rtm->afi == AF_IPV6) 
            return node->node_nw_prop.inet63;

        else return NULL;
    }

    /* Add more Rules here */


    /* Default Rules */
    if (indirect_nh->prefix.afi == AF_IPV4) return node->node_nw_prop.inet0;
    if (indirect_nh->prefix.afi == AF_IPV6) return node->node_nw_prop.inet6;
    if (indirect_nh->prefix.afi == AF_LABEL) return node->node_nw_prop.mpls0;

    return NULL;
}

