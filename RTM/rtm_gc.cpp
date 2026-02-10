#include <assert.h>
#include <memory.h>
#include <stdlib.h>
#include "../router_init.h"
#include "rtm_gc.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "../net.h"
#include "../EventDispatcher/event_dispatcher.h"
#include "../lmm_enums.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../Tracer/tracer.h"

static void
rtm_gc_job_cbk(
        event_dispatcher_t *ev, 
        void *arg, 
        uint32_t arg_size) {

    rtm_gc_t *gc ;
    glthread_t *curr;

    rtm_t *rtm = (rtm_t *)arg;

    rtm->gc_job = NULL;

    while ((curr = dequeue_glthread_first (&rtm->gc_queue.head))) {

        gc = glue_to_gc (curr);

        switch (gc->gc_type) {

            case RTM_GC_RT:
                rtm_route_check_and_delete(rtm, gc->u.route);
                break;
            case RTM_GC_NH:
                rtm_nh_check_and_delete(rtm, gc->u.nh);
                break;
            default: ;
        }

        XFREE (gc);
    }
}

void 
rtm_gc_route (rtm_t *rtm, rtm_route *route) {

    char prefix_str[48];

    assert (!route->ref_count);

    rtm_gc_t *gc = (rtm_gc_t *) XCALLOC2 (0, 1, rtm_gc_t);
    gc->gc_type = RTM_GC_RT;
    gc->u.route = route;
    gc->rtm = rtm;
    init_glthread (&gc->glue);

    Fglthread_add_last (&rtm->gc_queue, &gc->glue);

    tracer(rtm->node->cptr, DRTM, 
        "RTM[%s] : Route %s Queued for Garbage Collection\n",
        rtm->name,
        rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));

    if (rtm->gc_job) return;

    rtm->gc_job = task_create_new_job (
            EV(rtm->node),
            (void *)rtm,
            rtm_gc_job_cbk,
            TASK_ONE_SHOT, TASK_PRIORITY_GARBAGE_COLLECTOR );
}

void 
rtm_gc_nh (rtm_t *rtm, rtm_nh *nh) {

    char nh_str[48];
    assert (!nh->ref_count);

    rtm_gc_t *gc = (rtm_gc_t *) XCALLOC2 (0, 1, rtm_gc_t);
    gc->gc_type = RTM_GC_NH;
    gc->u.nh = nh;
    gc->rtm = rtm;
    init_glthread (&gc->glue);

    Fglthread_add_last (&rtm->gc_queue, &gc->glue);
   
    tracer(rtm->node->cptr, DRTM, 
        "RTM[%s] : NH:%s(%u) Queued for Garbage Collection\n",
        rtm->name,
        rtm_format_nexthop(&nh->prefix, nh_str, sizeof(nh_str)), nh->idx);

    if (rtm->gc_job) return;

    rtm->gc_job = task_create_new_job (
            EV(rtm->node),
            (void *)rtm,
            rtm_gc_job_cbk,
            TASK_ONE_SHOT, TASK_PRIORITY_GARBAGE_COLLECTOR );

}

/* ToDo : Need to convert it into AVL tree for optimization */
rtm_nh *
rtm_gc_lookup_nh (rtm_t *rtm, uint32_t nhidx) {

    glthread_t *curr;
    rtm_gc_t *gc ;

    ITERATE_GLTHREAD_BEGIN(&rtm->gc_queue.head, curr) {

        gc = glue_to_gc (curr);

        if (gc->gc_type != RTM_GC_NH) continue;

        if (gc->u.nh->idx == nhidx) {
            return gc->u.nh;
        }

    } ITERATE_GLTHREAD_END(&rtm->gc_queue.head, curr);

    return NULL;
}
