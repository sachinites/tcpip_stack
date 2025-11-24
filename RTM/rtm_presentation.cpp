#include "../graph.h"
#include "rtm.h"
#include "rtm_route.h"
#include "rtm_presentation.h"
#include "../EventDispatcher/event_dispatcher.h"

static void 
rtm_advt_job_cbk (event_dispatcher_t *ev, void *arg, uint32_t arg_size) {


}

static void 
rtm_presl_start_advt_job (rtm_t *rtm) {

    if (rtm->advt_job) return;

    rtm->advt_job = task_create_new_job ( EV(rtm->node),
             (void *)rtm,
             rtm_advt_job_cbk,
             TASK_ONE_SHOT, TASK_PRIORITY_COMPUTE );
}

void 
rtm_presentation_layer_route_add (rtm_t *rtm, rtm_nh *nh) {

    if (IS_QUEUED_UP_IN_THREAD(&nh->advt_glue)) return;
    Fglthread_add_last (&rtm->advt_nhs[nh->proto], &nh->advt_glue);
    rtm_nh_reference (nh);
    rtm_presl_start_advt_job (rtm);
}