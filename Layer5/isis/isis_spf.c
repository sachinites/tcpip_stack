#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_spf.h"


void
isis_schedule_spf_job(node_t *node) {

    printf("%s()... called \n", __FUNCTION__);
    ISIS_INCREMENT_NODE_STATS(node, spf_runs);
}