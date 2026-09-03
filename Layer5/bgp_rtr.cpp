#include <stdlib.h>

#include "../libs/LinuxMemoryManager/uapi_mm.h"
#include "../libs/Tracer/tracer.h"

#include "../vrf/vrf.h"
#include "../router_init.h"

#include "bgp_rtr.h"



bgp_inst_t *
bgp_init(node_t *node) {

    char log_file_name[128] = {0};

    def_vrf_t *def_vrf = (def_vrf_t *)NODE_DEF_VRF(node);

    assert (!def_vrf->bgp_inst);

    bgp_inst_t *bgp = (bgp_inst_t *)XCALLOC2(0, 1, bgp_inst_t);

    snprintf (log_file_name, sizeof (log_file_name), 
        "logs/%s-%s-gobgp-log.txt", 
        node->node_name, def_vrf->vrf.vrf_name);

    bgp->tr = tracer_init ("GoBGP", log_file_name, node->node_name, STDOUT_FILENO, 0);

    tracer_log_bit_set(bgp->tr, ~0);
    tracer_enable_file_logging(bgp->tr, true);

    bgp->recvd_route_processing_task = NULL;
    init_Fglthread (&bgp->pending_routes_list);

    return bgp;
}

void 
bgp_deinit (bgp_inst_t *bgp_inst) {

}

bgp_inst_t *
bgp_get_instance(node_t *node) {

    def_vrf_t *def_vrf = (def_vrf_t *)NODE_DEF_VRF(node);
    return def_vrf->bgp_inst;
}