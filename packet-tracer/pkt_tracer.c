#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "packet_tracer.h"
#include "../utils.h"
#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"
#include "../LinuxMemoryManager/uapi_mm.h"

void
pkt_tracer_init (pkt_tracer_t **pkt_tracer) {

    *pkt_tracer = (pkt_tracer_t *)XCALLOC(0, 1, pkt_tracer_t);
    (*pkt_tracer)->phase_no = 0;
    init_glthread(&((*pkt_tracer)->head));
    (*pkt_tracer)->enable = false;
}

void
pkt_tracer_logging_enable (pkt_tracer_t *pkt_tracer, bool enable) {

    pkt_tracer->enable = enable;

    if (enable == false) {
        pkt_tracer_destroy_internal(pkt_tracer);
    }
}

void
pkt_tracer_add_phase (pkt_tracer_t *pkt_tracer,
                                     pkt_tracer_type_t type,
                                     pkt_tracer_subtype_t subtype,
                                     pkt_tracer_result_t res,
                                     uint8_t n_configs,
                                     const unsigned char config[][PKT_TRACER_PHASE_CONFIG_LEN],
                                     const unsigned char *info) {

    int i;

    if (pkt_tracer->enable == false) return;

    pkt_tracer_phase_t *phase = (pkt_tracer_phase_t *)calloc(1, 
                                                        sizeof(pkt_tracer_phase_t));
    phase->phase_no = (pkt_tracer->phase_no++);
    phase->type = type;
    phase->subtype = subtype;
    phase->res = res;
    for (i = 0; i < n_configs; i++) {
        string_copy((char *)phase->config[i], config[i], PKT_TRACER_PHASE_CONFIG_LEN);
    }
    phase->config_no = n_configs;
    string_copy((char *)phase->info, info, PKT_TRACER_PHASE_INFO_LEN);
    init_glthread(&phase->glue);
    glthread_add_last(&pkt_tracer->head, &phase->glue);
}

uint32_t
pkt_tracer_print_phase (char *out_buff, 
                                       uint16_t fd,
                                       pkt_tracer_phase_t *phase) {

    int i;
    uint32_t rc = 0;
    
    rc += cprintf ("Phase 2 : %d\n", phase->phase_no);
    rc += cprintf ("Type: %s\n", pkt_tracer_type_to_str(phase->type));
    rc += cprintf ("Subtype: %s\n", pkt_tracer_subtype_to_str(phase->subtype));
    rc += cprintf ("Result: %s\n", phase->res ? "ALLOW" : "DROP");
    rc += cprintf ("Config:\n");
    for (i = 0; i < phase->config_no; i++) {
        rc += cprintf ("%s\n", phase->config[i]);
    }
    rc += cprintf ("Additional Information:\n");
    rc += cprintf ("%s\n", phase->info);
    rc += cprintf ("\n\n");
    return rc;
}

uint32_t
pkt_tracer_print (pkt_tracer_t*pkt_tracer, char *out_buff,  uint16_t fd){

    uint32_t rc = 0;
    glthread_t *curr;
    pkt_tracer_phase_t *phase;

    ITERATE_GLTHREAD_BEGIN(&pkt_tracer->head, curr) {

        phase = glthread_glue_to_pkt_tracer(curr);
        rc += pkt_tracer_print_phase (out_buff, fd, phase);

    } ITERATE_GLTHREAD_END(&pkt_tracer->head, curr)

    return rc;
}

void
pkt_tracer_destroy_internal (pkt_tracer_t *pkt_tracer) {

    glthread_t *curr;
    pkt_tracer_phase_t *phase;

    ITERATE_GLTHREAD_BEGIN(&pkt_tracer->head, curr) {

        phase = glthread_glue_to_pkt_tracer(curr);
        remove_glthread(&phase->glue);
        free(phase);

    } ITERATE_GLTHREAD_END(&pkt_tracer->head, curr)

    pkt_tracer->phase_no = 0;
    pkt_tracer->ingress_intf = NULL;
    pkt_tracer->egress_intf = NULL;
    memset(&pkt_tracer->start_time, 0, sizeof(time_t));
    memset(&pkt_tracer->end_time, 0, sizeof(time_t));
}

/* conf node <node-name> [no] packet-tracer */
/* run node <node-name> packet-tracer input <intf-name> <proto > <src-ip> [<src-port>] <dst-ip> [<dst-port> ]*/
void
pkt_tracer_build_cli_tree(param_t *param) {

}

void
pkt_tracer_mem_init () {

    MM_REG_STRUCT(0, pkt_tracer_t);
}
