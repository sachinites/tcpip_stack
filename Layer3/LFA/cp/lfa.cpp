#include <assert.h>
#include "../../../LinuxMemoryManager/uapi_mm.h"
#include "../../../lmm_testapp_enums.h"
#include "../../../graph.h"
#include "../../../Tracer/tracer.h"

#include "lfa.h"
#include "lfa_isis.h"


extern void 
lfa_isis_init (node_t *node, lfa_t *lfa, uint8_t level);

void lfa_init (node_t *node, lfa_t **lfa) {

    char log_file_name[NODE_NAME_SIZE + 16] = {0};

    assert (*lfa == NULL);
    *lfa = (lfa_t *) XCALLOC2 (0, 1, lfa_t);
    (*lfa)->enable = true;
    snprintf (log_file_name, sizeof (log_file_name), "logs/%s-lfa-log.txt", node->node_name);
    (*lfa)->tr = tracer_init ("lfa", log_file_name, node->node_name,
                            STDOUT_FILENO, 0);
    tracer_enable_all_logging((*lfa)->tr, true);
    tracer_enable_always_flush ((*lfa)->tr, true);
    tracer_enable_console_logging((*lfa)->tr, true);

    lfa_isis_init (node, *lfa, 1);
}


void 
lfa_cleanup (node_t *node, lfa_config_t *lfa_config, uint8_t prot_index) {

    switch (prot_index) {

        case ISIS_L1_LFA_INFEX:
        case ISIS_L2_LFA_INFEX:
            lfa_isis_cleanup(node, lfa_config);
        break;
        break;
        case OSPF_LFA_INDEX:
        case LDP_LFA_INDEX:
        case RSVP_LFA_INDEX:
        case MAX_LFA_INDEX:
        break;
    }
}