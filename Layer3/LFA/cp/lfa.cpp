#include <assert.h>
#include "../../../LinuxMemoryManager/uapi_mm.h"
#include "../../../lmm_testapp_enums.h"
#include "../../../graph.h"
#include "../../../Tracer/tracer.h"

#include "lfa.h"


extern void 
lfa_isis_init (node_t *node, lfa_t *lfa, uint8_t level);

void lfa_init (node_t *node, lfa_t **lfa) {

    char log_file_name[NODE_NAME_SIZE + 16] = {0};

    if (*lfa) return;

    *lfa = (lfa_t *) XCALLOC2 (0, 1, lfa_t);
    (*lfa)->enable = true;
    snprintf (log_file_name, sizeof (log_file_name), "logs/%s-lfa-log.txt", node->node_name);
    (*lfa)->tr = tracer_init ("lfa", log_file_name, node->node_name,
                            STDOUT_FILENO, 0);

    /* Enable Protocol Specific LFAs now */
    lfa_isis_init (node, *lfa, 1);
    lfa_isis_init (node, *lfa, 2);
}

void 
lfa_deinit (node_t *node, lfa_t **lfa) {

    uint8_t i;

    if (*lfa == NULL) {
        return;
    }

    FOR_ALL_LFA_INDEXES(i) {
        lfa_cleanup (node,  i);
    }

    tracer_deinit ((*lfa)->tr);
    (*lfa)->tr = NULL;

    XFREE (*lfa);
    *lfa = NULL;
}

void 
lfa_cleanup (node_t *node, uint8_t prot_index) {

    ted_db_t *ted_db;
    avltree_node_t *curr;
    ted_node_t *ted_node;


    lfa_t *lfa = LFA_NODE_INFO(node);

    lfa_config_t *lfa_config = &lfa->lfa_config[prot_index];
    ted_db = &lfa_config->u.isis.topo;

    switch (prot_index) {

        case ISIS_L1_LFA_INFEX:
        case ISIS_L2_LFA_INFEX:
        case OSPF_LFA_INDEX:
        case LDP_LFA_INDEX:
        case RSVP_LFA_INDEX:
        case MAX_LFA_INDEX:
        break;
    }

    /* Destroy the AVL tree*/
    ITERATE_AVL_TREE_BEGIN(&ted_db->teddb, curr) {

        ted_node = avltree_container_of(curr, ted_node_t, avl_glue);
        ted_delete_node(ted_db, ted_node);

    } ITERATE_AVL_TREE_END;

}

bool 
lfa_is_enabled (node_t *node) {

    lfa_t *lfa = LFA_NODE_INFO(node);

    if (!lfa) return false;
    if (!lfa->enable) return false;

    return true;
}

lfa_config_t *
lfa_get_config (node_t *node, uint8_t prot_index) {

    lfa_t *lfa = LFA_NODE_INFO(node);

    if (!lfa) return NULL;
    if (!lfa->enable) return NULL;

    lfa_config_t *lfa_config = &lfa->lfa_config[prot_index];
    return lfa_config;
}