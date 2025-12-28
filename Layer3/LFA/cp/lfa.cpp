#include <assert.h>
#include "../../../LinuxMemoryManager/uapi_mm.h"
#include "../../../lmm_enums.h"
#include "../../../router_init.h"
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
    //lfa_isis_init (node, *lfa, 1);
    //lfa_isis_init (node, *lfa, 2);
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

    switch (prot_index) {

        case ISIS_L1_LFA_INFEX:
            if (!lfa_config->u.isis.enable) return;
            ted_db = &lfa_config->u.isis.topo;
            break;
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

lfa_protected_resource_t *
lfa_get_available_protected_resource_slot (
        lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION]) {

    int i;
    lfa_protected_resource_t  *pr_res;

    for (i = 0; i < LFA_MAX_PROTECTION; i++) {
            
        pr_res = &(*arr)[i];
        if (!pr_res->link_protection && 
            !pr_res->node_protection && 
            !pr_res->srlg_protection) return pr_res;
    }

    return NULL;
}

lfa_protected_resource_t *
lfa_get_link_protection_resource (
        lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION], 
        uint32_t ifindex) {

    int i;
    lfa_protected_resource_t  *pr_res;

    for (i = 0; i < LFA_MAX_PROTECTION; i++) {
            
        pr_res = &(*arr)[i];
        if (!pr_res->link_protection) continue;
        if (pr_res->u.ifindex == ifindex) return pr_res;
    }

    return NULL;
}

lfa_protected_resource_t *
lfa_enable_link_protection (lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION], uint32_t ifindex) {

    lfa_protected_resource_t *pr_res;
    pr_res = lfa_get_available_protected_resource_slot (arr);
    if (!pr_res) return NULL;
    pr_res->link_protection = true;
    pr_res->u.ifindex = ifindex;
    return pr_res;
}

void
lfa_disable_link_protection (lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION], uint32_t ifindex) {

    lfa_protected_resource_t *pr_res;
    pr_res = lfa_get_link_protection_resource (arr, ifindex);
    if (!pr_res) return;
    pr_res->link_protection = false;
    pr_res->u.ifindex = 0;
}

lfa_protected_resource_t *
lfa_get_node_protection_resource (
        lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION], 
        uint32_t rtr_id, uint8_t pn_no) {

    int i;
    lfa_protected_resource_t  *pr_res;

    for (i = 0; i < LFA_MAX_PROTECTION; i++) {
            
        pr_res = &(*arr)[i];
        if (!pr_res->node_protection) continue;
        if (pr_res->u.node.rtr_id != rtr_id) continue;
        if (pr_res->u.node.pn_no != pn_no) continue;
        return pr_res;
    }

    return NULL;
}

lfa_protected_resource_t *
lfa_enable_node_protection (lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION], uint32_t rtr_id, uint8_t pn_no) {

    lfa_protected_resource_t *pr_res;
    pr_res = lfa_get_available_protected_resource_slot (arr);
    if (!pr_res) return NULL;
    pr_res->node_protection = true;
    pr_res->u.node.rtr_id = rtr_id;
    pr_res->u.node.pn_no = pn_no;
    return pr_res;
}

void
lfa_disable_node_protection (lfa_protected_resource_t (*arr)[LFA_MAX_PROTECTION], uint32_t rtr_id, uint8_t pn_no) {

    lfa_protected_resource_t *pr_res;
    pr_res = lfa_get_node_protection_resource (arr, rtr_id, pn_no);
    if (!pr_res) return;
    pr_res->node_protection = false;
    pr_res->u.node.rtr_id = 0;
    pr_res->u.node.pn_no = 0;
}
