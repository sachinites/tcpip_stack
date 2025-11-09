#include "rtm.h"
#include "rtm_common.h"

extern avltree_t rtm_tree;

/* Comparator function for RTM AVL tree */
static int
rtm_compare(const avltree_node_t *node1, const avltree_node_t *node2) {
    
    rtm_t *rtm1 = avltree_container_of(node1, rtm_t, rtm_glue);
    rtm_t *rtm2 = avltree_container_of(node2, rtm_t, rtm_glue);
    
    if (rtm1->vrf < rtm2->vrf) return -1;
    if (rtm1->vrf > rtm2->vrf) return 1;
    
    if (rtm1->afi < rtm2->afi) return -1;
    if (rtm1->afi > rtm2->afi) return 1;
    
    if (rtm1->rtm_id < rtm2->rtm_id) return -1;
    if (rtm1->rtm_id > rtm2->rtm_id) return 1;
    
    return 0;
}

void 
rtm_module_init () {

    avltree_init(&rtm_tree, rtm_compare);
}