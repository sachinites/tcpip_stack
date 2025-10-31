#include "../Tree/libtree.h"
#include "rtm_storage.h"

avltree_t rtm_tree;

static int rtm_instance_comp_fn(const avltree_node_t *a, const avltree_node_t *b) {

    rtm_t *inst_a = (rtm_t *)avltree_container_of(a, rtm_t, rtm_tree_node);
    rtm_t *inst_b = (rtm_t *)avltree_container_of(b, rtm_t, rtm_tree_node);

    if (inst_a->vrf < inst_b->vrf) {
        return -1;
    } else if (inst_a->vrf > inst_b->vrf) {
        return 1;
    } 

    if (inst_a->afi < inst_b->afi) {
        return -1;
    } else if (inst_a->afi > inst_b->afi) {
        return 1;
    }

    return 0;
}

void 
rtm_initialize () {

    avltree_init(&rtm_tree, rtm_instance_comp_fn);
}