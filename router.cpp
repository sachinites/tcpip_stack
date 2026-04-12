#include "router.h"
#include "router_init.h"

bool
rtr_eligible_to_remove_rtr_id(node_t *node) {

    for (int i = 0; i < MAX_VRF_PER_NODE; i++) {
        if (node->vrf[i] &&
            node->vrf[i]->isis_node_info) {
            return false;
        }
    }
    return true;
}