#include "../graph.h"
#include "rtm_enums.h"
#include "rtm_api.h"

void 
node_init_default_rtm(node_t *node) {

    node_nw_prop_t *node_nw_prop = &node->node_nw_prop;
    node_nw_prop->inet0    =  rtm_initialize (RTM_DEFAULT_VRF, RTM_AF_IPV4, 0); // inet.0
    node_nw_prop->inet3    = rtm_initialize (RTM_DEFAULT_VRF, RTM_AF_IPV4, 3); // inet.3
    node_nw_prop->mpls0  =  rtm_initialize (RTM_DEFAULT_VRF, RTM_AF_LABEL, 0); // mpls.0
    node_nw_prop->inet6    = rtm_initialize (RTM_DEFAULT_VRF, RTM_AF_IPV6, 0); // inet6.0
    node_nw_prop->inet63  = rtm_initialize (RTM_DEFAULT_VRF, RTM_AF_IPV6, 3); // inet6.3
    node_nw_prop->inet0->node   = node;
    node_nw_prop->inet3->node   = node;
    node_nw_prop->mpls0->node = node;
    node_nw_prop->inet6->node   = node;
    node_nw_prop->inet63->node = node;
}

rtm_t *
rtm_get(node_t *node, uint8_t vrf, RTM_AFI_T afi, uint8_t rtm_id) {

    if (vrf == RTM_DEFAULT_VRF) {

        if (afi == RTM_AF_IPV4) {

            if (rtm_id == 0) return node->node_nw_prop.inet0;
            if (rtm_id == 3) return node->node_nw_prop.inet3;
        }

        else if (afi == RTM_AF_IPV6) {

            if (rtm_id == 0) return node->node_nw_prop.inet6;
            if (rtm_id == 3) return node->node_nw_prop.inet63;
        }

        else if (afi == RTM_AF_LABEL) {

            if (rtm_id == 0) return node->node_nw_prop.mpls0;
        }
    }

    return NULL;
}