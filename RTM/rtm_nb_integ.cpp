#include "../graph.h"
#include "rtm_enums.h"
#include "rtm_error.h"
#include "rtm_api.h"
#include "rtm_route.h"
#include "rtm_nb_integ.h"

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

static rtm_error_t 
rtm_validate_cp_nexthop_template(cp_nexthop_template_t *nh_template) {

    if (!nh_template) return RTM_ERROR_INVALID_ARGUMENT;

    if (nh_template->proto >= RTM_PROTO_MAX) return RTM_ERROR_INVALID_PROTO;
    if (nh_template->sub_proto >= RTM_SUB_PROTO_MAX) return RTM_ERROR_INVALID_SUB_PROTO;
    if (nh_template->action >= RTM_NH_ACTION_MAX) return RTM_ERROR_NEXTHOP_INVALID_ACTION;
    if (nh_template->is_indirect && nh_template->Oif) return RTM_ERROR_INVALID_OIF_INDEX;
    if (!nh_template->is_indirect && !nh_template->Oif) return RTM_ERROR_INVALID_OIF_INDEX;
    if (rtm_prefix_is_null (&nh_template->gateway)) return RTM_ERROR_INVALID_GATEWAY;
    if (!nh_template->rtm_nh_proto) return RTM_ERROR_INVALID_NEXTHOP_PROTO;
    return RTM_SUCCESS;
}

static rtm_nh *
rtm_nh_create (cp_nexthop_template_t *nh_template) {

    rtm_nh *nh = (rtm_nh *)calloc(1, sizeof(rtm_nh));
    rtm_nh_initialize(nh);
    nh->rtm_nh_proto = (rtm_nh_proto_t *)calloc (1, sizeof (rtm_nh_proto_t));
    rtm_nh_proto_initialize (nh->rtm_nh_proto);
    memcpy (nh->rtm_nh_proto, nh_template->rtm_nh_proto, sizeof (rtm_nh_proto_t));
    return nh;
}

/* Install the route in RTM , Check for duplicate nexthop for the route.
    Return appropriate error code */
rtm_error_t 
cp_rtm_install_route ( 
                            rtm_t *rtm, 
                            rtm_prefix_t *prefix,
                            cp_nexthop_template_t *nh_template) {

    rtm_error_t rc = RTM_SUCCESS;

    if (!rtm || !prefix || !nh_template) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    if ((rc = rtm_validate_cp_nexthop_template(nh_template))) {

        if (rc != RTM_SUCCESS) return rc;
    } 

    /* look up the route*/

    rtm_route *route = rtm_route_lookup(rtm, prefix);

    if (!route) {
        
        route = (rtm_route *)calloc(1, sizeof(rtm_route));
        rtm_route_initialize(route);
        route->prefix = *prefix;
        rtm_route_add(rtm, route);
    }

    /* Install the nexthop in the route, it is application responsibility to not
    to install duplicate nexthops for the route  */
    rtm_nh *nh = rtm_nh_create(nh_template);
    assert (rtm_nh_proto_add(rtm, nh->rtm_nh_proto) == RTM_SUCCESS);
    rtm_route_add_nh(rtm, route, nh);
    return rc;
}