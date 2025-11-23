#include "../graph.h"
#include "rtm_enums.h"
#include "rtm_error.h"
#include "rtm_route.h"
#include "rtm_nb_integ.h"
#include "rtm_priv_api.h"
#include "rtm_proto.h"
#include "rtm_nh.h"
#include "rtm_fib_interface.h"
#include "../Interface/InterfaceUApi.h"
#include "../lmm_enums.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../Tracer/tracer.h"

/* static functions */
static rtm_error_t 
rtm_validate_cp_nexthop_template(cp_nexthop_template_t *nh_template) {

    if (!nh_template) return RTM_ERROR_INVALID_ARGUMENT;

    if (nh_template->proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_PROTO;
    }
    if (nh_template->sub_proto >= RTM_SUB_PROTO_MAX) {
        return RTM_ERROR_INVALID_SUB_PROTO;
    }
    if (nh_template->action >= RTM_NH_ACTION_MAX) {
        return RTM_ERROR_NEXTHOP_INVALID_ACTION;
    }
    if (nh_template->is_indirect && nh_template->Oif) {
        return RTM_ERROR_INVALID_OIF_INDEX;
    }
    if (!nh_template->is_indirect && !nh_template->Oif) {
        return RTM_ERROR_INVALID_OIF_INDEX;
    }
    if (nh_template->proto != RTM_PROTO_LOCAL &&
        nh_template->proto != RTM_PROTO_CONNECTED &&
        rtm_prefix_is_null (&nh_template->gateway)) {
        return RTM_ERROR_INVALID_GATEWAY;
    }
    if (!nh_template->rtm_nh_proto) {
        return RTM_ERROR_INVALID_NEXTHOP_PROTO;
    }
    return RTM_SUCCESS;
}

static rtm_nh *
rtm_nh_create_from_nh_template (cp_nexthop_template_t *nh_template) {

    rtm_nh *nh = (rtm_nh *)XCALLOC2(0, 1, rtm_nh);

    rtm_nh_initialize(nh);
    nh->rtm_nh_proto = (rtm_nh_proto_t *)XCALLOC2(0, 1, rtm_nh_proto_t);
    rtm_nh_proto_reference (nh->rtm_nh_proto);
    rtm_nh_proto_initialize (nh->rtm_nh_proto);

    rtm_nh_proto_copy (nh_template->rtm_nh_proto, nh->rtm_nh_proto);

    nh->flags = nh_template->flags;
    nh->proto = nh_template->proto;
    nh->sub_proto = nh_template->sub_proto;
    nh->ad = rtm_get_admin_distance (nh->proto , nh->sub_proto);
    nh->metric = nh_template->metric;
    nh->action = nh_template->action;
    nh->prefix = nh_template->gateway;
    nh->Oif = nh_template->Oif->GetSharedPtr();
    nh->is_indirect = nh_template->is_indirect;
    nh->is_resolved = nh_template->is_resolved;
    nh->is_active = false;
    nh->ref_count = 0;

    if (nh_template->u.l_stack.label_stack) {
        nh->label_stack = (rtm_lstack_t *)XCALLOC2(0, 1, rtm_lstack_t);
        nh->label_stack->curr_index = nh_template->u.l_stack.label_stack->curr_index;
        for (int i = 0; i < nh->label_stack->curr_index; i++) {
            nh->label_stack->labels[i].label_val = nh_template->u.l_stack.label_stack->labels[i].label_val;
            nh->label_stack->labels[i].op = nh_template->u.l_stack.label_stack->labels[i].op;
        }
    }
    nh->endfn = nh_template->u.srv6_stack.endfn;
    nh->n_segment_list = nh_template->u.srv6_stack.n_segment_list;
    nh->v6segment_lst = nh_template->u.srv6_stack.v6segment_lst;

    return nh;
}

static void 
rtm_nh_template_internals (cp_nexthop_template_t *nh_template) {

    if (nh_template->rtm_nh_proto) free (nh_template->rtm_nh_proto);
    if (nh_template->u.l_stack.label_stack) free (nh_template->u.l_stack.label_stack);
    if (nh_template->u.srv6_stack.v6segment_lst) free (nh_template->u.srv6_stack.v6segment_lst);
}



/* Static functions End*/

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

uint32_t
cp_rtm_install_local_or_connected_v4_routes ( 
    rtm_t *rtm, uint32_t prefix, uint8_t mask, InterfaceP Oif) {

    char addr_str[32];
    rtm_prefix_t route;
    route.afi = RTM_AF_IPV4;
    route.prefix_len = mask;
    route.u.v4_addr = prefix;
    rtm_nh_proto_t *nh_proto = NULL;

    cp_nexthop_template_t nh_template;
    memset (&nh_template, 0, sizeof(nh_template));

    nh_template.proto == (mask == 32) ? \
        nh_template.proto = RTM_PROTO_LOCAL : nh_template.proto = RTM_PROTO_CONNECTED;
    
    nh_template.sub_proto = RTM_SUB_PROTO_NA;
    nh_template.action =  (nh_template.proto ==RTM_PROTO_LOCAL) ? \
                                        RTM_NH_ACTION_LOCAL : \
                                        RTM_NH_ACTION_CONNECTED;

    nh_template.Oif = Oif.get();
    nh_template.is_resolved = true;
    nh_template.metric = (nh_template.proto == RTM_PROTO_LOCAL) ? 0 : 1;
    
    rtm_error_t rc = rtm_nh_proto_info_create(
            RTM_PROTO_LOCAL, RTM_SUB_PROTO_NA, 0, rtm->vrf, &nh_proto);
    assert (rc == RTM_SUCCESS);

    nh_template.rtm_nh_proto = nh_proto;

    tracer(rtm->node->cptr, DRTM ,
        "RTM[%s] : Route %s/%d  Gw:null recvd route installation request",  
        rtm->name, 
        rtm_format_prefix(&route, addr_str, sizeof(addr_str)), mask);

    rc = cp_rtm_install_route(rtm, &route, &nh_template);
    rtm_nh_template_internals (&nh_template);

    tracer(rtm->node->cptr, DRTM ,
        "RTM[%s] : Route %s/%d  Gw:null installation Result Code: %s",  
        rtm->name, 
        rtm_format_prefix(&route, addr_str, sizeof(addr_str)), mask,
        rtm_error_to_string (rc));

    return nh_template.idx;
}


uint32_t
cp_rtm_install_static_route (
        rtm_t *rtm,
        rtm_prefix_t *prefix, 
        rtm_prefix_t *gateway,
        InterfaceP oif, uint32_t cost) {

    char addr_str[32];
    char gw_str[32];
    rtm_nh_proto_t *nh_proto = NULL;

    cp_nexthop_template_t nh_template;
    memset(&nh_template, 0, sizeof(nh_template));

    if (!gateway || !oif) return 0;

    nh_template.proto = RTM_PROTO_STATIC;
    nh_template.sub_proto = RTM_SUB_PROTO_NA;
    nh_template.action = RTM_NH_ACTION_FORWARD;
    nh_template.Oif = oif.get();
    nh_template.is_resolved = true;
    nh_template.metric = cost;
    nh_template.gateway = *gateway;

    rtm_error_t rc = rtm_nh_proto_info_create(
        RTM_PROTO_STATIC, RTM_SUB_PROTO_NA, 0, rtm->vrf, &nh_proto);
    assert (rc == RTM_SUCCESS);

    nh_template.rtm_nh_proto =  nh_proto;

    tracer(rtm->node->cptr, DRTM ,
        "RTM[%s] : Route %s/%d  Gw:%s recvd route installation request",  
        rtm->name, 
        rtm_format_prefix(prefix, addr_str, sizeof(addr_str)), prefix->prefix_len,
        rtm_format_nexthop(gateway, gw_str, sizeof(gw_str)));

    rc = cp_rtm_install_route(rtm, prefix, &nh_template);
    rtm_nh_template_internals (&nh_template);

    tracer(rtm->node->cptr, DRTM ,
        "RTM[%s] : Route %s/%d  Gw:%s installation Result Code: %s",  
        rtm->name, 
        rtm_format_prefix(prefix, addr_str, sizeof(addr_str)), prefix->prefix_len,
        rtm_format_nexthop(gateway, gw_str, sizeof(gw_str)),
        rtm_error_to_string (rc));

    return nh_template.idx;   
}

rtm_error_t
cp_rtm_uninstall_static_route (
        rtm_t *rtm,
        rtm_prefix_t *prefix, 
        rtm_prefix_t *gateway,
        InterfaceP oif, uint32_t cost) {

    rtm_error_t rc = RTM_SUCCESS;
    cp_nexthop_template_t nh_template;
            
    memset(&nh_template, 0, sizeof(nh_template));

    nh_template.proto = RTM_PROTO_STATIC;
    nh_template.sub_proto = RTM_SUB_PROTO_NA;

    rc = rtm_nh_proto_info_create (
                    RTM_PROTO_STATIC, 
                    RTM_SUB_PROTO_NA, 
                    0, oif->GetVRF(), 
                    &nh_template.rtm_nh_proto);

    nh_template.metric = cost;
    nh_template.action = RTM_NH_ACTION_FORWARD;
    nh_template.gateway = *gateway;
    nh_template.Oif = oif.get();
    nh_template.is_indirect = false;
    nh_template.is_resolved = true;

    rc = cp_rtm_uninstall_route(rtm, prefix, &nh_template);
    free (nh_template.rtm_nh_proto);
    return rc;
}


/* Install the route in RTM , Check for duplicate nexthop for the route.
    Return appropriate error code */
rtm_error_t 
cp_rtm_install_route ( 
                            rtm_t *rtm, 
                            rtm_prefix_t *prefix,
                            cp_nexthop_template_t *cp_nh_template) {

    bool new_rt = false;
    rtm_error_t rc = RTM_SUCCESS;
    char prefix_str[48];
    char gw_str[48];

    if (!rtm || !prefix || !cp_nh_template) {
        if (rtm && rtm->node) {
            tracer(rtm->node->cptr, DRTM | DERR,
                "RTM[%s] : ERROR: Install route failed - Invalid argument (rtm=%p, prefix=%p, nh=%p)",
                rtm ? rtm->name : "null", rtm, prefix, cp_nh_template);
        }
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    rc = rtm_validate_cp_nexthop_template(cp_nh_template);
    if (rc != RTM_SUCCESS) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: NH template validation failed for route %s - %s",
            rtm->name,
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)),
            rtm_error_to_string(rc));
        return rc;
    }

    /* look up the route*/
    rtm_route *route = rtm_route_lookup(rtm, prefix);

    if (!route) {
        
        route = (rtm_route *)XCALLOC2(0, 1, rtm_route);
        rtm_route_initialize(route);
        route->prefix = *prefix;
        new_rt = true;
        rtm_route_add(rtm, route);
    }

    rtm_nh *nh = rtm_nh_create_from_nh_template(cp_nh_template);
    rtm_nh_proto_t *nh_proto = nh->rtm_nh_proto;
    rc = rtm_route_add_nh(rtm, route, nh);

    if (rc != RTM_SUCCESS) {

        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Failed to add NH to route %s - %s",
            rtm->name,
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)),
            rtm_error_to_string(rc));

        if (nh_proto == nh->rtm_nh_proto) {
            nh->rtm_nh_proto = NULL;
            rtm_nh_proto_dereference (rtm, nh_proto);
        }

        rtm_nh_dereference (rtm, nh);
        if (new_rt) rtm_route_delete (rtm, route);
        cp_nh_template->idx = 0;
        return rc;
    }

    rtm_nh_add_to_idx_tree(rtm, nh);
    glthread_add_next(&rtm->nhs_by_src[nh->proto], &nh->src_glue);
    rtm_nh_reference(nh);

    cp_nh_template->idx = nh->idx;
    rtm_route_refresh_nexthops (rtm, route);
    
    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Route %s installed successfully, NH idx=%u Proto=%s",
        rtm->name,
        rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)),
        nh->idx, rtm_proto_to_string(nh->proto));
    
    return rc;
}

rtm_error_t 
cp_rtm_uninstall_route_by_idx ( 
                            rtm_t *rtm, 
                            uint32_t idx) {

    rtm_error_t rc = RTM_SUCCESS;

    if (!rtm || !idx) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    /* Look up the idx in global NH tree */
    rtm_nh *nh = rtm_nh_lookup_by_idx(rtm, idx);

    if (!nh) {
        return RTM_ERROR_CONTAINER_LOOKUP_FAILED;
    }

    /* look up the route*/
    rtm_route *route = nh->owner_route;
    assert (route);

    /* Install the nexthop in the route, it is application responsibility to not
    to install duplicate nexthops for the route  */
    rc = rtm_route_delete_nh (rtm, route, nh);
    
    if (rc != RTM_SUCCESS) return rc;

    /* Now check if route has 0 Nexthops, then delete the route as well*/
    if (route->nh_count == 0) {
        rtm_route_delete(rtm, route);
    }

    return RTM_SUCCESS;
}

rtm_error_t 
cp_rtm_uninstall_route ( rtm_t *rtm, rtm_prefix_t *prefix, cp_nexthop_template_t *nh_template) {

    rtm_nh_proto_t *nh_proto;
    rtm_error_t rc = RTM_SUCCESS;
    char prefix_str[48];
    char gw_str[48];

    if (!rtm || !prefix || !nh_template) {
        if (rtm && rtm->node) {
            tracer(rtm->node->cptr, DRTM | DERR,
                "RTM[%s] : ERROR: Uninstall route failed - Invalid argument (rtm=%p, prefix=%p, nh=%p)",
                rtm ? rtm->name : "null", rtm, prefix, nh_template);
        }
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    if ((rc = rtm_validate_cp_nexthop_template(nh_template))) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: NH template validation failed - %s",
            rtm->name, rtm_error_to_string(rc));
        return rc;
    }

    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Uninstalling route %s",
        rtm->name,
        rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));

    /* look up the route*/
    rtm_route *route = rtm_route_lookup(rtm, prefix);
    if (!route) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Route %s not found",
            rtm->name,
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));
        return RTM_ERROR_CONTAINER_LOOKUP_FAILED;
    }

    rtm_nh *nh = rtm_nh_create_from_nh_template(nh_template);

    /* look up the actual nexthop*/
    rtm_nh *actual_nh = rtm_route_lookup_nh (route, nh);

    if (!actual_nh) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: NH not found for route %s",
            rtm->name,
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));
        return RTM_ERROR_NEXTHOP_NOT_FOUND;
    }

    rc = rtm_route_delete_nh (rtm, route, actual_nh);

    if (rc != RTM_SUCCESS) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Failed to delete NH from route %s - %s",
            rtm->name,
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)),
            rtm_error_to_string(rc));
        return rc;
    }

    /* Now check if route has 0 Nexthops, then delete the route as well*/
    if (route->nh_count == 0) {
        rtm_route_delete(rtm, route);
    }

    return RTM_SUCCESS;
}

/* Delete all nexthops whether Active or Inactive for a given protocol */
uint32_t
cp_rtm_uninstall_routes_by_proto ( rtm_t *rtm, rtm_prefix_t *route,  RTM_PROTO_T proto) {

    uint32_t deleted_count = 0;
    glthread_t *curr;
    rtm_nh *nh;

    if (!rtm || !route) {
        return 0;
    }

    if (proto >= RTM_PROTO_MAX) {
        return 0;
    }

    /* Look up the route */
    rtm_route *rt = rtm_route_lookup(rtm, route);
    if (!rt) {
        return 0;
    }

    /* Iterate through all nexthops of the route */
    ITERATE_GLTHREAD_BEGIN(&rt->path_list, curr) {

        nh = route_glue_to_rtm_nh(curr);

        /* Check if this nexthop belongs to the specified protocol */
        if (nh->proto == proto) {
            /* Delete the nexthop */
            rtm_route_delete_nh(rtm, rt, nh);
            deleted_count++;
        }

    } ITERATE_GLTHREAD_END(&rt->path_list, curr);

    /* If route has no more nexthops, delete the route */
    if (rt->nh_count == 0) {
        rtm_route_delete(rtm, rt);
    }

    return deleted_count;
}

uint32_t
cp_rtm_uninstall_routes_by_proto ( rtm_t *rtm, RTM_PROTO_T proto) {

    uint32_t deleted_count = 0;
    avltree_node_t *curr_node;
    glthread_t *curr_nh;
    rtm_nh *nh;

    if (!rtm) {
        return 0;
    }

    if (proto >= RTM_PROTO_MAX) {
        return 0;
    }

    /* Iterate through all routes in the RTM */
    ITERATE_AVL_TREE_BEGIN(&rtm->route_tree, curr_node) {

        rtm_route *route = avltree_container_of(curr_node, rtm_route, route_glue);

        /* Iterate through all nexthops of this route */
        ITERATE_GLTHREAD_BEGIN(&route->path_list, curr_nh) {

            nh = route_glue_to_rtm_nh(curr_nh);

            /* Check if this nexthop belongs to the specified protocol */
            if (nh->proto == proto) {
                /* Delete the nexthop */
                rtm_route_delete_nh(rtm, route, nh);
                deleted_count++;
            }

        } ITERATE_GLTHREAD_END(&route->path_list, curr_nh);

        /* If route has no more nexthops, delete the route */
        if (route->nh_count == 0) {
            rtm_route_delete(rtm, route);
        }

    } ITERATE_AVL_TREE_END

    return deleted_count;
}

/* Advanced API for complete route configuration */
rtm_error_t
cp_rtm_install_route_advanced (
    rtm_t *rtm,
    rtm_prefix_t *prefix,
    RTM_PROTO_T proto,
    RTM_SUB_PROTO_T sub_proto,
    uint32_t instance_no,
    RTM_NH_ACTION_TYPE_T action,
    uint32_t metric,
    rtm_prefix_t *gateway,
    InterfaceP oif,
    uint32_t *label_stack,
    uint8_t label_stack_count) {

    rtm_error_t rc = RTM_SUCCESS;
    cp_nexthop_template_t nh_template;
    rtm_nh_proto_t *nh_proto = NULL;

    if (!rtm || !prefix) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    /* Validate protocol and sub-protocol */
    if (proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_PROTO;
    }

    if (sub_proto >= RTM_SUB_PROTO_MAX) {
        return RTM_ERROR_INVALID_SUB_PROTO;
    }

    /* Validate action */
    if (action >= RTM_NH_ACTION_MAX) {
        return RTM_ERROR_NEXTHOP_INVALID_ACTION;
    }

    /* Initialize nexthop template */
    memset(&nh_template, 0, sizeof(nh_template));

    nh_template.proto = proto;
    nh_template.sub_proto = sub_proto;
    nh_template.action = action;
    nh_template.metric = metric;
    nh_template.is_resolved = true;

    /* Set gateway if provided */
    if (gateway && !rtm_prefix_is_null(gateway)) {
        nh_template.gateway = *gateway;
    }

    /* Set outgoing interface if provided */
    if (oif) {
        nh_template.Oif = oif.get();
        nh_template.is_indirect = false;
    } else {
        nh_template.is_indirect = true;
    }

    /* Create protocol info */
    rc = rtm_nh_proto_info_create(proto, sub_proto, instance_no, rtm->vrf, &nh_proto);
    if (rc != RTM_SUCCESS) {
        return rc;
    }

    nh_template.rtm_nh_proto = nh_proto;

    /* Handle label stack if provided */
    if (label_stack && label_stack_count > 0) {
        if (label_stack_count > MAX_LBL_DEPTH) {
            free(nh_proto);
            return RTM_ERROR_INVALID_ARGUMENT;
        }

        /* Allocate label stack */
        rtm_lstack_t *lstack = (rtm_lstack_t *)XCALLOC2(0, 1, rtm_lstack_t);
        lstack->curr_index = 0;

        for (uint8_t i = 0; i < label_stack_count; i++) {
            lstack->labels[i].label_val = label_stack[i];
            lstack->labels[i].op = RTM_LBL_PUSH;
            lstack->curr_index++;
        }

        nh_template.u.l_stack.label_stack = lstack;
    }

    /* Install the route */
    rc = cp_rtm_install_route(rtm, prefix, &nh_template);
    rtm_nh_template_internals (&nh_template);
    return rc;
}

/* Advanced API for route uninstallation */
rtm_error_t
cp_rtm_uninstall_route_advanced (
    rtm_t *rtm,
    rtm_prefix_t *prefix,
    RTM_PROTO_T proto,
    RTM_SUB_PROTO_T sub_proto,
    uint32_t instance_no,
    RTM_NH_ACTION_TYPE_T action,
    uint32_t metric,
    rtm_prefix_t *gateway,
    InterfaceP oif,
    uint32_t *label_stack,
    uint8_t label_stack_count) {

    rtm_error_t rc = RTM_SUCCESS;
    cp_nexthop_template_t nh_template;
    rtm_nh_proto_t *nh_proto = NULL;

    if (!rtm || !prefix) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    /* Validate protocol and sub-protocol */
    if (proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_PROTO;
    }

    if (sub_proto >= RTM_SUB_PROTO_MAX) {
        return RTM_ERROR_INVALID_SUB_PROTO;
    }

    /* Validate action */
    if (action >= RTM_NH_ACTION_MAX) {
        return RTM_ERROR_NEXTHOP_INVALID_ACTION;
    }

    /* Initialize nexthop template */
    memset(&nh_template, 0, sizeof(nh_template));

    nh_template.proto = proto;
    nh_template.sub_proto = sub_proto;
    nh_template.action = action;
    nh_template.metric = metric;
    nh_template.is_resolved = true;

    /* Set gateway if provided */
    if (gateway && !rtm_prefix_is_null(gateway)) {
        nh_template.gateway = *gateway;
    }

    /* Set outgoing interface if provided */
    if (oif) {
        nh_template.Oif = oif.get();
        nh_template.is_indirect = false;
    } else {
        nh_template.is_indirect = true;
    }

    /* Create protocol info */
    rc = rtm_nh_proto_info_create(proto, sub_proto, instance_no, rtm->vrf, &nh_proto);
    if (rc != RTM_SUCCESS) {
        return rc;
    }

    nh_template.rtm_nh_proto = nh_proto;

    /* Handle label stack if provided */
    if (label_stack && label_stack_count > 0) {
        if (label_stack_count > MAX_LBL_DEPTH) {
            free(nh_proto);
            return RTM_ERROR_INVALID_ARGUMENT;
        }

        /* Allocate label stack */
        rtm_lstack_t *lstack = (rtm_lstack_t *)XCALLOC2(0, 1, rtm_lstack_t);
        lstack->curr_index = 0;

        for (uint8_t i = 0; i < label_stack_count; i++) {
            lstack->labels[i].label_val = label_stack[i];
            lstack->labels[i].op = RTM_LBL_PUSH;
            lstack->curr_index++;
        }

        nh_template.u.l_stack.label_stack = lstack;
    }

    /* Uninstall the route */
    rc = cp_rtm_uninstall_route(rtm, prefix, &nh_template);
    rtm_nh_template_internals (&nh_template);
    return rc;
}