#include "../graph.h"
#include "rtm_enums.h"
#include "rtm_error.h"
#include "rtm_route.h"
#include "rtm_nb_integ.h"
#include "rtm_priv_api.h"
#include "rtm_proto.h"
#include "rtm_nh.h"
#include "rtm_fib_interface.h"
#include "rtm_presentation.h"
#include "rtm_resolution.h"
#include "../Interface/InterfaceUApi.h"
#include "../lmm_enums.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../Tracer/tracer.h"
#include "../prefix-list/prefixlst.h"

/* static functions */

/* Comparison function for subscription AVL tree */
static int
rtm_rt_subscription_compare(const avltree_node_t *node1, const avltree_node_t *node2) {
    
    rtm_rt_subscription_t *sub1 = avltree_container_of(node1, rtm_rt_subscription_t, avl_glue);
    rtm_rt_subscription_t *sub2 = avltree_container_of(node2, rtm_rt_subscription_t, avl_glue);
    
    /* Compare by target protocol first */
    if (sub1->target_proto < sub2->target_proto) return -1;
    if (sub1->target_proto > sub2->target_proto) return 1;
    
    /* Then by target sub-protocol */
    if (sub1->target_sub_proto < sub2->target_sub_proto) return -1;
    if (sub1->target_sub_proto > sub2->target_sub_proto) return 1;
    
    /* Then by target instance number */
    if (sub1->target_instance_no < sub2->target_instance_no) return -1;
    if (sub1->target_instance_no > sub2->target_instance_no) return 1;
    
    /* Finally by callback pointer for unique identification */
    if ((uintptr_t)sub1->cbk < (uintptr_t)sub2->cbk) return -1;
    if ((uintptr_t)sub1->cbk > (uintptr_t)sub2->cbk) return 1;
    
    return 0;
}

static void 
rtm_nh_template_internals (cp_nexthop_template_t *nh_template) {

    if (nh_template->rtm_nh_proto) XFREE (nh_template->rtm_nh_proto);
    if (nh_template->u.l_stack.label_stack) XFREE (nh_template->u.l_stack.label_stack);
    if (nh_template->u.srv6_stack.v6segment_lst) XFREE (nh_template->u.srv6_stack.v6segment_lst);
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

    nh_template.proto = (mask == 32) ? \
        RTM_PROTO_LOCAL : RTM_PROTO_CONNECTED;
    
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
    XFREE (nh_template.rtm_nh_proto);
    return rc;
}

rtm_error_t 
cp_rtm_install_route ( 
                            rtm_t *rtm, 
                            rtm_prefix_t *prefix,
                            cp_nexthop_template_t *cp_nh_template) {

    return rtm_install_route ( rtm,  prefix, cp_nh_template) ;
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
cp_rtm_uninstall_route ( rtm_t *rtm, rtm_prefix_t *prefix, 
                         cp_nexthop_template_t *nh_template) {

    return rtm_uninstall_route ( rtm, prefix, nh_template) ;
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

    /* Set gateway if provided */
    if (gateway && !rtm_prefix_is_null(gateway)) {
        nh_template.gateway = *gateway;
    }

    /* Set outgoing interface if provided */
    if (oif) {
        nh_template.Oif = oif.get();
        nh_template.is_indirect = false;
         nh_template.is_resolved = true;
    } else {
        nh_template.is_indirect = true;
         nh_template.is_resolved = false;
    }

    /* Create protocol info */
    rc = rtm_nh_proto_info_create(proto, sub_proto, instance_no, rtm->vrf, &nh_proto);
    if (rc != RTM_SUCCESS) return rc;
    
    nh_template.rtm_nh_proto = nh_proto;

    /* Handle label stack if provided */
    if (label_stack && label_stack_count > 0) {
        if (label_stack_count > MAX_LBL_DEPTH) {
            XFREE(nh_proto);
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
            XFREE(nh_proto);
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

/* ========================================================================
 * Protocol Registration and Subscription APIs
 * ======================================================================== */

/* Register a routing protocol with RTM */
bool
cp_rtm_protocol_register(rtm_t *rtm, RTM_PROTO_T proto, uint32_t instance_no, uint8_t vrf_id) {
    
    /* Validate protocol type */
    if (proto >= RTM_PROTO_MAX) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Protocol registration failed - Invalid protocol %d\n",
            rtm->name, proto);
        return false;
    }

    /* Check if protocol is already registered */
    rtm_proto_info_t *existing = rtm_proto_lookup(rtm, proto, instance_no);
    if (existing) {
        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : WARNING: Protocol %s instance %u already registered\n",
            rtm->name, rtm_proto_to_string(proto), instance_no);
        return false;
    }

    /* Create new protocol info */
    rtm_proto_info_t *proto_info = rtm_proto_info_create(rtm, proto, instance_no);
    if (!proto_info) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Failed to create protocol info for %s instance %u\n",
            rtm->name, rtm_proto_to_string(proto), instance_no);
        return false;
    }

    /* Initialize subscription database */
    avltree_init(&proto_info->sub_db, rtm_rt_subscription_compare);

    /* Add protocol info to RTM */
    rtm_error_t rc = rtm_proto_info_add(rtm, proto_info);

    if (rc != RTM_SUCCESS) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Failed to add protocol info for %s instance %u - %s\n",
            rtm->name, rtm_proto_to_string(proto), instance_no, rtm_error_to_string(rc));
        XFREE(proto_info);
        return false;
    }

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Protocol %s instance %u registered successfully\n",
        rtm->name, rtm_proto_to_string(proto), instance_no);

    return true;
}

/* Unregister a routing protocol from RTM */
bool
cp_rtm_protocol_unregister(rtm_t *rtm, RTM_PROTO_T proto, uint32_t instance_no, uint8_t vrf_id) {

    /* Validate protocol type */
    if (proto >= RTM_PROTO_MAX) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Protocol unregistration failed - Invalid protocol %d\n",
            rtm->name, proto);
        return false;
    }

    /* Validate VRF */
    if (vrf_id != rtm->vrf) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Protocol unregistration failed - VRF mismatch (expected %d, got %d)\n",
            rtm->name, rtm->vrf, vrf_id);
        return false;
    }

    /* Check if protocol is registered */
    rtm_proto_info_t *proto_info = rtm_proto_lookup(rtm, proto, instance_no);
    if (!proto_info) {
        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : WARNING: Protocol %s instance %u not registered\n",
            rtm->name, rtm_proto_to_string(proto), instance_no);
        return false;
    }

    /* Check if there are active subscriptions */
    if (!avltree_is_empty(&proto_info->sub_db)) {
        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : WARNING: Protocol %s instance %u has active subscriptions, clearing them\n",
            rtm->name, rtm_proto_to_string(proto), instance_no);
        
        /* Clear all subscriptions */
        while (!avltree_is_empty(&proto_info->sub_db)) {
            avltree_node_t *node = avltree_first(&proto_info->sub_db);
            rtm_rt_subscription_t *sub = avltree_container_of(node, rtm_rt_subscription_t, avl_glue);
            avltree_strict_remove(&sub->avl_glue, &proto_info->sub_db);
            XFREE(sub);
        }
    }

    /* Delete protocol info from RTM */
    rtm_error_t rc = rtm_proto_info_del(rtm, proto, instance_no);
    if (rc != RTM_SUCCESS) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Failed to delete protocol info for %s instance %u - %s\n",
            rtm->name, rtm_proto_to_string(proto), instance_no, rtm_error_to_string(rc));
        return false;
    }

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Protocol %s instance %u unregistered successfully\n",
        rtm->name, rtm_proto_to_string(proto), instance_no);

    return true;
}

/* Subscribe to route notifications */
rtm_error_t
cp_rtm_subscribe(rtm_t *rtm, 
                            uint8_t src_vrf, uint8_t src_instance_no, RTM_PROTO_T src_proto, 
                            rtm_rt_subscription_t *sub_template) {

    /* Validate target protocol */
    if (sub_template->target_proto >= RTM_PROTO_MAX) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Subscription failed - Invalid target protocol %d\n",
            rtm->name, sub_template->target_proto);
        return RTM_ERROR_INVALID_PROTO;
    }

    /* Validate target sub-protocol */
    if (sub_template->target_sub_proto >= RTM_SUB_PROTO_MAX) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Subscription failed - Invalid target sub-protocol %d\n",
            rtm->name, sub_template->target_sub_proto);
        return RTM_ERROR_INVALID_SUB_PROTO;
    }

    /* Check if target protocol is registered */
    rtm_proto_info_t *proto_info = rtm_proto_lookup(rtm, 
                                                     src_proto, src_instance_no);

    if (!proto_info) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Subscription failed - Target protocol %s instance %u not registered\n",
            rtm->name, rtm_proto_to_string(sub_template->target_proto), 
            sub_template->target_instance_no);
        return RTM_ERROR_PROTO_NOT_REGISTERED;
    }

    /* Allocate new subscription */
    rtm_rt_subscription_t *sub = (rtm_rt_subscription_t *)XCALLOC2(0, 1, rtm_rt_subscription_t);
    if (!sub) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Subscription failed - Memory allocation error\n",
            rtm->name);
        return RTM_ERROR_MEMORY_ALLOC_FAILED;
    }

    /* Copy subscription template */
    sub->target_proto = sub_template->target_proto;
    sub->target_sub_proto = sub_template->target_sub_proto;
    sub->target_instance_no = sub_template->target_instance_no;
    sub->prefix_list = sub_template->prefix_list;
    sub->cbk = sub_template->cbk;

    /* Initialize AVL glue */
    avltree_node_init(&sub->avl_glue);

    /* Add subscription to protocol's subscription database */
    if (avltree_insert(&sub->avl_glue, &proto_info->sub_db)) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Subscription failed - Failed to insert into subscription database\n",
            rtm->name);
        XFREE(sub);
        return RTM_ERROR_CONTAINER_INSERTION_FAILED;
    }

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Subscription added for protocol %s instance %u\n",
        rtm->name, rtm_proto_to_string(sub_template->target_proto), 
        sub_template->target_instance_no);

    return RTM_SUCCESS;
}

/* Unsubscribe from route notifications */
rtm_error_t
cp_rtm_unsubscribe(rtm_t *rtm, rtm_rt_subscription_t *sub_template) {
    
    if (!rtm || !sub_template) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    /* Validate target protocol */
    if (sub_template->target_proto >= RTM_PROTO_MAX) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Unsubscription failed - Invalid target protocol %d\n",
            rtm->name, sub_template->target_proto);
        return RTM_ERROR_INVALID_PROTO;
    }

    /* Check if target protocol is registered */
    rtm_proto_info_t *proto_info = rtm_proto_lookup(rtm, 
                                                     sub_template->target_proto, 
                                                     sub_template->target_instance_no);
    if (!proto_info) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Unsubscription failed - Target protocol %s instance %u not registered\n",
            rtm->name, rtm_proto_to_string(sub_template->target_proto), 
            sub_template->target_instance_no);
        return RTM_ERROR_PROTO_NOT_REGISTERED;
    }

    /* Search for the subscription in the database using lookup */
    
    avltree_node_t *node = avltree_lookup(&sub_template->avl_glue, &proto_info->sub_db);
    
    if (!node) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Unsubscription failed - Subscription not found for protocol %s instance %u\n",
            rtm->name, rtm_proto_to_string(sub_template->target_proto), 
            sub_template->target_instance_no);
        return RTM_ERROR_SUBSCRIPTION_NOT_FOUND;
    }
    
    rtm_rt_subscription_t *sub = avltree_container_of(node, rtm_rt_subscription_t, avl_glue);

    /* Remove subscription from database */
    avltree_strict_remove(&sub->avl_glue, &proto_info->sub_db);
    
    /* Free subscription */
    if (sub->prefix_list) prefix_list_dereference (sub->prefix_list);
    XFREE(sub);

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Subscription removed for protocol %s instance %u\n",
        rtm->name, rtm_proto_to_string(sub_template->target_proto), 
        sub_template->target_instance_no);

    return RTM_SUCCESS;
}
