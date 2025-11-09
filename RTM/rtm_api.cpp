#include <stdlib.h>
#include <assert.h>

#include "rtm.h"
#include "rtm_common.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_proto.h"
#include "rtm_error.h"
#include "rtm_priv_api.h"

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

rtm_error_t 
rtm_install_static_route (
                                        rtm_t *rtm,
                                        rtm_prefix_t *prefix, 
                                        rtm_prefix_t *gateway,
                                        uint32_t oif_index, uint32_t cost ) {

    /* Declare all variables at the beginning to avoid goto issues */
    bool new_route_created = false;
    bool new_nh_created = false;
    bool new_nh_proto_created = false;
    rtm_error_t rc = RTM_SUCCESS;
    rtm_route *existing_route = NULL;
    rtm_route *route = NULL;
    rtm_nh *nh = NULL;
    rtm_nh_proto_t *rtm_nh_proto = NULL;
    rtm_nh *existing_nh = NULL;
    
    /* Validate Arguments */
    if (!prefix) return  RTM_ERROR_INVALID_ARGUMENT;
    if (!gateway) return RTM_ERROR_INVALID_ARGUMENT;
    
    
    if (!rtm_validate_with_route  (rtm, prefix)) return RTM_ERROR_INVALID_PREFIX;
    if (!rtm_validate_with_route  (rtm, gateway)) return RTM_ERROR_INVALID_GATEWAY;
    if (oif_index == 0) return RTM_ERROR_INVALID_GATEWAY;

    existing_route = rtm_route_lookup(rtm, prefix);
    
    if (existing_route) {
        route = existing_route;
    } else {
        route = (rtm_route *)calloc(1, sizeof(rtm_route));
        rtm_route_initialize(route);
        route->prefix = *prefix;
        new_route_created = true;
    }

    /* Prepare a static nexthop */
    nh = (rtm_nh *)calloc(1, sizeof(rtm_nh));
    rtm_nh_initialize(nh);
    
    // Set nexthop attributes (const members must be cast to modify)
    *(RTM_PROTO_T*)&nh->proto = RTM_PROTO_STATIC;
    *(RTM_SUB_PROTO_T*)&nh->sub_proto = RTM_SUB_PROTO_STATIC;
    nh->ad = RTM_ADMIN_DIST_STATIC;
    nh->metric = cost;
    nh->action = RTM_NH_ACTION_FORWARD;
    nh->prefix = *gateway;
    nh->outgoing_if = oif_index;
    nh->is_resolved = true;
   
    /* Now prapre nexthop protocol info */
    rtm_nh_proto = rtm_nh_proto_lookup(rtm, nh->proto, nh->sub_proto, 0, rtm->vrf);

    if (!rtm_nh_proto) {
        rc = rtm_nh_proto_info_create(rtm, nh->proto, nh->sub_proto, 0, rtm->vrf, &rtm_nh_proto);
        if (rc != RTM_SUCCESS) goto CLEANUP;
        new_nh_proto_created = true;
    }

    nh->rtm_nh_proto = rtm_nh_proto;

    /* Check if nexthop already exists in the route */
    existing_nh = rtm_route_lookup_nh(route, nh);

    if (existing_nh) {
        free(nh);
        if (new_nh_proto_created) free (rtm_nh_proto);
        if (new_route_created) free (route);
        return RTM_ERROR_NEXTHOP_ALREADY_EXISTS;
    }

    new_nh_created = true;

    /* now do all the linkages and container updates */
    if (new_nh_proto_created) {
        rtm_nh_proto_add (rtm, rtm_nh_proto);
    }

    rtm_nh_proto_reference(rtm_nh_proto); // nh references to it
    
    assert (rtm_route_add_nh(route, nh) == RTM_SUCCESS);
    
    if (new_route_created) {
        rtm_route_add(rtm, route);
    }

    return RTM_SUCCESS;

    CLEANUP:
        if (new_nh_proto_created) free(rtm_nh_proto);
        if (new_nh_created) free (nh);
        if (new_route_created) free (route);
        return rc;
}

rtm_error_t 
rtm_install_static_local_route (
                                        rtm_t *rtm,
                                        rtm_prefix_t *prefix, 
                                        uint32_t oif_index, uint32_t cost ) {

    /* Declare all variables at the beginning to avoid goto issues */
    bool new_route_created = false;
    bool new_nh_created = false;
    bool new_nh_proto_created = false;
    rtm_error_t rc = RTM_SUCCESS;
    rtm_route *existing_route = NULL;
    rtm_route *route = NULL;
    rtm_nh *nh = NULL;
    rtm_nh_proto_t *rtm_nh_proto = NULL;
    rtm_nh *existing_nh = NULL;
    
    /* Validate Arguments */
    if (!prefix) return  RTM_ERROR_INVALID_ARGUMENT;
    
    
    if (!rtm_validate_with_route  (rtm, prefix)) return RTM_ERROR_INVALID_PREFIX;
    if (oif_index == 0) return RTM_ERROR_INVALID_ARGUMENT;

    existing_route = rtm_route_lookup(rtm, prefix);
    
    if (existing_route) {
        route = existing_route;
    } else {
        route = (rtm_route *)calloc(1, sizeof(rtm_route));
        rtm_route_initialize(route);
        route->prefix = *prefix;
        new_route_created = true;
    }

    /* Prepare a static local nexthop */
    nh = (rtm_nh *)calloc(1, sizeof(rtm_nh));
    rtm_nh_initialize(nh);
    
    // Set nexthop attributes (const members must be cast to modify)
    *(RTM_PROTO_T*)&nh->proto = RTM_PROTO_STATIC;
    *(RTM_SUB_PROTO_T*)&nh->sub_proto = RTM_SUB_PROTO_STATIC;
    nh->ad = RTM_ADMIN_DIST_STATIC;
    nh->metric = cost;
    nh->action = RTM_NH_ACTION_LOCAL;
    nh->prefix = *prefix;
    nh->outgoing_if = oif_index;
    nh->is_resolved = true;
   
    /* Now prapre nexthop protocol info */
    rtm_nh_proto = rtm_nh_proto_lookup(rtm, nh->proto, nh->sub_proto, 0, rtm->vrf);

    if (!rtm_nh_proto) {
        rc = rtm_nh_proto_info_create(rtm, nh->proto, nh->sub_proto, 0, rtm->vrf, &rtm_nh_proto);
        if (rc != RTM_SUCCESS) goto CLEANUP;
        new_nh_proto_created = true;
    }

    nh->rtm_nh_proto = rtm_nh_proto;

    /* Check if nexthop already exists in the route */
    existing_nh = rtm_route_lookup_nh(route, nh);

    if (existing_nh) {
        free(nh);
        if (new_nh_proto_created) free (rtm_nh_proto);
        if (new_route_created) free (route);
        return RTM_ERROR_NEXTHOP_ALREADY_EXISTS;
    }

    new_nh_created = true;

    /* now do all the linkages and container updates */
    if (new_nh_proto_created) {
        rtm_nh_proto_add (rtm, rtm_nh_proto);
    }

    rtm_nh_proto_reference(rtm_nh_proto); // nh references to it
    
    assert (rtm_route_add_nh(route, nh) == RTM_SUCCESS);
    
    if (new_route_created) {
        rtm_route_add(rtm, route);
    }

    return RTM_SUCCESS;

    CLEANUP:
        if (new_nh_proto_created) free(rtm_nh_proto);
        if (new_nh_created) free (nh);
        if (new_route_created) free (route);
        return rc;
}


rtm_error_t 
rtm_install_protocol_route (
        rtm_t *rtm,
        rtm_prefix_t *prefix, 
        rtm_prefix_t *gateway,
        RTM_PROTO_T proto,
        RTM_SUB_PROTO_T sub_proto,
        uint32_t instance_no,
        uint32_t oif_index, 
        uint32_t cost) {

    /* Declare all variables at the beginning to avoid goto issues */
    bool new_route_created = false;
    bool new_nh_created = false;
    bool new_nh_proto_created = false;
    rtm_error_t rc = RTM_SUCCESS;
    rtm_route *existing_route = NULL;
    rtm_route *route = NULL;
    rtm_nh *nh = NULL;
    rtm_nh_proto_t *rtm_nh_proto = NULL;
    rtm_nh *existing_nh = NULL;
    
    /* Validate Arguments */
    if (!prefix) return  RTM_ERROR_INVALID_ARGUMENT;
    if (!gateway) return RTM_ERROR_INVALID_ARGUMENT;
    
    
    if (!rtm_validate_with_route  (rtm, prefix)) return RTM_ERROR_INVALID_PREFIX;
    if (!rtm_validate_with_route  (rtm, gateway)) return RTM_ERROR_INVALID_GATEWAY;
    if (oif_index == 0) return RTM_ERROR_INVALID_GATEWAY;

    existing_route = rtm_route_lookup(rtm, prefix);
    
    if (existing_route) {
        route = existing_route;
    } else {
        route = (rtm_route *)calloc(1, sizeof(rtm_route));
        rtm_route_initialize(route);
        route->prefix = *prefix;
        new_route_created = true;
    }

    /* Prepare a protocol nexthop */
    nh = (rtm_nh *)calloc(1, sizeof(rtm_nh));
    rtm_nh_initialize(nh);
    
    // Set nexthop attributes (const members must be cast to modify)
    *(RTM_PROTO_T*)&nh->proto = proto;
    *(RTM_SUB_PROTO_T*)&nh->sub_proto = sub_proto;
    nh->ad = rtm_get_admin_distance(proto, sub_proto);
    nh->metric = cost;
    nh->action = RTM_NH_ACTION_FORWARD;
    nh->prefix = *gateway;
    nh->outgoing_if = oif_index;
    nh->is_resolved = true;
   
    /* Now prapre nexthop protocol info */
    rtm_nh_proto = rtm_nh_proto_lookup(rtm, nh->proto, nh->sub_proto, instance_no, rtm->vrf);

    if (!rtm_nh_proto) {
        rc = rtm_nh_proto_info_create(rtm, nh->proto, nh->sub_proto, instance_no, rtm->vrf, &rtm_nh_proto);
        if (rc != RTM_SUCCESS) goto CLEANUP;
        new_nh_proto_created = true;
    }

    nh->rtm_nh_proto = rtm_nh_proto;

    /* Check if nexthop already exists in the route */
    existing_nh = rtm_route_lookup_nh(route, nh);

    if (existing_nh) {
        free(nh);
        if (new_nh_proto_created) free (rtm_nh_proto);
        if (new_route_created) free (route);
        return RTM_ERROR_NEXTHOP_ALREADY_EXISTS;
    }

    new_nh_created = true;

    /* now do all the linkages and container updates */
    if (new_nh_proto_created) {
        rtm_nh_proto_add (rtm, rtm_nh_proto);
    }

    rtm_nh_proto_reference(rtm_nh_proto); // nh references to it
    
    assert (rtm_route_add_nh(route, nh) == RTM_SUCCESS);
    
    if (new_route_created) {
        rtm_route_add(rtm, route);
    }

    return RTM_SUCCESS;

    CLEANUP:
        if (new_nh_proto_created) free(rtm_nh_proto);
        if (new_nh_created) free (nh);
        if (new_route_created) free (route);
        return rc;
}


rtm_error_t 
rtm_install_protocol_route_nh (rtm_t *rtm,
                                            rtm_prefix_t *prefix, 
                                            rtm_nh *nh, 
                                            rtm_nh_proto_t *nh_proto) {

    /* Declare all variables at the beginning to avoid goto issues */
    bool new_route_created = false;
    bool new_nh_created = false;
    bool new_nh_proto_created = false;
    rtm_error_t rc = RTM_SUCCESS;
    rtm_route *existing_route = NULL;
    rtm_route *route = NULL;
    rtm_nh *heap_nh = NULL;
    rtm_nh_proto_t *rtm_nh_proto = NULL;
    rtm_nh *existing_nh = NULL;
    uint32_t instance_no = 0;
    
    /* Validate Arguments */
    if (!prefix) return  RTM_ERROR_INVALID_ARGUMENT;
    if (!nh) return RTM_ERROR_INVALID_ARGUMENT;
    
    
    if (!rtm_validate_with_route  (rtm, prefix)) return RTM_ERROR_INVALID_PREFIX;

    if (nh->outgoing_if == 0) return RTM_ERROR_INVALID_GATEWAY;

    existing_route = rtm_route_lookup(rtm, prefix);
    
    if (existing_route) {
        route = existing_route;
    } else {
        route = (rtm_route *)calloc(1, sizeof(rtm_route));
        rtm_route_initialize(route);
        route->prefix = *prefix;
        new_route_created = true;
    }

    /* Allocate heap memory for nexthop (input may be stack memory) */
    heap_nh = (rtm_nh *)calloc(1, sizeof(rtm_nh));
    rtm_nh_initialize(heap_nh);
    
    /* Copy all fields from provided nexthop */
    *(RTM_PROTO_T*)&heap_nh->proto = nh->proto;
    *(RTM_SUB_PROTO_T*)&heap_nh->sub_proto = nh->sub_proto;
    heap_nh->flags = nh->flags;
    heap_nh->pth_last_update_time = nh->pth_last_update_time;
    heap_nh->ad = nh->ad;
    heap_nh->metric = nh->metric;
    heap_nh->action = nh->action;
    heap_nh->prefix = nh->prefix;
    heap_nh->outgoing_if = nh->outgoing_if;
    heap_nh->is_resolved = nh->is_resolved;
    heap_nh->is_indirect = nh->is_indirect;
    
    /* Copy label stack if present */
    if (nh->label_stack) {
        heap_nh->label_stack = (lstack_t *)calloc(1, sizeof(lstack_t));
        *heap_nh->label_stack = *nh->label_stack;
    }

    /* Determine instance number */
    if (nh_proto) {
        instance_no = nh_proto->instance_no;
    } else if (nh->rtm_nh_proto) {
        instance_no = nh->rtm_nh_proto->instance_no;
    }

    /* Now prapre nexthop protocol info - use provided or lookup */
    if (nh_proto) {
        rtm_nh_proto = nh_proto;
    } else {
        rtm_nh_proto = rtm_nh_proto_lookup(rtm, heap_nh->proto, heap_nh->sub_proto, 
                                            instance_no, rtm->vrf);

        if (!rtm_nh_proto) {
            rc = rtm_nh_proto_info_create(rtm, heap_nh->proto, heap_nh->sub_proto, 
                                           instance_no, rtm->vrf, &rtm_nh_proto);
            if (rc != RTM_SUCCESS) goto CLEANUP;
            new_nh_proto_created = true;
        }
    }

    heap_nh->rtm_nh_proto = rtm_nh_proto;

    /* Check if nexthop already exists in the route */
    existing_nh = rtm_route_lookup_nh(route, heap_nh);

    if (existing_nh) {
        if (new_nh_proto_created) free (rtm_nh_proto);
        if (heap_nh->label_stack) free(heap_nh->label_stack);
        free(heap_nh);
        if (new_route_created) free (route);
        return RTM_ERROR_NEXTHOP_ALREADY_EXISTS;
    }

    new_nh_created = true;

    /* now do all the linkages and container updates */
    if (new_nh_proto_created) {
        rtm_nh_proto_add (rtm, rtm_nh_proto);
    }

    rtm_nh_proto_reference(rtm_nh_proto); // nh references to it
    
    assert (rtm_route_add_nh(route, heap_nh) == RTM_SUCCESS);
    
    if (new_route_created) {
        rtm_route_add(rtm, route);
    }

    return RTM_SUCCESS;

    CLEANUP:
        if (new_nh_proto_created) free(rtm_nh_proto);
        if (new_nh_created) {
            if (heap_nh->label_stack) free(heap_nh->label_stack);
            free(heap_nh);
        } else if (heap_nh) {
            if (heap_nh->label_stack) free(heap_nh->label_stack);
            free(heap_nh);
        }
        if (new_route_created) free (route);
        return rc;
}