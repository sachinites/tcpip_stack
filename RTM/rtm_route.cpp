#include <memory.h>
#include <stdlib.h>
#include <assert.h>
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_priv_api.h"
#include "rtm_proto.h"
#include "rtm_fib_interface.h"
#include "rtm_resolution.h"

/* Comparator function for route AVL tree */
int
rtm_route_compare(const avltree_node_t *node1, const avltree_node_t *node2) {
    
    rtm_route *route1 = avltree_container_of(node1, rtm_route, route_glue);
    rtm_route *route2 = avltree_container_of(node2, rtm_route, route_glue);
    
    rtm_prefix_t *p1 = &route1->prefix;
    rtm_prefix_t *p2 = &route2->prefix;
    
    // First compare AFI
    if (p1->afi != p2->afi) {
        return (p1->afi < p2->afi) ? -1 : 1;
    }
    
    // Then compare prefix length
    if (p1->prefix_len != p2->prefix_len) {
        return (p1->prefix_len < p2->prefix_len) ? -1 : 1;
    }
    
    // Finally compare the address based on AFI
    switch (p1->afi) {
        case RTM_AF_IPV4:
            if (p1->u.v4_addr < p2->u.v4_addr) return -1;
            if (p1->u.v4_addr > p2->u.v4_addr) return 1;
            return 0;
            
        case RTM_AF_IPV6:
            return memcmp(p1->u.v6_addr, p2->u.v6_addr, 16);
            
        case RTM_AF_LABEL:
            if (p1->u.mpls_label < p2->u.mpls_label) return -1;
            if (p1->u.mpls_label > p2->u.mpls_label) return 1;
            return 0;
            
        case RTM_AFI_MAC:
            return memcmp(p1->u.mac_addr, p2->u.mac_addr, 6);
            
        default:
            return 0;
    }
}

/* Initialize a route structure */
void 
rtm_route_initialize(rtm_route* route) {
    
    if (!route) return;
    
    init_glthread(&route->path_list);
    init_glthread(&route->unresolved_paths);
    init_glthread(&route->resolved_paths);
    avltree_node_init(&route->route_glue);
    route->flags = 0;
    route->nh_count = 0;
    route->ref_count = 0;
}

bool 
rtm_validate_with_route (rtm_t *rtm,  rtm_prefix_t *prefix) {

    if (!rtm || !prefix) return false;
    if (prefix->afi >= RTM_AFI_MAX) return false;
    if (rtm->afi != prefix->afi ) return false;
    return true;
}


rtm_route *
rtm_route_lookup( rtm_t* rtm, rtm_prefix_t* prefix_key) {
    
    if (!rtm || !prefix_key) {
        return nullptr;
    }
    
    rtm_route temp_route;
    memset(&temp_route, 0, sizeof(rtm_route));
    temp_route.prefix = *prefix_key;
    
    avltree_node_t *node = avltree_lookup(&temp_route.route_glue, 
                                          (avltree_t*)&rtm->route_tree);
    
    if (!node) {
        return NULL;
    }
    
    return avltree_container_of(node, rtm_route, route_glue);
}

/* Add a route to RTM */
rtm_error_t 
rtm_route_add(rtm_t* rtm, rtm_route* route) {
    
    if (!rtm || !route) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    // Validate AFI
    if (route->prefix.afi >= RTM_AFI_MAX) {
        return RTM_ERROR_INVALID_PREFIX;
    }
    
    // Check if route already exists
    rtm_route *existing = rtm_route_lookup(rtm, &route->prefix);

    if (existing) {
        return RTM_ERROR_CONTAINER_LOOKUP_FAILED;
    }
    
    // Insert into route tree
    if (avltree_insert(&route->route_glue, 
                       (avltree_t*)&rtm->route_tree)) {
	    return RTM_ERROR_CONTAINER_INSERTION_FAILED;
    }
    
    rtm_route_reference(route);
    
    return RTM_SUCCESS;
}

/* Remove a route from RTM */
rtm_error_t 
rtm_route_remove(rtm_t* rtm, rtm_prefix_t* prefix_key) {
    
    glthread_t *curr;

    if (!rtm || !prefix_key) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    // Find the route
    rtm_route *route = rtm_route_lookup(rtm, prefix_key);
    if (!route) {
        return RTM_ERROR_CONTAINER_LOOKUP_FAILED;
    }
    
    // Ensure all nexthops have been removed
    if (route->nh_count > 0) {
        return RTM_ERROR_INVALID_ROUTE;
    }

    ITERATE_GLTHREAD_BEGIN(&route->unresolved_paths, curr) {

        lnh_list_t *lnh_list = route_glue_to_lnh_list(curr);
        remove_glthread (&lnh_list->route_glue);
        glthread_add_next(&rtm->unresolvable_lnhs, &lnh_list->route_glue);

    } ITERATE_GLTHREAD_END(&route->unresolved_paths, curr);

    ITERATE_GLTHREAD_BEGIN(&route->resolved_paths, curr) {

        lnh_list_t *lnh_list = route_glue_to_lnh_list(curr);
        remove_glthread (&lnh_list->route_glue);
        glthread_add_next(&rtm->unresolvable_lnhs, &lnh_list->route_glue);

    } ITERATE_GLTHREAD_END(&route->unresolved_paths, curr);    

    avltree_remove(&route->route_glue, (avltree_t*)&rtm->route_tree);
    avltree_node_init (&route->route_glue);
    rtm_route_dereference(route);
    
    return RTM_SUCCESS;
}

/* Lookup a nexthop in a route */
rtm_nh* 
rtm_route_lookup_nh(rtm_route* route, rtm_nh* nh_template) {
    
    if (!route || !nh_template) {
        return nullptr;
    }
    
    glthread_t *curr;
    rtm_nh *nh;
    
    // Iterate through the path list to find matching nexthop
    ITERATE_GLTHREAD_BEGIN(&route->path_list, curr) {
        
        nh = route_glue_to_rtm_nh(curr);
        
        if (rtm_nh_is_equal (nh, nh_template) == 0) {
            return nh;
        }
        
    } ITERATE_GLTHREAD_END(&route->path_list, curr);
    
    return NULL;
}

/* Add a nexthop to a route */
rtm_error_t 
rtm_route_add_nh(rtm_t *rtm, rtm_route* route, rtm_nh* nh) {

    rtm_error_t rc = RTM_SUCCESS;
    rtm_nh_proto_t *existing_nh_proto = NULL;

    if (!route || !nh) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    // Check if nexthop already exists
    rtm_nh *existing = rtm_route_lookup_nh(route, nh);

    if (existing) {
        return RTM_ERROR_NEXTHOP_ALREADY_EXISTS;
    }
    
    assert (!nh->owner_route);

    // Set the owner route
    nh->owner_route = route;
    rtm_route_reference(route);
    
    rtm_route_add_nh_to_route_path_list (rtm, route, nh);
    route->nh_count++;

    glthread_add_next (&rtm->nhs_by_src[nh->proto], &nh->src_glue);
    rtm_nh_reference(nh);

    rc = rtm_nh_proto_add(rtm, nh->rtm_nh_proto, &existing_nh_proto) ;

    if (rc == RTM_ERROR_NEXTHOP_PROTO_ALREADY_EXISTS) {
        rtm_nh_proto_dereference(rtm, nh->rtm_nh_proto);
        nh->rtm_nh_proto = existing_nh_proto;
        rtm_nh_proto_reference(existing_nh_proto);
    }

    if (nh->is_active) {
        rtm_route_refresh_fib_nexthops(rtm, route);
    }

    return RTM_SUCCESS;
}

/* Delete the nexthop from the route, the nexthop is actual nexthop object
    of the route, not a template copy. Delete the route if its all nexthops are gone */
rtm_error_t 
rtm_route_delete_nh (rtm_t *rtm, rtm_route* route, rtm_nh* nh) {

    if (!route || !nh) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    RTM_NH_LOCK(nh);

    // Remove from path list
    remove_glthread(&nh->route_glue);
    rtm_nh_dereference(rtm, nh);

    // Remove nh from Src list
    remove_glthread (&nh->src_glue);
    rtm_nh_dereference(rtm, nh);

    /* Remove nh from idx tree*/
    rtm_nh_remove_from_idx_tree(rtm, nh);

    // Clear owner route
    nh->owner_route = NULL;
    route->nh_count--;
    rtm_route_dereference(route);    
    
    if (nh->is_active) {
        rtm_route_refresh_fib_nexthops(rtm, route);
    }

    /* Stop resolution tracking if indirect */
    if (nh->is_indirect) {
        rtm_untrack_for_resolution(rtm, nh);
    }

    RTM_NH_UNLOCK(rtm, nh);

    return RTM_SUCCESS;
}

rtm_error_t 
rtm_route_delete (rtm_t *rtm, rtm_route* route) {

    if (!rtm || !route) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    assert (route->nh_count == 0);
    assert (IS_GLTHREAD_LIST_EMPTY(&route->path_list));

    /* Move unresolved paths back to rtm->unresolved list */
    glthread_t *curr;
    ITERATE_GLTHREAD_BEGIN(&route->unresolved_paths, curr) {

        lnh_list_t *lnh_list = route_glue_to_lnh_list(curr);
        remove_glthread (&lnh_list->route_glue);
        glthread_add_next(&rtm->unresolvable_lnhs, &lnh_list->route_glue);

    } ITERATE_GLTHREAD_END(&route->unresolved_paths, curr);

    ITERATE_GLTHREAD_BEGIN(&route->resolved_paths, curr) {

        lnh_list_t *lnh_list = route_glue_to_lnh_list(curr);
        remove_glthread (&lnh_list->route_glue);
        glthread_add_next(&rtm->unresolvable_lnhs, &lnh_list->route_glue);

    } ITERATE_GLTHREAD_END(&route->unresolved_paths, curr);

    avltree_remove(&route->route_glue, (avltree_t*)&rtm->route_tree);
    avltree_node_init (&route->route_glue);
    rtm_route_dereference(route);

    return RTM_SUCCESS;
}


/* Increment route reference count */
void 
rtm_route_reference(rtm_route* route) {

    route->ref_count++;
}

/* Decrement route reference count and free if necessary */
void 
rtm_route_dereference(rtm_route* route) {
    
    if (!route) return;
    
    assert(route->ref_count > 0);
    
    route->ref_count--;
    
    if (route->ref_count == 0) {
        // Ensure all nexthops have been removed
        assert(route->nh_count == 0);
        assert(IS_GLTHREAD_LIST_EMPTY(&route->path_list));
        assert(IS_GLTHREAD_LIST_EMPTY(&route->unresolved_paths));
        assert(IS_GLTHREAD_LIST_EMPTY(&route->resolved_paths));
        
        // Free the route structure
        free(route);
    }
}

void 
rtm_route_refresh_fib_nexthops(rtm_t *rtm, rtm_route* route) {

}
