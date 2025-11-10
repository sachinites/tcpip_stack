#include <memory.h>
#include <stdlib.h>
#include <assert.h>
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_priv_api.h"

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
    
    memset(&route->route_glue, 0, sizeof(avltree_node_t));
    memset(&route->fib_glue, 0, sizeof(avltree_node_t));
    
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

/* Lookup a route in RTM by prefix */
rtm_route *
rtm_route_lookup(const rtm_t* rtm, rtm_prefix_t* prefix_key) {
    
    if (!rtm || !prefix_key) {
        return nullptr;
    }
    
    // Create a temporary route for lookup
    rtm_route temp_route;
    memset(&temp_route, 0, sizeof(rtm_route));
    temp_route.prefix = *prefix_key;
    
    // Look up in the route tree
    avltree_node_t *node = avltree_lookup(&temp_route.route_glue, 
                                          (avltree_t*)&rtm->route_tree);
    
    if (!node) {
        return NULL;
    }
    
    return avltree_container_of(node, rtm_route, route_glue);
}

/* Add a route to RTM */
rtm_error_t 
rtm_route_add(const rtm_t* rtm, rtm_route* route) {
    
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
rtm_route_remove(const rtm_t* rtm, rtm_prefix_t* prefix_key) {
    
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
    
    // Remove from route tree
    avltree_remove(&route->route_glue, (avltree_t*)&rtm->route_tree);
    
    // Decrement reference count (will free if ref_count reaches 0)
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
        
        nh = resolution_list_glue_to_rtm_nh(curr);
        
        if (rtm_nh_is_equal (nh, nh_template) == 0) {
            return nh;
        }
        
    } ITERATE_GLTHREAD_END(&route->path_list, curr);
    
    return NULL;
}

/* Add a nexthop to a route */
rtm_error_t 
rtm_route_add_nh(rtm_t *rtm, rtm_route* route, rtm_nh* nh) {
    
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

    return RTM_SUCCESS;
}

/* Remove a nexthop from a route */
rtm_error_t 
remove_nh(rtm_route* route, rtm_nh* nh) {
    
    if (!route || !nh) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    // Verify nexthop belongs to this route
    if (nh->owner_route != route) {
        return RTM_ERROR_INVALID_NH;
    }
    
    // Remove from path list
    remove_glthread(&nh->resolution_list_glue);
    
    // Clear owner route
    nh->owner_route = nullptr;
    
    // Decrement nexthop count
    if (route->nh_count > 0) {
        route->nh_count--;
    }
    
    // Decrement nexthop reference count
    rtm_nh_dereference(nh);
    
    // Decrement route reference count
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
