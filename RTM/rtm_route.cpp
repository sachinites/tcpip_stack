#include <memory.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>

#include "../graph.h"
#include "../tcp_ip_trace.h"
#include "../Tracer/tracer.h"
#include "../mtrie/mtrie.h"
#include "../BitOp/bitmap.h"
#include "../lmm_enums.h"
#include "../LinuxMemoryManager/uapi_mm.h"

#include "rtm_route.h"
#include "rtm_nh.h"

#include "rtm_priv_api.h"
#include "rtm_proto.h"
#include "rtm_fib_interface.h"
#include "rtm_resolution.h"
#include "rtm_presentation.h"
#include "rtm_gc.h"

extern void 
rtm_ppt_unregister_route (rtm_t *rtm, rtm_prefix_t *prefix);

/* Unreference all resources held by this route. No need to
     Unreference resources which hold a ref count back to
     the route, for example, path list as it is taken by ref_count
*/
static void 
rtm_route_release_all_resources(rtm_t *rtm, rtm_route *route) {

    rtm_ppt_unregister_route (rtm, &route->prefix);
}

void 
rtm_route_check_and_delete(rtm_t *rtm, rtm_route* route) {

    char prefix_str[48];
    rtm_route_release_all_resources(rtm, route);
    assert (IS_GLTHREAD_LIST_EMPTY(&route->path_list));
    assert (Fglthread_list_is_empty(&route->resolved_lnhs));
    assert (route->nh_count == 0);
    assert (route->ref_count == 0);
    assert (!avltree_node_is_inuse (&route->route_glue));
    assert (!IS_QUEUED_UP_IN_THREAD (&route->resolved_route_glue));
    assert (!IS_QUEUED_UP_IN_THREAD (&route->advt_glue));

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Route %s deleted successfully\n",
        rtm->name, rtm_format_prefix(&route->prefix, prefix_str, sizeof (prefix_str)));
    XFREE(route);
}

uint32_t
rtm_route_dereference(rtm_t *rtm, rtm_route* route) {

    route->ref_count--;

    if (route->ref_count == 0) {
        rtm_gc_route(rtm, route);
        return 0;
    }

    return route->ref_count;
}

void 
rtm_route_reference(rtm_route* route) {

    route->ref_count++;
}

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
    init_Fglthread(&route->resolved_lnhs);
    avltree_node_init(&route->route_glue);
    init_glthread(&route->advt_glue);
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
    
    char prefix_str[48];
    
    // Validate AFI
    if (route->prefix.afi >= RTM_AFI_MAX) {

        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR(%s) : Route %s : Add failed\n",
            rtm->name, 
            rtm_error_to_string(RTM_ERROR_INVALID_PREFIX),
            rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));

        return RTM_ERROR_INVALID_PREFIX;
    }
    
    // Check if route already exists
    rtm_route *existing = rtm_route_lookup(rtm, &route->prefix);

    if (existing) {

        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : Route %s already exists in routing table\n",
            rtm->name,
            rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));

        return RTM_ERROR_CONTAINER_LOOKUP_FAILED;
    }
    
    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Route %s : Adding route to routing table\n",
        rtm->name,
        rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));
    
    // Insert into route tree using wrapper
    rtm_route_avl_insert(route, (avltree_t*)&rtm->route_tree, &route->route_glue);
    
    /* Note: rtm_route_avl_insert already calls rtm_route_reference */
    
    /* Insert into LPM tree for fast longest prefix match lookups */
    if (route->prefix.afi == RTM_AF_IPV4 ||
        route->prefix.afi == RTM_AF_IPV6)
    {
        rtm_error_t lpm_result = rtm_lpm_tree_insert(rtm, route);

        if (lpm_result != RTM_SUCCESS)
        {
            /* LPM insertion failed, rollback AVL tree insertion */
            tracer(rtm->node->cptr, DRTM | DERR,
                   "RTM[%s] : ERROR(%s): Route %s LPM tree insertion failed, rolling back\n",
                   rtm->name, rtm_error_to_string(lpm_result), prefix_str);

            rtm_route_avl_remove(rtm, route, (avltree_t *)&rtm->route_tree, &route->route_glue);
            return lpm_result;
        }

        rtm_route_reference(route);
        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : Route %s added successfully to LPM tree\n",
            rtm->name, prefix_str);
    }
    
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

rtm_nh *
rtm_route_lookup_nh_with_same_fwding_behavior(
    rtm_route *route, rtm_nh *nh_template)
{

    rtm_nh *nh;
    glthread_t *curr;
    
    ITERATE_GLTHREAD_BEGIN(&route->path_list, curr) {
        
        nh = route_glue_to_rtm_nh(curr);
        
        if (rtm_nh_is_equal_in_data_plane (nh, nh_template) == 0) {
            return nh;
        }
        
    } ITERATE_GLTHREAD_END(&route->path_list, curr);
    
    return NULL;
}

/* Add a nexthop to a route */
rtm_error_t 
rtm_route_add_nh(rtm_t *rtm, rtm_route* route, rtm_nh* nh) {

    char gw_str[48];
    char prefix_str[48];

    rtm_error_t rc = RTM_SUCCESS;
    rtm_nh_proto_t *existing_nh_proto = NULL;
    
    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Adding NH to route %s, Proto=%s Gw=%s AD=%u Metric=%u\n",
        rtm->name,
        rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)),
        rtm_proto_to_string(nh->proto),
        rtm_format_nexthop(&nh->prefix, gw_str, sizeof(gw_str)),
        nh->ad, nh->metric);
    
    /* Nexthop protocol is freah mallocd object whose ref-count 
        expected to be zero*/
    assert (nh->rtm_nh_proto->ref_count == 0);

    rtm_nh *existing = rtm_route_lookup_nh(route, nh);

    if (existing) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: NH %s already exists for route %s\n",
            rtm->name, gw_str, prefix_str);
        return RTM_ERROR_NEXTHOP_ALREADY_EXISTS;
    }

    existing = rtm_route_lookup_nh_with_same_fwding_behavior(route, nh);

    if (existing) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Data Plane NH %s already exists for route %s\n",
            rtm->name,gw_str, prefix_str );
        return RTM_ERROR_NEXTHOP_ALREADY_EXISTS;
    }    
    
    assert (!nh->owner_route);

    // Set the owner route
    nh->owner_route = route;
    rtm_route_reference(route);
    
    rtm_route_add_nh_to_route_path_list (rtm, route, nh);

    rc = rtm_nh_proto_add(rtm, nh->rtm_nh_proto, &existing_nh_proto) ;

    if (rc == RTM_ERROR_NEXTHOP_PROTO_ALREADY_EXISTS) {
        XFREE(nh->rtm_nh_proto);
        nh->rtm_nh_proto = existing_nh_proto;
        rtm_nh_proto_reference(existing_nh_proto);
    }
    else {
         rtm_nh_proto_reference(nh->rtm_nh_proto);
    }

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Route : %s , NH %s added successfully, Total NHs=%u Active=%s\n",
        rtm->name, gw_str, prefix_str, 
        route->nh_count, nh->is_active ? "Yes" : "No");

    return RTM_SUCCESS;
}

/* Delete the nexthop from the route, the nexthop is actual nexthop object
    of the route, not a template copy. Delete the route if its all nexthops are gone */
rtm_error_t 
rtm_route_delete_nh (rtm_t *rtm, rtm_route* route, rtm_nh* nh) {

    char prefix_str[48];
    char gw_str[48];

    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Deleting NH %s from route %s, Proto=%s AD=%u\n",
        rtm->name,
        rtm_format_nexthop(&nh->prefix, gw_str, sizeof(gw_str)),
        rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)),
        rtm_proto_to_string(nh->proto), nh->ad);


    if (nh->is_active) {
        rtm_schedule_route_advertisement(rtm, route);
    }

    // Remove from path list using wrapper
    rtm_nh_remove_glthread(rtm, nh, &nh->route_glue);
    route->nh_count--;

    // Do not Clear owner route, it will be cleared in rtm_nh_release_all_resources( )
    // function, because we want to preserve the route
    // to be accessed by nh->owner_route until last breathe of nh.
    //nh->owner_route = NULL;
    //rtm_route_dereference(rtm, route);    
    
    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : NH %s deleted successfully from route %s, Remaining NHs=%u\n",
        rtm->name,
        rtm_format_nexthop(&nh->prefix, gw_str, sizeof(gw_str)),
        rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)),
        route->nh_count);
    
    return RTM_SUCCESS;
}

rtm_error_t 
rtm_route_delete (rtm_t *rtm, rtm_route* route) {

    rtm_nh *indirect_nh;
    glthread_t *curr_lnh_glue;    
    
    assert (route->nh_count == 0);
    assert (IS_GLTHREAD_LIST_EMPTY(&route->path_list));
    
    /* Remove from LPM tree */
    assert (rtm_lpm_tree_delete(rtm, &route->prefix) == RTM_SUCCESS);
    rtm_route_dereference(rtm, route);

    /* Handle INHs resolved over by this route */
    ITERATE_GLTHREAD_BEGIN(&route->resolved_lnhs.head, curr_lnh_glue) {

        indirect_nh = resolution_list_glue_to_rtm_nh(curr_lnh_glue);

        rtm_resolution_nh_withdraw(rtm, indirect_nh);
        
        rtm_nh_Fglthread_add_last (indirect_nh, 
                &rtm->unresolvable_paths, 
                &indirect_nh->unresolvable_list_glue);
        
        rtm_schedule_nh_resolution_worker(rtm);

    } ITERATE_GLTHREAD_END(&route->resolved_lnhs.head, curr_lnh_glue);

    rtm_route_avl_remove(rtm, route, &rtm->route_tree, &route->route_glue);

    return RTM_SUCCESS;
}

bool 
rtm_route_is_resolved (rtm_route* route) {

    glthread_t *curr;
    rtm_nh *curr_nh;

    ITERATE_GLTHREAD_BEGIN(&route->path_list, curr) {
        
        curr_nh = route_glue_to_rtm_nh(curr);
        
        if (rtm_nh_is_resolved (curr_nh)) {
            return true;
        }
        
    } ITERATE_GLTHREAD_END(&route->path_list, curr);

    return false;
}

void 
rtm_route_refresh_nexthops(rtm_t *rtm, rtm_route* route) {

    glthread_t *curr;
    rtm_nh *curr_nh;
    char prefix_str[48];
    uint32_t active_count = 0;
    bool nh_active_set_changed = false;
    bool rt_has_dnhs = false;
    glthread_t *best_glue = BASE(&route->path_list);

    if (!best_glue) {
        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : Route %s : Has no nexthops to refresh\n",
            rtm->name,
            rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));
        return;
    }
    
    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Route %s : Refreshing nexthops (Total NHs=%u)\n",
        rtm->name,
        rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)),
        route->nh_count);
    
    rtm_nh *best_nh = route_glue_to_rtm_nh(best_glue);
    
    if (!best_nh->is_active) {
        rtm_nh_set_active(rtm, best_nh);      
        nh_active_set_changed = true;
        active_count++;  
    }

    ITERATE_GLTHREAD_BEGIN(&route->path_list, curr) {
        
        curr_nh = route_glue_to_rtm_nh(curr);
        
        // Check if current nexthop is equal to the best one (ECMP)
        int cmp_result = rtm_nh_compare(curr_nh, best_nh);
        
        if (cmp_result == 0) {
            if (!curr_nh->is_active) {
                rtm_nh_set_active(rtm, curr_nh);
                nh_active_set_changed = true;
                active_count++;
            } else {
                active_count++;
            }
        } else {
            if (curr_nh->is_active) {
                rtm_nh_set_inactive(rtm, curr_nh);
                nh_active_set_changed = true;
            }
        }
        
    } ITERATE_GLTHREAD_END(&route->path_list, curr);

    if (!nh_active_set_changed) {
        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : Route %s :  Nexthop refresh complete, No Change in Active NH set\n",
            rtm->name,
            rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)),
            active_count);
        return;
    }

    if (nh_active_set_changed) {

        /* Routes Active Set has changed, update upstream routes recursively */
        tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Route %s :  Nexthop refresh complete, Propagating changes upstream\n",
        rtm->name,
        rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));
        rtm_resolve_routes_recursively (rtm, route);
    }
}

/* ============================================================================
 * LPM Tree Operations using mtrie library
 * ============================================================================ */

/* Callback function to free route data when mtrie node is deleted */
static void
rtm_lpm_tree_free_callback(mtrie_node_t *node) {

    assert (node->data);
    node->data = NULL;
}

/* Initialize LPM tree for RTM based on AFI */
void 
rtm_lpm_tree_init(rtm_t *rtm) {

    /* Allocate mtrie structure */
    rtm->lpm_rt_tree = (mtrie_t *)XCALLOC2(0, 1, mtrie_t);
    
    /* Initialize mtrie based on AFI
     * IPv4: 32 bits
     * IPv6: 128 bits
     * MPLS: Skip (as per user requirement - no MPLS)
     */
    uint16_t prefix_len = 0;
    
    switch (rtm->afi) {
        case RTM_AF_IPV4:
            prefix_len = 32;
            break;
        case RTM_AF_IPV6:
            prefix_len = 128;
            break;
        case RTM_AF_LABEL:
            /* MPLS not supported for LPM tree as per requirements */
            XFREE(rtm->lpm_rt_tree);
            rtm->lpm_rt_tree = NULL;
            return;
        case RTM_AFI_MAC:
            /* MAC not typically used for LPM routing */
            XFREE(rtm->lpm_rt_tree);
            rtm->lpm_rt_tree = NULL;
            return;
        default:
            XFREE(rtm->lpm_rt_tree);
            rtm->lpm_rt_tree = NULL;
            return;
    }
    
    init_mtrie(rtm->lpm_rt_tree, prefix_len, rtm_lpm_tree_free_callback);
}

/* Destroy LPM tree */
void 
rtm_lpm_tree_destroy(rtm_t *rtm) {
    
    if (!rtm || !rtm->lpm_rt_tree) return;
    
    mtrie_destroy(rtm->lpm_rt_tree);
    XFREE(rtm->lpm_rt_tree);
    rtm->lpm_rt_tree = NULL;
    
    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : LPM tree destroyed\n",
        rtm->name);
}

/* Insert route into LPM tree */
rtm_error_t 
rtm_lpm_tree_insert(rtm_t *rtm, rtm_route *route) {
    
    bitmap_t prefix_bm, wildcard_bm;
    mtrie_node_t *mnode = NULL;
    mtrie_ops_result_code_t result;
    char prefix_str[48];
    
    if (!rtm || !route) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    /* Skip if LPM tree not initialized (e.g., MPLS, MAC) */
    if (!rtm->lpm_rt_tree) {
        return RTM_SUCCESS;
    }

    if (route->prefix.afi != RTM_AF_IPV4 &&
            route->prefix.afi !=  RTM_AF_IPV6) return RTM_ERROR_INVALID_ARGUMENT;
    
    bitmap_init(&prefix_bm, route->prefix.afi == RTM_AF_IPV4 ? 32 : 128);
    bitmap_init(&wildcard_bm, route->prefix.afi == RTM_AF_IPV4 ? 32 : 128);
    
    /* Convert prefix to bitmap */
    rtm_prefix_to_bitmap(&route->prefix, &prefix_bm);
    rtm_prefix_to_wildcard_bitmap(&route->prefix, &wildcard_bm);
    
    /* Insert into mtrie */
    result = mtrie_insert_prefix(rtm->lpm_rt_tree, 
                                  &prefix_bm, 
                                  &wildcard_bm,
                                  route->prefix.afi == RTM_AF_IPV4 ? 32 : 128,
                                  &mnode);
    
    if (result == MTRIE_INSERT_SUCCESS) {
        /* Set the route pointer in the mtrie node */
        mnode->data = route;
        //rtm_route_reference (route);

        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : Route %s inserted into LPM tree\n",
            rtm->name,
            rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));
        
        bitmap_free_internal(&prefix_bm);
        bitmap_free_internal(&wildcard_bm);
        return RTM_SUCCESS;
    }
    else if (result == MTRIE_INSERT_DUPLICATE) {
        /* Route already exists in LPM tree */
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : Route %s already exists in LPM tree\n",
            rtm->name,
            rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));
        
        bitmap_free_internal(&prefix_bm);
        bitmap_free_internal(&wildcard_bm);
        return RTM_ERROR_CONTAINER_INSERTION_FAILED;
    }
    else {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : Failed to insert route %s into LPM tree\n",
            rtm->name,
            rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));
        
        bitmap_free_internal(&prefix_bm);
        bitmap_free_internal(&wildcard_bm);
        return RTM_ERROR_CONTAINER_INSERTION_FAILED;
    }
}

/* Delete route from LPM tree */
rtm_error_t 
rtm_lpm_tree_delete(rtm_t *rtm, rtm_prefix_t *prefix) {
    
    bitmap_t prefix_bm, wildcard_bm;
    void *app_data = NULL;
    mtrie_ops_result_code_t result;
    char prefix_str[48];
    
    if (!rtm || !prefix) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    /* Skip if LPM tree not initialized */
    if (!rtm->lpm_rt_tree) {
        return RTM_SUCCESS;
    }
    
    /* Initialize bitmaps based on AFI */
    uint16_t prefix_len = 0;
    switch (prefix->afi) {
        case RTM_AF_IPV4:
            prefix_len = 32;
            break;
        case RTM_AF_IPV6:
            prefix_len = 128;
            break;
        default:
            return RTM_ERROR_INVALID_PREFIX;
    }
    
    bitmap_init(&prefix_bm, prefix_len);
    bitmap_init(&wildcard_bm, prefix_len);
    
    /* Convert prefix to bitmap */
    rtm_prefix_to_bitmap(prefix, &prefix_bm);
    rtm_prefix_to_wildcard_bitmap(prefix, &wildcard_bm);
    
    /* Delete from mtrie */
    result = mtrie_delete_prefix(rtm->lpm_rt_tree, 
                                  &prefix_bm, 
                                  &wildcard_bm,
                                  &app_data);
    
    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&wildcard_bm);
    
    if (result == MTRIE_DELETE_SUCCESS) {
        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : Route %s deleted from LPM tree\n",
            rtm->name,
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));
        return RTM_SUCCESS;
    }
    else {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : Failed to delete route %s from LPM tree\n",
            rtm->name,
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));
        return RTM_ERROR_CONTAINER_LOOKUP_FAILED;
    }
}

/* Longest Prefix Match lookup in LPM tree */
rtm_route *
rtm_lpm_tree_lookup(rtm_t *rtm, rtm_prefix_t *prefix) {
    
    bitmap_t prefix_bm;
    mtrie_node_t *mnode = NULL;
    
    if (!rtm || !prefix) {
        return NULL;
    }
    
    /* Skip if LPM tree not initialized */
    if (!rtm->lpm_rt_tree) {
        return NULL;
    }
    
    /* Initialize bitmap based on AFI */
    uint16_t prefix_len = 0;
    switch (prefix->afi) {
        case RTM_AF_IPV4:
            prefix_len = 32;
            break;
        case RTM_AF_IPV6:
            prefix_len = 128;
            break;
        default:
            return NULL;
    }
    
    bitmap_init(&prefix_bm, prefix_len);
    
    /* Convert prefix to bitmap */
    rtm_prefix_to_bitmap(prefix, &prefix_bm);
    
    /* Perform LPM search */
    mnode = mtrie_longest_prefix_match_search(rtm->lpm_rt_tree, &prefix_bm);
    
    bitmap_free_internal(&prefix_bm);
    
    if (!mnode || !mnode->data) {
        return NULL;
    }
    
    /* Return the route stored in the mtrie node */
    return (rtm_route *)mnode->data;
}

void 
rtm_route_moved_to_resolved_state (rtm_t *rtm, rtm_route *route) {
    
    char prefix_str[48];

    tracer(rtm->node->cptr, DRTM,
           "RTM[%s] : Route : %s : Moved to Resolved State\n",
           rtm->name,
           rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));
}

void 
rtm_route_moved_to_unresolved_state (rtm_t *rtm, rtm_route *route) {

    char prefix_str[48];

    tracer(rtm->node->cptr, DRTM,
           "RTM[%s] : Route : %s : Moved to UnResolved State\n",
           rtm->name,
           rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)));    
}

/* ========================================================================
 * Wrapper Functions for rtm_route - Following the exact pattern from rtm_nh.cpp
 * These wrappers enforce reference counting for glthread and AVL operations
 * ======================================================================== */

void 
rtm_route_glthread_add_next (
    rtm_route *route, glthread_t *curr_glthread, glthread_t *new_glthread){
    
    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    glthread_add_next (curr_glthread, new_glthread);
    rtm_route_reference (route);
}

void 
rtm_route_remove_glthread (rtm_t *rtm, rtm_route *route, glthread_t *curr_glthread){

    assert (IS_QUEUED_UP_IN_THREAD(curr_glthread));
    remove_glthread (curr_glthread);
    rtm_route_dereference (rtm, route);
}

void 
rtm_route_fglthread_add_next (rtm_route *route, 
        Fglthread_t *head, 
        glthread_t *base_glthread, glthread_t *new_glthread) {

    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    Fglthread_add_next (head, base_glthread, new_glthread);
    rtm_route_reference (route);
}

void 
rtm_route_fglthread_add_before (rtm_route *route, 
        Fglthread_t *head, 
        glthread_t *base_glthread, glthread_t *new_glthread) {

    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    Fglthread_add_before (head, base_glthread, new_glthread);
    rtm_route_reference (route);
}

void
rtm_route_remove_Fglthread(rtm_t *rtm, rtm_route *route, 
                Fglthread_t *head, glthread_t *glthread){

    assert (IS_QUEUED_UP_IN_THREAD(glthread));
    remove_Fglthread (head, glthread);
    rtm_route_dereference (rtm, route);
}

void
rtm_route_Fglthread_add_last(rtm_route *route, 
        Fglthread_t *head, glthread_t *new_glthread) {


    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    Fglthread_add_last (head, new_glthread);
    rtm_route_reference (route);
}

void 
rtm_route_avl_insert (rtm_route *route, avltree_t *tree, avltree_node_t *avlnode){

    assert (!avltree_node_is_inuse(avlnode));
    assert (!avltree_insert(avlnode, tree));
    rtm_route_reference (route);
}

void 
rtm_route_avl_remove (rtm_t *rtm, rtm_route *route, 
    avltree_t *tree, avltree_node_t *avlnode){

    assert (avltree_node_is_inuse(avlnode));
    avltree_strict_remove(avlnode, tree); 
    rtm_route_dereference (rtm, route);
}
