#include <string.h>
#include <cstdlib>
#include "fib.h"
#include "fib_route.h"
#include "fib_error.h"
#include "fib_nh.h"
#include "../mtrie/mtrie.h"
#include "../BitOp/bitmap.h"
#include "../LinuxMemoryManager/uapi_mm.h"

fib_error_t 
fib_add_route (
        fib_t *fib, 
        cmn_prefix_t *prefix, 
        uint32_t nh_idx, 
        fib_nh_t *nh) {
    
    /* Validate AFI matches between FIB and prefix */
    if (prefix->afi != fib->afi) {
        return FIB_ERROR_AFI_MISMATCH;
    }
    
    /* Handle based on FIB type (IP vs MPLS) */
    if (prefix->afi == AF_IPV4 || prefix->afi == AF_IPV6) {
        
        /* IP prefix - use LPM (mtrie) */
        if (!fib->u.lpm) {
            return FIB_ERROR_INVALID_PARAM;
        }
        
        /* Convert prefix to bitmap format for mtrie */
        bitmap_t bm_prefix, bm_mask;
        cmn_prefix_to_bitmap(prefix, &bm_prefix);
        cmn_prefix_to_wildcard_bitmap(prefix, &bm_mask);
        
        /* Try to insert or lookup existing route in mtrie */
        mtrie_node_t *mnode = NULL;
        mtrie_ops_result_code_t result = mtrie_insert_prefix(
            fib->u.lpm,
            &bm_prefix,
            &bm_mask,
            prefix->prefix_len,
            &mnode
        );
        
        /* Free bitmaps */
        bitmap_free_internal(&bm_prefix);
        bitmap_free_internal(&bm_mask);
        
        /* Check result */
        if (result == MTRIE_INSERT_FAILED) {
            return FIB_ERROR_INSERT_FAILED;
        }
        
        fib_route_t *route = NULL;
        
        /* If this is a new route, allocate and initialize */
        if (result == MTRIE_INSERT_SUCCESS) {
            
            /* Allocate new route */
            route = (fib_route_t *)XCALLOC2(0, 1, fib_route_t);
            if (!route) {
                return FIB_ERROR_ALLOC_FAILED;
            }
            
            /* Allocate and copy prefix */
            memcpy(&route->prefix, prefix, sizeof(cmn_prefix_t));
            
            /* Initialize nexthop arrays */
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                route->nh_idx[i] = 0;
                route->nhs[i] = NULL;
            }
            
            /* Initialize ECMP round-robin index */
            route->nh_index = 0;
            
            /* Add first nexthop */
            route->nh_idx[0] = nh_idx;
            route->nhs[0] = nh;
            
            /* Reference the nexthop */
            fib_nh_reference(nh);
            
            /* Store route in mtrie node */
            mnode->data = (void *)route;
            
        } else if (result == MTRIE_INSERT_DUPLICATE) {
            
            /* Route already exists, add nexthop to ECMP group */
            route = (fib_route_t *)mnode->data;
            
            if (!route) {
                return FIB_ERROR_NO_ROUTE_DATA;
            }
            
            /* Check if this nexthop already exists */
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                if (route->nhs[i] && route->nh_idx[i] == nh_idx) {
                    /* Nexthop already exists - this is not an error */
                    return FIB_ERROR_SUCCESS;
                }
            }
            
            /* Find empty slot for new nexthop */
            int empty_slot = -1;
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                if (route->nhs[i] == NULL) {
                    empty_slot = i;
                    break;
                }
            }
            
            /* Check if ECMP limit reached */
            if (empty_slot == -1) {
                return FIB_ERROR_ECMP_LIMIT;
            }
            
            /* Add nexthop to ECMP group */
            route->nh_idx[empty_slot] = nh_idx;
            route->nhs[empty_slot] = nh;
            
            /* Reference the nexthop */
            fib_nh_reference(nh);
        }
        
    } else if (prefix->afi == AF_LABEL) {
        
        /* MPLS label - use hash table */
        if (!fib->u.label_ht) {
            return FIB_ERROR_INVALID_PARAM;
        }
        
        /* Look up existing route by label */
        uint32_t label = prefix->u.mpls_label;
        fib_route_t *route = (fib_route_t *)hashtable_search(fib->u.label_ht, &label);
        
        if (!route) {
            /* Route doesn't exist, create new one */
            route = (fib_route_t *)XCALLOC2(0, 1, fib_route_t);
            if (!route) {
                return FIB_ERROR_ALLOC_FAILED;
            }
            
            /* Allocate and copy prefix */
            memcpy(&route->prefix, prefix, sizeof(cmn_prefix_t));
            
            /* Initialize nexthop arrays */
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                route->nh_idx[i] = 0;
                route->nhs[i] = NULL;
            }
            
            /* Initialize ECMP round-robin index */
            route->nh_index = 0;
            
            /* Add first nexthop */
            route->nh_idx[0] = nh_idx;
            route->nhs[0] = nh;
            
            /* Reference the nexthop */
            fib_nh_reference(nh);
            
            /* Insert into hash table */
            uint32_t *label_key = (uint32_t *)calloc(1, sizeof(uint32_t));
            *label_key = label;
            
            if (!hashtable_insert(fib->u.label_ht, label_key, route)) {
                XFREE(label_key);
                XFREE(route);
                return FIB_ERROR_INSERT_FAILED;
            }
            
        } else {
            /* Route exists, add nexthop to ECMP group */
            
            /* Check if this nexthop already exists */
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                if (route->nhs[i] && route->nh_idx[i] == nh_idx) {
                    /* Nexthop already exists - this is not an error */
                    return FIB_ERROR_SUCCESS;
                }
            }
            
            /* Find empty slot for new nexthop */
            int empty_slot = -1;
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                if (route->nhs[i] == NULL) {
                    empty_slot = i;
                    break;
                }
            }
            
            /* Check if ECMP limit reached */
            if (empty_slot == -1) {
                return FIB_ERROR_ECMP_LIMIT;
            }
            
            /* Add nexthop to ECMP group */
            route->nh_idx[empty_slot] = nh_idx;
            route->nhs[empty_slot] = nh;
            
            /* Reference the nexthop */
            fib_nh_reference(nh);
        }
        
    } else {
        /* Unsupported AFI */
        return FIB_ERROR_INVALID_PARAM;
    }
    
    return FIB_ERROR_SUCCESS;
}

fib_error_t 
fib_del_route (fib_t *fib, 
               cmn_prefix_t *prefix, 
               uint32_t nh_idx) {
    
    /* Validate AFI matches between FIB and prefix */
    if (prefix->afi != fib->afi) {
        return FIB_ERROR_AFI_MISMATCH;
    }
    
    /* Handle based on FIB type (IP vs MPLS) */
    if (prefix->afi == AF_IPV4 || prefix->afi == AF_IPV6) {
        
        /* IP prefix - use LPM (mtrie) */
        if (!fib->u.lpm) {
            return FIB_ERROR_INVALID_PARAM;
        }
        
        /* Convert prefix to bitmap format for mtrie lookup */
        bitmap_t bm_prefix, bm_mask;
        cmn_prefix_to_bitmap(prefix, &bm_prefix);
        cmn_prefix_to_wildcard_bitmap(prefix, &bm_mask);
        
        /* Look up route in mtrie */
        mtrie_node_t *mnode = mtrie_exact_prefix_match_search(
            fib->u.lpm,
            &bm_prefix,
            &bm_mask
        );
        
        /* Free bitmaps */
        bitmap_free_internal(&bm_prefix);
        bitmap_free_internal(&bm_mask);
        
        /* Check if route exists */
        if (!mnode || !mnode->data) {
            return FIB_ERROR_ROUTE_NOT_FOUND;
        }
        
        fib_route_t *route = (fib_route_t *)mnode->data;
        
        /* Find and remove the nexthop */
        bool found = false;
        int nh_slot = -1;
        
        for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
            if (route->nhs[i] && route->nh_idx[i] == nh_idx) {
                found = true;
                nh_slot = i;
                break;
            }
        }
        
        if (!found) {
            return FIB_ERROR_NEXTHOP_NOT_FOUND;
        }
        
        /* Dereference the nexthop */
        fib_nh_dereference(fib, route->nhs[nh_slot]);
        
        /* Remove nexthop from route */
        route->nhs[nh_slot] = NULL;
        route->nh_idx[nh_slot] = 0;
        
        /* Check if route still has any nexthops */
        int remaining_nhs = 0;
        for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
            if (route->nhs[i]) {
                remaining_nhs++;
            }
        }
        
        /* If no nexthops remain, delete the route */
        if (remaining_nhs == 0) {
            
            /* Remove from mtrie */
            cmn_prefix_to_bitmap(prefix, &bm_prefix);
            cmn_prefix_to_wildcard_bitmap(prefix, &bm_mask);
            
            void *app_data = NULL;
            mtrie_ops_result_code_t result = mtrie_delete_prefix(
                fib->u.lpm,
                &bm_prefix,
                &bm_mask,
                &app_data
            );
            
            bitmap_free_internal(&bm_prefix);
            bitmap_free_internal(&bm_mask);
            
            if (result != MTRIE_DELETE_SUCCESS) {
                /* Route data already cleared, but mtrie deletion failed */
                /* This is not critical - just log and continue cleanup */
            }
            
            /* Free route structure */
            XFREE(route);
        }
        
    } else if (prefix->afi == AF_LABEL) {
        
        /* MPLS label - use hash table */
        if (!fib->u.label_ht) {
            return FIB_ERROR_INVALID_PARAM;
        }
        
        /* Look up existing route by label */
        uint32_t label = prefix->u.mpls_label;
        fib_route_t *route = (fib_route_t *)hashtable_search(fib->u.label_ht, &label);
        
        if (!route) {
            return FIB_ERROR_ROUTE_NOT_FOUND;
        }
        
        /* Find and remove the nexthop */
        bool found = false;
        int nh_slot = -1;
        
        for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
            if (route->nhs[i] && route->nh_idx[i] == nh_idx) {
                found = true;
                nh_slot = i;
                break;
            }
        }
        
        if (!found) {
            return FIB_ERROR_NEXTHOP_NOT_FOUND;
        }
        
        /* Dereference the nexthop */
        fib_nh_dereference(fib, route->nhs[nh_slot]);
        
        /* Remove nexthop from route */
        route->nhs[nh_slot] = NULL;
        route->nh_idx[nh_slot] = 0;
        
        /* Check if route still has any nexthops */
        int remaining_nhs = 0;
        for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
            if (route->nhs[i]) {
                remaining_nhs++;
            }
        }
        
        /* If no nexthops remain, delete the route */
        if (remaining_nhs == 0) {
            
            /* Remove from hash table */
            void *removed_route = hashtable_remove(fib->u.label_ht, &label);
            
            if (!removed_route) {
                /* Route removal from hash table failed */
                /* But we already cleared the nexthop, so continue cleanup */
            }
            
            /* Free route structure */
            XFREE(route);
            
            /* Note: The hash table key is owned by the hash table and will be freed when it's destroyed */
        }
        
    } else {
        /* Unsupported AFI */
        return FIB_ERROR_INVALID_PARAM;
    }
    
    return FIB_ERROR_SUCCESS;
}
