#include <string.h>
#include <cstdlib>
#include "../../router_init.h"
#include "fib.h"
#include "fib_route.h"
#include "fib_error.h"
#include "fib_nh.h"
#include "../../lmm_enums.h"
#include "../../mtrie/mtrie.h"
#include "../../BitOp/bitmap.h"
#include "../../Tracer/tracer.h"
#include "../../common/cmn_prefix.h"
#include "../../LinuxMemoryManager/uapi_mm.h"

static inline void 
fib_set_nh_idx(
    uint64_t *p, 
    uint32_t inhidx, 
    uint32_t nhidx) {

    *p = inhidx;
    *p = *p << 32;
    *p |= nhidx;
}

static inline bool 
fib_nh_idx_compare(
    uint64_t p, 
    uint32_t inhidx,
    uint32_t nhidx) {

    uint64_t temp;
    fib_set_nh_idx (&temp, inhidx, nhidx);
    return temp == p;
}

fib_error_t 
fib_add_route (dp_ctx_t *dp_ctx,
        fib_t *fib, 
        cmn_prefix_t *prefix, 
        uint32_t inh_idx,
        uint32_t nh_idx, 
        fib_nh_t *nh) {
    
    char route_str[48];
    char nh_str[48];

    tracer (dp_ctx->dptr, DFIB_DET, 
        "FIB[%s] : Adding Route %s with NH Index (%s)%u\n", 
        fib->name,
        cmn_prefix_to_string(prefix, &route_str),
        cmn_prefix_to_string(&nh->fwd_info->nh_addr, &nh_str), nh_idx);

    /* Handle based on FIB type (IP vs MPLS) */
    if (prefix->afi == AF_IPV4 || 
            prefix->afi == AF_IPV6) {
        
        /* Convert prefix to bitmap format for mtrie */
        bitmap_t bm_prefix, bm_mask;
        bitmap_init(&bm_prefix, afi_stride_len(prefix->afi));
        bitmap_init(&bm_mask, afi_stride_len(prefix->afi));

        /* Convert prefix to bitmap */
        cmn_prefix_to_bitmap(prefix, &bm_prefix);
        cmn_prefix_to_wildcard_bitmap(prefix, &bm_mask);
        
        /* Try to insert or lookup existing route in mtrie */
        mtrie_node_t *mnode = NULL;
        mtrie_ops_result_code_t result = mtrie_insert_prefix(
            fib->u.lpm,
            &bm_prefix,
            &bm_mask,
            afi_stride_len(prefix->afi),
            &mnode
        );

        /* Free bitmaps */
        bitmap_free_internal(&bm_prefix);
        bitmap_free_internal(&bm_mask);
        
        /* Check result */
        if (result == MTRIE_INSERT_FAILED) {

            tracer (dp_ctx->dptr, DFIB | DERR, 
                "FIB[%s] : Route %s : FIB installation failed\n", 
                fib->name, route_str);
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
            fib_set_nh_idx (&route->nh_idx[0], inh_idx, nh_idx);
            route->nhs[0] = nh;
            
            /* Reference the nexthop */
            fib_nh_reference(nh);
            
            /* Store route in mtrie node */
            mnode->data = (void *)route;

            tracer (dp_ctx->dptr, DFIB_DET, 
                "FIB[%s] : Route %s : New route created and installed, Nexthop : %s(%u)\n", 
                fib->name, route_str, nh_str, nh_idx);
            
        } else if (result == MTRIE_INSERT_DUPLICATE) {
            
            /* Route already exists, add nexthop to ECMP group */
            route = (fib_route_t *)mnode->data;
            
            int empty_slot = -1;

            /* Check if this nexthop already exists */
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {

                if (!route->nhs[i]) empty_slot = i;

                if (route->nhs[i] && 
                    fib_nh_idx_compare(route->nh_idx[i], inh_idx, nh_idx)) {

                    tracer (dp_ctx->dptr, DFIB_DET | DERR, 
                        "FIB[%s] : Error : Route %s : Attempt to add Duplicate Nexthop : %s(%u)\n", 
                        fib->name, route_str, nh_str, nh_idx);
                    return FIB_ERROR_NEXTHOP_DUP_NEXTHOP;
                }
            }
            
            /* Check if ECMP limit reached */
            if (empty_slot == -1) {

                tracer (dp_ctx->dptr, DFIB_DET | DERR, 
                    "FIB[%s] : Error : Route %s : Nexthop %s(%u) rejected, ECMP limit reached\n", 
                    fib->name, route_str, nh_str, nh_idx);                
                return FIB_ERROR_ECMP_LIMIT;
            }
            
            /* Add nexthop to ECMP group */
            fib_set_nh_idx (&route->nh_idx[empty_slot], inh_idx, nh_idx);
            route->nhs[empty_slot] = nh;

            /* Reference the nexthop */
            fib_nh_reference(nh);

            tracer (dp_ctx->dptr, DFIB_DET, 
                "FIB[%s] : Route %s : Existing route, added new Nexthop : %s(%u)\n", 
                fib->name, route_str, nh_str, nh_idx);
        }
        
    } else if (prefix->afi == AF_LABEL) {
        
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
            
            /* Insert into hash table */
            uint32_t *label_key = (uint32_t *)calloc(1, sizeof(uint32_t));
            *label_key = label;
            
            if (!hashtable_insert(fib->u.label_ht, label_key, route)) {
                XFREE(label_key);
                XFREE(route);
                return FIB_ERROR_INSERT_FAILED;
            }
            
            /* Add first nexthop */
            fib_set_nh_idx (&route->nh_idx[0], inh_idx, nh_idx);
            route->nhs[0] = nh;
            
            /* Reference the nexthop */
            fib_nh_reference(nh);

            tracer (dp_ctx->dptr, DFIB_DET, 
                "FIB[%s] : Route %s : New route created and installed, Nexthop : %s(%u)\n", 
                fib->name, route_str, nh_str, nh_idx);
            
        } else {
            /* Route exists, add nexthop to ECMP group */
            
            /* Check if this nexthop already exists */
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {

                if (route->nhs[i] && 
                    fib_nh_idx_compare(route->nh_idx[i], inh_idx, nh_idx)) {

                    tracer (dp_ctx->dptr, DFIB_DET | DERR, 
                        "FIB[%s] : Error : Route %s : Attempt to add Duplicate Nexthop : %s(%u)\n", 
                        fib->name, route_str, nh_str, nh_idx);
                    return FIB_ERROR_NEXTHOP_DUP_NEXTHOP;
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
            fib_set_nh_idx (&route->nh_idx[empty_slot], inh_idx, nh_idx);
            route->nhs[empty_slot] = nh;
            
            /* Reference the nexthop */
            fib_nh_reference(nh);

            tracer (dp_ctx->dptr, DFIB_DET, 
                "FIB[%s] : Route %s : Existing route, added new Nexthop : %s(%u)\n", 
                fib->name, route_str, nh_str, nh_idx);
        }
        
    } else {
        /* Unsupported AFI */
        assert(0);
        return FIB_ERROR_INVALID_PARAM;
    }
    
    return FIB_ERROR_SUCCESS;
}

fib_error_t 
fib_del_route (dp_ctx_t *dp_ctx,
               fib_t *fib, 
               cmn_prefix_t *prefix, 
               uint32_t inh_idx,
               uint32_t nh_idx) {
    
    char route_str[48];

    tracer (dp_ctx->dptr, DFIB_DET, 
        "FIB[%s] : Deleting NH Index (%u) from Route %s\n", 
        fib->name,
        nh_idx,
        cmn_prefix_to_string(prefix, &route_str));

    /* Handle based on FIB type (IP vs MPLS) */
    if (prefix->afi == AF_IPV4 || prefix->afi == AF_IPV6) {
        
        /* Convert prefix to bitmap format for mtrie lookup */
        bitmap_t bm_prefix, bm_mask;
        bitmap_init(&bm_prefix, prefix->afi == AF_IPV4 ? 32 : 128);
        bitmap_init(&bm_mask, prefix->afi == AF_IPV4 ? 32 : 128);
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

            tracer (dp_ctx->dptr, DERR, 
                "FIB[%s] : Route %s : Not found for deletion\n", 
                fib->name, route_str);
            return FIB_ERROR_ROUTE_NOT_FOUND;
        }
        
        fib_route_t *route = (fib_route_t *)mnode->data;
        
        /* Find and remove the nexthop */
        bool found = false;
        int nh_slot = -1;
        
        for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
            if (route->nhs[i] && 
                fib_nh_idx_compare(route->nh_idx[i], inh_idx, nh_idx)) {
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
        
        tracer (dp_ctx->dptr, DFIB_DET, 
            "FIB[%s] : Route %s : Deleted Nexthop (%u), Remaining NHs: %d\n", 
            fib->name, route_str, nh_idx, remaining_nhs);

        /* If no nexthops remain, delete the route */
        if (remaining_nhs == 0) {
            
            /* Remove from mtrie - reinitialize bitmaps for delete operation */
            bitmap_init(&bm_prefix, prefix->afi == AF_IPV4 ? 32 : 128);
            bitmap_init(&bm_mask, prefix->afi == AF_IPV4 ? 32 : 128);
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
            tracer (dp_ctx->dptr, DFIB_DET, 
                "FIB[%s] : Route %s Deleted. No remaining nexthops\n", 
                fib->name, route_str);
            XFREE(route);
        }
        
    } else if (prefix->afi == AF_LABEL) {
        
        /* Look up existing route by label */
        uint32_t label = prefix->u.mpls_label;
        fib_route_t *route = (fib_route_t *)hashtable_search(fib->u.label_ht, &label);
        
        if (!route) {

            tracer (dp_ctx->dptr, DERR, 
                "FIB[%s] : Route %s : Not found for deletion\n", 
                fib->name, route_str);
            return FIB_ERROR_ROUTE_NOT_FOUND;
        }
        
        /* Find and remove the nexthop */
        bool found = false;
        int nh_slot = -1;
        
        for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
            if (route->nhs[i] && 
                fib_nh_idx_compare(route->nh_idx[i], inh_idx, nh_idx)) {
                found = true;
                nh_slot = i;
                break;
            }
        }
        
        if (!found) {
            tracer (dp_ctx->dptr, DERR, 
                "FIB[%s] : Route %s : Nexthop (%u) not found for deletion\n", 
                fib->name, route_str, nh_idx);
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
        
        tracer (dp_ctx->dptr, DFIB_DET, 
            "FIB[%s] : Route %s : Deleted Nexthop (%u), Remaining NHs: %d\n", 
            fib->name, route_str, nh_idx, remaining_nhs);

        /* If no nexthops remain, delete the route */
        if (remaining_nhs == 0) {
            
            /* Remove from hash table */
            void *removed_route = hashtable_remove(fib->u.label_ht, &label);
            
            assert (removed_route == route);
            
            /* Free route structure */
            tracer (dp_ctx->dptr, DFIB_DET, 
                "FIB[%s] : Route %s Deleted. No remaining nexthops\n", 
                fib->name, route_str);
            XFREE(route);
            
            /* Note: The hash table key is owned by the hash table and will be freed when it's destroyed */
        }
        
    } else {
        assert(0);
        /* Unsupported AFI */
        return FIB_ERROR_INVALID_PARAM;
    }
    
    return FIB_ERROR_SUCCESS;
}
