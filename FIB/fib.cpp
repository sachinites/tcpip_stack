/*
 * =====================================================================================
 *
 *       Filename:  fib.cpp
 *
 *    Description:  FIB (Forwarding Information Base) implementation using mtrie data
 *                  structure. This simulates a hardware forwarding engine.
 *
 *                  The FIB supports multiple address families (AFI):
 *                  - IPv4 (32-bit addresses)
 *                  - IPv6 (128-bit addresses)
 *                  - MPLS Labels (20-bit labels)
 *                  - MAC addresses (48-bit addresses)
 *
 *                  Key Features:
 *                  - Fast LPM (Longest Prefix Match) lookups using mtrie
 *                  - ECMP (Equal Cost Multi-Path) support
 *                  - MPLS label stack operations (push, pop, swap)
 *                  - Hardware FIB simulation
 *
 * =====================================================================================
 */

#include <string.h>
#include <stdlib.h>
#include "fib.h"
#include "../pkt_block.h"
#include "../mtrie/mtrie.h"
#include "fib_api.h"
#include "fib_route.h"
#include "fib_nh.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../Interface/InterfaceUApi.h"

/**
 * Initialize FIB with appropriate stride length based on AFI
 * 
 * @param afi  Address Family Identifier (IPv4, IPv6, LABEL, MAC)
 * @return     Pointer to initialized FIB structure, NULL on failure
 *
 * Stride lengths:
 *   - IPv4: 32 bits
 *   - IPv6: 128 bits
 *   - MPLS: 20 bits
 *   - MAC:  48 bits
 */
fib_t *fib_init(FIB_AFI_T afi) {
    
    /* Allocate FIB structure */
    fib_t *fib = (fib_t *)XCALLOC2(0, 1, fib_t);
    if (!fib) {
        return NULL;
    }
    
    /* Set AFI */
    fib->afi = afi;
    
    /* Allocate mtrie */
    fib->mtrie = (mtrie_t *)XCALLOC2(0, 1, mtrie_t);
    if (!fib->mtrie) {
        XFREE(fib);
        return NULL;
    }
    
    /* Get stride length based on AFI and initialize mtrie */
    uint16_t stride_len = fib_get_stride_len_from_afi(afi);
    if (stride_len == 0) {
        XFREE(fib->mtrie);
        XFREE(fib);
        return NULL;
    }
    
    /* Initialize mtrie with stride length and free callback */
    init_mtrie(fib->mtrie, stride_len, fib_route_free_callback);
    
    return fib;
}

/**
 * Add a route to the FIB
 * 
 * @param fib     Pointer to FIB structure
 * @param prefix  Destination prefix to add
 * @param nh      Next hop information
 * @return        0 on success, error code on failure
 *
 * If the route already exists, the nexthop is added to the ECMP group.
 * Supports up to FIB_MAX_ECMP_NH (8) nexthops per route.
 */
fib_error_t fib_add_route(fib_t *fib, fib_prefix_t *prefix, fib_nh_t *nh) {
    
    if (!fib || !fib->mtrie || !prefix || !nh) {
        return FIB_ERROR_INVALID_PARAM;
    }
    
    /* Verify AFI matches */
    if (prefix->afi != fib->afi) {
        return FIB_ERROR_AFI_MISMATCH;
    }
    
    /* Convert FIB prefix to bitmap format */
    bitmap_t bm_prefix, bm_mask;
    fib_prefix_to_bitmap(prefix, &bm_prefix, &bm_mask);
    
    /* Try to insert or lookup existing route in mtrie */
    mtrie_node_t *mnode = NULL;
    mtrie_ops_result_code_t result = mtrie_insert_prefix(
        fib->mtrie,
        &bm_prefix,
        &bm_mask,
        prefix->prefix_len,
        &mnode
    );
    
    /* Check result */
    if (result == MTRIE_INSERT_FAILED) {
        bitmap_free_internal(&bm_prefix);
        bitmap_free_internal(&bm_mask);
        return FIB_ERROR_INSERT_FAILED;
    }
    
    /* If this is a new route, allocate and initialize route structure */
    if (result == MTRIE_INSERT_SUCCESS) {
        
        /* Allocate new route */
        fib_route_t *route = (fib_route_t *)XCALLOC2(0, 1, fib_route_t);
        if (!route) {
            bitmap_free_internal(&bm_prefix);
            bitmap_free_internal(&bm_mask);
            return FIB_ERROR_ALLOC_FAILED;
        }
        
        /* Allocate and copy prefix */
        route->prefix = (fib_prefix_t *)XCALLOC2(0, 1, fib_prefix_t);
        if (!route->prefix) {
            XFREE(route);
            bitmap_free_internal(&bm_prefix);
            bitmap_free_internal(&bm_mask);
            return FIB_ERROR_ALLOC_FAILED;
        }
        memcpy(route->prefix, prefix, sizeof(fib_prefix_t));
        
        /* Initialize nexthop array */
        for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
            route->nh[i] = NULL;
        }
        
        /* Initialize ECMP round-robin index */
        route->nh_index = 0;
        
        /* Add first nexthop */
        route->nh[0] = (fib_nh_t *)XCALLOC2(0, 1, fib_nh_t);
        if (!route->nh[0]) {
            XFREE(route->prefix);
            XFREE(route);
            bitmap_free_internal(&bm_prefix);
            bitmap_free_internal(&bm_mask);
            return FIB_ERROR_ALLOC_FAILED;
        }
        
        /* Copy nexthop data field by field */
        route->nh[0]->idx = nh->idx;
        route->nh[0]->gateway = nh->gateway;
        route->nh[0]->oif = nh->oif;
        route->nh[0]->lstack = NULL;
        
        /* Copy label stack if present */
        if (nh->lstack) {
            route->nh[0]->lstack = (fib_lstack_t *)XCALLOC2(0, 1, fib_lstack_t);
            if (route->nh[0]->lstack) {
                memcpy(route->nh[0]->lstack, nh->lstack, sizeof(fib_lstack_t));
            }
        }
        
        /* Store route in mtrie node */
        mnode->data = (void *)route;
        
    } else if (result == MTRIE_INSERT_DUPLICATE) {
        
        /* Route already exists, add nexthop to ECMP group */
        fib_route_t *route = (fib_route_t *)mnode->data;
        
        if (!route) {
            bitmap_free_internal(&bm_prefix);
            bitmap_free_internal(&bm_mask);
            return FIB_ERROR_NO_ROUTE_DATA;
        }
        
        /* Find empty slot for new nexthop */
        int empty_slot = -1;
        for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
            if (route->nh[i] == NULL) {
                empty_slot = i;
                break;
            }
        }
        
        if (empty_slot == -1) {
            bitmap_free_internal(&bm_prefix);
            bitmap_free_internal(&bm_mask);
            return FIB_ERROR_ECMP_LIMIT;
        }
        
        /* Add nexthop */
        route->nh[empty_slot] = (fib_nh_t *)XCALLOC2(0, 1, fib_nh_t);
        if (!route->nh[empty_slot]) {
            bitmap_free_internal(&bm_prefix);
            bitmap_free_internal(&bm_mask);
            return FIB_ERROR_ALLOC_FAILED;
        }
        
        /* Copy nexthop data field by field */
        route->nh[empty_slot]->idx = nh->idx;
        route->nh[empty_slot]->gateway = nh->gateway;
        route->nh[empty_slot]->oif = nh->oif;
        route->nh[empty_slot]->lstack = NULL;
        
        /* Copy label stack if present */
        if (nh->lstack) {
            route->nh[empty_slot]->lstack = (fib_lstack_t *)XCALLOC2(0, 1, fib_lstack_t);
            if (route->nh[empty_slot]->lstack) {
                memcpy(route->nh[empty_slot]->lstack, nh->lstack, sizeof(fib_lstack_t));
            }
        }
    }
    
    /* Clean up bitmaps */
    bitmap_free_internal(&bm_prefix);
    bitmap_free_internal(&bm_mask);
    
    return FIB_ERROR_SUCCESS;
}

/**
 * Delete a route from the FIB
 * 
 * @param fib     Pointer to FIB structure
 * @param prefix  Destination prefix to delete
 * @param nh      Specific nexthop to delete (NULL to delete entire route)
 * @return        0 on success, error code on failure
 *
 * If nh is NULL, the entire route is removed.
 * If nh is provided, only that specific nexthop is removed from the ECMP group.
 * If the last nexthop is removed, the entire route is deleted.
 */
fib_error_t fib_del_route(fib_t *fib, fib_prefix_t *prefix, fib_nh_t *nh) {
    
    if (!fib || !fib->mtrie || !prefix) {
        return FIB_ERROR_INVALID_PARAM;
    }
    
    /* Verify AFI matches */
    if (prefix->afi != fib->afi) {
        return FIB_ERROR_AFI_MISMATCH;
    }
    
    /* Convert FIB prefix to bitmap format */
    bitmap_t bm_prefix, bm_mask;
    fib_prefix_to_bitmap(prefix, &bm_prefix, &bm_mask);
    
    /* If no specific nexthop provided, delete entire route */
    if (!nh) {
        
        void *app_data = NULL;
        mtrie_ops_result_code_t result = mtrie_delete_prefix(
            fib->mtrie,
            &bm_prefix,
            &bm_mask,
            &app_data
        );
        
        bitmap_free_internal(&bm_prefix);
        bitmap_free_internal(&bm_mask);
        
        if (result == MTRIE_DELETE_SUCCESS) {
            return FIB_ERROR_SUCCESS;
        } else {
            return FIB_ERROR_ROUTE_NOT_FOUND;
        }
        
    } else {
        
        /* Find the route and remove specific nexthop */
        mtrie_node_t *mnode = mtrie_exact_prefix_match_search(
            fib->mtrie,
            &bm_prefix,
            &bm_mask
        );
        
        if (!mnode || !mnode->data) {
            bitmap_free_internal(&bm_prefix);
            bitmap_free_internal(&bm_mask);
            return FIB_ERROR_ROUTE_NOT_FOUND;
        }
        
        fib_route_t *route = (fib_route_t *)mnode->data;
        
        /* Find and remove the specific nexthop */
        bool found = false;
        int nh_count = 0;
        
        for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
            if (route->nh[i]) {
                nh_count++;
                
                /* Match nexthop by index or gateway */
                if (route->nh[i]->idx == nh->idx ||
                    (route->nh[i]->gateway.afi == nh->gateway.afi &&
                     route->nh[i]->gateway.u.v4_addr == nh->gateway.u.v4_addr)) {
                    
                    /* Free nexthop */
                    if (route->nh[i]->lstack) {
                        XFREE(route->nh[i]->lstack);
                    }
                    XFREE(route->nh[i]);
                    route->nh[i] = NULL;
                    found = true;
                    nh_count--;
                    break;
                }
            }
        }
        
        if (!found) {
            bitmap_free_internal(&bm_prefix);
            bitmap_free_internal(&bm_mask);
            return FIB_ERROR_NEXTHOP_NOT_FOUND;
        }
        
        /* If no more nexthops, delete entire route */
        if (nh_count == 0) {
            void *app_data = NULL;
            mtrie_delete_prefix(fib->mtrie, &bm_prefix, &bm_mask, &app_data);
        }
        
        bitmap_free_internal(&bm_prefix);
        bitmap_free_internal(&bm_mask);
        
        return FIB_ERROR_SUCCESS;
    }
}

/**
 * Forward a packet using the FIB
 * 
 * @param fib  Pointer to FIB structure
 * @param pkt  Packet block to forward
 * @return     0 on success, error code on failure
 *
 * This function performs:
 * 1. Extracts destination address from packet based on header type
 * 2. Performs lookup in FIB:
 *    - IPv4/IPv6: Longest Prefix Match (LPM) lookup
 *    - MPLS/MAC: Exact Match lookup
 * 3. Selects active nexthop (round-robin for ECMP)
 * 4. Applies MPLS label stack operations if present
 * 5. Decrements TTL for IP packets
 * 6. Marks packet for forwarding (simulates hardware forwarding)
 */
fib_error_t fib_forward(fib_t *fib, pkt_block_t *pkt) {
    
    if (!fib || !fib->mtrie || !pkt) {
        return FIB_ERROR_INVALID_PARAM;
    }
    
    /* Extract destination address from packet */
    fib_prefix_t dest;
    if (!fib_extract_dest_from_pkt(pkt, &dest)) {
        return FIB_ERROR_EXTRACT_DEST_FAILED;
    }
    
    /* Verify AFI matches */
    if (dest.afi != fib->afi) {
        return FIB_ERROR_AFI_MISMATCH;
    }
    
    /* Convert destination to bitmap format */
    bitmap_t bm_dest, bm_mask;
    fib_prefix_to_bitmap(&dest, &bm_dest, &bm_mask);
    
    /* Perform lookup based on AFI type:
     * - IPv4/IPv6: Use Longest Prefix Match (LPM)
     * - MPLS/MAC: Use Exact Match
     */
    mtrie_node_t *mnode = NULL;
    
    if (fib->afi == FIB_AF_LABEL || fib->afi == FIB_AFI_MAC) {
        /* MPLS and MAC require exact match lookup */
        mnode = mtrie_exact_prefix_match_search(
            fib->mtrie,
            &bm_dest,
            &bm_mask
        );
    } else {
        /* IPv4 and IPv6 use longest prefix match */
        mnode = mtrie_longest_prefix_match_search(
            fib->mtrie,
            &bm_dest
        );
    }
    
    /* Clean up bitmaps */
    bitmap_free_internal(&bm_dest);
    bitmap_free_internal(&bm_mask);
    
    /* Check if route found */
    if (!mnode || !mnode->data) {
        return FIB_ERROR_NO_ROUTE;
    }
    
    fib_route_t *route = (fib_route_t *)mnode->data;
    
    /* Get active nexthop (thread-safe round-robin for ECMP) */
    fib_nh_t *active_nh = NULL;
    
    /* Count valid nexthops and select one */
    int valid_nh_count = 0;
    for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
        if (route->nh[i]) {
            valid_nh_count++;
        }
    }
    
    if (valid_nh_count == 0) {
        return FIB_ERROR_NO_VALID_NEXTHOP;
    }
    
    /* Select nexthop using round-robin (per-route index) */
    int selected = route->nh_index % valid_nh_count;
    route->nh_index++;
    
    int count = 0;
    for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
        if (route->nh[i]) {
            if (count == selected) {
                active_nh = route->nh[i];
                break;
            }
            count++;
        }
    }
    
    if (!active_nh) {
        return FIB_ERROR_NO_VALID_NEXTHOP;
    }
    
    /* Forward packet to selected nexthop */
    return fib_forward_pkt_to_nh(fib, pkt, active_nh);
}

/**
 * Display FIB contents
 * 
 * @param fib  Pointer to FIB structure
 *
 * Displays all routes in the FIB with their nexthops and label stacks.
 * Format is similar to standard routing table display.
 */
void fib_show(fib_t *fib) {
    
    extern int cprintf(const char *fmt, ...);
    
    if (!fib || !fib->mtrie) {
        cprintf("Error: Invalid FIB\n");
        return;
    }
    
    /* Check if FIB is empty */
    if (IS_GLTHREAD_LIST_EMPTY(&fib->mtrie->list_head)) {
        cprintf("FIB is empty (AFI: %s)\n", fib_afi_to_str(fib->afi));
        return;
    }
    
    /* Print header */
    cprintf("\n");
    cprintf("===============================================================================\n");
    cprintf("FIB Table (AFI: %s)\n", fib_afi_to_str(fib->afi));
    cprintf("===============================================================================\n");
    
    /* Determine lookup type */
    const char *lookup_type = (fib->afi == FIB_AF_LABEL || fib->afi == FIB_AFI_MAC) 
                              ? "Exact Match" : "Longest Prefix Match";
    cprintf("Lookup Method: %s\n", lookup_type);
    cprintf("Total Routes: %d\n", fib->mtrie->N);
    cprintf("===============================================================================\n\n");
    
    /* Iterate through all routes in the FIB */
    glthread_t *curr = NULL;
    mtrie_node_t *mnode;
    fib_route_t *route;
    int route_count = 0;
    char prefix_str[128];
    char gateway_str[128];
    
    ITERATE_GLTHREAD_BEGIN(&fib->mtrie->list_head, curr) {
        
        mnode = list_glue_to_mtrie_node(curr);
        route = (fib_route_t *)mnode->data;
        
        if (!route || !route->prefix) {
            continue;
        }
        
        route_count++;
        
        /* Print route prefix */
        fib_prefix_to_str(route->prefix, prefix_str, sizeof(prefix_str));
        cprintf("Route %d: %s\n", route_count, prefix_str);
        
        /* Count and display nexthops */
        int nh_count = 0;
        for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
            if (route->nh[i]) {
                nh_count++;
            }
        }
        
        if (nh_count == 0) {
            cprintf("  -> No nexthops\n");
        } else {
            if (nh_count > 1) {
                cprintf("  -> ECMP Group (%d nexthops):\n", nh_count);
            }
            
            /* Display each nexthop */
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                fib_nh_t *nh = route->nh[i];
                if (!nh) continue;
                
                const char *prefix_str = (nh_count > 1) ? "     " : "  -> ";
                
                /* Gateway address */
                if (nh->gateway.afi != FIB_AFI_MAX) {
                    fib_prefix_to_str(&nh->gateway, gateway_str, sizeof(gateway_str));
                    cprintf("%sNexthop: %s", prefix_str, gateway_str);
                } else {
                    cprintf("%sNexthop: -", prefix_str);
                }
                
                /* Output interface */
                if (nh->oif) {
                    cprintf("  OIF: %s", nh->oif->if_name.c_str());
                } else {
                    cprintf("  OIF: none");
                }
                
                /* Index */
                cprintf("  (idx: %u)", nh->idx);
                cprintf("  (hit_count: %u)", nh->hit_count);
                cprintf("\n");
                
                /* Label stack if present */
                if (nh->lstack && nh->lstack->curr_index > 0) {
                    cprintf("%s   Label Stack: ", prefix_str);
                    
                    for (int j = 0; j < FIB_MAX_LBL_DEPTH; j++) {
                        if (nh->lstack->labels[j].op == FIB_LBL_STACK_OPS_UNKNOWN) {
                            continue;
                        }
                        
                        cprintf("[%u:%s] ", 
                                nh->lstack->labels[j].label_val,
                                fib_mpls_op_to_str(nh->lstack->labels[j].op));
                    }
                    cprintf("\n");
                }
            }
        }
        
        cprintf("\n");
        
    } ITERATE_GLTHREAD_END(&fib->mtrie->list_head, curr);
    
    cprintf("===============================================================================\n");
    cprintf("Total Routes Displayed: %d\n", route_count);
    cprintf("===============================================================================\n\n");
}
