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
#include "../lmm_enums.h"
#include "../common/mpls_lstack.h"
#include "fib.h"
#include "../pkt_block.h"
#include "../mtrie/mtrie.h"
#include "fib_api.h"
#include "fib_route.h"
#include "fib_nh.h"
#include "../RTM/rtm_fib_common.h"
#include "../RTM/rtm_priv_api.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../Interface/InterfaceUApi.h"

extern int
fib_nh_comp_fn(const avltree_node_t *node1, 
                const avltree_node_t *node2);

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

#define HASH_PRIME_CONST 5381

static int
mpls_rt_table_equalkeys(void *k1, void *k2)
{
    mpls_label_val_t *ky1 = (mpls_label_val_t *)k1;
    mpls_label_val_t *ky2 = (mpls_label_val_t *)k2;

    if (mpls_label_get_value(*ky1) != mpls_label_get_value(*ky2)) return 0;

    return 1;
}

static unsigned int
hashfromkey_label (void *key)
{
    mpls_label_val_t *key1 = (mpls_label_val_t *)key;
    return (uint32_t) (mpls_label_get_value(*key1));
}


fib_t *fib_init(node_t *node, AFI_T afi, uint8_t vrf_id) {
    
    /* Allocate FIB structure */
    fib_t *fib = (fib_t *)XCALLOC2(0, 1, fib_t);
    
    /* Set AFI */
    fib->afi = afi;
    fib->vrf_id = vrf_id;
    
    vrf_t *vrf = vrf_get_by_id(node, vrf_id);
    snprintf (fib->name, sizeof(fib->name), "%s.%s",
              vrf ? vrf->vrf_name : "0",
              (afi == AF_IPV4) ? "inet" :
              (afi == AF_IPV6) ? "inet6" :
              (afi == AF_LABEL) ? "mpls" :
              (afi == AF_MAC) ? "mac" : "Unknown",
              vrf_id);

    switch (afi) {

        case AF_IPV4:
            fib->u.lpm = (mtrie_t *)XCALLOC2(0, 1, mtrie_t);
            init_mtrie (fib->u.lpm, 32, 0);
            break;
        case AF_IPV6:
            fib->u.lpm = (mtrie_t *)XCALLOC2(0, 1, mtrie_t);
            init_mtrie (fib->u.lpm, 128, 0);
            break;
        case AF_LABEL:
            fib->u.label_ht = create_hashtable(32, 
                hashfromkey_label, mpls_rt_table_equalkeys);
            break;
        default: ;
    }

    avltree_init (&fib->nhs, fib_nh_comp_fn);
    return fib;
}

fib_t *
fib_get (node_t *node, AFI_T afi, uint8_t vrf_id) {

    fib_t *fib;

    if (vrf_id == DEFAULT_VRF)
    {
        switch (afi)
        {
        case AF_IPV4:
            fib = NODE_DEF_VRF_VRF_MEMBER(node, fib_inet0);
            break;
        case AF_IPV6:
            fib = NODE_DEF_VRF_VRF_MEMBER(node, fib_inet6);
            break;
        case AF_LABEL:
            fib = NODE_DEF_VRF_MEMBER(node, mpls_fib);
            break;
        default:
            return NULL;
        }
        return;
    }

    vrf_t *vrf = vrf_get_by_id (node, vrf_id);

    switch (afi)
    {
    case AF_IPV4:
        fib = vrf->fib_inet0;
        break;
    case AF_IPV6:
        fib = vrf->fib_inet6;
        break;
    default:
        return NULL;
    }
    return fib;
}

fib_t *
fib_get_by_name (node_t *node, char *fib_name) {

    if (!fib_name) {
        return NULL;
    }

    /* Parse rtm_name in format: x.inet.y or x.inet6.y or x.mpls.y or x.mac.y 
       where x is vrf id and y is table id */
    char vrf_name[VRF_NAME_LEN] = {0};
    char afi_str[16] = {0};
    
    /* Parse the name format vrf.afi.table_id */
    if (sscanf(fib_name, "%[^.].%[^.]", vrf_name, afi_str) != 2) {
        return NULL;
    }

    /* Convert afi string to AFI_T */
    AFI_T afi;
    if (strcmp(afi_str, "inet") == 0) {
        afi = AF_IPV4;
    } else if (strcmp(afi_str, "inet6") == 0) {
        afi = AF_IPV6;
    } else if (strcmp(afi_str, "mpls") == 0) {
        afi = AF_LABEL;
    } else if (strcmp(afi_str, "mac") == 0) {
        afi = AF_MAC;
    } else {
        return NULL;
    }
    
    vrf_t *vrf = vrf_get_by_name(node, vrf_name);
    return fib_get(node, afi, vrf ? vrf->vrf_id : 0);
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
fib_error_t 
fib_forward(node_t *node, pkt_block_t *pkt, uint8_t vrf_id) {
    
    /* Extract destination address from packet */
    fib_t *fib;
    fib_route_t *route;
    cmn_prefix_t dest;
    
    if (!fib_extract_dest_from_pkt(pkt, &dest)) {
        return FIB_ERROR_EXTRACT_DEST_FAILED;
    }
    
    /* VRF to be supported later ...*/
    fib = fib_get (node, dest.afi, vrf_id);
   
    if (fib->afi == AF_LABEL) {

        mpls_label_val_t label_val = mpls_label_get_value (dest.u.mpls_label);
        route = (fib_route_t *)hashtable_search(fib->u.label_ht, &label_val);
        if (!route) return FIB_ERROR_ROUTE_NOT_FOUND;
    }
    else {

        bitmap_t bm_dest, bm_mask;
        cmn_prefix_to_bitmap(&dest, &bm_dest, &bm_mask);

        mtrie_node_t *mnode = mtrie_longest_prefix_match_search(
                                fib->u.lpm, &bm_dest);

        bitmap_free_internal(&bm_dest);
        bitmap_free_internal(&bm_mask);

        if (!mnode) return FIB_ERROR_ROUTE_NOT_FOUND;
        route = (fib_route_t *)mnode->data;
        assert (route);
    }
    
    /* Get active nexthop (thread-safe round-robin for ECMP) */
    fib_nh_t *active_nh = NULL;

    active_nh = fib_get_active_nexthop(route);
    
    /* Forward packet to selected nexthop */
    return fib_forward_pkt_to_nh(node, pkt, active_nh);
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

    cmn_prefix_t temp;
    
    if (!fib) {
        cprintf("Error: Invalid FIB\n");
        return;
    }
    
    /* Print header */
    printw("\n");
    cprintf("===============================================================================\n");
    cprintf("FIB Table (AFI: %s)\n", 
            fib->afi == AF_IPV4 ? "IPv4" :
            fib->afi == AF_IPV6 ? "IPv6" :
            fib->afi == AF_LABEL ? "MPLS" : "Unknown");
    cprintf("===============================================================================\n");
    
    int route_count = 0;
    char prefix_str[128];
    char nh_addr_str[128];
    
    /* Handle based on FIB type */
    if (fib->afi == AF_IPV4 || fib->afi == AF_IPV6) {
        
        /* IP routes - use mtrie */
        if (!fib->u.lpm) {
            cprintf("Error: FIB LPM tree not initialized\n");
            return;
        }
        
        /* Check if FIB is empty */
        if (IS_GLTHREAD_LIST_EMPTY(&fib->u.lpm->list_head)) {
            cprintf("FIB is empty\n");
            cprintf("===============================================================================\n\n");
            return;
        }
        
        cprintf("Lookup Method: Longest Prefix Match\n");
        cprintf("Total Routes: %d\n", fib->u.lpm->N);
        cprintf("===============================================================================\n\n");
        
        /* Iterate through all routes in the mtrie */
        glthread_t *curr = NULL;
        mtrie_node_t *mnode;
        fib_route_t *route;
        
        ITERATE_GLTHREAD_BEGIN(&fib->u.lpm->list_head, curr) {
            
            mnode = list_glue_to_mtrie_node(curr);
            route = (fib_route_t *)mnode->data;
            
            route_count++;
            
            /* Print route prefix */
            rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str));
            cprintf("Route %d: %s\n", route_count, prefix_str);
            
            /* Count and display nexthops */
            int nh_count = 0;
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                if (route->nhs[i]) {
                    nh_count++;
                }
            }
            
            if (nh_count == 0) {
                cprintf("  -> No nexthops\n");
            } else {
                if (nh_count > 1) {
                    cprintf("  -> ECMP Group (%d nexthops, RR index: %u):\n", 
                            nh_count, route->nh_index);
                }
                
                /* Display each nexthop */
                for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                    fib_nh_t *nh = route->nhs[i];
                    if (!nh) continue;
                    
                    const char *indent = (nh_count > 1) ? "     " : "  -> ";
                    
                    /* Nexthop address */
                    rtm_format_nexthop(&nh->fwd_info->nh_addr, nh_addr_str, sizeof(nh_addr_str));
                    cprintf("%sNexthop: %s", indent, nh_addr_str);
                    
                    /* Output interface */
                    if (nh->fwd_info->oif) {
                        cprintf("  OIF: %s", nh->fwd_info->oif->if_name.c_str());
                    } else {
                        cprintf("  OIF: none");
                    }
                    
                    /* Nexthop index and stats */
                    cprintf("  (idx: %u)", route->nh_idx[i]);
                    cprintf("  (hit: %u)", nh->hit_count);
                    cprintf("  (ref: %u)", nh->ref_count);
                    printw("\n");
                    
                    /* MPLS label stack if present */
                    if ((nh->fwd_info->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK))
                    {
                        mpls_lstack_t *lstack = &nh->fwd_info->u.mpls_fwd.label_stack;

                        cprintf("%s   MPLS Stack: ", indent);

                        for (int j = 0; j <= lstack->curr_index; j++)
                        {
                            cprintf("[%u:%s] ",
                                    lstack->labels[j].label_val,
                                    lstack->labels[j].op == MPLS_OP_PUSH ? "PUSH" : lstack->labels[j].op == MPLS_OP_POP ? "POP"
                                                                                : lstack->labels[j].op == MPLS_OP_SWAP  ? "SWAP"
                                                                                                                        : "UNK");
                        }
                        printw("\n");
                    }

                    /* SRv6 segment list if present */
                    if ((nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV6_STCK)) {
                        
                        cprintf("%s   SRv6 Segments (%u): ", indent, 
                                nh->fwd_info->u.v6_fwd.n_segment_list);
                        
                        for (int j = 0; j < nh->fwd_info->u.v6_fwd.n_segment_list; j++) {
                            char seg_str[64];
                            cmn_prefix_t v6_addr_temp;
                            cmn_prefix_initialize_v6 (&v6_addr_temp, 
                                &nh->fwd_info->u.v6_fwd.v6segment_lst[j], 128);
                            rtm_format_prefix(&v6_addr_temp, seg_str, sizeof(seg_str));
                            cprintf("[%s] ", seg_str);
                        }
                        printw("\n");
                    }
                }
            }
            
            printw("\n");
            
        } ITERATE_GLTHREAD_END(&fib->u.lpm->list_head, curr);
        
    } else if (fib->afi == AF_LABEL) {
        
        /* MPLS routes - use hash table */
        if (!fib->u.label_ht) {
            cprintf("Error: FIB hash table not initialized\n");
            return;
        }
        
        unsigned int count = hashtable_count(fib->u.label_ht);
        
        if (count == 0) {
            return;
        }
        
        cprintf("Lookup Method: Exact Match (MPLS Label)\n");
        cprintf("Total Routes: %u\n", count);
        cprintf("================================\n\n");
        
        /* Iterate through hash table */
        hashtable_itr *itr = hashtable_iterator(fib->u.label_ht);
        
        if (itr) {
            do {
                uint32_t *label_key = (uint32_t *)hashtable_iterator_key(itr);
                fib_route_t *route = (fib_route_t *)hashtable_iterator_value(itr);
                
                route_count++;
                
                /* Print route prefix (MPLS label) */
                cprintf("Route %d: Label %u\n", route_count, *label_key);
                
                /* Count and display nexthops */
                int nh_count = 0;
                for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                    if (route->nhs[i]) {
                        nh_count++;
                    }
                }
                
                if (nh_count == 0) {
                    cprintf("  -> No nexthops\n");
                } else {
                    if (nh_count > 1) {
                        cprintf("  -> ECMP Group (%d nexthops, RR index: %u):\n", 
                                nh_count, route->nh_index);
                    }
                    
                    /* Display each nexthop */
                    for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                        fib_nh_t *nh = route->nhs[i];
                        if (!nh) continue;
                        
                        const char *indent = (nh_count > 1) ? "     " : "  -> ";
                        
                        /* Nexthop address */
                        rtm_format_nexthop(&nh->fwd_info->nh_addr, nh_addr_str, sizeof(nh_addr_str));
                        cprintf("%sNexthop: %s", indent, nh_addr_str);
                        
                        /* Output interface */
                        if (nh->fwd_info->oif) {
                            cprintf("  OIF: %s", nh->fwd_info->oif->if_name.c_str());
                        } else {
                            cprintf("  OIF: none");
                        }
                        
                        /* Nexthop index and stats */
                        cprintf("  (idx: %u)", route->nh_idx[i]);
                        cprintf("  (hit: %u)", nh->hit_count);
                        cprintf("  (ref: %u)", nh->ref_count);
                        printw("\n");
                        
                        /* MPLS label stack if present */
                        if ((nh->fwd_info->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK)) {
                            
                            mpls_lstack_t *lstack = &nh->fwd_info->u.mpls_fwd.label_stack;
                            if (lstack->curr_index > 0) {
                                cprintf("%s   MPLS Stack: ", indent);
                                
                                for (int j = 0; j < lstack->curr_index; j++) {
                                    cprintf("[%u:%s] ", 
                                            lstack->labels[j].label_val,
                                            lstack->labels[j].op == MPLS_OP_PUSH ? "PUSH" :
                                            lstack->labels[j].op == MPLS_OP_POP ? "POP" :
                                            lstack->labels[j].op == MPLS_OP_SWAP ? "SWAP" : "UNK");
                                }
                                printw("\n");
                            }
                        }
                    }
                }
                
                printw("\n");
                
            } while (hashtable_iterator_advance(itr));
            
            free(itr);
        }
        
    } else {
        cprintf("Error: Unsupported AFI\n");
        return;
    }
    
    cprintf("Total Routes Displayed: %d\n", route_count);
}

void 
fib_destroy (fib_t*fib) {

}