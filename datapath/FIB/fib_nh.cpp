#include "fib_nh.h"
#include "fib.h"
#include "fib_route.h"
#include "fib_error.h"
#include "fib_api.h"
#include <string.h>
#include "../../lmm_enums.h"
#include "../../libs/common/mpls_lstack.h"
#include "../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../../libs/Tree/libtree.h"
#include "../../libs/mtrie/mtrie.h"
#include "../../libs/mtrie/atomic_mtrie.h"
#include "../../libs/c-hashtable/hashtable.h"

int
fib_nh_comp_fn(const avltree_node_t *node1, 
                    const avltree_node_t *node2){

    /* Extract fib_nh_t from AVL tree nodes */
    fib_nh_t *nh1 = avltree_container_of(node1, fib_nh_t, idx_glue);
    fib_nh_t *nh2 = avltree_container_of(node2, fib_nh_t, idx_glue);
    
    /* Compare forwarding flags first - determines forwarding type */
    if (nh1->fwd_info->fwd_flags < nh2->fwd_info->fwd_flags) return -1;
    if (nh1->fwd_info->fwd_flags > nh2->fwd_info->fwd_flags) return 1;
    
    /* Compare nexthop addresses */
    int8_t prefix_cmp = cmn_prefix_compare(&nh1->fwd_info->nh_addr, &nh2->fwd_info->nh_addr);
    if (prefix_cmp != 0) return prefix_cmp;
    
    /* Compare outgoing interfaces (pointer comparison) */
    dp_intf_t *oif1 = nh1->fwd_info->oif;
    dp_intf_t *oif2 = nh2->fwd_info->oif;
    if (oif1 < oif2) return -1;
    if (oif1 > oif2) return 1;
    
    /* Based on forwarding flags, compare type-specific fields */
    
    /* Compare MPLS label stack if present */
    if (nh1->fwd_info->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) {
        mpls_lstack_t *ls1 = &nh1->fwd_info->u.mpls_fwd.label_stack;
        mpls_lstack_t *ls2 = &nh2->fwd_info->u.mpls_fwd.label_stack;
        
        /* Handle NULL label stacks */
        if (!ls1 && ls2) return -1;
        if (ls1 && !ls2) return 1;
        
        /* Both non-NULL: compare using memcmp */
        if (ls1 && ls2) {
            int cmp = memcmp(ls1, ls2, sizeof(mpls_lstack_t));
            if (cmp != 0) return (cmp < 0) ? -1 : 1;
        }
    }
    
    /* Compare SRv6 segment list if present */
    if (nh1->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) {
        /* Compare end function */
        if (nh1->fwd_info->u.v6_fwd.endfn < nh2->fwd_info->u.v6_fwd.endfn) return -1;
        if (nh1->fwd_info->u.v6_fwd.endfn > nh2->fwd_info->u.v6_fwd.endfn) return 1;
        
        /* Compare segment list count */
        if (nh1->fwd_info->u.v6_fwd.n_segment_list < nh2->fwd_info->u.v6_fwd.n_segment_list) return -1;
        if (nh1->fwd_info->u.v6_fwd.n_segment_list > nh2->fwd_info->u.v6_fwd.n_segment_list) return 1;
        
        /* Compare each segment in the list */
        uint8_t n = nh1->fwd_info->u.v6_fwd.n_segment_list;
        for (uint8_t i = 0; i < n; i++) {
            if (!nh1->fwd_info->u.v6_fwd.v6segment_lst && nh2->fwd_info->u.v6_fwd.v6segment_lst) return -1;
            if (nh1->fwd_info->u.v6_fwd.v6segment_lst && !nh2->fwd_info->u.v6_fwd.v6segment_lst) return 1;
            
            if (nh1->fwd_info->u.v6_fwd.v6segment_lst && nh2->fwd_info->u.v6_fwd.v6segment_lst) {
                cmn_prefix_t p1, p2;
                cmn_prefix_initialize_v6(&p1, &nh1->fwd_info->u.v6_fwd.v6segment_lst[i], 128);
                cmn_prefix_initialize_v6(&p2, &nh2->fwd_info->u.v6_fwd.v6segment_lst[i], 128);
                int8_t seg_cmp = cmn_prefix_compare(&p1, &p2);
                if (seg_cmp != 0) return seg_cmp;
            }
        }
    }
    
    /* All fields are equal */
    return 0;
}

fib_nh_t* 
fib_nh_create(fib_t *fib, fib_nh_t *nh_template) {
    
    /* Allocate memory for new FIB nexthop */
    fib_nh_t *new_nh = (fib_nh_t *)XCALLOC2(0, 1, fib_nh_t);
    new_nh->fwd_info = (fib_nh_fwd_info_t *)calloc(1, sizeof(fib_nh_fwd_info_t));

    /* Copy forwarding flags */
    new_nh->fwd_info->fwd_flags = nh_template->fwd_info->fwd_flags;
    
    /* Copy nexthop address */
    new_nh->fwd_info->nh_addr = nh_template->fwd_info->nh_addr;
    
    /* Copy outgoing interface (shared pointer - simple copy) */
    new_nh->fwd_info->oif = nh_template->fwd_info->oif;
    
    /* Deep copy MPLS label stack if present */
    if (nh_template->fwd_info->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) {

        memcpy (&new_nh->fwd_info->u.mpls_fwd.label_stack, 
            &nh_template->fwd_info->u.mpls_fwd.label_stack,
            sizeof (nh_template->fwd_info->u.mpls_fwd.label_stack));
    }
    
    /* Deep copy SRv6 segment list if present */
    if (nh_template->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) {

        memcpy (&new_nh->fwd_info->u.v6_fwd, 
                &nh_template->fwd_info->u.v6_fwd,
                sizeof (nh_template->fwd_info->u.v6_fwd));
    }

    /* Deep copy GRE tunnel information if present */
    if (nh_template->fwd_info->fwd_flags & FIB_NH_FWD_F_TUNNEL) {
        memcpy(&new_nh->fwd_info->u.gre_fwd,
               &nh_template->fwd_info->u.gre_fwd,
               sizeof(nh_template->fwd_info->u.gre_fwd));
    }

    /* Initialize AVL tree node */
    avltree_node_init(&new_nh->idx_glue);
    
    /* Initialize counters */
    new_nh->hit_count = 0;
    new_nh->ref_count = 0;
    return new_nh;
}

void 
fib_nh_reference(fib_nh_t *nh) {

    nh->ref_count++;
}

void 
fib_nh_dereference(fib_t *fib, fib_nh_t *nh) {
    
    assert (nh->ref_count);

    nh->ref_count--;
    
    /* If reference count reaches zero, free the nexthop */
    if (nh->ref_count == 0) {
        assert (avltree_node_is_inuse(&fib->nhs, &nh->idx_glue));
        avltree_remove(&nh->idx_glue, &fib->nhs);
        free( nh->fwd_info);
        XFREE(nh);
    }
}

void 
fib_register_nh(fib_t *fib, fib_nh_t *nh) {
    
    assert (!avltree_node_is_inuse(&fib->nhs, &nh->idx_glue));
    avltree_insert(&nh->idx_glue, &fib->nhs);
    // Dont increment ref count
}


fib_nh_t* fib_nh_lookup (fib_t *fib, fib_nh_t *nh_template) {

    avltree_node_t *node = avltree_lookup (&nh_template->idx_glue, &fib->nhs);
    if (!node) return NULL;
    return avltree_container_of (node, fib_nh_t, idx_glue);
}

fib_nh_t *fib_get_forwarding_nh(fib_t *fib, cmn_prefix_t *prefix) {
    
    fib_route_t *route = NULL;
    
    /* Perform lookup based on AFI type */
    if (fib->afi == AF_LABEL) {
        /* MPLS label lookup - exact match using hashtable */
        mpls_label_val_t label_val = mpls_label_get_value(prefix->u.mpls_label);
        route = (fib_route_t *)hashtable_search(fib->u.label_ht, &label_val);
        if (!route) return NULL;
    }
    else if (fib->afi == AF_IPV4 || fib->afi == AF_IPV6) {
        /* IP lookup - longest prefix match using mtrie */
        bitmap_t bm_dest, bm_mask;
        cmn_prefix_to_bitmap(prefix, &bm_dest, &bm_mask);
        
        atomic_mtrie_node_t *mnode = atomic_mtrie_longest_prefix_match_search(
                                fib->u.rts.lpm, &bm_dest);
        
        bitmap_free_internal(&bm_dest);
        bitmap_free_internal(&bm_mask);
        
        if (!mnode) return NULL;
        route = (fib_route_t *)mnode->data;
        if (!route) return NULL;
    }
    else {
        /* Unsupported AFI */
        return NULL;
    }
    
    /* ECMP load balancing: round-robin selection with index update */
    fib_nh_t *selected_nh = NULL;
    
    /* Find the next valid nexthop starting from current index + 1 */
    int start_idx = (route->nh_index + 1) % FIB_MAX_ECMP_NH;
    int idx = start_idx;
    
    /* Search from start_idx to end of array */
    for (int i = start_idx; i < FIB_MAX_ECMP_NH; i++) {
        if (route->nhs[i]) {
            selected_nh = route->nhs[i];
            route->nh_index = i;  /* Update for next call */
            selected_nh->hit_count++;  /* Increment hit counter */
            return selected_nh;
        }
    }
    
    /* Wrap around: search from beginning to start_idx */
    for (int i = 0; i < start_idx; i++) {
        if (route->nhs[i]) {
            selected_nh = route->nhs[i];
            route->nh_index = i;  /* Update for next call */
            selected_nh->hit_count++;  /* Increment hit counter */
            return selected_nh;
        }
    }
    
    /* No valid nexthop found */
    return NULL;
}