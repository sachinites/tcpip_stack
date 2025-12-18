#include "fib_nh.h"
#include "fib.h"
#include "fib_route.h"
#include "fib_error.h"
#include <string.h>
#include "../Interface/Interface.h"
#include "../common/mpls_lstack.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../Tree/libtree.h"

static int8_t 
fib_nh_fwd_info_compare (
        fib_nh_fwd_info_t *p1, 
        fib_nh_fwd_info_t *p2) {

    return 0;
}

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
    Interface *oif1 = nh1->fwd_info->oif.get();
    Interface *oif2 = nh2->fwd_info->oif.get();
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
                cmn_prefix_initialize_v6(&p1, nh1->fwd_info->u.v6_fwd.v6segment_lst[i], 128);
                cmn_prefix_initialize_v6(&p2, nh2->fwd_info->u.v6_fwd.v6segment_lst[i], 128);
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
    nh_template->fwd_info = new fib_nh_fwd_info_t;

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
        assert (avltree_node_is_inuse(&nh->idx_glue));
        avltree_remove(&nh->idx_glue, &fib->nhs);
        delete nh->fwd_info;
        XFREE(nh);
    }
}

void 
fib_register_nh(fib_t *fib, fib_nh_t *nh) {
    
    assert (!avltree_node_is_inuse(&nh->idx_glue));
    avltree_insert(&nh->idx_glue, &fib->nhs);
    // Dont increment ref count
}


fib_nh_t* fib_nh_lookup (fib_t *fib, fib_nh_t *nh_template) {

    avltree_node_t *node = avltree_lookup (&nh_template->idx_glue, &fib->nhs);
    if (!node) return NULL;
    return avltree_container_of (node, fib_nh_t, idx_glue);
}