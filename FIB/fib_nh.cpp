#include "fib_nh.h"
#include "fib.h"
#include "fib_route.h"
#include "fib_error.h"
#include <string.h>
#include "../Interface/Interface.h"
#include "../common/mpls_lstack.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../Tree/libtree.h"

int
fib_nh_comp_fn(const avltree_node_t *node1, 
                    const avltree_node_t *node2){

    /* Extract fib_nh_t from AVL tree nodes */
    fib_nh_t *nh1 = avltree_container_of(node1, fib_nh_t, idx_glue);
    fib_nh_t *nh2 = avltree_container_of(node2, fib_nh_t, idx_glue);
    
    /* Compare forwarding flags first - determines forwarding type */
    if (nh1->fwd_info.fwd_flags < nh2->fwd_info.fwd_flags) return -1;
    if (nh1->fwd_info.fwd_flags > nh2->fwd_info.fwd_flags) return 1;
    
    /* Compare nexthop addresses */
    int8_t prefix_cmp = cmn_prefix_compare(&nh1->fwd_info.nh_addr, &nh2->fwd_info.nh_addr);
    if (prefix_cmp != 0) return prefix_cmp;
    
    /* Compare outgoing interfaces (pointer comparison) */
    Interface *oif1 = nh1->fwd_info.oif.get();
    Interface *oif2 = nh2->fwd_info.oif.get();
    if (oif1 < oif2) return -1;
    if (oif1 > oif2) return 1;
    
    /* Based on forwarding flags, compare type-specific fields */
    
    /* Compare MPLS label stack if present */
    if (nh1->fwd_info.fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) {
        mpls_lstack_t *ls1 = nh1->fwd_info.u.mpls_fwd.label_stack;
        mpls_lstack_t *ls2 = nh2->fwd_info.u.mpls_fwd.label_stack;
        
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
    if (nh1->fwd_info.fwd_flags & FIB_NH_FWD_F_IPV6_STCK) {
        /* Compare end function */
        if (nh1->fwd_info.u.v6_fwd.endfn < nh2->fwd_info.u.v6_fwd.endfn) return -1;
        if (nh1->fwd_info.u.v6_fwd.endfn > nh2->fwd_info.u.v6_fwd.endfn) return 1;
        
        /* Compare segment list count */
        if (nh1->fwd_info.u.v6_fwd.n_segment_list < nh2->fwd_info.u.v6_fwd.n_segment_list) return -1;
        if (nh1->fwd_info.u.v6_fwd.n_segment_list > nh2->fwd_info.u.v6_fwd.n_segment_list) return 1;
        
        /* Compare each segment in the list */
        uint8_t n = nh1->fwd_info.u.v6_fwd.n_segment_list;
        for (uint8_t i = 0; i < n; i++) {
            if (!nh1->fwd_info.u.v6_fwd.v6segment_lst && nh2->fwd_info.u.v6_fwd.v6segment_lst) return -1;
            if (nh1->fwd_info.u.v6_fwd.v6segment_lst && !nh2->fwd_info.u.v6_fwd.v6segment_lst) return 1;
            
            if (nh1->fwd_info.u.v6_fwd.v6segment_lst && nh2->fwd_info.u.v6_fwd.v6segment_lst) {
                int8_t seg_cmp = cmn_prefix_compare(
                    &nh1->fwd_info.u.v6_fwd.v6segment_lst[i],
                    &nh2->fwd_info.u.v6_fwd.v6segment_lst[i]
                );
                if (seg_cmp != 0) return seg_cmp;
            }
        }
    }
    
    /* All fields are equal */
    return 0;
}

fib_nh_t* 
fib_nh_create(fib_t *fib, fib_nh_t *nh_template) {
    
    if (!nh_template) {
        return NULL;
    }
    
    /* Allocate memory for new FIB nexthop */
    fib_nh_t *new_nh = (fib_nh_t *)XCALLOC2(0, 1, fib_nh_t);
    if (!new_nh) {
        return NULL;
    }
    
    /* Initialize basic fields */
    memset(new_nh, 0, sizeof(fib_nh_t));
    
    /* Copy forwarding flags */
    new_nh->fwd_info.fwd_flags = nh_template->fwd_info.fwd_flags;
    
    /* Copy nexthop address */
    new_nh->fwd_info.nh_addr = nh_template->fwd_info.nh_addr;
    
    /* Copy outgoing interface (shared pointer - simple copy) */
    new_nh->fwd_info.oif = nh_template->fwd_info.oif;
    
    /* Deep copy MPLS label stack if present */
    if (nh_template->fwd_info.fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) {
        if (nh_template->fwd_info.u.mpls_fwd.label_stack) {
            mpls_lstack_t *src_stack = nh_template->fwd_info.u.mpls_fwd.label_stack;
            
            /* Allocate new label stack */
            new_nh->fwd_info.u.mpls_fwd.label_stack = (mpls_lstack_t *)XCALLOC2(0, 1, mpls_lstack_t);
            if (new_nh->fwd_info.u.mpls_fwd.label_stack) {
                /* Copy label stack contents */
                new_nh->fwd_info.u.mpls_fwd.label_stack->curr_index = src_stack->curr_index;
                for (int i = 0; i < src_stack->curr_index; i++) {
                    new_nh->fwd_info.u.mpls_fwd.label_stack->labels[i].label_val = 
                        src_stack->labels[i].label_val;
                    new_nh->fwd_info.u.mpls_fwd.label_stack->labels[i].op = 
                        src_stack->labels[i].op;
                }
            }
        }
    }
    
    /* Deep copy SRv6 segment list if present */
    if (nh_template->fwd_info.fwd_flags & FIB_NH_FWD_F_IPV6_STCK) {
        /* Copy end function */
        new_nh->fwd_info.u.v6_fwd.endfn = nh_template->fwd_info.u.v6_fwd.endfn;
        
        /* Copy segment list count */
        new_nh->fwd_info.u.v6_fwd.n_segment_list = nh_template->fwd_info.u.v6_fwd.n_segment_list;
        
        /* Deep copy segment list if present */
        if (nh_template->fwd_info.u.v6_fwd.v6segment_lst && 
            nh_template->fwd_info.u.v6_fwd.n_segment_list > 0) {
            
            size_t seg_list_size = nh_template->fwd_info.u.v6_fwd.n_segment_list * sizeof(cmn_prefix_t);
            new_nh->fwd_info.u.v6_fwd.v6segment_lst = (cmn_prefix_t *)XCALLOC_BUFF(0, seg_list_size);
            
            if (new_nh->fwd_info.u.v6_fwd.v6segment_lst) {
                /* Copy all segments */
                memcpy(new_nh->fwd_info.u.v6_fwd.v6segment_lst,
                       nh_template->fwd_info.u.v6_fwd.v6segment_lst,
                       seg_list_size);
            }
        }
    }
    
    /* Initialize AVL tree node */
    avltree_node_init(&new_nh->idx_glue);
    
    /* Initialize counters */
    new_nh->hit_count = 0;
    new_nh->ref_count = 1;  /* Start with reference count of 1 */
    
    return new_nh;
}

void 
fib_nh_reference(fib_nh_t *nh) {
    
    if (!nh) {
        return;
    }
    
    nh->ref_count++;
}

void 
fib_nh_dereference(fib_t *fib, fib_nh_t *nh) {
    
    if (!nh) {
        return;
    }
    
    if (nh->ref_count == 0) {
        /* Already at zero - this shouldn't happen */
        return;
    }
    
    nh->ref_count--;
    
    /* If reference count reaches zero, free the nexthop */
    if (nh->ref_count == 0) {
        
        /* Remove from global nexthop tree if it's registered */
        if (fib && avltree_node_is_inuse(&nh->idx_glue)) {
            avltree_remove(&nh->idx_glue, &fib->nhs);
            avltree_node_init(&nh->idx_glue);
        }
        
        /* Free MPLS label stack if present */
        if ((nh->fwd_info.fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) &&
            nh->fwd_info.u.mpls_fwd.label_stack) {
            XFREE(nh->fwd_info.u.mpls_fwd.label_stack);
            nh->fwd_info.u.mpls_fwd.label_stack = NULL;
        }
        
        /* Free SRv6 segment list if present */
        if ((nh->fwd_info.fwd_flags & FIB_NH_FWD_F_IPV6_STCK) &&
            nh->fwd_info.u.v6_fwd.v6segment_lst) {
            XFREE(nh->fwd_info.u.v6_fwd.v6segment_lst);
            nh->fwd_info.u.v6_fwd.v6segment_lst = NULL;
        }
        
        /* Free the nexthop structure itself */
        XFREE(nh);
    }
}

void 
fib_register_nh(fib_t *fib, fib_nh_t *nh) {
    
    if (!fib || !nh) {
        return;
    }
    
    /* Only register if not already in the tree */
    if (!avltree_node_is_inuse(&nh->idx_glue)) {
        avltree_insert(&nh->idx_glue, &fib->nhs);
    }
}
