
#include "rtm_fib_common.h"
#include "rtm_nh.h"
#include "../FIB/fib_nh.h"
#include "../graph.h"
#include "../Interface/InterfaceUApi.h"

void
rtm_fib_copy_fwd_info (node_t *node, 
                       rtm_nh_fwd_info_t *src, 
                       fib_nh_fwd_info_t *dst) {

    dst->oif = node_get_intf_by_ifindex(node, src->oif)->GetSharedPtr();
    dst->nh_addr = src->nh_addr;
    dst->fwd_flags = src->fwd_flags;

    if (src->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) {

        memcpy (&dst->u.mpls_fwd.label_stack, 
                &src->u.mpls_fwd.label_stack,
                sizeof (dst->u.mpls_fwd.label_stack) );
    }

    if (src->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) {

        dst->u.v6_fwd.n_segment_list = src->u.v6_fwd.n_segment_list;
        
        for (int i = 0; i < dst->u.v6_fwd.n_segment_list; i++) {
            *dst->u.v6_fwd.v6segment_lst[i] = *src->u.v6_fwd.v6segment_lst[i];
        }
    }
    
}

FIB_OPN_T
rtm_to_fib_map_opn(rtm_ppt_operation_t rtm_opn) {

    switch (rtm_opn) {
        case RTM_PPT_OP_ADD:
            return FIB_ADD;
        case RTM_PPT_OP_DELETE:
            return FIB_DELETE;
        default:
            return FIB_DELETE; // Default to delete for unknown ops
    }
}