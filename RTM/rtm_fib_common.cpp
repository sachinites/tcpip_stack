
#include "rtm_fib_common.h"
#include "rtm_nh.h"
#include "../FIB/fib_nh.h"
#include "../router_init.h"
#include "../Interface/InterfaceUApi.h"
#include "../datapath/Interface/dp_intf_store.h"

void
rtm_fib_copy_fwd_info (node_t *node, 
                       rtm_nh_fwd_info_t *src, 
                       fib_nh_fwd_info_t *dst) {

    /* SRv6 Local SIDs with END function may not have any interface*/
    if (src->oif) {
        dst->oif = dp_look_up_interface(node->dp_intf_ht, src->oif);
    }

    dst->nh_addr = src->nh_addr;
    dst->fwd_flags = src->fwd_flags;

    if (src->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) {

        memcpy (&dst->u.mpls_fwd.label_stack, 
                &src->u.mpls_fwd.label_stack,
                sizeof (dst->u.mpls_fwd.label_stack) );
    }

    if (src->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) {

        dst->u.v6_fwd.endfn = src->u.v6_fwd.endfn;
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

uint16_t 
rtm_set_fib_forwarding_action_flag (RTM_NH_ACTION_TYPE_T action) {

    switch(action) {

        case RTM_NH_ACTION_LOCAL:
            return FIB_NH_FWD_F_LOCAL;
        case RTM_NH_ACTION_CONNECTED:
            return FIB_NH_FWD_F_CONNECTED;
        case RTM_NH_ACTION_FORWARD:
            return FIB_NH_FWD_F_FORWARD;
        case RTM_NH_ACTION_TUNNEL:
            return FIB_NH_FWD_F_TUNNEL;
        case RTM_NH_ACTION_DISCARD:
            return FIB_NH_FWD_F_DISCARD;
        case RTM_NH_ACTION_REJECT:
            return FIB_NH_FWD_F_REJECT;
        default : 
            return 0;
    }
    return 0;
}