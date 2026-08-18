
#include "rtm_fib_common.h"
#include "rtm_nh.h"
#include "../datapath/FIB/fib_nh.h"
#include "../datapath/Vrfs/dp_vrf.h"
#include "../router_init.h"
#include "../Interface/InterfaceUApi.h"
#include "../datapath/Interface/dp_intf_store.h"
#include "../datapath/dp-program/dp-prog-struct.h"

void
rtm_fib_copy_fwd_info (dp_ctx_t *dp_ctx,
                       dp_fib_nh_fwd_info_t *src, 
                       fib_nh_fwd_info_t *dst) {

    dst->nh_addr = src->nh_addr;
    dst->fwd_flags = src->fwd_flags;

    if (src->oif == MPLS_TO_VRF_INTF_STEER_IFINDEX ) {

        /* Steer to VPN VRF */
        uint8_t vrf_id = (uint8_t)src->nh_addr.u.v4_addr;
        dst->oif = dp_ctx->intf_table[src->oif];
        dst->xconnect_id = vrf_id;
        cmn_prefix_initialize_v4(&dst->nh_addr, 0, 0);
    }

    if (src->oif == SRv6_TO_VRF_INTF_STEER_IFINDEX) {

        /* Steer to VPN VRF */
        uint8_t vrf_id = (uint8_t)src->nh_addr.u.v6_addr[0];
        dst->oif = dp_ctx->intf_table[src->oif];
        dst->xconnect_id = vrf_id;
        cmn_prefix_initialize_v6(&dst->nh_addr, 0, 0);
    }    

    else if (src->oif == MPLS_TO_BD_INTF_STEER_IFINDEX) {

        /* Steer to Bridge-Domain */
        uint8_t bd_id = (uint8_t)src->nh_addr.u.v4_addr;
        dst->oif = dp_ctx->intf_table[src->oif];
        dst->xconnect_id = bd_id;
        cmn_prefix_initialize_v4(&dst->nh_addr, 0, 0);
    }    
    
    if (src->oif == SRv6_TO_BD_STEER_IFINDEX) {

        /* Steer to Bridge-Domain */
        uint8_t bd_id = (uint8_t)src->nh_addr.u.v6_addr[0];
        dst->oif = dp_ctx->intf_table[src->oif];
        dst->xconnect_id = bd_id;
        cmn_prefix_initialize_v6(&dst->nh_addr, 0, 0);
    }   

    else if (src->oif) {
        dst->oif = dp_ctx->intf_table[src->oif];
    }

    if (src->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) {

        memcpy (&dst->u.mpls_fwd.label_stack, 
                &src->u.mpls_fwd.label_stack,
                sizeof (dst->u.mpls_fwd.label_stack) );
    }

    if (src->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) {

        dst->u.v6_fwd.endfn = src->u.v6_fwd.endfn;
        dst->u.v6_fwd.n_segment_list = src->u.v6_fwd.n_segment_list;
        
        for (int i = 0; i < dst->u.v6_fwd.n_segment_list; i++) {
            memcpy(dst->u.v6_fwd.v6segment_lst[i],
                   src->u.v6_fwd.v6segment_lst[i],
                   sizeof(dst->u.v6_fwd.v6segment_lst[i]));
        }
    }

    if (src->fwd_flags & FIB_NH_FWD_F_TUNNEL) {
        dst->u.gre_fwd.gre_tunnel_src = src->u.gre_fwd.gre_tunnel_src;
        dst->u.gre_fwd.gre_tunnel_dst = src->u.gre_fwd.gre_tunnel_dst;
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
