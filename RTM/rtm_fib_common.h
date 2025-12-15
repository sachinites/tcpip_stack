#ifndef __RTM_FIB_COMMON__
#define __RTM_FIB_COMMON__

#include "rtm_common.h"
#include "../Interface/InterfaceFwd.h"
#include "../Layer3/SegmentRouting/SRv6/common/srv6_const.h"

typedef struct mpls_lstack_ mpls_lstack_t;

#pragma pack(push, 8)

typedef struct fib_nh_fwd_info_ {

    InterfaceP oif;
    rtm_prefix_t nh_addr;
    uint16_t fwd_flags;

    union {
        
        /*MPLS  Label Stack*/
        struct {
            mpls_lstack_t *label_stack;
        } mpls_fwd;

        /*SRv6 Stack*/
        struct {    
            Srv6_endpcode_t endfn;
            uint8_t n_segment_list;
            rtm_prefix_t *v6segment_lst;
        } v6_fwd;

    }u;

} fib_nh_fwd_info_t;

#pragma pack(pop)


#define FIB_NH_FWD_F_IPV4 1
#define FIB_NH_FWD_F_IPV6 2
#define FIB_NH_FWD_F_MPLS_LBL_STCK 4
#define FIB_NH_FWD_F_IPV6_STCK 8

#define FIB_MAX_ECMP_NH 8


#endif 