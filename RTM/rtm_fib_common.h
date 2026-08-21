#ifndef __RTM_FIB_COMMON__
#define __RTM_FIB_COMMON__

#include "../libs/common/cmn_prefix.h"
#include "../Interface/InterfaceFwd.h"
#include "../Layer3/SegmentRouting/SRv6/common/srv6_const.h"
#include "rtm_presentation.h"   

typedef struct rtm_nh_fwd_info_ rtm_nh_fwd_info_t;
typedef struct fib_nh_fwd_info_ fib_nh_fwd_info_t;
typedef struct dp_ctx_ dp_ctx_t; 
typedef struct dp_fib_nh_fwd_info_ dp_fib_nh_fwd_info_t;

#define FIB_NH_FWD_F_IPV4 1
#define FIB_NH_FWD_F_IPV6 2
#define FIB_NH_FWD_F_MPLS_LBL_STCK 4
#define FIB_NH_FWD_F_IPV6_STCK 8
#define FIB_NH_FWD_F_LOCAL 16
#define FIB_NH_FWD_F_CONNECTED 32
#define FIB_NH_FWD_F_FORWARD 64
#define FIB_NH_FWD_F_TUNNEL 128
#define FIB_NH_FWD_F_DISCARD 256
#define FIB_NH_FWD_F_REJECT 512
#define FIB_NH_FWD_F_SRv6_FORWARD 1024

#define FIB_MAX_ECMP_NH 8

/* GRE encap uses FIB_NH_FWD_F_TUNNEL; SRv6 reuses RTM_NH_ACTION_TUNNEL but must
 * not be treated as GRE (union holds v6_fwd, not gre_fwd). */
static inline bool
fib_nh_fwd_is_gre_encap(uint16_t fwd_flags)
{
    return (fwd_flags & FIB_NH_FWD_F_TUNNEL) &&
           !(fwd_flags & FIB_NH_FWD_F_SRv6_FORWARD);
}


typedef enum FIB_OPN_ {

    FIB_ADD = 1,      /* Route/NH is being added */
    FIB_DELETE = 2,   /* Route/NH is being deleted */

} FIB_OPN_T;

FIB_OPN_T
rtm_to_fib_map_opn(rtm_ppt_operation_t rtm_opn);

void
rtm_fib_copy_fwd_info (dp_ctx_t *dp_ctx, 
                       dp_fib_nh_fwd_info_t *src, 
                       fib_nh_fwd_info_t *dst);

uint16_t 
rtm_set_fib_forwarding_action_flag (RTM_NH_ACTION_TYPE_T action);

#endif 
