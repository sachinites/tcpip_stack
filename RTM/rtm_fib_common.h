#ifndef __RTM_FIB_COMMON__
#define __RTM_FIB_COMMON__

#include "../common/cmn_prefix.h"
#include "../Interface/InterfaceFwd.h"
#include "../Layer3/SegmentRouting/SRv6/common/srv6_const.h"
#include "rtm_presentation.h"   

typedef struct rtm_nh_fwd_info_ rtm_nh_fwd_info_t;
typedef struct fib_nh_fwd_info_ fib_nh_fwd_info_t;
typedef struct node_ node_t;

#define FIB_NH_FWD_F_IPV4 1
#define FIB_NH_FWD_F_IPV6 2
#define FIB_NH_FWD_F_MPLS_LBL_STCK 4
#define FIB_NH_FWD_F_IPV6_STCK 8

#define FIB_MAX_ECMP_NH 8


typedef enum FIB_OPN_ {

    FIB_ADD = 1,      /* Route/NH is being added */
    FIB_DELETE = 2,   /* Route/NH is being deleted */

} FIB_OPN_T;

FIB_OPN_T
rtm_to_fib_map_opn(rtm_ppt_operation_t rtm_opn);

void
rtm_fib_copy_fwd_info (node_t *node, 
                       rtm_nh_fwd_info_t *src, 
                       fib_nh_fwd_info_t *dst);



#endif 
