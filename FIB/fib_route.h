#ifndef  __FIB_ROUTE__
#define  __FIB_ROUTE__

#include <stdint.h>
#include "../RTM/rtm_fib_common.h"

typedef struct fib_nh_ fib_nh_t;

#pragma pack(push, 8)

typedef struct fib_route_ {

    cmn_prefix_t prefix;
    uint32_t nh_idx[FIB_MAX_ECMP_NH];
    fib_nh_t *nhs[FIB_MAX_ECMP_NH];
    uint8_t nh_index;  /* Round-robin index for ECMP load balancing */

}fib_route_t ;


#pragma pack(pop)

fib_error_t 
fib_add_route (
        fib_t *fib, 
        cmn_prefix_t *prefix, 
        uint32_t nh_idx, 
        fib_nh_t *nh);

fib_error_t 
fib_del_route (fib_t *fib, 
               cmn_prefix_t *prefix, 
               uint32_t nh_idx);

#endif // ! __FIB_ROUTE__
