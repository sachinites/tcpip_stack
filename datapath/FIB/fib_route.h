#ifndef  __FIB_ROUTE__
#define  __FIB_ROUTE__

#include <stdint.h>
#include "../../libs/gluethread/glthread.h"
#include "../../RTM/rtm_fib_common.h"

typedef struct fib_nh_ fib_nh_t;
typedef struct dp_ctx_ dp_ctx_t;

#pragma pack(push, 8)

typedef struct fib_route_ {

    cmn_prefix_t prefix;
    uint64_t nh_idx[FIB_MAX_ECMP_NH];
    fib_nh_t *nhs[FIB_MAX_ECMP_NH];
    uint8_t nh_index;  /* Round-robin index for ECMP load balancing */
    glthread_t glue;

}fib_route_t ;

#pragma pack(pop)

GLTHREAD_TO_STRUCT(fib_route_to_lst_glue, fib_route_t , glue);

fib_error_t 
fib_add_route (dp_ctx_t *dp_ctx,
        fib_t *fib, 
        cmn_prefix_t *prefix, 
        uint32_t inh_idx,
        uint32_t nh_idx, 
        fib_nh_t *nh);

fib_error_t 
fib_del_route (dp_ctx_t *dp_ctx,
               fib_t *fib, 
               cmn_prefix_t *prefix, 
               uint32_t inh_idx,
               uint32_t nh_idx);

#endif // ! __FIB_ROUTE__
