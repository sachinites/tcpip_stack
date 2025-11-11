#ifndef  __FIB_ROUTE__
#define  __FIB_ROUTE__

#include <stdint.h>

#pragma pack(push, 8)

#include "fib_enums.h"

typedef struct fib_nh_ fib_nh_t;
typedef struct fib_prefix_ fib_prefix_t;

typedef struct fib_route_ {

    fib_prefix_t *prefix;
    fib_nh_t *nh[FIB_MAX_ECMP_NH];
    uint8_t nh_index;  /* Round-robin index for ECMP load balancing */

}fib_route_t ;

#pragma pack(pop)

#endif // ! __FIB_ROUTE__
