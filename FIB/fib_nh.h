#ifndef __FIB_NH__
#define __FIB_NH__

#include <stdint.h>
#include "fib_common.h"
#include "../Interface/InterfaceFwd.h"

#pragma pack(push, 8)

typedef struct fib_nh_ {

    uint32_t idx;
    fib_prefix_t gateway;
    InterfaceP oif;
    fib_lstack_t *lstack;
    uint32_t hit_count;

} fib_nh_t;

#pragma pack(pop)
#endif 