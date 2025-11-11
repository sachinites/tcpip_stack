#ifndef __FIB_COMN__
#define __FIB_COMN__

#include <stdint.h>
#include "fib_enums.h"

#pragma pack(push, 8)

typedef struct fib_prefix_ {

    union {
        uint32_t v4_addr;
        uint16_t v6_addr[8];
        uint32_t mpls_label;
        uint8_t mac_addr[6];
    } u;

    uint8_t prefix_len;
    FIB_AFI_T afi;

} fib_prefix_t;


typedef struct fib_label_ {

    uint32_t label_val;
    fib_mpls_op_t op;

} fib_label_t; 


typedef struct fib_dest_ {

    FIB_AFI_T afi;

    union {
        uint32_t dummy;
    } u;
} fib_dest_t;

#define FIB_MAX_LBL_DEPTH 8

typedef struct fib_lstack_ {

    uint8_t curr_index;
    fib_label_t labels[FIB_MAX_LBL_DEPTH];

} fib_lstack_t;


#pragma pack(pop)

#endif 