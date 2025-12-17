#ifndef __FIB_NH__
#define __FIB_NH__

#include <stdint.h>
#include "../Tree/libtree.h"
#include "../RTM/rtm_fib_common.h"

typedef struct fib_ fib_t;
typedef struct fib_nh_ fib_nh_t;


#pragma pack(push, 8)

typedef struct fib_nh_ {

    fib_nh_fwd_info_t fwd_info;
    avltree_node_t idx_glue;
    uint32_t hit_count;
    uint32_t ref_count;

} fib_nh_t;

#pragma pack(pop)

void fib_nh_reference (fib_nh_t *nh);
void fib_nh_dereference (fib_t *fib, fib_nh_t *nh);
fib_nh_t* fib_nh_create (fib_t *fib, fib_nh_t *nh_template);
void fib_register_nh(fib_t *fib, fib_nh_t *nh);

#endif 