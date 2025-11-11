#ifndef __FIB__
#define __FIB__

#include <stdint.h>

#include "fib_error.h"
#include "fib_common.h"

typedef struct mtrie_ mtrie_t;
typedef struct fib_nh_ fib_nh_t;
typedef struct fib_prefix_ fib_prefix_t;
typedef struct pkt_block_ pkt_block_t;

typedef struct fib_ {

    FIB_AFI_T afi;
    mtrie_t *mtrie;

} fib_t;

fib_t *fib_init (FIB_AFI_T afi);
fib_error_t fib_add_route (fib_t *fib, fib_prefix_t *prefix, fib_nh_t *nh);
fib_error_t fib_del_route (fib_t *fib, fib_prefix_t *prefix, fib_nh_t *nh);
fib_error_t fib_forward (fib_t *fib, pkt_block_t *pkt);
void fib_show(fib_t *fib);

#endif 