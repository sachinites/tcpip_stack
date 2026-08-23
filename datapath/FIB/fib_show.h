#ifndef __FIB_SHOW__
#define __FIB_SHOW__

#include <stdint.h>

typedef struct fib_ fib_t;
typedef struct dp_ctx_ dp_ctx_t;

/* Display FIB contents - detailed view with all routes and nexthops */
void fib_show_routes(dp_ctx_t *dp_ctx, fib_t *fib);

/* Display FIB contents - compact/brief view optimized for maximum routes per screen */
void fib_show_routes_brief(dp_ctx_t *dp_ctx, fib_t *fib);

#endif /* __FIB_SHOW__ */

