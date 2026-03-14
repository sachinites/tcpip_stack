#ifndef __FIB_SHOW__
#define __FIB_SHOW__

#include <stdint.h>

typedef struct fib_ fib_t;

/* Display FIB contents - detailed view with all routes and nexthops */
void fib_show_routes(fib_t *fib);

/* Display FIB contents - compact/brief view optimized for maximum routes per screen */
void fib_show_routes_brief(fib_t *fib);

#endif /* __FIB_SHOW__ */

