#ifndef __FIB_ERROR__
#define __FIB_ERROR__

typedef enum fib_error_ {

    FIB_ERROR_SUCCESS = 0,              /* Operation successful */
    FIB_ERROR_INVALID_PARAM,            /* Invalid parameters passed */
    FIB_ERROR_AFI_MISMATCH,             /* AFI mismatch between FIB and prefix */
    FIB_ERROR_INSERT_FAILED,            /* Mtrie insert operation failed */
    FIB_ERROR_ALLOC_FAILED,             /* Memory allocation failed */
    FIB_ERROR_NO_ROUTE_DATA,            /* Route data missing in mtrie node */
    FIB_ERROR_ECMP_LIMIT,               /* ECMP nexthop limit reached */
    FIB_ERROR_ROUTE_NOT_FOUND,          /* Route not found in FIB */
    FIB_ERROR_NEXTHOP_NOT_FOUND,        /* Nexthop not found in route */
    FIB_ERROR_EXTRACT_DEST_FAILED,      /* Cannot extract destination from packet */
    FIB_ERROR_NO_ROUTE,                 /* No matching route found (lookup) */
    FIB_ERROR_NO_VALID_NEXTHOP,         /* No valid nexthop available */
    FIB_ERROR_TTL_EXPIRED,              /* Packet TTL expired */
    FIB_ERROR_UNKNOWN                   /* Unknown error */

} fib_error_t;

/* Convert error code to string */
static inline const char *fib_error_str(fib_error_t error) {
    switch (error) {
        case FIB_ERROR_SUCCESS:
            return "Success";
        case FIB_ERROR_INVALID_PARAM:
            return "Invalid parameters";
        case FIB_ERROR_AFI_MISMATCH:
            return "AFI mismatch";
        case FIB_ERROR_INSERT_FAILED:
            return "Insert failed";
        case FIB_ERROR_ALLOC_FAILED:
            return "Allocation failed";
        case FIB_ERROR_NO_ROUTE_DATA:
            return "No route data";
        case FIB_ERROR_ECMP_LIMIT:
            return "ECMP limit reached";
        case FIB_ERROR_ROUTE_NOT_FOUND:
            return "Route not found";
        case FIB_ERROR_NEXTHOP_NOT_FOUND:
            return "Nexthop not found";
        case FIB_ERROR_EXTRACT_DEST_FAILED:
            return "Cannot extract destination";
        case FIB_ERROR_NO_ROUTE:
            return "No route found";
        case FIB_ERROR_NO_VALID_NEXTHOP:
            return "No valid nexthop";
        case FIB_ERROR_TTL_EXPIRED:
            return "TTL expired";
        default:
            return "Unknown error";
    }
}

#endif 