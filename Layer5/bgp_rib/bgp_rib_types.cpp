#include "bgp_rib_types.h"

const char *
bgp_rib_err_to_string(bgp_rib_err_t err)
{
    switch (err) {
    case BGP_RIB_OK:
        return "ok";
    case BGP_RIB_ERR_NULL:
        return "null argument";
    case BGP_RIB_ERR_NOMEM:
        return "out of memory";
    case BGP_RIB_ERR_NOT_FOUND:
        return "not found";
    case BGP_RIB_ERR_INVALID_KEY:
        return "invalid key";
    case BGP_RIB_ERR_UNSUPPORTED_NLRI:
        return "unsupported NLRI";
    case BGP_RIB_ERR_DECODE:
        return "decode error";
    case BGP_RIB_ERR_ENCODE:
        return "encode error";
    default:
        return "unknown error";
    }
}
