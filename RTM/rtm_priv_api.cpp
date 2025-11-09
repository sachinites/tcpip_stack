#include "rtm_priv_api.h"

/* Helper function to get admin distance based on protocol and sub-protocol */
RTM_AD_T
rtm_get_admin_distance(RTM_PROTO_T proto, RTM_SUB_PROTO_T sub_proto) {
    switch (proto) {
        case RTM_PROTO_CONNECTED:
            return RTM_ADMIN_DIST_CONNECTED;
        case RTM_PROTO_STATIC:
        case RTM_PROTO_LOCAL:
            return RTM_ADMIN_DIST_STATIC;
        case RTM_PROTO_BGP:
            if (sub_proto == RTM_PROTO_BGP_INT) {
                return RTM_ADMIN_DIST_BGP_INT;
            } else {
                return RTM_ADMIN_DIST_BGP_EXT;
            }
        case RTM_PROTO_ISIS:
            return RTM_ADMIN_DIST_ISIS;
        case RTM_PROTO_LDP:
        case RTM_PROTO_SR:
        case RTM_PROTO_SRTE:
            return RTM_ADMIN_DIST_TNL_ENDP;
        default:
            return RTM_ADMIN_DIST_UNKNOWN;
    }
}