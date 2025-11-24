#ifndef __RTM_ERROR__
#define __RTM_ERROR__


typedef enum rtm_error_ {

    RTM_SUCCESS,
    RTM_ERROR_INVALID_PREFIX,
    RTM_ERROR_INVALID_NH,
    RTM_ERROR_INVALID_ROUTE,
    RTM_ERROR_INVALID_PROTO,
    RTM_ERROR_INVALID_SUB_PROTO,
    RTM_ERROR_INVALID_API,
    RTM_ERROR_INVALID_ARGUMENT,
    RTM_ERROR_CONTAINER_INSERTION_FAILED,
    RTM_ERROR_CONTAINER_LOOKUP_FAILED,
    RTM_ERROR_CONTAINER_REMOVAL_FAILED,
    RTM_ERROR_UPDATE_FAILED,
    RTM_ERROR_LINK_FAILED,
    RTM_ERROR_UNLINK_FAILED,
    RTM_ERROR_NEXTHOP_NOT_FOUND,
    RTM_ERROR_NEXTHOP_ALREADY_EXISTS,
    RTM_ERROR_NEXTHOP_PROTO_ALREADY_EXISTS,
    RTM_ERROR_NEXTHOP_INVALID_ACTION,
    RTM_ERROR_NEXTHOP_CREATION_FAILED,
    RTM_ERROR_PROTO_INFO_ALREADY_EXISTS,
    RTM_ERROR_INVALID_GATEWAY,
    RTM_ERROR_INVALID_OIF_INDEX,
    RTM_ERROR_INVALID_NEXTHOP_PROTO,
    RTM_ERROR_PROTO_NOT_REGISTERED,
    RTM_ERROR_MEMORY_ALLOC_FAILED,
    RTM_ERROR_SUBSCRIPTION_NOT_FOUND,
    RTM_ERROR_MAX

} rtm_error_t;

static const char *
rtm_error_to_string (rtm_error_t err) {

    switch (err) {
        case RTM_SUCCESS:
            return "Success";
        case RTM_ERROR_INVALID_PREFIX:
            return "Invalid prefix";
        case RTM_ERROR_INVALID_NH:
            return "Invalid nexthop";
        case RTM_ERROR_INVALID_ROUTE:
            return "Invalid route";
        case RTM_ERROR_INVALID_PROTO:
            return "Invalid protocol";
        case RTM_ERROR_INVALID_SUB_PROTO:
            return "Invalid sub-protocol";
        case RTM_ERROR_INVALID_API:
            return "Invalid API";
        case RTM_ERROR_INVALID_ARGUMENT:
            return "Invalid argument";
        case RTM_ERROR_CONTAINER_INSERTION_FAILED:
            return "Container insertion failed";
        case RTM_ERROR_CONTAINER_LOOKUP_FAILED:
            return "Container lookup failed";
        case RTM_ERROR_CONTAINER_REMOVAL_FAILED:
            return "Container removal failed";
        case RTM_ERROR_UPDATE_FAILED:
            return "Update failed";
        case RTM_ERROR_LINK_FAILED:
            return "Link failed";
        case RTM_ERROR_UNLINK_FAILED:
            return "Unlink failed";
        case RTM_ERROR_NEXTHOP_NOT_FOUND:
            return "Nexthop not found";
        case RTM_ERROR_NEXTHOP_ALREADY_EXISTS:
            return "Nexthop already exists";
        case RTM_ERROR_NEXTHOP_PROTO_ALREADY_EXISTS:
            return "Nexthop protocol already exists";
        case RTM_ERROR_NEXTHOP_INVALID_ACTION:
            return "Nexthop invalid action";
        case RTM_ERROR_PROTO_INFO_ALREADY_EXISTS:
            return "Protocol info already exists";
        case RTM_ERROR_INVALID_GATEWAY:
            return "Invalid gateway";
        case RTM_ERROR_INVALID_OIF_INDEX:
            return "Invalid OIF index";
        case RTM_ERROR_INVALID_NEXTHOP_PROTO:
            return "Invalid nexthop protocol";
        case RTM_ERROR_NEXTHOP_CREATION_FAILED:
            return "Nexthop creation failed";
        case RTM_ERROR_PROTO_NOT_REGISTERED:
            return "Protocol not registered";
        case RTM_ERROR_MEMORY_ALLOC_FAILED:
            return "Memory allocation failed";
        case RTM_ERROR_SUBSCRIPTION_NOT_FOUND:
            return "Subscription not found";
        case RTM_ERROR_MAX:
            return "Max error";
    }

    return "Unknown error";
}

#endif 