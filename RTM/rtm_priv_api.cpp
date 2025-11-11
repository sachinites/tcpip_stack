#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "rtm_priv_api.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_enums.h"
#include "rtm_common.h"

/* Helper function to get admin distance based on protocol and sub-protocol */
RTM_AD_T
rtm_get_admin_distance(RTM_PROTO_T proto, RTM_SUB_PROTO_T sub_proto) 
{
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

/* Insert the nh at appripriate position in route path list using fn rtm_nh_compare () 
    Set is_active to true/false depending if this is the best path in route list
    invoke fn : rtm_nh_set_active ( ) / rtm_nh_set_inactive ( ) if the state of the nexthop
    switches from inactive to active or active to inactive. Use rtm_nh_compare( ) to compare two
    nexthops
*/
void
 rtm_route_add_nh_to_route_path_list (rtm_t *rtm, rtm_route *route, rtm_nh *nh) {

    if (!rtm || !route || !nh) return;
    
    // Find the correct position to insert based on rtm_nh_compare
    glthread_t *curr;
    rtm_nh *curr_nh;
    glthread_t *insert_before = NULL;
    
    ITERATE_GLTHREAD_BEGIN(&route->path_list, curr) {
        
        curr_nh = route_glue_to_rtm_nh(curr);
        
        // If new nh is better (returns -1), insert before curr
        if (rtm_nh_compare(nh, curr_nh) < 0) {
            insert_before = curr;
            break;
        }
        
    } ITERATE_GLTHREAD_END(&route->path_list, curr);
    
    // Insert the nexthop at the appropriate position
    if (insert_before) {
        // Insert before the found position
        glthread_add_before(insert_before, &nh->route_glue);
    } else {
        // Insert at the end (or empty list)
        glthread_add_last(&route->path_list, &nh->route_glue);
    }
    
    // Increment reference count for the nexthop
    rtm_nh_reference(nh);
    
    // Update active/inactive states for all nexthops in the list
    // All nexthops equal to the best (first) should be active, rest should be inactive
    glthread_t *best_glue = BASE(&route->path_list);
    if (!best_glue) return; // Empty list, nothing to do
    
    rtm_nh *best_nh = route_glue_to_rtm_nh(best_glue);
    
    ITERATE_GLTHREAD_BEGIN(&route->path_list, curr) {
        
        curr_nh = route_glue_to_rtm_nh(curr);
        
        // Check if current nexthop is equal to the best one (ECMP)
        int cmp_result = rtm_nh_compare(curr_nh, best_nh);
        
        if (cmp_result == 0) {
            // This nexthop is equal to best, should be active
            if (!curr_nh->is_active) {
                rtm_nh_set_active(rtm, curr_nh);
            }
        } else {
            // This nexthop is worse than best, should be inactive
            if (curr_nh->is_active) {
                rtm_nh_set_inactive(rtm, curr_nh);
            }
        }
        
    } ITERATE_GLTHREAD_END(&route->path_list, curr);
 }


void rtm_format_prefix(rtm_prefix_t *prefix, char *buffer, size_t buflen) {
    
    uint32_t temp;
    char addr_buf[INET6_ADDRSTRLEN];
    
    switch(prefix->afi) {
        case RTM_AF_IPV4:
            temp = htonl(prefix->u.v4_addr);
            inet_ntop(AF_INET, &temp, addr_buf, sizeof(addr_buf));
            snprintf(buffer, buflen, "%s/%u", addr_buf, prefix->prefix_len);
            break;
        case RTM_AF_IPV6:
            inet_ntop(AF_INET6, prefix->u.v6_addr, addr_buf, sizeof(addr_buf));
            snprintf(buffer, buflen, "%s/%u", addr_buf, prefix->prefix_len);
            break;
        case RTM_AF_LABEL:
            snprintf(buffer, buflen, "Label:%u", prefix->u.mpls_label);
            break;
        case RTM_AFI_MAC:
            snprintf(buffer, buflen, "%02x:%02x:%02x:%02x:%02x:%02x",
                    prefix->u.mac_addr[0], prefix->u.mac_addr[1], 
                    prefix->u.mac_addr[2], prefix->u.mac_addr[3],
                    prefix->u.mac_addr[4], prefix->u.mac_addr[5]);
            break;
        default:
            snprintf(buffer, buflen, "Unknown");
    }
}

/* Helper function to format nexthop (without prefix length) */
void rtm_format_nexthop(rtm_prefix_t *prefix, char *buffer, size_t buflen) {
    
    uint32_t temp;
    char addr_buf[INET6_ADDRSTRLEN];
    
    switch(prefix->afi) {
        case RTM_AF_IPV4:
            temp = htonl(prefix->u.v4_addr);
            inet_ntop(AF_INET, &temp, addr_buf, sizeof(addr_buf));
            snprintf(buffer, buflen, "%s", addr_buf);
            break;
        case RTM_AF_IPV6:
            inet_ntop(AF_INET6, prefix->u.v6_addr, addr_buf, sizeof(addr_buf));
            snprintf(buffer, buflen, "%s", addr_buf);
            break;
        case RTM_AF_LABEL:
            snprintf(buffer, buflen, "Label:%u", prefix->u.mpls_label);
            break;
        case RTM_AFI_MAC:
            snprintf(buffer, buflen, "%02x:%02x:%02x:%02x:%02x:%02x",
                    prefix->u.mac_addr[0], prefix->u.mac_addr[1], 
                    prefix->u.mac_addr[2], prefix->u.mac_addr[3],
                    prefix->u.mac_addr[4], prefix->u.mac_addr[5]);
            break;
        default:
            snprintf(buffer, buflen, "Unknown");
    }
}
