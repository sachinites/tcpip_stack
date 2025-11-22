#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "../graph.h"
#include "../Interface/InterfaceUApi.h"
#include "rtm_priv_api.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_enums.h"
#include "rtm_common.h"
#include "../RTM/rtm_nb_integ.h"
#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"
#include "../utils.h"

extern graph_t * topo;

/* Helper function to get admin distance based on protocol and sub-protocol */
RTM_AD_T
rtm_get_admin_distance(RTM_PROTO_T proto, RTM_SUB_PROTO_T sub_proto) 
{
    switch (proto) {
        case RTM_PROTO_CONNECTED:
            return RTM_ADMIN_DIST_CONNECTED;
        case RTM_PROTO_STATIC:
            return RTM_ADMIN_DIST_STATIC;
        case RTM_PROTO_OSPF:
            if (sub_proto == RTM_SUB_PROTO_OSPF_INTER) {
                return RTM_ADMIN_DIST_OSPF_INTER;
            } else if (sub_proto == RTM_SUB_PROTO_OSPF_INTRA) {
                return RTM_ADMIN_DIST_OSPF_INTRA;
            } else if (sub_proto == RTM_SUB_PROTO_OSPF_EXT) {
                return RTM_ADMIN_DIST_OSPF_EXT;
            }
            break;
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
    
    glthread_t *curr;
    rtm_nh *curr_nh;
    glthread_t *insert_before = NULL;
    
    ITERATE_GLTHREAD_BEGIN(&route->path_list, curr) {
        
        curr_nh = route_glue_to_rtm_nh(curr);
        
        if (rtm_nh_compare(nh, curr_nh) < 0) {
            insert_before = curr;
            break;
        }
        
    } ITERATE_GLTHREAD_END(&route->path_list, curr);
    
    if (insert_before) {
        glthread_add_before(insert_before, &nh->route_glue);
    } else {
        glthread_add_last(&route->path_list, &nh->route_glue);
    }
    
    rtm_nh_reference(nh);
    
    rtm_route_refresh_nexthops (rtm, route);
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

int
config_rtm_route_cli_handler(int cmdcode,
                              Stack_t *tlv_stack,
                              op_mode enable_or_disable) {

    node_t *node = NULL;
    c_string node_name = NULL;
    c_string prefix_mask = NULL;
    c_string gw_ip = NULL;
    c_string if_name = NULL;
    uint32_t vrf_id = RTM_DEFAULT_VRF;
    uint32_t table_id = 0;
    uint32_t proto_id = 0;
    uint32_t sub_proto_id = 0;
    uint32_t instance_no = 0;
    uint32_t action_id = 0;
    uint32_t metric = 0;
    uint32_t label_stack[MAX_LBL_DEPTH] = {0};
    uint8_t label_stack_count = 0;
    tlv_struct_t *tlv = NULL;

    /* Parse TLVs from CLI input */
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "vrf-id"))
            vrf_id = atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "table-id"))
            table_id = atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "prefix-mask"))
            prefix_mask = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "proto-id"))
            proto_id = atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "sub-proto-id"))
            sub_proto_id = atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "instance-no"))
            instance_no = atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "action-id"))
            action_id = atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "metric"))
            metric = atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "gw-ip"))
            gw_ip = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "if-name"))
            if_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "label-list")) {
            if (label_stack_count < MAX_LBL_DEPTH) {
                label_stack[label_stack_count] = atoi((const char *)tlv->value);
                label_stack_count++;
            }
        }

    } TLV_LOOP_END;

    /* Validate inputs */
    if (!node_name) {
        cprintf("Error: node-name missing\n");
        return -1;
    }

    if (!prefix_mask) {
        cprintf("Error: prefix/mask is required\n");
        return -1;
    }

    /* Get the node */
    node = node_get_node_by_name(topo, node_name);
    if (!node) {
        cprintf("Error: Node %s not found\n", node_name);
        return -1;
    }

    switch (enable_or_disable) {

        case CONFIG_ENABLE:
        {
            /* Parse prefix/mask */
            char prefix_str[48];
            uint8_t mask;

            /* Parse prefix/mask format (e.g., "192.168.1.0/24") */
            if (sscanf((const char *)prefix_mask, "%[^/]/%hhu", prefix_str, &mask) != 2) {
                cprintf("Error: Invalid prefix/mask format. Use: <ip>/<mask>\n");
                return -1;
            }

            if (mask > 32) {
                cprintf("Error: Invalid mask value. Must be 0-32\n");
                return -1;
            }

            /* Get RTM */
            rtm_t *rtm = rtm_get(node, vrf_id, RTM_AF_IPV4, table_id);
            if (!rtm) {
                cprintf("Error: RTM not found for node %s VRF %u table %u\n",
                        node_name, vrf_id, table_id);
                return -1;
            }

            /* Prepare prefix */
            rtm_prefix_t prefix;
            memset(&prefix, 0, sizeof(prefix));
            prefix.afi = RTM_AF_IPV4;
            prefix.prefix_len = mask;
            prefix.u.v4_addr = tcp_ip_convert_ip_p_to_n((c_string)prefix_str);

            /* Prepare gateway */
            rtm_prefix_t gateway;
            memset(&gateway, 0, sizeof(gateway));
            if (gw_ip) {
                gateway.afi = RTM_AF_IPV4;
                gateway.prefix_len = 32;
                gateway.u.v4_addr = tcp_ip_convert_ip_p_to_n(gw_ip);
            }

            /* Get interface */
            InterfaceP oif = nullptr;
            if (if_name) {
                Interface *intf = node_get_intf_by_name(node, (const char *)if_name);
                if (!intf) {
                    cprintf("Error: Interface %s not found on node %s\n",
                            if_name, node_name);
                    return -1;
                }
                oif = intf->GetSharedPtr();
            }

            /* Validate protocol and action IDs */
            if (proto_id >= RTM_PROTO_MAX) {
                cprintf("Error: Invalid proto-id %u. Must be 0-%u\n", proto_id, RTM_PROTO_MAX - 1);
                return -1;
            }

            if (sub_proto_id >= RTM_SUB_PROTO_MAX) {
                cprintf("Error: Invalid sub-proto-id %u. Must be 0-%u\n", sub_proto_id, RTM_SUB_PROTO_MAX - 1);
                return -1;
            }

            if (action_id >= RTM_NH_ACTION_MAX) {
                cprintf("Error: Invalid action-id %u. Must be 0-%u\n", action_id, RTM_NH_ACTION_MAX - 1);
                return -1;
            }

            /* Install route */
            rtm_error_t rc = cp_rtm_install_route_advanced(
                rtm,
                &prefix,
                (RTM_PROTO_T)proto_id,
                (RTM_SUB_PROTO_T)sub_proto_id,
                instance_no,
                (RTM_NH_ACTION_TYPE_T)action_id,
                metric,
                gw_ip ? &gateway : NULL,
                oif,
                label_stack_count > 0 ? label_stack : NULL,
                label_stack_count
            );

            if (rc != RTM_SUCCESS) {
                cprintf("Error: Failed to install route: %s\n", rtm_error_to_string(rc));
                return -1;
            }

            cprintf("Route installed successfully\n");
        }
        break;

        case CONFIG_DISABLE:
        {
            /* Parse prefix/mask */
            char prefix_str[48];
            uint8_t mask;

            /* Parse prefix/mask format (e.g., "192.168.1.0/24") */
            if (sscanf((const char *)prefix_mask, "%[^/]/%hhu", prefix_str, &mask) != 2) {
                cprintf("Error: Invalid prefix/mask format. Use: <ip>/<mask>\n");
                return -1;
            }

            if (mask > 32) {
                cprintf("Error: Invalid mask value. Must be 0-32\n");
                return -1;
            }

            /* Get RTM */
            rtm_t *rtm = rtm_get(node, vrf_id, RTM_AF_IPV4, table_id);
            if (!rtm) {
                cprintf("Error: RTM not found for node %s VRF %u table %u\n",
                        node_name, vrf_id, table_id);
                return -1;
            }

            /* Prepare prefix */
            rtm_prefix_t prefix;
            memset(&prefix, 0, sizeof(prefix));
            prefix.afi = RTM_AF_IPV4;
            prefix.prefix_len = mask;
            prefix.u.v4_addr = tcp_ip_convert_ip_p_to_n((c_string)prefix_str);

            /* Prepare gateway */
            rtm_prefix_t gateway;
            memset(&gateway, 0, sizeof(gateway));
            if (gw_ip) {
                gateway.afi = RTM_AF_IPV4;
                gateway.prefix_len = 32;
                gateway.u.v4_addr = tcp_ip_convert_ip_p_to_n(gw_ip);
            }

            /* Get interface */
            InterfaceP oif = nullptr;
            if (if_name) {
                Interface *intf = node_get_intf_by_name(node, (const char *)if_name);
                if (!intf) {
                    cprintf("Error: Interface %s not found on node %s\n",
                            if_name, node_name);
                    return -1;
                }
                oif = intf->GetSharedPtr();
            }

            /* Validate protocol and action IDs */
            if (proto_id >= RTM_PROTO_MAX) {
                cprintf("Error: Invalid proto-id %u. Must be 0-%u\n", proto_id, RTM_PROTO_MAX - 1);
                return -1;
            }

            if (sub_proto_id >= RTM_SUB_PROTO_MAX) {
                cprintf("Error: Invalid sub-proto-id %u. Must be 0-%u\n", sub_proto_id, RTM_SUB_PROTO_MAX - 1);
                return -1;
            }

            if (action_id >= RTM_NH_ACTION_MAX) {
                cprintf("Error: Invalid action-id %u. Must be 0-%u\n", action_id, RTM_NH_ACTION_MAX - 1);
                return -1;
            }

            /* Uninstall route */
            rtm_error_t rc = cp_rtm_uninstall_route_advanced(
                rtm,
                &prefix,
                (RTM_PROTO_T)proto_id,
                (RTM_SUB_PROTO_T)sub_proto_id,
                instance_no,
                (RTM_NH_ACTION_TYPE_T)action_id,
                metric,
                gw_ip ? &gateway : NULL,
                oif,
                label_stack_count > 0 ? label_stack : NULL,
                label_stack_count
            );

            if (rc != RTM_SUCCESS) {
                cprintf("Error: Failed to uninstall route: %s\n", rtm_error_to_string(rc));
                return -1;
            }

            cprintf("Route uninstalled successfully\n");
        }
        break;

        default:
            ;
    }

    return 0;
}
