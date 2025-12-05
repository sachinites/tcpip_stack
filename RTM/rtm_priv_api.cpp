#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "../lmm_enums.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../graph.h"
#include "../Interface/InterfaceUApi.h"
#include "rtm_priv_api.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_enums.h"
#include "rtm_common.h"
#include "rtm_proto.h"
#include "rtm_resolution.h"
#include "../RTM/rtm_nb_integ.h"
#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"
#include "../utils.h"
#include "../tcp_ip_trace.h"
#include "../Tracer/tracer.h"
#include "../Layer3/ipv6/ipv6_utils.h"

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
    return RTM_ADMIN_DIST_UNKNOWN;
}

/* Insert the nh at appripriate position in route path list using fn rtm_nh_compare () 
    Set is_active to true/false depending if this is the best path in route list
    invoke fn : rtm_nh_set_active ( ) / rtm_nh_set_inactive ( ) if the state of the nexthop
    switches from inactive to active or active to inactive. Use rtm_nh_compare( ) to compare two
    nexthops
*/
void
 rtm_route_add_nh_to_route_path_list (rtm_t *rtm, rtm_route *route, rtm_nh *nh) {

    
    char gw_str[48];
    rtm_nh *curr_nh;
    glthread_t *curr;
    char prefix_str[48];
    glthread_t *insert_before = NULL;

    ITERATE_GLTHREAD_BEGIN(&route->path_list, curr) {
        
        curr_nh = route_glue_to_rtm_nh(curr);
        
        if (rtm_nh_compare(nh, curr_nh) < 0) {
            insert_before = curr;
            break;
        }
        
    } ITERATE_GLTHREAD_END(&route->path_list, curr);
    
    assert (!IS_QUEUED_UP_IN_THREAD(&nh->route_glue));
    
    /* Use wrapper functions for glthread operations */
    if (insert_before) {
        glthread_add_before(insert_before, &nh->route_glue);
    } else {
        glthread_add_last(&route->path_list, &nh->route_glue);
    }
    
    rtm_nh_reference(nh);

    route->nh_count++;

    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Route %s : Adding NH %s to route path list, NH-Attr : AD=%u Metric=%u\n",
        rtm->name,
        rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)),
        rtm_format_nexthop(&nh->prefix, gw_str, sizeof(gw_str)),
        nh->ad, nh->metric);
 }


char *
rtm_format_prefix(rtm_prefix_t *prefix, char *buffer, size_t buflen) {
    
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
            snprintf(buffer, buflen, "%u", prefix->u.mpls_label);
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
    return buffer;
}

/* Helper function to format nexthop (without prefix length) */
char *rtm_format_nexthop(rtm_prefix_t *prefix, char *buffer, size_t buflen) {
    
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
            snprintf(buffer, buflen, "%u", prefix->u.mpls_label);
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
    return buffer;
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
            /* Parse prefix/mask - could be IP/mask or Label:value */
            char prefix_str[48];
            uint8_t mask;
            uint32_t mpls_label;
            RTM_AFI_T afi;
            bool is_mpls = false;
            bool is_ipv6_prefix = false;

            /* Check if this is an MPLS label */
            /* Try multiple formats: "Label:xxx", "label:xxx", or just plain number "xxx" */
            if (sscanf((const char *)prefix_mask, "Label:%u", &mpls_label) == 1 ||
                sscanf((const char *)prefix_mask, "label:%u", &mpls_label) == 1 ||
                sscanf((const char *)prefix_mask, "Label: %u", &mpls_label) == 1 ||
                sscanf((const char *)prefix_mask, "label: %u", &mpls_label) == 1) {
                /* Explicit Label: format */
                is_mpls = true;
                afi = RTM_AF_LABEL;
                
                /* MPLS labels are 20-bit values (0 to 1048575) */
                if (mpls_label > 1048575) {
                    cprintf("Error: Invalid MPLS label %u. Must be 0-1048575\n", mpls_label);
                    return -1;
                }
                
            } else if (strchr((const char *)prefix_mask, '/') != NULL) {
                /* Parse IP prefix/mask format (e.g., "192.168.1.0/24" or "2001:db8::/32") */
                if (sscanf((const char *)prefix_mask, "%[^/]/%hhu", prefix_str, &mask) != 2) {
                    cprintf("Error: Invalid prefix/mask format.\n");
                    cprintf("       Use: <ip>/<mask> for IP routes or Label:<value> for MPLS\n");
                    return -1;
                }

                /* Detect address family from prefix */
                is_ipv6_prefix = (strchr(prefix_str, ':') != NULL);
                afi = is_ipv6_prefix ? RTM_AF_IPV6 : RTM_AF_IPV4;

                /* Validate the IP address format */
                if (is_ipv6_prefix) {
                    /* Validate IPv6 address */
                    struct in6_addr test_addr;
                    if (inet_pton(AF_INET6, prefix_str, &test_addr) != 1) {
                        cprintf("Error: Invalid IPv6 address '%s'\n", prefix_str);
                        return -1;
                    }
                } else {
                    /* Validate IPv4 address */
                    struct in_addr test_addr;
                    if (inet_pton(AF_INET, prefix_str, &test_addr) != 1) {
                        cprintf("Error: Invalid IPv4 address '%s'\n", prefix_str);
                        return -1;
                    }
                }

                /* Validate mask based on address family */
                uint8_t max_mask = is_ipv6_prefix ? 128 : 32;
                if (mask > max_mask) {
                    cprintf("Error: Invalid mask value. Must be 0-%u for %s\n",
                            max_mask, is_ipv6_prefix ? "IPv6" : "IPv4");
                    return -1;
                }

                /* If gateway is provided, validate it matches prefix address family */
                if (gw_ip) {
                    bool is_ipv6_gateway = (strchr((const char *)gw_ip, ':') != NULL);
                    if (is_ipv6_prefix != is_ipv6_gateway) {
                        cprintf("Error: Gateway address family must match prefix address family.\n");
                        cprintf("       Prefix is %s but gateway is %s\n",
                                is_ipv6_prefix ? "IPv6" : "IPv4",
                                is_ipv6_gateway ? "IPv6" : "IPv4");
                        return -1;
                    }

                    /* Validate gateway IP address format */
                    if (is_ipv6_gateway) {
                        struct in6_addr test_addr;
                        if (inet_pton(AF_INET6, (const char *)gw_ip, &test_addr) != 1) {
                            cprintf("Error: Invalid IPv6 gateway address '%s'\n", gw_ip);
                            return -1;
                        }
                    } else {
                        struct in_addr test_addr;
                        if (inet_pton(AF_INET, (const char *)gw_ip, &test_addr) != 1) {
                            cprintf("Error: Invalid IPv4 gateway address '%s'\n", gw_ip);
                            return -1;
                        }
                    }
                }
            } else {
                /* Try to parse as plain numeric MPLS label */
                char *endptr;
                long label_val = strtol((const char *)prefix_mask, &endptr, 10);
                
                /* Check if entire string was consumed and it's a valid number */
                if (*endptr == '\0' && endptr != (const char *)prefix_mask && label_val >= 0) {
                    /* It's a plain number - treat as MPLS label */
                    mpls_label = (uint32_t)label_val;
                    is_mpls = true;
                    afi = RTM_AF_LABEL;
                    
                    /* MPLS labels are 20-bit values (0 to 1048575) */
                    if (mpls_label > 1048575) {
                        cprintf("Error: Invalid MPLS label %u. Must be 0-1048575\n", mpls_label);
                        return -1;
                    }
                } else {
                    /* Neither MPLS label nor IP prefix format */
                    cprintf("Error: Invalid prefix format '%s'\n", prefix_mask);
                    cprintf("       Use: <ip>/<mask> for IP routes or plain number/Label:<value> for MPLS\n");
                    return -1;
                }
            }

            /* Get RTM */
            rtm_t *rtm = rtm_get(node, vrf_id, afi, table_id);
            if (!rtm) {
                cprintf("Error: RTM not found for node %s VRF %u table %u\n",
                        node_name, vrf_id, table_id);
                return -1;
            }

            /* Prepare prefix */
            rtm_prefix_t prefix;
            memset(&prefix, 0, sizeof(prefix));
            prefix.afi = afi;

            if (is_mpls) {
                /* MPLS label */
                prefix.u.mpls_label = mpls_label;
                prefix.prefix_len = 0; /* Not applicable for MPLS */
            } else {
                prefix.prefix_len = mask;
                
                if (is_ipv6_prefix) {
                    /* Parse IPv6 prefix */
                    ipv6_addr_t v6_addr;
                    inet_pton6(prefix_str, &v6_addr);
                    memcpy(prefix.u.v6_addr, v6_addr.addr, 16);
                } else {
                    /* Parse IPv4 prefix */
                    prefix.u.v4_addr = tcp_ip_convert_ip_p_to_n((c_string)prefix_str);
                }
            }

            /* Prepare gateway */
            rtm_prefix_t gateway;
            memset(&gateway, 0, sizeof(gateway));
            if (gw_ip) {
                /* For MPLS, gateway must be IP (can't be MPLS label) */
                bool is_ipv6_gateway = (strchr((const char *)gw_ip, ':') != NULL);
                
                if (is_mpls) {
                    /* MPLS prefix with IP gateway - valid for label swap */
                    afi = is_ipv6_gateway ? RTM_AF_IPV6 : RTM_AF_IPV4;
                }
                
                gateway.afi = is_ipv6_gateway ? RTM_AF_IPV6 : RTM_AF_IPV4;
                
                if (is_ipv6_gateway) {
                    /* Parse IPv6 gateway */
                    gateway.prefix_len = 128;
                    ipv6_addr_t v6_gw;
                    inet_pton6((char *)gw_ip, &v6_gw);
                    memcpy(gateway.u.v6_addr, v6_gw.addr, 16);
                } else {
                    /* Parse IPv4 gateway */
                    gateway.prefix_len = 32;
                    gateway.u.v4_addr = tcp_ip_convert_ip_p_to_n(gw_ip);
                }
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

            printw("Route installed successfully\n");
        }
        break;

        case CONFIG_DISABLE:
        {
            /* Parse prefix/mask - could be IP/mask or Label:value */
            char prefix_str[48];
            uint8_t mask;
            uint32_t mpls_label;
            RTM_AFI_T afi;
            bool is_mpls = false;
            bool is_ipv6_prefix = false;

            /* Check if this is an MPLS label (format: "Label:xxx" or "label:xxx") */
            /* Try multiple formats to handle whitespace variations */
            if (sscanf((const char *)prefix_mask, "Label:%u", &mpls_label) == 1 ||
                sscanf((const char *)prefix_mask, "label:%u", &mpls_label) == 1 ||
                sscanf((const char *)prefix_mask, "Label: %u", &mpls_label) == 1 ||
                sscanf((const char *)prefix_mask, "label: %u", &mpls_label) == 1) {
                is_mpls = true;
                afi = RTM_AF_LABEL;
                
                /* MPLS labels are 20-bit values (0 to 1048575) */
                if (mpls_label > 1048575) {
                    cprintf("Error: Invalid MPLS label %u. Must be 0-1048575\n", mpls_label);
                    return -1;
                }
            } else if (strchr((const char *)prefix_mask, '/') != NULL) {
                /* Parse IP prefix/mask format (e.g., "192.168.1.0/24" or "2001:db8::/32") */
                if (sscanf((const char *)prefix_mask, "%[^/]/%hhu", prefix_str, &mask) != 2) {
                    cprintf("Error: Invalid prefix/mask format.\n");
                    cprintf("       Use: <ip>/<mask> for IP routes or Label:<value> for MPLS\n");
                    return -1;
                }

                /* Detect address family from prefix */
                is_ipv6_prefix = (strchr(prefix_str, ':') != NULL);
                afi = is_ipv6_prefix ? RTM_AF_IPV6 : RTM_AF_IPV4;

                /* Validate the IP address format */
                if (is_ipv6_prefix) {
                    /* Validate IPv6 address */
                    struct in6_addr test_addr;
                    if (inet_pton(AF_INET6, prefix_str, &test_addr) != 1) {
                        cprintf("Error: Invalid IPv6 address '%s'\n", prefix_str);
                        return -1;
                    }
                } else {
                    /* Validate IPv4 address */
                    struct in_addr test_addr;
                    if (inet_pton(AF_INET, prefix_str, &test_addr) != 1) {
                        cprintf("Error: Invalid IPv4 address '%s'\n", prefix_str);
                        return -1;
                    }
                }

                /* Validate mask based on address family */
                uint8_t max_mask = is_ipv6_prefix ? 128 : 32;
                if (mask > max_mask) {
                    cprintf("Error: Invalid mask value. Must be 0-%u for %s\n",
                            max_mask, is_ipv6_prefix ? "IPv6" : "IPv4");
                    return -1;
                }

                /* If gateway is provided, validate it matches prefix address family */
                if (gw_ip) {
                    bool is_ipv6_gateway = (strchr((const char *)gw_ip, ':') != NULL);
                    if (is_ipv6_prefix != is_ipv6_gateway) {
                        cprintf("Error: Gateway address family must match prefix address family.\n");
                        cprintf("       Prefix is %s but gateway is %s\n",
                                is_ipv6_prefix ? "IPv6" : "IPv4",
                                is_ipv6_gateway ? "IPv6" : "IPv4");
                        return -1;
                    }

                    /* Validate gateway IP address format */
                    if (is_ipv6_gateway) {
                        struct in6_addr test_addr;
                        if (inet_pton(AF_INET6, (const char *)gw_ip, &test_addr) != 1) {
                            cprintf("Error: Invalid IPv6 gateway address '%s'\n", gw_ip);
                            return -1;
                        }
                    } else {
                        struct in_addr test_addr;
                        if (inet_pton(AF_INET, (const char *)gw_ip, &test_addr) != 1) {
                            cprintf("Error: Invalid IPv4 gateway address '%s'\n", gw_ip);
                            return -1;
                        }
                    }
                }
            } else {
                /* Try to parse as plain numeric MPLS label */
                char *endptr;
                long label_val = strtol((const char *)prefix_mask, &endptr, 10);
                
                /* Check if entire string was consumed and it's a valid number */
                if (*endptr == '\0' && endptr != (const char *)prefix_mask && label_val >= 0) {
                    /* It's a plain number - treat as MPLS label */
                    mpls_label = (uint32_t)label_val;
                    is_mpls = true;
                    afi = RTM_AF_LABEL;
                    
                    /* MPLS labels are 20-bit values (0 to 1048575) */
                    if (mpls_label > 1048575) {
                        cprintf("Error: Invalid MPLS label %u. Must be 0-1048575\n", mpls_label);
                        return -1;
                    }
                } else {
                    /* Neither MPLS label nor IP prefix format */
                    cprintf("Error: Invalid prefix format '%s'\n", prefix_mask);
                    cprintf("       Use: <ip>/<mask> for IP routes or plain number/Label:<value> for MPLS\n");
                    return -1;
                }
            }

            /* Get RTM */
            rtm_t *rtm = rtm_get(node, vrf_id, afi, table_id);
            if (!rtm) {
                cprintf("Error: RTM not found for node %s VRF %u table %u\n",
                        node_name, vrf_id, table_id);
                return -1;
            }

            /* Prepare prefix */
            rtm_prefix_t prefix;
            memset(&prefix, 0, sizeof(prefix));
            prefix.afi = afi;

            if (is_mpls) {
                /* MPLS label */
                prefix.u.mpls_label = mpls_label;
                prefix.prefix_len = 0; /* Not applicable for MPLS */
            } else {
                prefix.prefix_len = mask;
                
                if (is_ipv6_prefix) {
                    /* Parse IPv6 prefix */
                    ipv6_addr_t v6_addr;
                    inet_pton6(prefix_str, &v6_addr);
                    memcpy(prefix.u.v6_addr, v6_addr.addr, 16);
                } else {
                    /* Parse IPv4 prefix */
                    prefix.u.v4_addr = tcp_ip_convert_ip_p_to_n((c_string)prefix_str);
                }
            }

            /* Prepare gateway */
            rtm_prefix_t gateway;
            memset(&gateway, 0, sizeof(gateway));
            if (gw_ip) {
                /* For MPLS, gateway must be IP (can't be MPLS label) */
                bool is_ipv6_gateway = (strchr((const char *)gw_ip, ':') != NULL);
                
                if (is_mpls) {
                    /* MPLS prefix with IP gateway - valid for label swap */
                    afi = is_ipv6_gateway ? RTM_AF_IPV6 : RTM_AF_IPV4;
                }
                
                gateway.afi = is_ipv6_gateway ? RTM_AF_IPV6 : RTM_AF_IPV4;
                
                if (is_ipv6_gateway) {
                    /* Parse IPv6 gateway */
                    gateway.prefix_len = 128;
                    ipv6_addr_t v6_gw;
                    inet_pton6((char *)gw_ip, &v6_gw);
                    memcpy(gateway.u.v6_addr, v6_gw.addr, 16);
                } else {
                    /* Parse IPv4 gateway */
                    gateway.prefix_len = 32;
                    gateway.u.v4_addr = tcp_ip_convert_ip_p_to_n(gw_ip);
                }
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

            printw("Route uninstalled successfully\n");
        }
        break;

        default:
            ;
    }

    return 0;
}

/* Split Rib name to get VRF id and table id . Rib name is expeccted in 
    x.inet.y or x.inet6.y or x.mpls.y format where x is vrf id and y is table id*/

rtm_t *
rtm_get_by_name (node_t *node, char *rtm_name) {

    if (!rtm_name) {
        return NULL;
    }

    /* Parse rtm_name in format: x.inet.y or x.inet6.y or x.mpls.y or x.mac.y 
       where x is vrf id and y is table id */
    uint32_t vrf_id = 0;
    uint32_t table_id = 0;
    char afi_str[16] = {0};
    
    /* Parse the name format vrf.afi.table_id */
    if (sscanf(rtm_name, "%u.%[^.].%u", &vrf_id, afi_str, &table_id) != 3) {
        return NULL;
    }
    
    /* Convert afi string to RTM_AFI_T */
    RTM_AFI_T afi;
    if (strcmp(afi_str, "inet") == 0) {
        afi = RTM_AF_IPV4;
    } else if (strcmp(afi_str, "inet6") == 0) {
        afi = RTM_AF_IPV6;
    } else if (strcmp(afi_str, "mpls") == 0) {
        afi = RTM_AF_LABEL;
    } else if (strcmp(afi_str, "mac") == 0) {
        afi = RTM_AFI_MAC;
    } else {
        return NULL;
    }
    
    return rtm_get(node, vrf_id, afi, table_id);
}

static rtm_error_t 
rtm_validate_cp_nexthop_template(cp_nexthop_template_t *nh_template) {

    if (!nh_template) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    if (nh_template->proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_PROTO;
    }
    if (nh_template->sub_proto >= RTM_SUB_PROTO_MAX) {
        return RTM_ERROR_INVALID_SUB_PROTO;
    }
    if (nh_template->action >= RTM_NH_ACTION_MAX) {
        return RTM_ERROR_NEXTHOP_INVALID_ACTION;
    }
    if (nh_template->is_indirect && nh_template->Oif) {
        return RTM_ERROR_INVALID_OIF_INDEX;
    }
    if (!nh_template->is_indirect && !nh_template->Oif) {
        return RTM_ERROR_INVALID_OIF_INDEX;
    }
    if (nh_template->proto != RTM_PROTO_LOCAL &&
        nh_template->proto != RTM_PROTO_CONNECTED &&
        rtm_prefix_is_null (&nh_template->gateway)) {
        return RTM_ERROR_INVALID_GATEWAY;
    }
    if (!nh_template->rtm_nh_proto) {
        return RTM_ERROR_INVALID_NEXTHOP_PROTO;
    }
    
    /* Validation successful - template is valid */
    return RTM_SUCCESS;
}

static rtm_nh *
rtm_nh_create_from_nh_template (cp_nexthop_template_t *nh_template) {

    rtm_nh *nh = (rtm_nh *)XCALLOC2(0, 1, rtm_nh);
    rtm_nh_initialize(nh);
    nh->flags = nh_template->flags;
    nh->proto = nh_template->proto;
    nh->sub_proto = nh_template->sub_proto;
    nh->ad = rtm_get_admin_distance (nh->proto , nh->sub_proto);
    nh->metric = nh_template->metric;
    nh->action = nh_template->action;
    nh->prefix = nh_template->gateway;
    nh->Oif = nh_template->Oif ? nh_template->Oif->GetSharedPtr() : nullptr;
    nh->is_indirect = nh_template->is_indirect;
    nh->is_active = false;
    nh->ref_count = 0;

    if (nh_template->u.l_stack.label_stack) {
        nh->label_stack = (rtm_lstack_t *)XCALLOC2(0, 1, rtm_lstack_t);
        nh->label_stack->curr_index = nh_template->u.l_stack.label_stack->curr_index;
        for (int i = 0; i < nh->label_stack->curr_index; i++) {
            nh->label_stack->labels[i].label_val = nh_template->u.l_stack.label_stack->labels[i].label_val;
            nh->label_stack->labels[i].op = nh_template->u.l_stack.label_stack->labels[i].op;
        }
    }

    nh->endfn = nh_template->u.srv6_stack.endfn;
    nh->n_segment_list = nh_template->u.srv6_stack.n_segment_list;
    nh->v6segment_lst = nh_template->u.srv6_stack.v6segment_lst;

    /* NH created successfully - note: cannot trace here as we don't have RTM context */
    return nh;
}


/* Install the route in RTM , Check for duplicate nexthop for the route.
    Return appropriate error code */
rtm_error_t 
rtm_install_route ( 
                            rtm_t *rtm, 
                            rtm_prefix_t *prefix,
                            cp_nexthop_template_t *cp_nh_template) {

    char gw_str[128];
    char prefix_str[48];
    bool new_rt = false;
    rtm_nh_proto_t *nh_proto;
    rtm_error_t rc = RTM_SUCCESS;

    rc = rtm_validate_cp_nexthop_template(cp_nh_template);

    if (rc != RTM_SUCCESS) {

        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR(%s): NH template validation failed for route %s\n",
            rtm->name,
            rtm_error_to_string(rc),
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));

        return rc;
    }

    /* look up the route*/
    rtm_route *route = rtm_route_lookup(rtm, prefix);

    if (!route) {
        
        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : Creating New Route %s\n",
            rtm->name,
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));

        route = (rtm_route *)XCALLOC2(0, 1, rtm_route);
        rtm_route_initialize(route);
        route->prefix = *prefix;
        new_rt = true;
        rc = rtm_route_add(rtm, route);
        
        if (rc != RTM_SUCCESS) {

            tracer(rtm->node->cptr, DRTM | DERR,
                "RTM[%s] : ERROR(%s): Route %s addition failed\n", 
                rtm->name, rtm_error_to_string(rc),
                rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));
            XFREE(route);
            return rc;
        }

        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : Success : New Route %s Added to RTM DB\n",
            rtm->name,
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));        
    }

    rtm_nh *nh = rtm_nh_create_from_nh_template(cp_nh_template);

    if (!nh) {

        tracer(rtm->node->cptr, DRTM|DERR,
            "RTM[%s] : ERROR(%s): Failed to create NH from template for route %s\n",
            rtm->name,
            rtm_error_to_string(RTM_ERROR_NEXTHOP_CREATION_FAILED),
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));

        if (new_rt) {

            rtm_route_delete(rtm, route);
            tracer(rtm->node->cptr, DRTM_DET,
                "RTM[%s] : New Route %s deleted from RTM DB due to NH creation failure\n",
                rtm->name,
                rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));
        }

        return RTM_ERROR_NEXTHOP_CREATION_FAILED;
    }

    nh->rtm_nh_proto = (rtm_nh_proto_t *)XCALLOC2(0, 1, rtm_nh_proto_t);
    rtm_nh_proto_initialize (nh->rtm_nh_proto);
    rtm_nh_proto_copy (cp_nh_template->rtm_nh_proto, nh->rtm_nh_proto);

    nh_proto = nh->rtm_nh_proto;

    rc = rtm_route_add_nh(rtm, route, nh);

    if (rc != RTM_SUCCESS) {

        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR(%s): Route %s : Failed to add NH\n",
            rtm->name, 
            rtm_error_to_string(rc),
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));

        if (nh_proto == nh->rtm_nh_proto) {
            nh->rtm_nh_proto = NULL;
            rtm_nh_proto_dereference (rtm, nh_proto);
        }

        rtm_nh_dereference (rtm, nh);
        
        if (new_rt) {

            rtm_route_delete(rtm, route);
            tracer(rtm->node->cptr, DRTM_DET,
                "RTM[%s] : New Route %s deleted from RTM DB due to NH Addition failure\n",
                rtm->name,
                rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));
        
        }
        cp_nh_template->idx = 0;
        return rc;
    }

    rtm_nh_add_to_idx_tree(rtm, nh);
    rtm_nh_glthread_add_next(nh, &rtm->nhs_by_src[nh->proto], &nh->src_glue);

    cp_nh_template->idx = nh->idx;

    rtm_route_refresh_nexthops (rtm, route);
    
    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Success : Route %s installed, NH %s\n",
        rtm->name,
        rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)),
        rtm_nh_one_liner_trace(nh, gw_str, sizeof(gw_str)));
        
    if (new_rt && rtm_route_is_resolved (route)) {

        if (!Fglthread_list_is_empty(&rtm->unresolvable_paths)) {

        /* If the new route is added, then check any unresolvable paths could
            be resolved on this route */      
            tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : Scheduling NH resolution worker, Reason : New Resolved Route %s Added\n",
            rtm->name, prefix_str);

            rtm_schedule_nh_resolution_worker (rtm);
        }
        else {
            tracer (rtm->node->cptr, DRTM_DET,
                "RTM[%s] : Skipping Scheduling NH resolution worker, "
                "Reason : No unresolvable paths to resolve on newly added route %s\n",
                rtm->name, prefix_str);
        }

        /* Also this could be the next route which other already resolved INHs could be
            resolved better now (as per LPM), so re-resolved such INHs */
        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : Re-resolving INHs, Reason : New Resolved Route Added\n",
            rtm->name);

        rtm_re_resolve_inhs (rtm, &route->prefix);
    }

    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Success: Route %s installation completed, nexthop : %s\n",
        rtm->name,
        rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)),
        rtm_nh_one_liner_trace(nh, gw_str, sizeof(gw_str)));

    return rc;
}


rtm_error_t 
rtm_uninstall_route ( rtm_t *rtm, rtm_prefix_t *prefix, 
                         cp_nexthop_template_t *nh_template) {

    rtm_nh_proto_t nh_proto_obj;
    rtm_error_t rc = RTM_SUCCESS;
    char prefix_str[48];
    char gw_str[48];

    rc = rtm_validate_cp_nexthop_template(nh_template);

    if (rc != RTM_SUCCESS) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: NH template validation failed - %s\n",
            rtm->name, rtm_error_to_string(rc));
        return rc;
    }

    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Uninstalling route %s\n",
        rtm->name,
        rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));

    /* look up the route*/
    rtm_route *route = rtm_route_lookup(rtm, prefix);
    if (!route) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Route %s not found\n",
            rtm->name,
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));
        return RTM_ERROR_CONTAINER_LOOKUP_FAILED;
    }

    rtm_nh *nh = rtm_nh_create_from_nh_template(nh_template);

    if (!nh) {
        return RTM_ERROR_NEXTHOP_CREATION_FAILED;
    }

    rtm_nh_proto_initialize (&nh_proto_obj);
    rtm_nh_proto_copy (nh_template->rtm_nh_proto, &nh_proto_obj);
    nh->rtm_nh_proto = &nh_proto_obj;

    /* look up the actual nexthop*/
    rtm_nh *actual_nh = rtm_route_lookup_nh (route, nh);
    
    XFREE(nh);

    if (!actual_nh) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: NH not found for route %s\n",
            rtm->name,
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)));
        return RTM_ERROR_NEXTHOP_NOT_FOUND;
    }

    /* Handle resolution by this NH */
    rtm_resolution_nh_withdraw (rtm, actual_nh);

    rc = rtm_route_delete_nh (rtm, route, actual_nh);

    if (rc != RTM_SUCCESS) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Failed to delete NH from route %s - %s\n",
            rtm->name,
            rtm_format_prefix(prefix, prefix_str, sizeof(prefix_str)),
            rtm_error_to_string(rc));
        return rc;
    }

    if (actual_nh->is_active && route->nh_count){
        rtm_route_refresh_nexthops (rtm, route);
    }
    
    /* Remove nh from idx tree*/
    rtm_nh_remove_from_idx_tree(rtm, actual_nh);    
    /* Use wrapper function for glthread removal */
    rtm_nh_remove_glthread(rtm, actual_nh, &actual_nh->src_glue);
    /* Note: rtm_nh_remove_glthread already calls rtm_nh_dereference */

    /* Now check if route has 0 Nexthops, then delete the route as well*/
    if (route->nh_count == 0) {
        rtm_route_delete(rtm, route);
    }

    return RTM_SUCCESS;
}
