/*
 * =====================================================================================
 *
 *       Filename:  rtm_priv_api.cpp
 *
 *    Description:  RTM Private API - Core Route Installation and Management
 *
 *        This file contains the private/internal APIs for the RTM system.
 *        These functions handle the core logic of route installation, uninstallation,
 *        nexthop management, and L3VPN route propagation.
 *
 *        Key Responsibilities:
 *        1. Route Installation/Uninstallation (core logic)
 *        2. Nexthop Management and Path Selection
 *        3. Admin Distance Calculation
 *        4. L3VPN Route Propagation to Customer VRFs
 *        5. CLI Handler for Route Configuration
 *        6. Route Formatting and Display
 *
 *        Route Installation Flow:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ 1. Validate Nexthop Template                                │
 *        │    - Check protocol, sub-protocol, action                   │
 *        │    - Validate gateway and interface                         │
 *        │    - Verify MPLS label stack (if present)                    │
 *        ├─────────────────────────────────────────────────────────────┤
 *        │ 2. Lookup or Create Route                                   │
 *        │    - Search route tree by prefix                             │
 *        │    - If not found, create new route structure                │
 *        │    - Add route to RTM's route tree                           │
 *        ├─────────────────────────────────────────────────────────────┤
 *        │ 3. Create Nexthop from Template                              │
 *        │    - Allocate nexthop structure                             │
 *        │    - Copy protocol information                              │
 *        │    - Set admin distance and metric                          │
 *        │    - Configure forwarding flags                             │
 *        ├─────────────────────────────────────────────────────────────┤
 *        │ 4. Add Nexthop to Route                                     │
 *        │    - Insert in sorted order (by AD, metric, etc.)           │
 *        │    - Update route's nexthop count                           │
 *        │    - Add to RTM's nexthop index tree                        │
 *        │    - Add to protocol-specific nexthop list                  │
 *        ├─────────────────────────────────────────────────────────────┤
 *        │ 5. Refresh Route Nexthops                                    │
 *        │    - Determine active nexthop(s)                            │
 *        │    - Update is_active flags                                 │
 *        │    - Trigger FIB updates if needed                           │
 *        ├─────────────────────────────────────────────────────────────┤
 *        │ 6. Handle Route Resolution                                   │
 *        │    - If route is resolved, check unresolvable paths         │
 *        │    - Schedule resolution worker if needed                    │
 *        │    - Re-resolve dependent indirect nexthops                  │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Nexthop Path Selection (Best Path Algorithm):
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ Route: 192.168.1.0/24                                       │
 *        │ ┌─────────────────────────────────────────────────────────┐ │
 *        │ │ Nexthop 1: AD=110, Metric=10, Proto=OSPF               │ │
 *        │ │ Nexthop 2: AD=20,  Metric=5,  Proto=BGP               │ │ ← Best (Lower AD)
 *        │ │ Nexthop 3: AD=20,  Metric=10, Proto=BGP               │ │
 *        │ │ Nexthop 4: AD=1,   Metric=0,  Proto=STATIC            │ │ ← Best (Lower AD)
 *        │ └─────────────────────────────────────────────────────────┘ │
 *        │                                                              │
 *        │ Selection Order:                                            │
 *        │ 1. Admin Distance (lower is better)                         │
 *        │ 2. Metric (lower is better)                                 │
 *        │ 3. Protocol-specific tie-breakers                            │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        L3VPN Route Propagation:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ Default VRF: bgp.l3vpn.0                                    │
 *        │   Route: 10.1.1.0/24 (RD: 100:1, RT: 200:1)                │
 *        │   └─> Customer VRF 1 (Import RT: 200:1)                     │
 *        │       └─> vrf1.inet.0: 10.1.1.0/24                         │
 *        │   └─> Customer VRF 2 (Import RT: 200:2)                    │
 *        │       └─> (Not imported - RT mismatch)                      │
 *        │   └─> Customer VRF 3 (Import RT: 200:1)                      │
 *        │       └─> vrf3.inet.0: 10.1.1.0/24                         │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Version:  1.0
 *        Created:  [Original Date]
 *       Revision:  1.0
 *       Compiler:  gcc/g++
 *
 * =====================================================================================
 */

#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "../lmm_enums.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../router_init.h"
#include "../Interface/InterfaceUApi.h"
#include "../RTM/rtm_nb_integ.h"
#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"
#include "../utils.h"
#include "../tcp_ip_trace.h"
#include "../Tracer/tracer.h"
#include "../Layer3/ipv6/ipv6_utils.h"
#include "rtm_priv_api.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_enums.h"
#include "rtm_proto.h"
#include "rtm_resolution.h"
#include "rtm_presentation.h"
#include "../common/mpls_lstack.h"
#include "../vrf/vrf.h"

extern graph_t * topo;

/* ========================================================================
 * Admin Distance Management
 * ======================================================================== */

/**
 * @brief Get admin distance based on protocol and sub-protocol
 * 
 * Admin Distance (AD) determines route preference when multiple protocols
 * advertise the same route. Lower AD values are preferred.
 * 
 * Admin Distance Table:
 * ┌─────────────────────┬──────────────────────────┬──────────────┐
 * │ Protocol            │ Sub-Protocol             │ Admin Dist   │
 * ├─────────────────────┼──────────────────────────┼──────────────┤
 * │ CONNECTED           │ N/A                      │ 0            │
 * │ STATIC              │ N/A                      │ 1            │
 * │ LOCAL               │ N/A                      │ 1            │
 * │ OSPF                │ INTER                    │ 10           │
 * │ OSPF                │ INTRA                    │ 10           │
 * │ OSPF                │ EXT                     │ 150          │
 * │ ISIS                │ N/A                      │ 115          │
 * │ BGP                 │ INTERNAL                │ 200          │
 * │ BGP                 │ EXTERNAL                │ 20           │
 * │ LDP                 │ N/A                      │ 5            │
 * │ SR/SRTE             │ N/A                      │ 5            │
 * └─────────────────────┴──────────────────────────┴──────────────┘
 * 
 * Route Selection Priority:
 * 1. Lower Admin Distance = Higher Priority
 * 2. If AD is equal, lower metric wins
 * 3. Protocol-specific tie-breakers
 * 
 * @param proto Protocol type
 * @param sub_proto Sub-protocol type
 * 
 * @return Admin distance value
 */
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
            } else if (sub_proto == RTM_SUB_PROTO_SR || sub_proto == RTM_SUB_PROTO_SRv6) {
                return RTM_ADMIN_DIST_SRTE;
            } else if (sub_proto == RTM_SUB_PROTO_SRTE || sub_proto == RTM_SUB_PROTO_SRv6_SRTE) {
                return RTM_ADMIN_DIST_SRTE;
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
            switch (sub_proto) {
                case  RTM_PROTO_L1_ISIS_INT:
                case RTM_PROTO_L2_ISIS_INT: 
                case RTM_PROTO_L1_ISIS_EXT:
                case RTM_PROTO_L2_ISIS_EXT:
                return RTM_ADMIN_DIST_ISIS;
                case  RTM_SUB_PROTO_SR:
                case RTM_SUB_PROTO_SRTE:
                case  RTM_SUB_PROTO_SRv6:
                case RTM_SUB_PROTO_SRv6_SRTE:
                return RTM_ADMIN_DIST_SRTE;
            }
            return RTM_ADMIN_DIST_ISIS;
        case RTM_PROTO_LDP:
            return RTM_ADMIN_DIST_LDP;
        default:
            return RTM_ADMIN_DIST_UNKNOWN;
    }
    return RTM_ADMIN_DIST_UNKNOWN;
}

/* ========================================================================
 * Nexthop Path List Management
 * ======================================================================== */

/**
 * @brief Add nexthop to route's path list in sorted order
 * 
 * This function inserts a nexthop into a route's path list, maintaining
 * sorted order based on the nexthop comparison function (rtm_nh_compare).
 * The path list is sorted by:
 * 1. Admin Distance (lower is better)
 * 2. Metric (lower is better)
 * 3. Protocol-specific tie-breakers
 * 
 * Path List Structure:
 * ┌─────────────────────────────────────────────────────────┐
 * │ Route: 192.168.1.0/24                                   │
 * │ path_list (sorted by preference):                       │
 * │   [NH1: AD=1, Metric=0]  ← Best (Active)               │
 * │   [NH2: AD=20, Metric=5]                                │
 * │   [NH3: AD=20, Metric=10]                               │
 * │   [NH4: AD=110, Metric=10]                              │
 * └─────────────────────────────────────────────────────────┘
 * 
 * After insertion, the function:
 * - Updates route's nexthop count
 * - References the nexthop (increments ref_count)
 * - Triggers route refresh to determine active nexthop(s)
 * 
 * @param rtm Pointer to routing table
 * @param route Route to add nexthop to
 * @param nh Nexthop to add
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


/* ========================================================================
 * Formatting and Display Functions
 * ======================================================================== */

/**
 * @brief Format prefix for display
 * 
 * Converts a prefix structure to a human-readable string format.
 * Supports IPv4, IPv6, MPLS labels, and MAC addresses.
 * 
 * Format Examples:
 * - IPv4: "192.168.1.0/24"
 * - IPv6: "2001:db8::1/64"
 * - MPLS: "100" (label value)
 * - MAC:  "aa:bb:cc:dd:ee:ff"
 * 
 * @param prefix Prefix structure to format
 * @param buffer Output buffer
 * @param buflen Buffer length
 * 
 * @return Pointer to formatted string (same as buffer)
 */
char *
rtm_format_prefix(cmn_prefix_t *prefix, char *buffer, size_t buflen) {
    
    uint32_t temp;
    char addr_buf[INET6_ADDRSTRLEN];
    
    switch(prefix->afi) {
        case AF_IPV4:
            temp = htonl(prefix->u.v4_addr);
            inet_ntop(AF_INET, &temp, addr_buf, sizeof(addr_buf));
            snprintf(buffer, buflen, "%s/%u", addr_buf, prefix->prefix_len);
            break;
        case AF_IPV6:
            inet_ntop(AF_INET6, prefix->u.v6_addr, addr_buf, sizeof(addr_buf));
            snprintf(buffer, buflen, "%s/%u", addr_buf, prefix->prefix_len);
            break;
        case AF_LABEL:
            snprintf(buffer, buflen, "%u", prefix->u.mpls_label);
            break;
        case AF_MAC:
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

/**
 * @brief Format nexthop address for display (without prefix length)
 * 
 * Similar to rtm_format_prefix() but omits the prefix length.
 * Used for displaying gateway/nexthop addresses.
 * 
 * @param prefix Prefix structure to format
 * @param buffer Output buffer
 * @param buflen Buffer length
 * 
 * @return Pointer to formatted string (same as buffer)
 */
char *rtm_format_nexthop(cmn_prefix_t *prefix, char *buffer, size_t buflen) {
    
    uint32_t temp;
    char addr_buf[INET6_ADDRSTRLEN];
    
    switch(prefix->afi) {
        case AF_IPV4:
            temp = htonl(prefix->u.v4_addr);
            inet_ntop(AF_INET, &temp, addr_buf, sizeof(addr_buf));
            snprintf(buffer, buflen, "%s", addr_buf);
            break;
        case AF_IPV6:
            inet_ntop(AF_INET6, prefix->u.v6_addr, addr_buf, sizeof(addr_buf));
            snprintf(buffer, buflen, "%s", addr_buf);
            break;
        case AF_LABEL:
            snprintf(buffer, buflen, "%u", prefix->u.mpls_label);
            break;
        case AF_MAC:
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

/* ========================================================================
 * CLI Handler for Route Configuration
 * ======================================================================== */

/**
 * @brief CLI handler for route configuration
 * 
 * This function handles CLI commands for installing/uninstalling routes.
 * It parses TLV (Type-Length-Value) parameters from the CLI and converts
 * them into route installation/uninstallation calls.
 * 
 * Supported CLI Parameters:
 * ┌─────────────────────┬─────────────────────────────────────────────┐
 * │ Parameter           │ Description                                 │
 * ├─────────────────────┼─────────────────────────────────────────────┤
 * │ node-name           │ Target node name                            │
 * │ vrf-id              │ VRF identifier (0 for default)              │
 * │ prefix-mask         │ Route prefix (IP/mask or Label:value)        │
 * │ proto-id            │ Protocol type                                │
 * │ sub-proto-id        │ Sub-protocol type                            │
 * │ instance-no         │ Protocol instance number                     │
 * │ action-id           │ Nexthop action (FORWARD, LOCAL, etc.)         │
 * │ metric              │ Route metric                                 │
 * │ gw-ip               │ Gateway/next-hop address                     │
 * │ if-name             │ Outgoing interface name                       │
 * │ vpn-label           │ L3VPN service label                          │
 * │ label-list          │ MPLS label stack (multiple values)           │
 * └─────────────────────┴─────────────────────────────────────────────┘
 * 
 * Prefix Format Support:
 * - IPv4: "192.168.1.0/24"
 * - IPv6: "2001:db8::1/64"
 * - MPLS: "Label:100" or plain "100"
 * 
 * @param cmdcode Command code
 * @param tlv_stack Stack of TLVs from CLI parser
 * @param enable_or_disable CONFIG_ENABLE or CONFIG_DISABLE
 * 
 * @return 0 on success, -1 on error
 */
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
    uint32_t proto_id = 0;
    uint32_t sub_proto_id = 0;
    uint32_t instance_no = 0;
    uint32_t action_id = 0;
    uint32_t metric = 0;
    uint32_t label_stack[MAX_LBL_DEPTH] = {0};
    uint8_t label_stack_count = 0;
    mpls_label_val_t l3_vpn_label = 0;
    c_string vpn_label_str = NULL;
    tlv_struct_t *tlv = NULL;

    /* Parse TLVs from CLI input */
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "vrf-id"))
            vrf_id = atoi((const char *)tlv->value);
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
        else if (parser_match_leaf_id(tlv->leaf_id, "vpn-label"))
            vpn_label_str = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "label-list")) {
            if (label_stack_count < MAX_LBL_DEPTH) {
                uint32_t plain_label = atoi((const char *)tlv->value);
                /* Encode label value in upper 20 bits */
                mpls_label_set_value(&label_stack[label_stack_count], plain_label);
                label_stack_count++;
            }
        }

    } TLV_LOOP_END;

    /* Validate inputs */

    if (!prefix_mask) {
        cprintf("Error: prefix/mask is required\n");
        return -1;
    }

    /* Get the node */
    node = node_get_node_by_name(topo, node_name);

    switch (enable_or_disable) {

        case CONFIG_ENABLE:
        {
            /* Parse prefix/mask - could be IP/mask or Label:value */
            char prefix_str[48];
            uint8_t mask;
            uint32_t mpls_label;
            AFI_T afi;
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
                afi = AF_LABEL;
                
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
                afi = is_ipv6_prefix ? AF_IPV6 : AF_IPV4;

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
                    afi = AF_LABEL;
                    
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

            /* Prepare prefix */
            cmn_prefix_t prefix;
            memset(&prefix, 0, sizeof(prefix));
            prefix.afi = afi;

            if (is_mpls) {
                /* MPLS label */
                prefix.u.mpls_label = mpls_label;
                prefix.u.mpls_label = prefix.u.mpls_label << 12;
                prefix.prefix_len = 20; 
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
            cmn_prefix_t gateway;
            memset(&gateway, 0, sizeof(gateway));
            if (gw_ip) {
                /* Check if gateway is an MPLS label or IP address */
                /* MPLS labels are pure numeric (no dots or colons) */
                bool is_mpls_gateway = true;
                bool has_colon = false;
                bool has_dot = false;
                
                /* Scan the gateway string to determine its type */
                for (const char *p = (const char *)gw_ip; *p; p++) {
                    if (*p == ':') {
                        has_colon = true;
                        is_mpls_gateway = false;
                        break;
                    } else if (*p == '.') {
                        has_dot = true;
                        is_mpls_gateway = false;
                        break;
                    } else if (!isdigit(*p)) {
                        /* Non-digit, non-dot, non-colon character */
                        is_mpls_gateway = false;
                        break;
                    }
                }
                
                if (is_mpls_gateway && strlen((const char *)gw_ip) > 0) {
                    /* Gateway is an MPLS label */
                    char *endptr;
                    long label_val = strtol((const char *)gw_ip, &endptr, 10);
                    
                    /* Validate it's a complete numeric value */
                    if (*endptr == '\0' && endptr != (const char *)gw_ip && label_val >= 0) {
                        uint32_t gw_label = (uint32_t)label_val;
                        
                        /* MPLS labels are 20-bit values (0 to 1048575) */
                        if (gw_label > 1048575) {
                            cprintf("Error: Invalid MPLS gateway label %u. Must be 0-1048575\n", gw_label);
                            return -1;
                        }
                        
                        /* Set gateway as MPLS label */
                        gateway.afi = AF_LABEL;
                        gateway.u.mpls_label = gw_label;
                        gateway.prefix_len = 0; /* Not applicable for MPLS */
                        
                        cprintf("Debug: Parsed gateway as MPLS label: %u\n", gw_label);
                    } else {
                        cprintf("Error: Invalid gateway value '%s'\n", gw_ip);
                        return -1;
                    }
                } else {
                    /* Gateway is an IP address */
                    bool is_ipv6_gateway = has_colon;
                    
                    gateway.afi = is_ipv6_gateway ? AF_IPV6 : AF_IPV4;
                    
                    if (is_ipv6_gateway) {
                        /* Parse IPv6 gateway */
                        gateway.prefix_len = 128;
                        
                        /* Validate IPv6 address format */
                        struct in6_addr test_addr;
                        if (inet_pton(AF_INET6, (const char *)gw_ip, &test_addr) != 1) {
                            cprintf("Error: Invalid IPv6 gateway address '%s'\n", gw_ip);
                            return -1;
                        }
                        
                        /* Parse and store IPv6 gateway */
                        ipv6_addr_t v6_gw;
                        inet_pton6((char *)gw_ip, &v6_gw);
                        memcpy(gateway.u.v6_addr, v6_gw.addr, 16);
                    } else {
                        /* Parse IPv4 gateway */
                        gateway.prefix_len = 32;
                        uint32_t v4_gw = tcp_ip_convert_ip_p_to_n(gw_ip);
                        if (v4_gw == 0 && strcmp((const char *)gw_ip, "0.0.0.0") != 0) {
                            cprintf("Error: Invalid IPv4 gateway address '%s'\n", gw_ip);
                            return -1;
                        }
                        gateway.u.v4_addr = v4_gw;
                    }
                }
            }

            /* Get interface and VRF*/
            vrf_t *vrf = NODE_DEF_VRF(node);
            InterfaceP oif = nullptr;
            if (if_name) {
                Interface *intf = node_interface_lookup_by_name(node, (const char *)if_name);
                if (!intf) {
                    cprintf("Error: Interface %s not found on node %s\n",
                            if_name, node_name);
                    return -1;
                }
                oif = intf->GetSharedPtr();
                vrf = oif->vrf;
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

            /* Validate and parse VPN label if provided */
            if (vpn_label_str) {
                /* VPN label is only valid for BGP-VPN routes */
                if (proto_id != RTM_PROTO_BGP || sub_proto_id != RTM_PROTO_BGP_VPN) {
                    cprintf("Error: l3vpn label is only valid for proto-id=%d (RTM_PROTO_BGP) and sub-proto-id=%d (RTM_PROTO_BGP_VPN)\n",
                            RTM_PROTO_BGP, RTM_PROTO_BGP_VPN);
                    cprintf("       Current proto-id=%u, sub-proto-id=%u\n", proto_id, sub_proto_id);
                    return -1;
                }

                uint32_t plain_vpn_label = atoi((const char *)vpn_label_str);
                
                /* MPLS labels are 20-bit values (0 to 1048575) */
                if (plain_vpn_label > 1048575) {
                    cprintf("Error: Invalid VPN label %u. Must be 0-1048575\n", plain_vpn_label);
                    return -1;
                }

                l3_vpn_label = plain_vpn_label;
            }

            rtm_t *rtm = cp_rtm_get_route_target_rtm (
                            node, 
                            vrf, 
                            prefix.afi, 
                            (RTM_PROTO_T)proto_id, 
                            (RTM_SUB_PROTO_T)sub_proto_id);

            if (!rtm) {
                cprintf ("Error : Compatible RIB not found\n");
                return RTM_ERROR_INVALID_ROUTE;
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
                label_stack_count,
                l3_vpn_label);

            if (rc != RTM_SUCCESS) {
                cprintf("Error: Failed to install route: %s\n", rtm_error_to_string(rc));
                return -1;
            }

            cprintf ("Route installed successfully\n");
        }
        break;

        case CONFIG_DISABLE:
        {
            /* Parse prefix/mask - could be IP/mask or Label:value */
            char prefix_str[48];
            uint8_t mask;
            uint32_t mpls_label;
            AFI_T afi;
            bool is_mpls = false;
            bool is_ipv6_prefix = false;

            /* Check if this is an MPLS label (format: "Label:xxx" or "label:xxx") */
            /* Try multiple formats to handle whitespace variations */
            if (sscanf((const char *)prefix_mask, "Label:%u", &mpls_label) == 1 ||
                sscanf((const char *)prefix_mask, "label:%u", &mpls_label) == 1 ||
                sscanf((const char *)prefix_mask, "Label: %u", &mpls_label) == 1 ||
                sscanf((const char *)prefix_mask, "label: %u", &mpls_label) == 1) {
                is_mpls = true;
                afi = AF_LABEL;
                
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
                afi = is_ipv6_prefix ? AF_IPV6 : AF_IPV4;

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
                    afi = AF_LABEL;
                    
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

            /* Prepare prefix */
            cmn_prefix_t prefix;
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
            cmn_prefix_t gateway;
            memset(&gateway, 0, sizeof(gateway));
            if (gw_ip) {
                /* Check if gateway is an MPLS label or IP address */
                /* MPLS labels are pure numeric (no dots or colons) */
                bool is_mpls_gateway = true;
                bool has_colon = false;
                bool has_dot = false;
                
                /* Scan the gateway string to determine its type */
                for (const char *p = (const char *)gw_ip; *p; p++) {
                    if (*p == ':') {
                        has_colon = true;
                        is_mpls_gateway = false;
                        break;
                    } else if (*p == '.') {
                        has_dot = true;
                        is_mpls_gateway = false;
                        break;
                    } else if (!isdigit(*p)) {
                        /* Non-digit, non-dot, non-colon character */
                        is_mpls_gateway = false;
                        break;
                    }
                }
                
                if (is_mpls_gateway && strlen((const char *)gw_ip) > 0) {
                    /* Gateway is an MPLS label */
                    char *endptr;
                    long label_val = strtol((const char *)gw_ip, &endptr, 10);
                    
                    /* Validate it's a complete numeric value */
                    if (*endptr == '\0' && endptr != (const char *)gw_ip && label_val >= 0) {
                        uint32_t gw_label = (uint32_t)label_val;
                        
                        /* MPLS labels are 20-bit values (0 to 1048575) */
                        if (gw_label > 1048575) {
                            cprintf("Error: Invalid MPLS gateway label %u. Must be 0-1048575\n", gw_label);
                            return -1;
                        }
                        
                        /* Set gateway as MPLS label */
                        gateway.afi = AF_LABEL;
                        gateway.u.mpls_label = gw_label;
                        gateway.prefix_len = 0; /* Not applicable for MPLS */
                        
                        cprintf("Debug: Parsed gateway as MPLS label: %u\n", gw_label);
                    } else {
                        cprintf("Error: Invalid gateway value '%s'\n", gw_ip);
                        return -1;
                    }
                } else {
                    /* Gateway is an IP address */
                    bool is_ipv6_gateway = has_colon;
                    
                    gateway.afi = is_ipv6_gateway ? AF_IPV6 : AF_IPV4;
                    
                    if (is_ipv6_gateway) {
                        /* Parse IPv6 gateway */
                        gateway.prefix_len = 128;
                        
                        /* Validate IPv6 address format */
                        struct in6_addr test_addr;
                        if (inet_pton(AF_INET6, (const char *)gw_ip, &test_addr) != 1) {
                            cprintf("Error: Invalid IPv6 gateway address '%s'\n", gw_ip);
                            return -1;
                        }
                        
                        /* Parse and store IPv6 gateway */
                        ipv6_addr_t v6_gw;
                        inet_pton6((char *)gw_ip, &v6_gw);
                        memcpy(gateway.u.v6_addr, v6_gw.addr, 16);
                    } else {
                        /* Parse IPv4 gateway */
                        gateway.prefix_len = 32;
                        uint32_t v4_gw = tcp_ip_convert_ip_p_to_n(gw_ip);
                        if (v4_gw == 0 && strcmp((const char *)gw_ip, "0.0.0.0") != 0) {
                            cprintf("Error: Invalid IPv4 gateway address '%s'\n", gw_ip);
                            return -1;
                        }
                        gateway.u.v4_addr = v4_gw;
                    }
                }
            }

            /* Get interface and vrf */
            InterfaceP oif = nullptr;
           vrf_t *vrf = NODE_DEF_VRF(node);
            if (if_name) {
                Interface *intf = node_interface_lookup_by_name(node, (const char *)if_name);
                if (!intf) {
                    cprintf("Error: Interface %s not found on node %s\n",
                            if_name, node_name);
                    return -1;
                }
                oif = intf->GetSharedPtr();
                vrf = oif->vrf;
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

            /* Validate and parse VPN label if provided */
            if (vpn_label_str) {
                /* VPN label is only valid for BGP-VPN routes */
                if (proto_id != RTM_PROTO_BGP || sub_proto_id != RTM_PROTO_BGP_VPN) {
                    cprintf("Error: l3vpn label is only valid for proto-id=%d (RTM_PROTO_BGP) and sub-proto-id=%d (RTM_PROTO_BGP_VPN)\n",
                            RTM_PROTO_BGP, RTM_PROTO_BGP_VPN);
                    cprintf("       Current proto-id=%u, sub-proto-id=%u\n", proto_id, sub_proto_id);
                    return -1;
                }

                uint32_t plain_vpn_label = atoi((const char *)vpn_label_str);
                
                /* MPLS labels are 20-bit values (0 to 1048575) */
                if (plain_vpn_label > 1048575) {
                    cprintf("Error: Invalid VPN label %u. Must be 0-1048575\n", plain_vpn_label);
                    return -1;
                }

                l3_vpn_label = plain_vpn_label;
            }

            rtm_t *rtm = cp_rtm_get_route_target_rtm (
                            node, 
                            vrf, 
                            prefix.afi, 
                            (RTM_PROTO_T)proto_id, 
                            (RTM_SUB_PROTO_T)sub_proto_id);

            if (!rtm) {
                cprintf ("Error : Compatible RIB not found\n");
                return RTM_ERROR_INVALID_ROUTE;
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
                label_stack_count,
                l3_vpn_label
            );

            if (rc != RTM_SUCCESS) {
                cprintf("Error: Failed to uninstall route: %s\n", rtm_error_to_string(rc));
                return -1;
            }

            cprintf ("Route uninstalled successfully\n");
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
    char vrf_name[32] = {0};
    uint32_t table_id = 0;
    char afi_str[16] = {0};
    
    /* Parse the name format vrf.afi.table_id */
    if (sscanf(rtm_name, "%[^.].%[^.].%u", vrf_name, afi_str, &table_id) != 3) {
        return NULL;
    }

    /* Convert afi string to AFI_T */
    AFI_T afi;
    if (strcmp(afi_str, "inet") == 0) {
        afi = AF_IPV4;
    } else if (strcmp(afi_str, "inet6") == 0) {
        afi = AF_IPV6;
    } else if (strcmp(afi_str, "mpls") == 0) {
        afi = AF_LABEL;
    } else if (strcmp(afi_str, "mac") == 0) {
        afi = AF_MAC;
    } else {
        return NULL;
    }
    
    vrf_t *vrf = vrf_get_by_name(node, vrf_name);
    return rtm_get(node, vrf ? vrf->vrf_id : 0, afi, table_id);
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
    if (nh_template->is_indirect && nh_template->oif) {
        return RTM_ERROR_INVALID_OIF_INDEX;
    }

    if (nh_template->action == RTM_NH_ACTION_LOCAL){
        if (nh_template->is_indirect) 
            return RTM_ERROR_NEXTHOP_INVALID_ACTION;
    }

    if (nh_template->action == RTM_NH_ACTION_FORWARD &&
        nh_template->sub_proto != RTM_SUB_PROTO_SRv6 &&
        (!nh_template->is_indirect && !nh_template->oif)) {
        return RTM_ERROR_INVALID_OIF_INDEX;
    }

    if (nh_template->proto != RTM_PROTO_LOCAL &&
        nh_template->proto != RTM_PROTO_CONNECTED &&
        nh_template->sub_proto != RTM_SUB_PROTO_SRv6 &&
        cmn_prefix_is_null (&nh_template->gateway)) {
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
    /* If idx value is provided, then create NH with this same value. This
    is useful in scenarios when Same route need to be created in client VPN RIBs.*/
    if (nh_template->idx) nh->idx = nh_template->idx;
    nh->fwd_flags = nh_template->fwd_flags;
    nh->proto = nh_template->proto;
    nh->sub_proto = nh_template->sub_proto;
    nh->ad = rtm_get_admin_distance (nh->proto , nh->sub_proto);
    nh->metric = nh_template->metric;
    nh->action = nh_template->action;
    nh->prefix = nh_template->gateway;
    nh->oif = nh_template->oif;
    nh->is_indirect = nh_template->is_indirect;
    nh->is_active = false;
    nh->ref_count = 0;
    nh->l3_vpn_label = nh_template->l3_vpn_label;

    if (IS_BIT_SET (nh_template->fwd_flags, FIB_NH_FWD_F_MPLS_LBL_STCK)) {
        nh->label_stack = (mpls_lstack_t *)XCALLOC2(0, 1, mpls_lstack_t);
        nh->label_stack->curr_index = nh_template->u.l_stack.label_stack->curr_index;
        for (int i = 0; i <= nh->label_stack->curr_index; i++) {
            nh->label_stack->labels[i].label_val = nh_template->u.l_stack.label_stack->labels[i].label_val;
            nh->label_stack->labels[i].op = nh_template->u.l_stack.label_stack->labels[i].op;
        }
    }

    if (IS_BIT_SET (nh_template->fwd_flags, FIB_NH_FWD_F_IPV6_STCK)) {

        nh->endfn = nh_template->u.srv6_stack.endfn;

        if (nh_template->u.srv6_stack.n_segment_list) {

            nh->n_segment_list = nh_template->u.srv6_stack.n_segment_list;

            nh->v6segment_lst = (cmn_prefix_t *)XCALLOC2(0, 
                nh_template->u.srv6_stack.n_segment_list, cmn_prefix_t);

            for (int i = 0; i < nh->n_segment_list; i++) {
                memcpy (&nh->v6segment_lst[i], 
                    &nh_template->u.srv6_stack.v6segment_lst[i],
                    sizeof(nh->v6segment_lst[i]));
            }
        }
    }

    /* NH created successfully - note: cannot trace here as we don't have RTM context */
    return nh;
}


/* Install the route in RTM , Check for duplicate nexthop for the route.
/* ========================================================================
 * Core Route Installation/Uninstallation Functions
 * ======================================================================== */

/**
 * @brief Install route in RTM (core function)
 * 
 * This is the core route installation function. It handles:
 * - Route creation if it doesn't exist
 * - Nexthop creation from template
 * - Nexthop insertion into route's path list
 * - Route resolution triggering
 * - FIB updates
 * 
 * Installation Process:
 * ┌─────────────────────────────────────────────────────────┐
 * │ 1. Validate nexthop template                           │
 * │ 2. Lookup route (create if new)                         │
 * │ 3. Create nexthop from template                         │
 * │ 4. Add nexthop to route (sorted insertion)              │
 * │ 5. Add nexthop to RTM index tree                        │
 * │ 6. Add nexthop to protocol list                         │
 * │ 7. Refresh route to determine active nexthop            │
 * │ 8. If route is resolved, trigger resolution worker     │
 * │ 9. Re-resolve dependent indirect nexthops               │
 * └─────────────────────────────────────────────────────────┘
 * 
 * Error Handling:
 * - If route creation fails, return error
 * - If nexthop creation fails, clean up route (if new)
 * - If nexthop addition fails, clean up nexthop and route
 * 
 * @param rtm Pointer to routing table
 * @param prefix Route prefix
 * @param cp_nh_template Nexthop template with all route information
 * 
 * @return RTM_SUCCESS on success, appropriate error code on failure
 */
rtm_error_t 
rtm_install_route ( 
                rtm_t *rtm, 
                cmn_prefix_t *prefix,
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
            rtm_error_to_string(RTM_ERROR_NEXTHOP_CREATION_FAILED), prefix_str);

        if (new_rt) {

            rtm_route_delete(rtm, route);
            tracer(rtm->node->cptr, DRTM_DET,
                "RTM[%s] : New Route %s deleted from RTM DB due to NH creation failure\n",
                rtm->name, prefix_str);
        }

        return RTM_ERROR_NEXTHOP_CREATION_FAILED;
    }

    nh->rtm = rtm;
    nh->rtm_nh_proto = (rtm_nh_proto_t *)XCALLOC2(0, 1, rtm_nh_proto_t);
    rtm_nh_proto_initialize (nh->rtm_nh_proto);
    rtm_nh_proto_copy (cp_nh_template->rtm_nh_proto, nh->rtm_nh_proto);

    nh_proto = nh->rtm_nh_proto;

    rc = rtm_route_add_nh(rtm, route, nh);

    if (rc != RTM_SUCCESS) {

        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR(%s): Route %s : Failed to add NH\n",
            rtm->name, 
            rtm_error_to_string(rc), prefix_str);

        if (nh_proto == nh->rtm_nh_proto) {
            nh->rtm_nh_proto = NULL;
            rtm_nh_proto_dereference (rtm, nh_proto);
        }

        rtm_nh_dereference (rtm, nh);
        
        if (new_rt) {

            rtm_route_delete(rtm, route);
            tracer(rtm->node->cptr, DRTM_DET,
                "RTM[%s] : New Route %s deleted from RTM DB due to NH Addition failure\n",
                rtm->name, prefix_str);
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
        prefix_str,
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

        //    1. A new Route is added 
        rtm_schedule_nh_resolution_worker_of_dependent_rtms (rtm);
    }

    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Success: Route %s installation completed, nexthop : %s\n",
        rtm->name, prefix_str,
        rtm_nh_one_liner_trace(nh, gw_str, sizeof(gw_str)));

    return rc;
}


/**
 * @brief Uninstall route from RTM (core function)
 * 
 * Removes a nexthop from a route. If this is the last nexthop,
 * the route itself is also removed.
 * 
 * Uninstallation Process:
 * ┌─────────────────────────────────────────────────────────┐
 * │ 1. Validate nexthop template                           │
 * │ 2. Lookup route                                        │
 * │ 3. Create nexthop from template (for matching)         │
 * │ 4. Find matching nexthop in route                       │
 * │ 5. Withdraw from resolution system                     │
 * │ 6. Delete nexthop from route                           │
 * │ 7. If route has active nexthops, refresh them          │
 * │ 8. Remove nexthop from index tree                      │
 * │ 9. If route has 0 nexthops, delete route                │
 * └─────────────────────────────────────────────────────────┘
 * 
 * @param rtm Pointer to routing table
 * @param prefix Route prefix
 * @param nh_template Nexthop template to match for removal
 * 
 * @return RTM_SUCCESS on success, error code on failure
 */
rtm_error_t 
rtm_uninstall_route ( rtm_t *rtm, cmn_prefix_t *prefix, 
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
            rtm->name, prefix_str);
        return RTM_ERROR_CONTAINER_LOOKUP_FAILED;
    }

    //bool was_resolved = rtm_route_is_resolved (route);

    rtm_nh *nh = rtm_nh_create_from_nh_template(nh_template);

    if (!nh) {
        return RTM_ERROR_NEXTHOP_CREATION_FAILED;
    }
    
    nh->rtm = rtm;
    rtm_nh_proto_initialize (&nh_proto_obj);
    rtm_nh_proto_copy (nh_template->rtm_nh_proto, &nh_proto_obj);
    nh->rtm_nh_proto = &nh_proto_obj;

    /* look up the actual nexthop*/
    rtm_nh *actual_nh = rtm_route_lookup_nh (route, nh);
    
    XFREE(nh);

    if (!actual_nh) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: NH not found for route %s\n",
            rtm->name, prefix_str);
        return RTM_ERROR_NEXTHOP_NOT_FOUND;
    }

    /* Handle resolution by this NH */
    rtm_resolution_nh_withdraw (rtm, actual_nh);

    rc = rtm_route_delete_nh (rtm, route, actual_nh);

    if (rc != RTM_SUCCESS) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Failed to delete NH from route %s - %s\n",
            rtm->name, prefix_str,
            rtm_error_to_string(rc));
        return rc;
    }

    nh_template->idx = actual_nh->idx;

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
        rtm_schedule_route_advertisement (rtm, route);
        rtm_route_delete(rtm, route);

        //     2. A Route is Deleted
        // Delete cases Automatically handled
        //if (was_resolved) rtm_schedule_nh_resolution_worker_of_dependent_rtms (rtm, &route->prefix);
    }

    return RTM_SUCCESS;
}

/* ========================================================================
 * L3VPN Route Propagation Functions
 * ======================================================================== */

/**
 * @brief Copy routes from source RIB to destination RIB
 * 
 * This function copies routes from a source RIB (typically bgp.l3vpn.0)
 * to a destination RIB (typically a customer VRF's inet.0/inet6.0).
 * Routes are filtered based on Import Route Target (RT).
 * 
 * L3VPN Route Copy Flow:
 * ┌─────────────────────────────────────────────────────────┐
 * │ Source RIB: bgp.l3vpn.0                                 │
 * │   Route: 10.1.1.0/24 (RT: 200:1)                       │
 * │   └─> Filter by Import RT: 200:1                       │
 * │       └─> Match! Copy to destination RIB                │
 * │                                                          │
 * │ Destination RIB: vrf1.inet.0                            │
 * │   Route: 10.1.1.0/24 (copied with VRF label)            │
 * └─────────────────────────────────────────────────────────┘
 * 
 * Route Target Filtering:
 * - If import_rt is (0:0), all routes are copied (pass-through)
 * - Otherwise, only routes with matching RT are copied
 * 
 * @param node Pointer to network node
 * @param src_rib Source routing table
 * @param dst_rib Destination routing table
 * @param import_rt Import Route Target for filtering
 */
static void 
rtm_copy_ribs (node_t *node, 
        rtm_t *src_rib, 
        rtm_t *dst_rib, rt_t import_rt) {

    rtm_error_t rc;
    glthread_t *curr;
    uint32_t nh_copied;
    rtm_nh *nh, *new_nh;
    char prefix_str[48];
    rtm_route *src_route;
    rtm_route *dst_route;
    avltree_node_t *src_rt_node;

    bool pass_through = (import_rt.asn == 0 && import_rt.number == 0);

    ITERATE_AVL_TREE_BEGIN(&src_rib->route_tree, src_rt_node) {

        src_route = avltree_container_of(src_rt_node, rtm_route, route_glue);
        dst_route = rtm_route_lookup(dst_rib, &src_route->prefix);

        if (!dst_route) {

            dst_route = (rtm_route *)XCALLOC2(0, 1, rtm_route);
            rtm_route_initialize(dst_route);
            dst_route->prefix = src_route->prefix;
            rc = rtm_route_add(dst_rib, dst_route);

            if (rc != RTM_SUCCESS) {

                tracer(node->cptr, DRTM_DET,
                    "RTM[%s] : ERROR(%s): Route %s addition failed\n", 
                    dst_rib->name, rtm_error_to_string(rc),
                    rtm_format_prefix(&dst_route->prefix, prefix_str, sizeof(prefix_str)));
                XFREE(dst_route);
                continue;
            }

            tracer(node->cptr, DRTM_DET,
                "RTM[%s] : Success : New Route %s Added to RTM DB\n",
                dst_rib->name,
                rtm_format_prefix(&dst_route->prefix, prefix_str, sizeof(prefix_str)));   
        }

        nh_copied = 0;

        ITERATE_GLTHREAD_BEGIN(&src_route->path_list, curr) {

            nh = route_glue_to_rtm_nh(curr);

            if (!pass_through &&
                (nh->import_rt.asn != import_rt.asn || 
                nh->import_rt.number != import_rt.number)) continue;
            
            new_nh = rtm_nh_duplicate (nh);
            rc = rtm_route_add_nh(dst_rib, dst_route, new_nh);
            assert (rc == RTM_SUCCESS);
            nh_copied++;

            /* Glue the nexthop to global RTM hooks */
            new_nh->rtm = dst_rib;
            rtm_nh_add_to_idx_tree(dst_rib, new_nh);
            rtm_nh_glthread_add_next(new_nh, 
                &dst_rib->nhs_by_src[new_nh->proto], 
                &new_nh->src_glue);

        } ITERATE_GLTHREAD_END(&src_route->path_list, curr);

        if (nh_copied == 0) {
            /* Back out the route */
            rtm_route_delete(dst_rib, dst_route);
        }
        else {
            // No need to refresh nexthops, they are already arranged in
            // src rib.
            //rtm_route_refresh_nexthops (dst_rib, dst_route);
        }

    } ITERATE_AVL_TREE_END(&src_rib->route_tree, src_rt_node);

}

/**
 * @brief Copy L3VPN routes to customer VRF RIBs
 * 
 * Propagates routes from bgp.l3vpn.0 to customer VRF RIBs based on
 * Import Route Targets. This implements the L3VPN route distribution
 * mechanism.
 * 
 * L3VPN Distribution:
 * ┌─────────────────────────────────────────────────────────┐
 * │ Default VRF: bgp.l3vpn.0 (IPv4)                        │
 * │   Route: 10.1.1.0/24 (RD: 100:1, RT: 200:1)            │
 * │                                                          │
 * │ Customer VRFs:                                          │
 * │   VRF1 (Import RT: 200:1) → Match! Copy to vrf1.inet.0 │
 * │   VRF2 (Import RT: 200:2) → No match, skip              │
 * │   VRF3 (Import RT: 200:1) → Match! Copy to vrf3.inet.0  │
 * └─────────────────────────────────────────────────────────┘
 * 
 * @param node Pointer to network node
 * @param afi Address family (AF_IPV4 or AF_IPV6)
 * @param target_vrf_id Specific VRF ID (0 for all VRFs)
 * @param perform_resolution Whether to perform route resolution after copy
 */
void 
rtm_copy_l3vpn_to_vrf_client_ribs (
        node_t *node,
        AFI_T afi,
        uint8_t target_vrf_id, 
        bool perform_resolution) {

    int i;
    vrf_t *vrf = NULL;
    int resolved_count = 0;

    assert (afi == AF_IPV4 || afi == AF_IPV6);

    rtm_t *src_rib = (afi == AF_IPV4 ) ? \
                node->node_nw_prop.def_vrf->l3vpnv4 : \
                node->node_nw_prop.def_vrf->l3vpnv6;

    if (target_vrf_id) {

        vrf = vrf_get_by_id (node, target_vrf_id);
        if (!vrf) return;
        rtm_t *dst_rib = (afi == AF_IPV4 ) ? vrf->inet0 : vrf->inet6;
        rtm_copy_ribs (node, src_rib, dst_rib, vrf->import_rt);
        if (perform_resolution) {
            rtm_all_inh_unresolve(dst_rib, NULL);
            rtm_try_unresolvable_paths_resolution (dst_rib, &resolved_count);
        }
        return;
    }

    for (i = 0; i < MAX_VRF_PER_NODE; i++) {

        vrf = node->vrf[i];
        if (!vrf) continue;
        rtm_t *dst_rib = (afi == AF_IPV4 ) ? vrf->inet0 : vrf->inet6;
        rtm_copy_ribs (node, src_rib, dst_rib, vrf->import_rt);
        if (perform_resolution) {
            rtm_all_inh_unresolve(dst_rib, NULL);
            rtm_try_unresolvable_paths_resolution (dst_rib, &resolved_count);
        }
    }
}

/**
 * @brief Get list of client RIBs for a given parent RIB
 * 
 * Returns a list of client RIBs that should receive route updates
 * from the parent RIB. This is used for L3VPN route propagation.
 * 
 * Client RIB Relationship:
 * ┌─────────────────────────────────────────────────────────┐
 * │ Parent RIB: bgp.l3vpn.0                                │
 * │   └─> Client RIBs:                                      │
 * │       - vrf1.inet.0                                     │
 * │       - vrf2.inet.0                                     │
 * │       - vrf3.inet.0                                     │
 * │                                                          │
 * │ When route is installed/deleted in parent:              │
 * │   → Automatically propagated to all client RIBs          │
 * └─────────────────────────────────────────────────────────┘
 * 
 * @param rtm Parent routing table
 * @param lst_head_out Output list head for client RIBs
 */
static void
rtm_get_client_rtm_set (rtm_t *rtm, glthread_t *lst_head_out) {

    int i;
    vrf_t *vrf;
    node_t *node = rtm->node;
    glthread_data_node_t *data_node;

    init_glthread(lst_head_out);

    /* L3 VPN case */
    if (rtm == node->node_nw_prop.def_vrf->l3vpnv4 ||
        rtm == node->node_nw_prop.def_vrf->l3vpnv6)
    {
        for (i = 0; i < MAX_VRF_PER_NODE; i++)
        {
            if (!node->vrf[i]) continue;
            vrf = node->vrf[i];
            data_node = (glthread_data_node_t *)XCALLOC2(0, 1, glthread_data_node_t);
            rtm_t *client_rtm = rtm_get(node, vrf->vrf_id, rtm->afi, 0);
            data_node->data = (void *)client_rtm;
            init_glthread(&data_node->glue);
            glthread_add_next(lst_head_out, &data_node->glue);
        }
    }
}

void 
rtm_install_l3vpn_routes_to_all_client_ribs(
        rtm_t *rtm, 
        cmn_prefix_t *prefix, 
        cp_nexthop_template_t *cp_nh_template,
        bool install){

    vrf_t *vrf;
    rtm_error_t rc;
    glthread_t *curr;
    char route_str[48];
    char nh_str[48];
    rtm_t *client_rtm;
    glthread_t client_rtm_list;
    glthread_data_node_t *data_node;

    rtm_get_client_rtm_set(rtm, &client_rtm_list);

    rtm_format_prefix(prefix, route_str, sizeof (route_str));
    rtm_format_nexthop(&cp_nh_template->gateway, nh_str, sizeof (nh_str));

    ITERATE_GLTHREAD_BEGIN (&client_rtm_list, curr) {

        data_node = glue_to_glthread_data_node(curr);
        client_rtm = (rtm_t *)data_node->data;

        vrf = vrf_get_by_id(rtm->node, client_rtm->vrf);

        if (vrf->import_rt.asn == cp_nh_template->import_rt.asn &&
            vrf->import_rt.number == cp_nh_template->import_rt.number) {

            if (install) {
                rc = rtm_install_route ( client_rtm,  prefix, cp_nh_template);
            }
            else {
                rc = rtm_uninstall_route ( client_rtm,  prefix, cp_nh_template);
            }
            tracer (rtm->node->cptr, DRTM_DET, 
                "RTM[%s] : L3 VPN Route %s, %s %sInstalled in Client RTM[%s] Result : %s\n",
                rtm->name, route_str, nh_str, 
                install ? "" : "Un",
                client_rtm->name, rtm_error_to_string(rc));
        }
        
    } ITERATE_GLTHREAD_END (&client_rtm_list, curr);

    while((curr = dequeue_glthread_first(&client_rtm_list))) {
        data_node = glue_to_glthread_data_node(curr);
        XFREE(data_node);
    }
}


void 
rtm_uninstall_l3vpn_routes_to_all_client_ribs(
        rtm_t *rtm, 
        uint32_t idx) {

    glthread_t *curr;
    rtm_t *client_rtm;
    glthread_t client_rtm_list;
    glthread_data_node_t *data_node;

    rtm_get_client_rtm_set(rtm, &client_rtm_list);

    ITERATE_GLTHREAD_BEGIN (&client_rtm_list, curr) {

        data_node = glue_to_glthread_data_node(curr);
        client_rtm = (rtm_t *)data_node->data;
        cp_rtm_uninstall_route_by_idx(client_rtm, idx);
        
    } ITERATE_GLTHREAD_END (&client_rtm_list, curr);

    while((curr = dequeue_glthread_first(&client_rtm_list))) {
        data_node = glue_to_glthread_data_node(curr);
        XFREE(data_node);
    }
}
