/*
 * =====================================================================================
 *
 *       Filename:  rtm_show.cpp
 *
 *    Description:  RTM Show Commands - CLI Display and Debugging
 *
 *        This file implements CLI show commands for displaying RTM information.
 *        It provides various display formats including detailed route information,
 *        Cisco-style RIB display, and protocol-specific views.
 *
 *        Show Command Features:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ 1. Detailed Route Display                                    │
 *        │    - Route prefix and attributes                             │
 *        │    - All nexthops with full details                          │
 *        │    - Resolution information for indirect nexthops             │
 *        │    - Dependent paths resolved by this route                  │
 *        │                                                              │
 *        │ 2. Cisco-Style RIB Display                                   │
 *        │    - Compact table format                                    │
 *        │    - Protocol codes (C, S, O, B, etc.)                       │
 *        │    - Admin distance and metric                                │
 *        │    - Next-hop and outgoing interface                         │
 *        │                                                              │
 *        │ 3. Protocol-Specific Views                                   │
 *        │    - Filter routes by protocol                                │
 *        │    - Show protocol statistics                                │
 *        │                                                              │
 *        │ 4. Route Filtering                                           │
 *        │    - Prefix-list based filtering                             │
 *        │    - VRF-based filtering                                     │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Display Format Example:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │ Route: 192.168.1.0/24                                       │
 *        │ ====================                                        │
 *        │   Nexthop Count  : 2                                        │
 *        │   Resolved Nexthop Count : 1                                │
 *        │   Flags          : 0x0                                     │
 *        │   Ref Count      : 3                                       │
 *        │                                                              │
 *        │   Nexthop 1:                                                │
 *        │     Idx            : 1                                      │
 *        │     Protocol       : BGP                                    │
 *        │     Next-Hop       : 10.1.1.1                               │
 *        │     Admin Distance : 20                                      │
 *        │     Metric         : 0                                      │
 *        │     Active         : Yes                                     │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Version:  1.0
 *        Created:  [Original Date]
 *       Revision:  1.0
 *       Compiler:  gcc/g++
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>
#include "../libs/Tree/libtree.h"
#include "../libs/gluethread/glthread.h"
#include "../Interface/InterfaceUApi.h"
#include "../router_init.h"
#include "rtm_show.h"
#include "rtm.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_proto.h"
#include "rtm_enums.h"
#include "rtm_priv_api.h"
#include "rtm_presentation.h"
#include "rtm_dist_mgr.h"
#include "../libs/prefix-list/prefixlst.h"
#include "../libs/common/mpls_lstack.h"
#include "../libs/common/cmn_prefix.h"
#include "../Layer3/SegmentRouting/SRv6/common/srv6_const.h"

typedef struct graph_ graph_t;

extern int cprintf (const char * format, ...);
extern graph_t *topo;

/* ========================================================================
 * Forward Declarations
 * ======================================================================== */

static void rtm_show_single_route_detail(rtm_t *rtm, rtm_route *route);

/* ========================================================================
 * Detailed Route Display Functions
 * ======================================================================== */

/**
 * @brief Display detailed information about a single route
 * 
 * Shows comprehensive information about a route including:
 * - Route prefix and basic attributes
 * - All nexthops with full details
 * - Resolution information for indirect nexthops
 * - Dependent paths that resolve over this route
 * - MPLS label stacks (if present)
 * 
 * @param rtm Pointer to routing table
 * @param route Route to display
 */
static void rtm_show_single_route_detail(rtm_t *rtm, rtm_route *route) {

    char prefix_str[128];
    byte time_str[HRS_MIN_SEC_FMT_TIME_LEN];
    
    rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str));
    
    /* Display route prefix and attributes */
    cprintf("\nRoute: %s\n", prefix_str);
    cprintf("====================\n");
    cprintf("  Nexthop Count  : %u\n", route->nh_count);
    cprintf("  Resolved Nexthop Count : %u\n", route->resolved_inh_count);
    cprintf("  Flags          : 0x%x\n", route->flags);
    cprintf("  Ref Count      : %u\n", route->ref_count);

    /* Print the paths this route resolved */
    cprintf("  Dependent Paths:");

    if (Fglthread_list_is_empty(&route->resolved_lnhs)) {

        cprintf(" None\n");

    } else {

        glthread_t *curr_lnh_glue = NULL;
        int resolved_count = 0;
        printw("\n");

        ITERATE_GLTHREAD_BEGIN(&route->resolved_lnhs.head, curr_lnh_glue) {

            rtm_nh *indirect_nh = resolution_list_glue_to_rtm_nh(curr_lnh_glue);
            char inh_prefix_str[128];
            rtm_format_nexthop(&indirect_nh->prefix, inh_prefix_str, sizeof(inh_prefix_str));
            resolved_count++;
            cprintf("    [%d] %s, %s from RIB %s\n", 
                resolved_count, inh_prefix_str, 
                rtm_proto_to_string (indirect_nh->proto),
                indirect_nh->rtm->name);

        } ITERATE_GLTHREAD_END(&route->resolved_lnhs.head, curr_lnh_glue);

    }

    /* Iterate through all nexthops in the route */
    glthread_t *curr_glthread = NULL;
    int nh_index = 0;
    
    ITERATE_GLTHREAD_BEGIN(&route->path_list, curr_glthread) {
        
        rtm_nh *nh = route_glue_to_rtm_nh(curr_glthread);
        char nh_prefix_str[128];
        rtm_format_nexthop(&nh->prefix, nh_prefix_str, sizeof(nh_prefix_str));

        nh_index++;
        cprintf("\n  Nexthop %d:\n", nh_index);
        cprintf("    Idx            : %u(%p)\n", nh->idx, nh);
        cprintf("    flags          : %u\n", nh->fwd_flags);
        cprintf("    Protocol       : %s\n", rtm_proto_to_string(nh->proto));
        cprintf("    Sub-Protocol   : %s\n", rtm_sub_proto_to_string(nh->sub_proto));
        cprintf("    Next-Hop       : %s\n", nh_prefix_str);
        cprintf("    Action         : %s\n", rtm_nh_action_to_string(nh->action));
        {
            const char *oif_name = "-";
            if (nh->oif) {
                Interface *oif_intf = node_get_intf_by_ifindex(rtm->node, nh->oif);
                oif_name = oif_intf ? oif_intf->if_name.c_str() : "<unknown>";
            }
            cprintf("    OIF            : %s\n", oif_name);
        }
        cprintf("    Admin Distance : %u\n", nh->ad);
        cprintf("    Metric         : %u\n", nh->metric);
        cprintf("    Resolved       : %s\n", rtm_nh_is_resolved(nh) ? "Yes" : "No");
        cprintf("    Indirect       : %s\n", nh->is_indirect ? "Yes" : "No");
        
        /* Display L3 VPN label if present (for BGP-VPN routes) */
        if (nh->proto == RTM_PROTO_BGP && 
            nh->sub_proto == RTM_PROTO_BGP_VPN && 
            nh->l3_vpn_label != 0) {

            cprintf("    L3 VPN Label   : %u\n", nh->l3_vpn_label);
        }
        
        /* Display resolution information for indirect nexthops */
        if (nh->is_indirect) {
            cprintf("    Resolution Info:\n");
            
            /* Show the resolver route */
            if (nh->resolved_via_route) {
                char resolver_prefix_str[128];
                rtm_format_prefix(&nh->resolved_via_route->prefix, 
                                  resolver_prefix_str, 
                                  sizeof(resolver_prefix_str));
                cprintf("      Resolved By Route : %s\n", resolver_prefix_str);
            } else {
                cprintf("      Resolved By Route : Unresolved\n");
            }
            
            /* Count and display direct nexthops */
            int direct_nh_count = 0;
            glthread_t *dnh_glthread = NULL;
            ITERATE_GLTHREAD_BEGIN(&nh->direct_nh_list.head, dnh_glthread) {
                direct_nh_count++;
            } ITERATE_GLTHREAD_END(&nh->direct_nh_list.head, dnh_glthread);
            
            cprintf("      Direct Nexthops   : %d\n", direct_nh_count);
            
            /* Display each direct nexthop */
            if (direct_nh_count > 0) {
                dnh_glthread = NULL;
                
                ITERATE_GLTHREAD_BEGIN(&nh->direct_nh_list.head, dnh_glthread) {
                    
                    glthread_data_node_t *data_node = glue_to_glthread_data_node(dnh_glthread);
                    rtm_nh *direct_nh = (rtm_nh *)data_node->data;
                    
                    char direct_nh_prefix_str[128];
                    rtm_format_nexthop(&direct_nh->prefix, 
                                      direct_nh_prefix_str, 
                                      sizeof(direct_nh_prefix_str));
                    
                    Interface *dnh_intf = node_get_intf_by_ifindex(rtm->node, direct_nh->oif);
                    cprintf("        [%d] %s, %s, %s\n",
                           direct_nh->idx,
                           direct_nh_prefix_str,
                           dnh_intf ? dnh_intf->if_name.c_str() : "<unknown>",
                           rtm_proto_to_string(direct_nh->proto));
                           
                } ITERATE_GLTHREAD_END(&nh->direct_nh_list.head, dnh_glthread);
            }
        }
        
        cprintf ("    Active         : %s\n", nh->is_active ? "Yes" : "No");
        cprintf ("    Uptime         : %s\n",  RTM_UP_TIME (nh->install_time, time_str, sizeof(time_str)));
        cprintf("    Ref Count      : %u\n", nh->ref_count);
        
        /* Display label stack if present */
        if (nh->label_stack && nh->label_stack->curr_index > 0) {
            cprintf("    Label Stack    : ");
            for (int i = 0; i <= nh->label_stack->curr_index; i++) {
                mpls_label_t *label = &nh->label_stack->labels[i];
                const char *op_str = "UNK";
                switch (label->op) {
                    case MPLS_OP_SWAP: op_str = "Swap"; break;
                    case MPLS_OP_PUSH: op_str = "Push"; break;
                    case MPLS_OP_POP: op_str = "Pop"; break;
                    default: break;
                }
                /* Extract the actual 20-bit label value */
                uint32_t label_value = mpls_label_get_value(label->label_val);
                cprintf("[%u:%s]", label_value, op_str);
                if (i < nh->label_stack->curr_index) {
                    cprintf(" -> ");
                }
            }
            printw("\n");
        }

        /* Display SRv6 Endpoint Function */
        if (nh->endfn != SRV6_END_FN_NONE)
        {
            cprintf("    SRv6 Endpoint Fn: %s\n", srv6_end_fn_str(nh->endfn));
        }

        /* Display SRv6 Segment List if present */
        if (nh->n_segment_list > 0 && nh->v6segment_lst)
        {
            cprintf("    SRv6 Segment List: ");
            for (int i = 0; i < nh->n_segment_list; i++)
            {
                char seg_str[48];
                rtm_format_prefix(&nh->v6segment_lst[i], seg_str, sizeof(seg_str));
                cprintf("%s", seg_str);
                if (i < nh->n_segment_list - 1)
                {
                    cprintf(" -> ");
                }
            }
            printw("\n");
        }
    } ITERATE_GLTHREAD_END(&route->path_list, curr_glthread);

    /* Blank line after route display */
    printw("\n");
}

/**
 * @brief Get protocol code for Cisco-style display
 * 
 * Returns single-letter or short protocol codes used in Cisco-style
 * routing table displays.
 * 
 * Protocol Codes:
 * ┌─────────────────────┬──────────────────────────┬──────────┐
 * │ Protocol            │ Sub-Protocol             │ Code     │
 * ├─────────────────────┼──────────────────────────┼──────────┤
 * │ CONNECTED           │ N/A                      │ C        │
 * │ STATIC              │ N/A                      │ S        │
 * │ LOCAL               │ N/A                      │ L        │
 * │ OSPF                │ INTRA                    │ O        │
 * │ OSPF                │ INTER                    │ O IA     │
 * │ OSPF                │ EXT                      │ O E2     │
 * │ BGP                 │ N/A                      │ B        │
 * │ ISIS                │ L1                       │ I L1     │
 * │ ISIS                │ L2                       │ I L2     │
 * │ LDP                 │ N/A                      │ D        │
 * │ SR                  │ N/A                      │ SR       │
 * │ SRTE                │ N/A                      │ SR-TE    │
 * └─────────────────────┴──────────────────────────┴──────────┘
 * 
 * @param proto Protocol type
 * @param sub_proto Sub-protocol type
 * 
 * @return Protocol code string
 */
static const char* rtm_get_proto_code(RTM_PROTO_T proto, RTM_SUB_PROTO_T sub_proto) {
    switch(proto) {
        case RTM_PROTO_CONNECTED:
            return "C";
        case RTM_PROTO_STATIC:
            return "S";
        case RTM_PROTO_LOCAL:
            return "L";
        case RTM_PROTO_OSPF:
            switch(sub_proto) {
                case RTM_SUB_PROTO_OSPF_INTRA:
                    return "O";
                case RTM_SUB_PROTO_OSPF_INTER:
                    return "O IA";
                case RTM_SUB_PROTO_OSPF_EXT:
                    return "O E2";
                case RTM_SUB_PROTO_SRv6:
                    return "O SR";
                default:
                    return "O";
            }
        case RTM_PROTO_BGP:
            return "B";
        case RTM_PROTO_ISIS:
            switch(sub_proto) {
                case RTM_PROTO_L1_ISIS_INT:
                    return "I L1";
                case RTM_PROTO_L2_ISIS_INT:
                    return "I L2";
                case RTM_PROTO_L1_ISIS_EXT:
                    return "I L1";
                case RTM_PROTO_L2_ISIS_EXT:
                    return "I L2";
                case RTM_SUB_PROTO_SRv6:
                    return "I SR";
                default:
                    return "I";
            }
        case RTM_PROTO_LDP:
            return "D";
        default:
            return "?";
    }
}

/* ========================================================================
 * Cisco-Style RIB Display
 * ======================================================================== */

extern "C" {

/**
 * @brief Display RIB in Cisco-style format
 * 
 * Displays the routing table in a compact, Cisco IOS-like format.
 * Shows routes with protocol codes, admin distance, metric, next-hop,
 * and outgoing interface.
 * 
 * Display Format:
 * ┌─────────────────────────────────────────────────────────────┐
 * │ Codes: C - connected, S - static, O - OSPF, B - BGP      │
 * │        * - candidate default route                         │
 * │                                                              │
 * │ Gateway of last resort is 10.1.1.1 to network 0.0.0.0     │
 * │                                                              │
 * │      10.0.0.0/8 is variably subnetted, 2 subnets, 1 mask   │
 * │ C       10.1.1.0/24 is directly connected, eth0            │
 * │ O       10.2.2.0/24 [110/10] via 10.1.1.1, eth1           │
 * │ B       192.168.1.0/24 [20/0] via 10.1.1.2, eth1           │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * @param rtm Pointer to routing table
 * @param prefix_filter Optional prefix filter (NULL for all routes)
 */
void rtm_show_rib_standard(rtm_t *rtm, char *prefix_filter) {

    printw("\n");
    
    /* Display legend/codes - Cisco style */
    cprintf("Codes: I - IGRP derived, R - RIP derived, O - OSPF derived\n");
    cprintf("       C - connected, S - static, E - EGP derived, B - BGP derived\n");
    cprintf("       * - candidate default route, IA - OSPF inter area route\n");
    cprintf("       E1 - OSPF external type 1 route, E2 - OSPF external type 2 route\n");
    cprintf("       L1 - ISIS level-1, L2 - ISIS level-2, SRv6 - Segment Routing v6\n");
    
    /* Find default route gateway if exists */
    char default_gw[48] = "not set";
    char default_net[48] = "0.0.0.0";
    cmn_prefix_t default_prefix;
    memset(&default_prefix, 0, sizeof(default_prefix));
    default_prefix.afi = AF_IPV4;
    default_prefix.prefix_len = 0;
    
    rtm_route *default_route = rtm_route_lookup(rtm, &default_prefix);
    if (default_route) {
        glthread_t *curr_glthread = NULL;
        ITERATE_GLTHREAD_BEGIN(&default_route->path_list, curr_glthread) {
            rtm_nh *nh = route_glue_to_rtm_nh(curr_glthread);
            if (nh->is_active && !cmn_prefix_is_null(&nh->prefix)) {
                rtm_format_nexthop(&nh->prefix, default_gw, sizeof(default_gw));
                break;
            }
        } ITERATE_GLTHREAD_END(&default_route->path_list, curr_glthread);
    }
    
    cprintf("Gateway of last resort is %s to network %s\n\n", default_gw, default_net);

    if (avltree_is_empty(&rtm->route_tree)) {
        cprintf("No routes in routing table\n\n");
        return;
    }

    /* Parse prefix filter if provided */
    cmn_prefix_t filter_prefix;
    bool has_filter = false;
    
    if (prefix_filter && strlen(prefix_filter) > 0) {
        memset(&filter_prefix, 0, sizeof(filter_prefix));
        if (cmn_parse_prefix_string(prefix_filter, &filter_prefix) == 0) {
            has_filter = true;
        }
    }

    /* Iterate through all routes in the tree */
    avltree_node_t *curr_node = NULL;
    int displayed_routes = 0;
    
    ITERATE_AVL_TREE_BEGIN(&rtm->route_tree, curr_node) {
        
        rtm_route *route = avltree_container_of(curr_node, rtm_route, route_glue);
        
        /* Apply filter if specified */
        if (has_filter) {
            if (filter_prefix.afi != route->prefix.afi ||
                filter_prefix.prefix_len != route->prefix.prefix_len ||
                memcmp(&filter_prefix.u, &route->prefix.u, 
                       (filter_prefix.afi == AF_IPV4 ? 4 : 16)) != 0) {
                continue;
            }
        }
        
        /* Collect all active nexthops for this route */
        glthread_t *curr_glthread = NULL;
        rtm_nh *best_nh = NULL;
        int active_nh_count = 0;
        
        /* Count active nexthops and get the first one */
        ITERATE_GLTHREAD_BEGIN(&route->path_list, curr_glthread) {
            rtm_nh *nh = route_glue_to_rtm_nh(curr_glthread);
            if (nh->is_active) {
                if (!best_nh) {
                    best_nh = nh;
                }
                active_nh_count++;
            }
        } ITERATE_GLTHREAD_END(&route->path_list, curr_glthread);
        
        /* If no active nexthop found, use the first one */
        if (!best_nh && !IS_GLTHREAD_LIST_EMPTY(&route->path_list)) {
            best_nh = route_glue_to_rtm_nh(route->path_list.right);
            active_nh_count = 1;
        }
        
        if (!best_nh) {
            continue; /* Skip routes with no nexthops */
        }
        
        /* Format the destination prefix */
        char prefix_str[64];
        rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str));
        
        /* Get protocol code */
        const char *proto_code = rtm_get_proto_code(best_nh->proto, best_nh->sub_proto);
        
        /* Display first nexthop */
        {
            /* Format nexthop address */
            char nh_addr_str[48];
            rtm_format_nexthop(&best_nh->prefix, nh_addr_str, sizeof(nh_addr_str));
            
            /* Format uptime - Cisco uses h:mm:ss format */
            byte time_str[HRS_MIN_SEC_FMT_TIME_LEN];
            RTM_UP_TIME(best_nh->install_time, time_str, sizeof(time_str));
            
            /* Get interface name */
            const char *if_name = "-";
            if (best_nh->oif) {
                Interface *intf = node_get_intf_by_ifindex(rtm->node, best_nh->oif);
                if_name = intf ? intf->if_name.c_str() : "<unknown>";
            } else if (best_nh->is_indirect && !Fglthread_list_is_empty(&best_nh->direct_nh_list)) {
                /* For indirect nexthops, try to get interface from first direct nexthop */
                glthread_t *dnh_glthread = best_nh->direct_nh_list.head.right;
                if (dnh_glthread && dnh_glthread != &best_nh->direct_nh_list.head) {
                    glthread_data_node_t *data_node = glue_to_glthread_data_node(dnh_glthread);
                    rtm_nh *direct_nh = (rtm_nh *)data_node->data;
                    if (direct_nh && direct_nh->oif) {
                        Interface *intf = node_get_intf_by_ifindex(rtm->node, direct_nh->oif);
                        if_name = intf ? intf->if_name.c_str() : "<unknown>";
                    }
                }
            }
            
            /* Determine the display format based on action type - Cisco style */
            if (best_nh->action == RTM_NH_ACTION_CONNECTED) {
               
                cprintf("%-4s %-18s is directly connected, %s\n",
                       proto_code,
                       prefix_str,
                       if_name);
        
            } else if (best_nh->action == RTM_NH_ACTION_LOCAL) {
                
                cprintf("%-4s %-18s is local, %s\n",
                                    proto_code,
                                    prefix_str,
                                    if_name);
        
            } else {
                /* Other routes: show with nexthop - format: code prefix [ad/metric] via gateway, time, interface */
                if (cmn_prefix_is_null(&best_nh->prefix)) {
                    /* No explicit nexthop (e.g., blackhole, reject) */
                    cprintf("%-4s %-18s [%u/%u], %s, %s\n",
                           proto_code,
                           prefix_str,
                           best_nh->ad,
                           best_nh->metric,
                           (char *)time_str,
                           if_name);
                } else {
                    /* Normal route with nexthop - Cisco format */
                    cprintf("%-4s %-18s [%u/%u] via %s, %s, %s\n",
                           proto_code,
                           prefix_str,
                           best_nh->ad,
                           best_nh->metric,
                           nh_addr_str,
                           (char *)time_str,
                           if_name);
                }
            }
        }
        
        /* Display additional nexthops for ECMP routes */
        if (active_nh_count > 1) {
            bool first_nh_displayed = false;
            
            ITERATE_GLTHREAD_BEGIN(&route->path_list, curr_glthread) {
                rtm_nh *nh = route_glue_to_rtm_nh(curr_glthread);
                
                if (!nh->is_active) {
                    continue;
                }
                
                /* Skip the first nexthop as it's already displayed */
                if (!first_nh_displayed) {
                    first_nh_displayed = true;
                    continue;
                }
                
                /* Format nexthop address */
                char nh_addr_str[48];
                rtm_format_nexthop(&nh->prefix, nh_addr_str, sizeof(nh_addr_str));
                
                /* Format uptime */
                byte time_str[HRS_MIN_SEC_FMT_TIME_LEN];
                RTM_UP_TIME(nh->install_time, time_str, sizeof(time_str));
                
                /* Get interface name */
                const char *if_name = "-";
                if (nh->oif) {
                    Interface *intf = node_get_intf_by_ifindex(rtm->node, nh->oif);
                    if_name = intf ? intf->if_name.c_str() : "<unknown>";
                } else if (nh->is_indirect && !Fglthread_list_is_empty(&nh->direct_nh_list)) {
                    glthread_t *dnh_glthread = nh->direct_nh_list.head.right;
                    if (dnh_glthread && dnh_glthread != &nh->direct_nh_list.head) {
                        glthread_data_node_t *data_node = glue_to_glthread_data_node(dnh_glthread);
                        rtm_nh *direct_nh = (rtm_nh *)data_node->data;
                        if (direct_nh && direct_nh->oif) {
                            Interface *intf = node_get_intf_by_ifindex(rtm->node, direct_nh->oif);
                            if_name = intf ? intf->if_name.c_str() : "<unknown>";
                        }
                    }
                }
                
                /* Display continuation line for additional nexthops */
                if (!cmn_prefix_is_null(&nh->prefix)) {
                    /* Nexthop has explicit gateway address */
                    cprintf("%-4s %-18s [%u/%u] via %s, %s, %s\n",
                           "",  /* Empty protocol code for continuation lines */
                           "",  /* Empty prefix for continuation lines */
                           nh->ad,
                           nh->metric,
                           nh_addr_str,
                           (char *)time_str,
                           if_name);
                } else {
                    /* Nexthop is interface-only (no explicit gateway) */
                    cprintf("%-4s %-18s [%u/%u], %s, %s\n",
                           "",  /* Empty protocol code for continuation lines */
                           "",  /* Empty prefix for continuation lines */
                           nh->ad,
                           nh->metric,
                           (char *)time_str,
                           if_name);
                }
                
            } ITERATE_GLTHREAD_END(&route->path_list, curr_glthread);
        }
        
        displayed_routes++;

    } ITERATE_AVL_TREE_END(&rtm->route_tree, curr_node);

    if (displayed_routes == 0 && has_filter) {
        cprintf("No routes matching filter\n");
    }
    
    printw("\n");
}

/* Display RIB in detailed format (line by line, not tabular) */
void rtm_show_rib_detail(rtm_t *rtm, const char *prefix_filter) {
    
    /* Parse the prefix filter if provided */
    cmn_prefix_t prefix_key;
    memset (&prefix_key, 0 , sizeof (prefix_key));
    
    bool has_filter = false;
    
    if (prefix_filter && strlen(prefix_filter) > 0) {
        if (!cmn_parse_prefix_string(prefix_filter, &prefix_key)) {
            cprintf("Error: Invalid prefix format '%s'\n", prefix_filter);
            cprintf("Expected formats: x.x.x.x/mask (IPv4), x:x::x/mask (IPv6), or label (MPLS)\n");
            return;
        }
        has_filter = true;
        
        /* Validate AFI matches RTM */
        if (prefix_key.afi != rtm->afi) {
            cprintf("Error: Prefix AFI mismatch. RTM is %s but prefix is %s\n",
                   (rtm->afi == AF_IPV4) ? "IPv4" :
                   (rtm->afi == AF_IPV6) ? "IPv6" :
                   (rtm->afi == AF_LABEL) ? "MPLS" : "Unknown",
                   (prefix_key.afi == AF_IPV4) ? "IPv4" :
                   (prefix_key.afi == AF_IPV6) ? "IPv6" :
                   (prefix_key.afi == AF_LABEL) ? "MPLS" : "Unknown");
            return;
        }
    }
    
    /* If filter is specified, lookup and display only that route */
    if (has_filter) {
        rtm_route *route = rtm_route_lookup(rtm, &prefix_key);
        
        if (!route) {
            char prefix_str[128];
            rtm_format_prefix(&prefix_key, prefix_str, sizeof(prefix_str));
            cprintf("Route %s not found in RTM[%s]\n", prefix_str, rtm->name);
            return;
        }
        
        /* Display the single route */
        rtm_show_single_route_detail(rtm, route);
        return;
    }
    
    /* No filter - display all routes */
    cprintf("VRF: %s, AFI: %s, Table ID: %u\n\n",
           vrf_name(rtm->node, rtm->vrf),
           (rtm->afi == AF_IPV4) ? "IPv4" :
           (rtm->afi == AF_IPV6) ? "IPv6" :
           (rtm->afi == AF_LABEL) ? "MPLS" : "Unknown",
           rtm->rtm_id);
    
    /* Iterate through all routes */
    avltree_node_t *node = avltree_first((avltree_t*)&rtm->route_tree);
    int route_count = 0;
    
    while (node) {
        rtm_route *route = avltree_container_of(node, rtm_route, route_glue);
        route_count++;
        
        rtm_show_single_route_detail(rtm, route);
        
        node = avltree_next(node);
    }
    
    if (route_count == 0) {
        cprintf("No routes in RTM[%s]\n", rtm->name);
    } else {
        cprintf("\n========== Total Routes: %d ==========\n\n", route_count);
    }
}


/* Display nexthop protocol information */
void rtm_show_nh_proto_info(rtm_t *rtm) {

    cprintf("\nRTM :: %s\n", rtm->name); 

    if (avltree_is_empty(&rtm->nh_proto_info_tree)) {
        cprintf("  No nexthop protocol info registered\n\n");
        return;
    }

    cprintf("%-15s %-20s %-12s %-8s %-10s\n",
           "Protocol", "Sub-Protocol", "Instance", "VRF", "Ref Count");
    cprintf("%-15s %-20s %-12s %-8s %-10s\n",
           "--------", "------------", "--------", "---", "---------");

    /* Iterate through all NH protocol info */
    avltree_node_t *curr_node = NULL;
    ITERATE_AVL_TREE_BEGIN(&rtm->nh_proto_info_tree, curr_node) {
        
        rtm_nh_proto_t *nh_proto = avltree_container_of(curr_node, rtm_nh_proto_t, proto_glue);

        cprintf("%-15s %-20s %-12u %-8u %-10u\n",
               rtm_proto_to_string(nh_proto->proto),
               rtm_sub_proto_to_string(nh_proto->sub_proto),
               nh_proto->instance_no,
               nh_proto->vrf_id,
               nh_proto->ref_count);

    } ITERATE_AVL_TREE_END(&rtm->nh_proto_info_tree, curr_node);

    printw("\n");
}

/* Display general protocol information */
void rtm_show_proto_info(rtm_t *rtm) {
    
    cprintf("\nRTM :: %s\n", rtm->name); 

    bool found_any = false;

    /* Iterate through all protocol types */
    for (int proto = 0; proto < RTM_PROTO_MAX; proto++) {
        
        if (avltree_is_empty(&rtm->proto_info_tree[proto])) {
            continue;
        }

        if (!found_any) {
            cprintf("%-15s %-12s %-8s\n",
                   "Protocol", "Instance", "VRF");
            cprintf("%-15s %-12s %-8s\n",
                   "--------", "--------", "---");
            found_any = true;
        }

        /* Iterate through all instances of this protocol */
        avltree_node_t *curr_node = NULL;
        ITERATE_AVL_TREE_BEGIN(&rtm->proto_info_tree[proto], curr_node) {
            
            rtm_proto_info_t *proto_info = avltree_container_of(curr_node, rtm_proto_info_t, proto_glue);

            cprintf("%-15s %-12u %-8u\n",
                   rtm_proto_to_string(proto_info->proto),
                   proto_info->instance_no,
                   proto_info->vrf_id);

        } ITERATE_AVL_TREE_END(&rtm->proto_info_tree[proto], curr_node);
    }

    if (!found_any) {
        cprintf("  No protocol info registered\n");
    }

    printw("\n");
}

/* Display unresolvable nexthops */

/* Display protocol subscriptions */
void rtm_show_protocol_subscriptions(rtm_t *rtm) {

    bool found_any = false;
    int total_subscriptions = 0;

    cprintf("\nRTM : %s\n",  rtm->name);

    /* Iterate through all protocol types */
    for (int proto = 0; proto < RTM_PROTO_MAX; proto++) {
        
        if (avltree_is_empty(&rtm->proto_info_tree[proto])) {
            continue;
        }

        /* Iterate through all instances of this protocol */
        avltree_node_t *proto_node = NULL;
        ITERATE_AVL_TREE_BEGIN(&rtm->proto_info_tree[proto], proto_node) {
            
            rtm_proto_info_t *proto_info = avltree_container_of(proto_node, rtm_proto_info_t, proto_glue);

            /* Check if this protocol has any subscriptions */
            if (avltree_is_empty(&proto_info->sub_db)) {
                continue;
            }

            found_any = true;

            /* Print protocol key header (protocol, instance, VRF) */
            cprintf(" Client : %u.%s.%u\n", proto_info->vrf_id, 
                            rtm_proto_to_string(proto_info->proto),
                            proto_info->instance_no);

            cprintf("  %-15s %-20s %-12s %-15s\n",
                   "Target Proto", "Target Sub-Proto", "Target Inst", "Prefix List");
            cprintf("  %-15s %-20s %-12s %-15s\n",
                   "------------", "----------------", "-----------", "-----------");

            /* Iterate through subscriptions for this protocol */
            avltree_node_t *sub_node = NULL;
            ITERATE_AVL_TREE_BEGIN(&proto_info->sub_db, sub_node) {
                
                rtm_rt_subscription_t *sub = avltree_container_of(sub_node, rtm_rt_subscription_t, avl_glue);
                total_subscriptions++;

                const char *prefix_list_str = sub->prefix_list ? 
                    (const char *)sub->prefix_list->name : "None";

                cprintf("  %-15s %-20s %-12u %-15s\n",
                       rtm_proto_to_string(sub->target_proto),
                       rtm_sub_proto_to_string(sub->target_sub_proto),
                       sub->target_instance_no,
                       prefix_list_str);

            } ITERATE_AVL_TREE_END(&proto_info->sub_db, sub_node);

            printw("\n");

        } ITERATE_AVL_TREE_END(&rtm->proto_info_tree[proto], proto_node);
    }

    if (!found_any) {
        cprintf("  No protocol subscriptions registered\n");
    } else {
        cprintf("Total Subscriptions: %d\n", total_subscriptions);
    }

    printw("\n");
}

/* Display unresolvable routes (indirect nexthops that cannot be resolved) */

void rtm_show_unresolvable_routes(rtm_t *rtm) {
    

    cprintf("\nRTM : %s\n",  rtm->name);

    /* Check if there are any unresolvable paths */
    if (Fglthread_list_is_empty(&rtm->unresolvable_paths)) {
        cprintf("  No unresolvable routes\n\n");
        return;
    }

    /* Display header */
    cprintf("%-20s %-12s %-15s %-10s %-10s %-15s %-8s\n",
           "Route Prefix", "Protocol", "Gateway", "Action", "Metric", "OIF", "Active");
    cprintf("%-20s %-12s %-15s %-10s %-10s %-15s %-8s\n",
           "------------", "--------", "-------", "------", "------", "---", "------");

    /* Iterate through unresolvable paths */
    glthread_t *curr_glue = NULL;
    int count = 0;
    
    ITERATE_GLTHREAD_BEGIN(&rtm->unresolvable_paths.head, curr_glue) {
        
        rtm_nh *indirect_nh = unresolvable_list_glue_to_rtm_nh(curr_glue);
        count++;

        /* Get the route prefix from the owner route */
        char route_prefix_str[128] = "N/A";
        if (indirect_nh->owner_route) {
            rtm_format_prefix(&indirect_nh->owner_route->prefix, route_prefix_str, sizeof(route_prefix_str));
        }

        /* Format gateway/nexthop */
        char gateway_str[128];
        rtm_format_nexthop(&indirect_nh->prefix, gateway_str, sizeof(gateway_str));

        /* Get action string */
        const char *action_str = rtm_nh_action_to_string(indirect_nh->action);

        /* Get OIF name */
        const char *oif_str = "-";
        if (indirect_nh->oif) {
            Interface *ind_intf = node_get_intf_by_ifindex(rtm->node, indirect_nh->oif);
            oif_str = ind_intf ? ind_intf->if_name.c_str() : "<unknown>";
        }

        /* Display the unresolvable route information */
        cprintf("%-20s %-12s %-15s %-10s %-10u %-15s %-8s\n",
               route_prefix_str,
               rtm_proto_to_string(indirect_nh->proto),
               gateway_str,
               action_str,
               indirect_nh->metric,
               oif_str,
               indirect_nh->is_active ? "Yes" : "No");

    } ITERATE_GLTHREAD_END(&rtm->unresolvable_paths.head, curr_glue);

    cprintf("\nTotal Unresolvable Routes: %d\n\n", count);
}

void 
rtm_show_presentation_db(rtm_t *rtm, char *prefix_filter) {
    
    if (!rtm) {
        cprintf("RTM is NULL\n");
        return;
    }
    
    avltree_t *ppt_db_tree = &rtm->ppt_db_route_tree;
    
    if (avltree_is_empty(ppt_db_tree)) {
        cprintf("Presentation database is empty\n");
        return;
    }
    
    /* Parse filter if provided */
    cmn_prefix_t filter_prefix;
    bool has_filter = false;
    
    if (prefix_filter && strlen(prefix_filter) > 0) {
        char prefix_copy[64];
        strncpy(prefix_copy, prefix_filter, sizeof(prefix_copy) - 1);
        prefix_copy[sizeof(prefix_copy) - 1] = '\0';
        
        char *slash = strchr(prefix_copy, '/');
        if (slash) {
            *slash = '\0';
            filter_prefix.prefix_len = atoi(slash + 1);
        } else {
            filter_prefix.prefix_len = 32;  // Default to /32
        }
        
        filter_prefix.afi = AF_IPV4;
        if (inet_pton(AF_INET, prefix_copy, &filter_prefix.u.v4_addr) == 1) {
            filter_prefix.u.v4_addr = ntohl(filter_prefix.u.v4_addr);
            has_filter = true;
        }
    }
    
    printw("\n");
    cprintf("RTM Presentation Database :: %s\n", rtm->name);
    if (has_filter) {
        char filter_str[48];
        rtm_format_prefix(&filter_prefix, filter_str, sizeof(filter_str));
        cprintf("Filter: %s\n", filter_str);
    }
    
    int total_routes = 0;
    avltree_node_t *route_node;
    rtm_ppt_route_t *ppt_route;
    
    /* Iterate through all routes in the presentation database */
    ITERATE_AVL_TREE_BEGIN(ppt_db_tree, route_node) {
        
        ppt_route = avltree_container_of(route_node, rtm_ppt_route_t, route_glue);
        
        /* Apply filter if specified */
        if (has_filter) {
            if (ppt_route->prefix.afi != filter_prefix.afi ||
                ppt_route->prefix.prefix_len != filter_prefix.prefix_len ||
                ppt_route->prefix.u.v4_addr != filter_prefix.u.v4_addr) {
                continue;
            }
        }
        
        total_routes++;
        
        /* Format route prefix */
        char prefix_str[48];
        rtm_format_prefix(&ppt_route->prefix, prefix_str, sizeof(prefix_str));
        
        cprintf("Route: %-20s(%p)  NHs: %u\n", 
               prefix_str, 
               ppt_route,
               ppt_route->nhidx_list_count);
        
        /* Display each nexthop */
        for (int i = 0; i < ppt_route->nhidx_list_count; i++) {
            rtm_ppt_nhidx_t *nh_entry = &ppt_route->nhidx_list[i];
            
            cprintf("  [%d] NH idx: %-5u", i, nh_entry->nh_pidx);
            
            if (nh_entry->dnh_list_count > 0) {
                cprintf("  DNHs(%u): [", nh_entry->dnh_list_count);
                for (int j = 0; j < nh_entry->dnh_list_count; j++) {
                    cprintf("%u", nh_entry->dnh_list[j]);
                    if (j < nh_entry->dnh_list_count - 1) {
                        cprintf(", ");
                    }
                }
                cprintf("]");
            }
            printw("\n");
        }
        printw("\n");
        
    } ITERATE_AVL_TREE_END;
    
    if (total_routes == 0 && has_filter) {
        cprintf("No routes matching filter\n\n");
    }
    
    cprintf("Total Routes in Presentation DB: %d\n", total_routes);
}

void
rtm_show_dist_mgr_database (dist_mgr_t *dist_mgr) {

    if (!dist_mgr) return;

    avltree_node_t *avl_node;
    rt_redist_route_t *redis_rt;
    char prefix_str[48];
    int entry_count = 0;

    cprintf("\n%-26s %-12s %-16s %-20s %-16s\n",
            "Route", "Proto", "Sub-Proto", "Cnhidx", "VRF");
    cprintf("%-26s %-12s %-16s %-20s %-16s\n",
            "--------------------------", "------------",
            "----------------", "--------------------", "----------------");

    ITERATE_AVL_TREE_BEGIN(&dist_mgr->nhidx_tree, avl_node)
    {
        redis_rt = avltree_container_of(avl_node, rt_redist_route_t, nhidx_glue);

        cmn_prefix_to_string(&redis_rt->prefix, &prefix_str);

        cprintf("%-26s %-12s %-16s 0x%-18llx %-16s\n",
                prefix_str,
                rtm_proto_to_string(redis_rt->nh_proto->proto),
                rtm_sub_proto_to_string(redis_rt->nh_proto->sub_proto),
                (unsigned long long)redis_rt->Cnhidx,
                vrf_name(dist_mgr->node, redis_rt->nh_proto->vrf_id));

        entry_count++;
    }
    ITERATE_AVL_TREE_END;

    cprintf("\nTotal: %d entr%s\n", entry_count, entry_count == 1 ? "y" : "ies");
}

static void
rtm_show_dist_mgr_comm_fmt(uint32_t wc, char *buf, size_t buflen)
{
    uint32_t hi = (wc >> 16) & 0xFFFFu;
    uint32_t lo = wc & 0xFFFFu;

    snprintf(buf, buflen, "%u:%u", hi, lo);
}

/* Reconstruct the exact "redistribute ..." CLI line that would create
   `rule`. Only fields that the CLI actually exposes are emitted; defaults
   that the user could not have typed are dropped so the output round-trips
   through the parser. */
static void
rtm_dist_rule_format_cli(const dist_rule_t *rule, char *buf, size_t buflen)
{
    int n = snprintf(buf, buflen, "redistribute %s",
                     rtm_proto_to_cli_keyword(rule->src_proto));

    if (n < 0 || (size_t)n >= buflen) return;

    if (rule->pfx_lst) {
        n += snprintf(buf + n, buflen - n, " prefix-list %s",
                      (const char *)rule->pfx_lst->name);
        if (n < 0 || (size_t)n >= buflen) return;
    }

    if (rule->out_cost) {
        snprintf(buf + n, buflen - n, " metric %u",
                 (unsigned)rule->out_cost);
    }
}

void
rtm_show_dist_mgr_policies(dist_mgr_t *dist_mgr)
{
    redist_target_t *target;
    dist_rule_t *rule;
    int rule_no;
    char comm_buf[24];

    if (!dist_mgr)
        return;

    printw("\n");
    cprintf("RTM redistribution policies\n");

    target = dist_mgr->target_lst;
    if (!target) {
        cprintf("No redistribution targets configured.\n\n");
        return;
    }

    for (target = dist_mgr->target_lst; target; target = target->next) {
        char vrf_buf[48];
        char client_id[128];
        const char *vrf_str = target->vrf->vrf_name;

        snprintf(vrf_buf, sizeof(vrf_buf), "%s", vrf_str);

        snprintf(
            client_id,
            sizeof(client_id),
            "%s.%s.%u",
            vrf_buf,
            rtm_proto_to_string(target->proto),
            (unsigned)target->instance_no);

        cprintf("\nClient : %s\n", client_id);
        cprintf(
            "------------------------------------------------------------------\n");

        rule = target->rule_list;
        if (!rule) {
            cprintf("  (no rules)\n");
            continue;
        }

        rule_no = 0;
        for (; rule; rule = rule->next, rule_no++) {
            const char *pfx_str;
            char pfx_line[PFX_LST_NAME_LEN + 4];

            if (rule->pfx_lst) {
                snprintf(
                    pfx_line,
                    sizeof(pfx_line),
                    "%s",
                    (const char *)rule->pfx_lst->name);
                pfx_str = pfx_line;
            } else {
                pfx_str = "(any)";
            }

            rtm_show_dist_mgr_comm_fmt(rule->out_community, comm_buf, sizeof(comm_buf));

            cprintf("  Rule %d\n", rule_no + 1);

            char cli_buf[256];
            rtm_dist_rule_format_cli(rule, cli_buf, sizeof(cli_buf));
            cprintf("    CLI: %s\n", cli_buf);

            cprintf("    Source\n");
            cprintf(
                "      %-14s %s\n",
                "Src-VRF:",
                vrf_buf);
            cprintf(
                "      %-14s %s\n",
                "Protocol:",
                rtm_proto_to_string(rule->src_proto));
            cprintf(
                "      %-14s %s\n",
                "Sub-protocol:",
                rtm_sub_proto_to_string(rule->src_sub_proto));
            cprintf(
                "      %-14s %u\n",
                "Instance:",
                (unsigned)rule->src_instance_no);

            cprintf("    Filter\n");
            cprintf(
                "      %-14s %s\n",
                "Prefix-list:",
                pfx_str);

            cprintf("    Action\n");
            cprintf(
                "      %-14s %u\n",
                "Metric:",
                (unsigned)rule->out_cost);
            cprintf(
                "      %-14s %u\n",
                "Tag:",
                (unsigned)rule->out_tag);
            cprintf(
                "      %-14s %s\n",
                "Community:",
                comm_buf);

            cprintf(
                "------------------------------------------------------------------\n");
        }
    }

    printw("\n");
}

void
rtm_show_dist_mgr_targets (dist_mgr_t *dist_mgr,
                           char *vrf_name_in,
                           char *proto_name,
                           uint32_t instance_no)
{
    if (!dist_mgr) {
        cprintf("Error : distribution manager is NULL\n");
        return;
    }

    if (!proto_name) {
        cprintf("Error : protocol name missing\n");
        return;
    }

    /* Resolve target proto */
    RTM_PROTO_T target_proto = rtm_string_to_protocol_enum(proto_name);
    if (target_proto >= RTM_PROTO_MAX) {
        cprintf("Error : unknown protocol '%s'\n", proto_name);
        return;
    }

    /* Resolve target VRF (NULL => default VRF) */
    vrf_t *vrf = vrf_get_by_name(dist_mgr->node, vrf_name_in);
    if (!vrf) {
        cprintf("Error : VRF '%s' not found\n",
                vrf_name_in ? vrf_name_in : "default");
        return;
    }
    uint8_t target_vrf_id = vrf->vrf_id;

    /* Locate the target */
    redist_target_t *target = NULL;
    for (redist_target_t *t = dist_mgr->target_lst; t; t = t->next) {
        if (t->proto == target_proto &&
            t->instance_no == instance_no &&
            t->vrf->vrf_id == target_vrf_id) {
            target = t;
            break;
        }
    }

    if (!target) {
        cprintf("redistribution target %s.%s.%u not found\n",
                vrf->vrf_name,
                rtm_proto_to_string(target_proto),
                instance_no);
        return;
    }

    printw("\n");
    cprintf("Routes advertised to target : %s.%s.%u\n",
            vrf->vrf_name,
            rtm_proto_to_string(target_proto),
            instance_no);

    if (avltree_is_empty(&target->rt_advertised)) {
        cprintf("  (no routes advertised)\n\n");
        return;
    }

    /* Tabular header */
    cprintf("%-4s %-26s %-12s %-14s %-12s %-10s %-20s\n",
            "#", "Route", "Src-Proto", "Src-Sub-Proto",
            "Src-VRF", "Src-Inst", "Cnhidx");
    cprintf("%-4s %-26s %-12s %-14s %-12s %-10s %-20s\n",
            "----", "--------------------------",
            "------------", "--------------",
            "------------", "----------",
            "--------------------");

    avltree_node_t *avl_node;
    rt_advertised_node_t *adv_node;
    rt_redist_route_t *dist_rt;
    char prefix_str[48];
    int idx = 0;

    ITERATE_AVL_TREE_BEGIN(&target->rt_advertised, avl_node)
    {
        adv_node = avltree_container_of(avl_node, rt_advertised_node_t, glue);
        dist_rt = adv_node->dist_rt;
        if (!dist_rt || !dist_rt->nh_proto) continue;

        rtm_format_prefix(&dist_rt->prefix, prefix_str, sizeof(prefix_str));

        const char *src_vrf_name = vrf_name(dist_mgr->node,
                                            dist_rt->nh_proto->vrf_id);

        cprintf("%-4d %-26s %-12s %-14s %-12s %-10u 0x%-18llx\n",
                ++idx,
                prefix_str,
                rtm_proto_to_string(dist_rt->nh_proto->proto),
                rtm_sub_proto_to_string(dist_rt->nh_proto->sub_proto),
                src_vrf_name ? src_vrf_name : "?",
                dist_rt->nh_proto->instance_no,
                (unsigned long long)dist_rt->Cnhidx);
    }
    ITERATE_AVL_TREE_END;

    cprintf("\nTotal advertised routes : %d\n\n", idx);
}

/* For each redistribution source row (same prefix, different NH / Cnhidx), list
 * every target client that currently has this route in rt_advertised and show
 * the metric/tag/community from the first matching redistribute rule (same
 * logic as live advertisement).  Attributes are not stored per-advertisement;
 * they are derived from policy at show time. */
void
rtm_show_dist_mgr_target_route(dist_mgr_t *dist_mgr, const char *prefix_str)
{
    cmn_prefix_t key;
    avltree_node_t *avl_node;
    avl_prefix_node_t *pfx_node;
    glthread_t *curr;
    int inst = 0;

    if (!dist_mgr) {
        cprintf("Error : distribution manager is NULL\n");
        return;
    }
    if (!prefix_str || !prefix_str[0]) {
        cprintf("Error : prefix is required\n");
        return;
    }
    memset(&key, 0, sizeof(key));
    if (!cmn_parse_prefix_string(prefix_str, &key)) {
        cprintf("Error : invalid prefix '%s'\n", prefix_str);
        return;
    }

    avl_prefix_node_t pfx_tmplate;
    memcpy(&pfx_tmplate.prefix, &key, sizeof(pfx_tmplate.prefix));
    avltree_node_init(&pfx_tmplate.glue);

    avl_node = avltree_lookup(&pfx_tmplate.glue, &dist_mgr->route_tree_by_prefix);
    if (!avl_node) {
        char ps[128];
        rtm_format_prefix(&key, ps, sizeof(ps));
        cprintf("\nNo redistribution state for prefix %s (prefix not in dist-mgr)\n\n", ps);
        return;
    }

    pfx_node = avltree_container_of(avl_node, avl_prefix_node_t, glue);
    if (Fglthread_list_is_empty(&pfx_node->rt_pfx_lst)) {
        char ps[128];
        rtm_format_prefix(&key, ps, sizeof(ps));
        cprintf("\nNo redistribution entries linked for prefix %s\n\n", ps);
        return;
    }

    char ps[128];
    rtm_format_prefix(&key, ps, sizeof(ps));
    cprintf("\nRTM dist-mgr: redistribution by target for prefix %s\n", ps);
    cprintf("============================================================\n");

    ITERATE_GLTHREAD_BEGIN(&pfx_node->rt_pfx_lst.head, curr)
    {
        rt_redist_route_t *dist_rt = (rt_redist_route_t *)((char *)curr -
                offsetof(rt_redist_route_t, rt_pfx_lst_glue));
        redist_target_t *target;
        char rt_line[128];
        int n_clients = 0;

        if (!dist_rt->nh_proto)
            continue;

        inst++;
        rtm_format_prefix(&dist_rt->prefix, rt_line, sizeof(rt_line));
        cprintf("\nRedist source #%d  %s\n", inst, rt_line);
        cprintf("  Cnhidx       : 0x%llx\n",
                (unsigned long long)dist_rt->Cnhidx);
        cprintf("  Source       : %s / %s  vrf=%s  instance=%u\n",
                rtm_proto_to_string(dist_rt->nh_proto->proto),
                rtm_sub_proto_to_string(dist_rt->nh_proto->sub_proto),
                vrf_name(dist_mgr->node, dist_rt->nh_proto->vrf_id)
                    ? vrf_name(dist_mgr->node, dist_rt->nh_proto->vrf_id)
                    : "?",
                dist_rt->nh_proto->instance_no);
        cprintf("  State        : %s\n",
                dist_rt->is_deleted ? "deleted (withdraw pending)" : "active");

        cprintf("  Advertised to clients:\n");

        for (target = dist_mgr->target_lst; target; target = target->next) {

            if (!redist_route_is_advertised_to_client(dist_rt, target))
                continue;

            n_clients++;

            char vrf_buf[48];
            const char *vrf_str = target->vrf->vrf_name;
            snprintf(vrf_buf, sizeof(vrf_buf), "%s", vrf_str);

            cprintf("    - %s.%s.%u\n",
                    vrf_buf,
                    rtm_proto_to_string(target->proto),
                    (unsigned)target->instance_no);

            if (dist_rt->is_deleted) {
                cprintf("        Note: route deleted; client should receive withdraw\n");
                continue;
            }

            dist_rule_t *rule = NULL;
            if (!rtm_dist_mgr_target_first_permitting_rule(target, dist_rt,
                                                            &rule)) {
                cprintf("        Policy: no matching permit rule now "
                        "(advertised; may be stale until policy refresh)\n");
                continue;
            }

            char comm_buf[24];
            rtm_show_dist_mgr_comm_fmt(rule->out_community, comm_buf,
                                       sizeof(comm_buf));

            cprintf("        Rule metric (out_cost) : %u\n",
                    (unsigned)rule->out_cost);
            cprintf("        Rule tag               : %u\n",
                    (unsigned)rule->out_tag);
            cprintf("        Rule community         : %s\n", comm_buf);
            if (rule->pfx_lst) {
                cprintf("        Prefix-list filter     : %s\n",
                        (const char *)rule->pfx_lst->name);
            } else {
                cprintf("        Prefix-list filter     : (none)\n");
            }
        }

        if (n_clients == 0)
            cprintf("    (not advertised to any redistribution target)\n");

    } ITERATE_GLTHREAD_END(&pfx_node->rt_pfx_lst.head, curr);

    cprintf("\n");
}

} /* extern "C" */

int 
rtm_show_dist_mgr_database_handler (int cmdcode,
    Stack_t *tlv_stack,
    op_mode enable_or_disable)
{
    node_t *node = NULL;
    c_string node_name = NULL;
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv)
    {
        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    rtm_show_dist_mgr_database(node->dist_mgr);
    return 0;
}

int
rtm_show_dist_mgr_policies_handler(int cmdcode,
                                   Stack_t *tlv_stack,
                                   op_mode enable_or_disable)
{
    node_t *node = NULL;
    c_string node_name = NULL;
    tlv_struct_t *tlv = NULL;

    (void)cmdcode;
    (void)enable_or_disable;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv)
    {
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
    }
    TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    rtm_show_dist_mgr_policies(node->dist_mgr);
    return 0;
}

int
rtm_show_dist_mgr_targets_handler(int cmdcode,
                                  Stack_t *tlv_stack,
                                  op_mode enable_or_disable)
{
    node_t *node = NULL;
    c_string node_name = NULL;
    c_string proto_name = NULL;
    c_string vrf_name_in = NULL;
    uint32_t instance_no = 0;
    tlv_struct_t *tlv = NULL;

    (void)cmdcode;
    (void)enable_or_disable;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv)
    {
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "proto-name"))
            proto_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "vrf-name"))
            vrf_name_in = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "instance-no"))
            instance_no = (uint32_t)atoi((const char *)tlv->value);
    }
    TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    rtm_show_dist_mgr_targets(node->dist_mgr,
                              (char *)vrf_name_in,
                              (char *)proto_name,
                              instance_no);
    return 0;
}

int
rtm_show_dist_mgr_target_route_handler(int cmdcode,
                                       Stack_t *tlv_stack,
                                       op_mode enable_or_disable)
{
    node_t *node = NULL;
    c_string node_name = NULL;
    c_string route_prefix = NULL;
    tlv_struct_t *tlv = NULL;

    (void)cmdcode;
    (void)enable_or_disable;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv)
    {
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "route-prefix"))
            route_prefix = tlv->value;
    }
    TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    rtm_show_dist_mgr_target_route(node->dist_mgr, (const char *)route_prefix);
    return 0;
}