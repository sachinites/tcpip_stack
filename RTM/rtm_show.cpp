#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../Tree/libtree.h"
#include "../gluethread/glthread.h"
#include "../Interface/InterfaceUApi.h"
#include "../graph.h"
#include "rtm_show.h"
#include "rtm.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_proto.h"
#include "rtm_enums.h"
#include "rtm_priv_api.h"
#include "rtm_presentation.h"
#include "../prefix-list/prefixlst.h"
#include "../common/mpls_lstack.h"

extern int cprintf (const char * format, ...);

/* Forward declaration */
static void rtm_show_single_route_detail(rtm_t *rtm, rtm_route *route);

/* Helper function to display a single route in detail */
static void rtm_show_single_route_detail(rtm_t *rtm, rtm_route *route) {

    char prefix_str[128];
    byte time_str[HRS_MIN_SEC_FMT_TIME_LEN];
    
    rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str));
    
    /* Display route prefix and attributes */
    cprintf("\nRoute: %s\n", prefix_str);
    cprintf("========================================\n");
    cprintf("  Nexthop Count  : %u\n", route->nh_count);
    cprintf("  Flags          : 0x%04x\n", route->flags);
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
            cprintf("    [%d] %s, %s\n", 
                resolved_count, inh_prefix_str, 
                rtm_proto_to_string (indirect_nh->proto));

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
        cprintf("    Idx            : %u\n", nh->idx);
        cprintf("    Protocol       : %s\n", rtm_proto_to_string(nh->proto));
        cprintf("    Sub-Protocol   : %s\n", rtm_sub_proto_to_string(nh->sub_proto));
        cprintf("    Next-Hop       : %s\n", nh_prefix_str);
        cprintf("    Action         : %s\n", rtm_nh_action_to_string(nh->action));
        cprintf("    OIF            : %s\n", (nh->oif) ?  \
            node_get_intf_by_ifindex(rtm->node, nh->oif)->if_name.c_str() : "-");
        cprintf("    Admin Distance : %u\n", nh->ad);
        cprintf("    Metric         : %u\n", nh->metric);
        cprintf("    Resolved       : %s\n", rtm_nh_is_resolved(nh) ? "Yes" : "No");
        cprintf("    Indirect       : %s\n", nh->is_indirect ? "Yes" : "No");
        
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
                    
                    cprintf("        [%d] %s, %s, %s\n",
                           direct_nh->idx,
                           direct_nh_prefix_str,
                           node_get_intf_by_ifindex(rtm->node, direct_nh->oif)->if_name.c_str(),
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
            for (int i = 0; i < nh->label_stack->curr_index; i++) {
                mpls_label_t *label = &nh->label_stack->labels[i];
                const char *op_str = "UNK";
                switch (label->op) {
                    case MPLS_OP_SWAP: op_str = "Swap"; break;
                    case MPLS_OP_PUSH: op_str = "Push"; break;
                    case MPLS_OP_POP: op_str = "Pop"; break;
                    default: break;
                }
                cprintf("[%u:%s]", label->label_val, op_str);
                if (i < nh->label_stack->curr_index - 1) {
                    cprintf(" -> ");
                }
            }
            printw("\n");
        }
        
    } ITERATE_GLTHREAD_END(&route->path_list, curr_glthread);

    /* Blank line after route display */
    printw("\n");
}

/* Helper function to get protocol code for Cisco-style display */
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
                default:
                    return "I";
            }
        case RTM_PROTO_LDP:
            return "D";
        case RTM_PROTO_SR:
            return "SR";
        case RTM_PROTO_SRTE:
            return "SR-TE";
        default:
            return "?";
    }
}

extern "C" {

/* Display RIB (Routing Information Base) in Cisco style */
void rtm_show_rib_standard(rtm_t *rtm, char *prefix_filter) {

    cprintf("\n");
    
    /* Display legend/codes - Cisco style */
    cprintf("Codes: I - IGRP derived, R - RIP derived, O - OSPF derived\n");
    cprintf("       C - connected, S - static, E - EGP derived, B - BGP derived\n");
    cprintf("       * - candidate default route, IA - OSPF inter area route\n");
    cprintf("       E1 - OSPF external type 1 route, E2 - OSPF external type 2 route\n");
    cprintf("       L1 - ISIS level-1, L2 - ISIS level-2\n");
    
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
                if_name = node_get_intf_by_ifindex(rtm->node, best_nh->oif)->if_name.c_str();
            } else if (best_nh->is_indirect && !Fglthread_list_is_empty(&best_nh->direct_nh_list)) {
                /* For indirect nexthops, try to get interface from first direct nexthop */
                glthread_t *dnh_glthread = best_nh->direct_nh_list.head.right;
                if (dnh_glthread && dnh_glthread != &best_nh->direct_nh_list.head) {
                    glthread_data_node_t *data_node = glue_to_glthread_data_node(dnh_glthread);
                    rtm_nh *direct_nh = (rtm_nh *)data_node->data;
                    if (direct_nh && direct_nh->oif) {
                        if_name = node_get_intf_by_ifindex(rtm->node, direct_nh->oif)->if_name.c_str();
                    }
                }
            }
            
            /* Determine the display format based on action type - Cisco style */
            if (best_nh->action == RTM_NH_ACTION_CONNECTED || 
                best_nh->action == RTM_NH_ACTION_LOCAL) {
                /* Connected/Local routes: show as directly connected */
                cprintf("%-4s %-18s is directly connected, %s\n",
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
                    if_name = node_get_intf_by_ifindex(rtm->node, nh->oif)->if_name.c_str();
                } else if (nh->is_indirect && !Fglthread_list_is_empty(&nh->direct_nh_list)) {
                    glthread_t *dnh_glthread = nh->direct_nh_list.head.right;
                    if (dnh_glthread && dnh_glthread != &nh->direct_nh_list.head) {
                        glthread_data_node_t *data_node = glue_to_glthread_data_node(dnh_glthread);
                        rtm_nh *direct_nh = (rtm_nh *)data_node->data;
                        if (direct_nh && direct_nh->oif) {
                            if_name = node_get_intf_by_ifindex(rtm->node, direct_nh->oif)->if_name.c_str();
                        }
                    }
                }
                
                /* Display continuation line for additional nexthops */
                if (!cmn_prefix_is_null(&nh->prefix)) {
                    cprintf("%-4s %-18s [%u/%u] via %s, %s, %s\n",
                           "",  /* Empty protocol code for continuation lines */
                           "",  /* Empty prefix for continuation lines */
                           nh->ad,
                           nh->metric,
                           nh_addr_str,
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
    
    cprintf("\n");
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
    cprintf("\n========== RTM[%s] Detailed Route Information ==========\n", rtm->name);
    cprintf("VRF: %u, AFI: %s, Table ID: %u\n\n",
           rtm->vrf,
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
            oif_str = node_get_intf_by_ifindex(
                rtm->node, indirect_nh->oif)->if_name.c_str();
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
    
    cprintf("\n");
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
            cprintf("\n");
        }
        cprintf("\n");
        
    } ITERATE_AVL_TREE_END;
    
    if (total_routes == 0 && has_filter) {
        cprintf("No routes matching filter\n\n");
    }
    
    cprintf("Total Routes in Presentation DB: %d\n", total_routes);
}

} // extern "C"
