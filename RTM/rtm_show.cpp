#include <stdio.h>
#include <string.h>
#include "../Tree/libtree.h"
#include "../gluethread/glthread.h"
#include "../Interface/InterfaceUApi.h"
#include "rtm_show.h"
#include "rtm.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_proto.h"
#include "rtm_enums.h"
#include "rtm_common.h"
#include "rtm_priv_api.h"

extern int cprintf (const char * format, ...);

/* Display RIB (Routing Information Base) */
void rtm_show_rib(rtm_t *rtm) {

    cprintf("\nRIB :: VRF: %u, AFI: %s, RTM ID: %u\n", 
           rtm->vrf, rtm_afi_to_string(rtm->afi), rtm->rtm_id);
    cprintf("========================================\n\n");

    if (avltree_is_empty(&rtm->route_tree)) {
        cprintf("  No routes in RIB\n\n");
        return;
    }

    cprintf("%-25s %-10s %-11s %-18s %-10s %-8s %-8s %-20s\n",
           "Route", "Protocol", "Action", "Next-Hop", "OIF", "AD", "Metric", "Label Stack");
    cprintf("%-25s %-10s %-11s %-18s %-10s %-8s %-8s %-20s\n",
           "------", "--------", "------", "--------", "---", "--", "------", "-----------");

    /* Iterate through all routes in the tree */
    avltree_node_t *curr_node = NULL;
    ITERATE_AVL_TREE_BEGIN(&rtm->route_tree, curr_node) {
        
        rtm_route *route = avltree_container_of(curr_node, rtm_route, route_glue);
        char prefix_str[128];
        rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str));

        /* Iterate through all nexthops in the route */
        glthread_t *curr_glthread = NULL;
        ITERATE_GLTHREAD_BEGIN(&route->path_list, curr_glthread) {
            
            rtm_nh *nh = route_glue_to_rtm_nh(curr_glthread);
            char nh_prefix_str[128];
            rtm_format_nexthop(&nh->prefix, nh_prefix_str, sizeof(nh_prefix_str));

            /* Format label stack if present */
            char label_stack_str[128] = "-";
            if (nh->label_stack && nh->label_stack->curr_index > 0) {
                char temp[64];
                label_stack_str[0] = '\0';
                for (int i = 0; i < nh->label_stack->curr_index; i++) {
                    const char *op_str = "";
                    switch (nh->label_stack->labels[i].op) {
                        case RTM_LBL_SWAP: op_str = "SWAP"; break;
                        case RTM_LBL_PUSH: op_str = "PUSH"; break;
                        case RTM_LBL_POP: op_str = "POP"; break;
                        default: op_str = "UNK"; break;
                    }
                    if (nh->label_stack->labels[i].op != RTM_LBL_STACK_OPS_UNKNOWN) {
                        snprintf(temp, sizeof(temp), "%s%s:%u", 
                                i > 0 ? "," : "",
                                op_str, 
                                nh->label_stack->labels[i].label_val);
                        strncat(label_stack_str, temp, sizeof(label_stack_str) - strlen(label_stack_str) - 1);
                    }
                }
            }

            cprintf("%-25s %-10s %-11s %-18s %-10s %-8u %-8u %-20s\n",
                   prefix_str,
                   rtm_proto_to_string(nh->proto),
                   rtm_nh_action_to_string(nh->action),
                   nh_prefix_str,
                   nh->Oif->if_name.c_str(),
                   nh->ad,
                   nh->metric,
                   label_stack_str);

            /* Print only prefix on first line, empty for subsequent nexthops of same route */
            prefix_str[0] = '\0';
            
        } ITERATE_GLTHREAD_END(&route->path_list, curr_glthread);

    } ITERATE_AVL_TREE_END(&rtm->route_tree, curr_node);

    cprintf("\n");
}

/* Display RIB in detailed format (line by line, not tabular) */
void rtm_show_rib_detail(rtm_t *rtm) {
    if (!rtm) {
        cprintf("Error: NULL RTM pointer\n");
        return;
    }

    cprintf("RIB :: VRF:%u AFI:%s RTM ID: %u\n", 
           rtm->vrf, rtm_afi_to_string(rtm->afi), rtm->rtm_id);
    cprintf("========================================\n\n");

    if (avltree_is_empty(&rtm->route_tree)) {
        cprintf("  No routes in RIB\n\n");
        return;
    }

    /* Iterate through all routes in the tree */
    avltree_node_t *curr_node = NULL;
    int route_count = 0;
    
    ITERATE_AVL_TREE_BEGIN(&rtm->route_tree, curr_node) {
        
        rtm_route *route = avltree_container_of(curr_node, rtm_route, route_glue);
        char prefix_str[128];
        rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str));

        route_count++;
        
        /* Display route prefix and attributes */
        cprintf("Route %d:\n", route_count);
        cprintf("  Prefix         : %s\n", prefix_str);
        cprintf("  Nexthop Count  : %u\n", route->nh_count);
        cprintf("  Flags          : 0x%04x\n", route->flags);
        cprintf("  Ref Count      : %u\n", route->ref_count);

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
            cprintf("    OIF            : %s\n", nh->Oif->if_name.c_str());
            cprintf("    Admin Distance : %u\n", nh->ad);
            cprintf("    Metric         : %u\n", nh->metric);
            cprintf("    Resolved       : %s\n", nh->is_resolved ? "Yes" : "No");
            cprintf("    Indirect       : %s\n", nh->is_indirect ? "Yes" : "No");
            cprintf ("    Active         : %s\n", nh->is_active ? "Yes" : "No");
            cprintf("    Ref Count      : %u\n", nh->ref_count);
            
            /* Display label stack if present */
            if (nh->label_stack && nh->label_stack->curr_index > 0) {

                cprintf("    Label Stack    : ");

                for (int i = 0; i < nh->label_stack->curr_index; i++) {

                    const char *op_str = "";

                    switch (nh->label_stack->labels[i].op) {
                        case RTM_LBL_SWAP: op_str = "SWAP"; break;
                        case RTM_LBL_PUSH: op_str = "PUSH"; break;
                        case RTM_LBL_POP: op_str = "POP"; break;
                        default: op_str = "UNK"; break;
                    }
                    
                    if (nh->label_stack->labels[i].op != RTM_LBL_STACK_OPS_UNKNOWN) {
                        cprintf("%s%s:%u", 
                            i > 0 ? ", " : "",
                            op_str, 
                            nh->label_stack->labels[i].label_val);
                    }
                }
                cprintf("\n");
            } else {
                cprintf("    Label Stack    : None\n");
            }
            
        } ITERATE_GLTHREAD_END(&route->path_list, curr_glthread);

        /* Blank line before next route */
        cprintf("\n");

    } ITERATE_AVL_TREE_END(&rtm->route_tree, curr_node);

    cprintf("Total Routes: %d\n\n", route_count);
}

/* Display FIB (Forwarding Information Base) */
void rtm_show_fib(rtm_t *rtm) {

    cprintf("FIB :: VRF:%u AFI:%s RTM ID: %u\n", 
           rtm->vrf, rtm_afi_to_string(rtm->afi), rtm->rtm_id);
    cprintf("========================================\n\n");

    if (avltree_is_empty(&rtm->route_tree)) {
        cprintf("  No routes in FIB\n\n");
        return;
    }

    cprintf("%-25s %-15s %-10s\n",
           "Prefix", "Next-Hop", "OIF");
    cprintf("%-25s %-15s %-10s\n",
           "------", "--------", "---");

    bool has_active_routes = false;

    /* Iterate through all routes and show only those with active nexthops */
    avltree_node_t *curr_node = NULL;
    ITERATE_AVL_TREE_BEGIN(&rtm->route_tree, curr_node) {
        
        rtm_route *route = avltree_container_of(curr_node, rtm_route, route_glue);
        char prefix_str[128];
        rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str));

        bool route_has_active_nh = false;

        /* Iterate through paths and show only active nexthops */
        glthread_t *curr_glthread = NULL;
        ITERATE_GLTHREAD_BEGIN(&route->path_list, curr_glthread) {
            
            rtm_nh *nh = route_glue_to_rtm_nh(curr_glthread);
            if (!nh->is_active) continue;
            
            route_has_active_nh = true;
            has_active_routes = true;
            
            char nh_prefix_str[128];
            rtm_format_nexthop(&nh->prefix, nh_prefix_str, sizeof(nh_prefix_str));

            cprintf("%-25s %-15s %-10u\n",
                   prefix_str,
                   nh_prefix_str,
                   nh->outgoing_if);

            prefix_str[0] = '\0';
            
        } ITERATE_GLTHREAD_END(&route->path_list, curr_glthread);

    } ITERATE_AVL_TREE_END(&rtm->route_tree, curr_node);

    if (!has_active_routes) {
        cprintf("  No active routes in FIB\n");
    }

    cprintf("\n");
}

/* Display nexthop protocol information */
void rtm_show_nh_proto_info(rtm_t *rtm) {
    if (!rtm) {
        cprintf("Error: NULL RTM pointer\n");
        return;
    }

    cprintf("\n========================================\n");
    cprintf("RTM Nexthop Protocol Information\n");
    cprintf("========================================\n");
    cprintf("VRF: %u, AFI: %s, RTM ID: %u\n", 
           rtm->vrf, rtm_afi_to_string(rtm->afi), rtm->rtm_id);
    cprintf("========================================\n\n");

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

    cprintf("\n");
}

/* Display general protocol information */
void rtm_show_proto_info(rtm_t *rtm) {
    if (!rtm) {
        cprintf("Error: NULL RTM pointer\n");
        return;
    }

    cprintf("\n========================================\n");
    cprintf("RTM Protocol Information\n");
    cprintf("========================================\n");
    cprintf("VRF: %u, AFI: %s, RTM ID: %u\n", 
           rtm->vrf, rtm_afi_to_string(rtm->afi), rtm->rtm_id);
    cprintf("========================================\n\n");

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

    cprintf("\n");
}

/* Display unresolvable nexthops */
void rtm_show_unresolvable_lnhs(rtm_t *rtm) {
    if (!rtm) {
        cprintf("Error: NULL RTM pointer\n");
        return;
    }

    cprintf("\n========================================\n");
    cprintf("RTM Unresolvable Nexthops\n");
    cprintf("========================================\n");
    cprintf("VRF: %u, AFI: %s, RTM ID: %u\n", 
           rtm->vrf, rtm_afi_to_string(rtm->afi), rtm->rtm_id);
    cprintf("========================================\n\n");

    if (IS_GLTHREAD_LIST_EMPTY(&rtm->unresolvable_lnhs)) {
        cprintf("  No unresolvable nexthops\n\n");
        return;
    }

    cprintf("%-15s %-20s %-40s %-10s\n",
           "Protocol", "Sub-Protocol", "Nexthop Prefix", "OIF");
    cprintf("%-15s %-20s %-40s %-10s\n",
           "--------", "------------", "--------------", "---");

    /* Iterate through unresolvable nexthops */
    glthread_t *curr_glthread = NULL;
    ITERATE_GLTHREAD_BEGIN(&rtm->unresolvable_lnhs, curr_glthread) {
        
        rtm_nh *nh = resolution_list_glue_to_rtm_nh(curr_glthread);
        char nh_prefix_str[128];
        rtm_format_nexthop(&nh->prefix, nh_prefix_str, sizeof(nh_prefix_str));

        cprintf("%-15s %-20s %-40s %-10u\n",
               rtm_proto_to_string(nh->proto),
               rtm_sub_proto_to_string(nh->sub_proto),
               nh_prefix_str,
               nh->outgoing_if);

    } ITERATE_GLTHREAD_END(&rtm->unresolvable_lnhs, curr_glthread);

    cprintf("\n");
}