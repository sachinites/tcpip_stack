#include <stdio.h>
#include <string.h>
#include "../Tree/libtree.h"
#include "../gluethread/glthread.h"

#include "rtm_api.h"
#include "rtm_show.h"
#include "rtm.h"
#include "rtm_route.h"
#include "rtm_nh.h"
#include "rtm_proto.h"
#include "rtm_enums.h"
#include "rtm_common.h"
#include "rtm_priv_api.h"

/* Display RIB (Routing Information Base) */
void rtm_show_rib(rtm_t *rtm) {

    printf("RIB :: VRF: %u, AFI: %s, RTM ID: %u\n", 
           rtm->vrf, rtm_afi_to_string(rtm->afi), rtm->rtm_id);
    printf("========================================\n\n");

    if (avltree_is_empty(&rtm->route_tree)) {
        printf("  No routes in RIB\n\n");
        return;
    }

    printf("%-40s %-10s %-8s %-15s %-10s %-8s %-8s %-20s\n",
           "Prefix", "Protocol", "Action", "Next-Hop", "OIF", "AD", "Metric", "Label Stack");
    printf("%-40s %-10s %-8s %-15s %-10s %-8s %-8s %-20s\n",
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
                        case LBL_SWAP: op_str = "SWAP"; break;
                        case LBL_PUSH: op_str = "PUSH"; break;
                        case LBL_POP: op_str = "POP"; break;
                        default: op_str = "UNK"; break;
                    }
                    snprintf(temp, sizeof(temp), "%s%s:%u", 
                            i > 0 ? "," : "",
                            op_str, 
                            nh->label_stack->labels[i].label_val);
                    strncat(label_stack_str, temp, sizeof(label_stack_str) - strlen(label_stack_str) - 1);
                }
            }

            printf("%-40s %-10s %-8s %-15s %-10u %-8u %-8u %-20s\n",
                   prefix_str,
                   rtm_proto_to_string(nh->proto),
                   rtm_nh_action_to_string(nh->action),
                   nh_prefix_str,
                   nh->outgoing_if,
                   nh->ad,
                   nh->metric,
                   label_stack_str);

            /* Print only prefix on first line, empty for subsequent nexthops of same route */
            prefix_str[0] = '\0';
            
        } ITERATE_GLTHREAD_END(&route->path_list, curr_glthread);

    } ITERATE_AVL_TREE_END(&rtm->route_tree, curr_node);

    printf("\n");
}

/* Display RIB in detailed format (line by line, not tabular) */
void rtm_show_rib_detail(rtm_t *rtm) {
    if (!rtm) {
        printf("Error: NULL RTM pointer\n");
        return;
    }

    printf("RIB :: VRF:%u AFI:%s RTM ID: %u\n", 
           rtm->vrf, rtm_afi_to_string(rtm->afi), rtm->rtm_id);
    printf("========================================\n\n");

    if (avltree_is_empty(&rtm->route_tree)) {
        printf("  No routes in RIB\n\n");
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
        printf("Route %d:\n", route_count);
        printf("  Prefix         : %s\n", prefix_str);
        printf("  Nexthop Count  : %u\n", route->nh_count);
        printf("  Flags          : 0x%04x\n", route->flags);
        printf("  Ref Count      : %u\n", route->ref_count);

        /* Iterate through all nexthops in the route */
        glthread_t *curr_glthread = NULL;
        int nh_index = 0;
        
        ITERATE_GLTHREAD_BEGIN(&route->path_list, curr_glthread) {
            
            rtm_nh *nh = route_glue_to_rtm_nh(curr_glthread);
            char nh_prefix_str[128];
            rtm_format_nexthop(&nh->prefix, nh_prefix_str, sizeof(nh_prefix_str));

            nh_index++;
            printf("\n  Nexthop %d:\n", nh_index);
            printf("    Idx            : %u\n", nh->idx);
            printf("    Protocol       : %s\n", rtm_proto_to_string(nh->proto));
            printf("    Sub-Protocol   : %s\n", rtm_sub_proto_to_string(nh->sub_proto));
            printf("    Next-Hop       : %s\n", nh_prefix_str);
            printf("    Action         : %s\n", rtm_nh_action_to_string(nh->action));
            printf("    OIF            : %u\n", nh->outgoing_if);
            printf("    Admin Distance : %u\n", nh->ad);
            printf("    Metric         : %u\n", nh->metric);
            printf("    Resolved       : %s\n", nh->is_resolved ? "Yes" : "No");
            printf("    Indirect       : %s\n", nh->is_indirect ? "Yes" : "No");
            printf ("    Active         : %s\n", nh->is_active ? "Yes" : "No");
            printf("    Ref Count      : %u\n", nh->ref_count);
            
            /* Display label stack if present */
            if (nh->label_stack && nh->label_stack->curr_index > 0) {
                printf("    Label Stack    : ");
                for (int i = 0; i < nh->label_stack->curr_index; i++) {
                    const char *op_str = "";
                    switch (nh->label_stack->labels[i].op) {
                        case LBL_SWAP: op_str = "SWAP"; break;
                        case LBL_PUSH: op_str = "PUSH"; break;
                        case LBL_POP: op_str = "POP"; break;
                        default: op_str = "UNK"; break;
                    }
                    printf("%s%s:%u", 
                           i > 0 ? ", " : "",
                           op_str, 
                           nh->label_stack->labels[i].label_val);
                }
                printf("\n");
            } else {
                printf("    Label Stack    : None\n");
            }
            
        } ITERATE_GLTHREAD_END(&route->path_list, curr_glthread);

        /* Blank line before next route */
        printf("\n");

    } ITERATE_AVL_TREE_END(&rtm->route_tree, curr_node);

    printf("Total Routes: %d\n\n", route_count);
}

/* Display FIB (Forwarding Information Base) */
void rtm_show_fib(rtm_t *rtm) {

    printf("FIB :: VRF:%u AFI:%s RTM ID: %u\n", 
           rtm->vrf, rtm_afi_to_string(rtm->afi), rtm->rtm_id);
    printf("========================================\n\n");

    if (avltree_is_empty(&rtm->route_tree)) {
        printf("  No routes in FIB\n\n");
        return;
    }

    printf("%-25s %-15s %-10s\n",
           "Prefix", "Next-Hop", "OIF");
    printf("%-25s %-15s %-10s\n",
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

            printf("%-25s %-15s %-10u\n",
                   prefix_str,
                   nh_prefix_str,
                   nh->outgoing_if);

            prefix_str[0] = '\0';
            
        } ITERATE_GLTHREAD_END(&route->path_list, curr_glthread);

    } ITERATE_AVL_TREE_END(&rtm->route_tree, curr_node);

    if (!has_active_routes) {
        printf("  No active routes in FIB\n");
    }

    printf("\n");
}

/* Display nexthop protocol information */
void rtm_show_nh_proto_info(rtm_t *rtm) {
    if (!rtm) {
        printf("Error: NULL RTM pointer\n");
        return;
    }

    printf("\n========================================\n");
    printf("RTM Nexthop Protocol Information\n");
    printf("========================================\n");
    printf("VRF: %u, AFI: %s, RTM ID: %u\n", 
           rtm->vrf, rtm_afi_to_string(rtm->afi), rtm->rtm_id);
    printf("========================================\n\n");

    if (avltree_is_empty(&rtm->nh_proto_info_tree)) {
        printf("  No nexthop protocol info registered\n\n");
        return;
    }

    printf("%-15s %-20s %-12s %-8s %-10s\n",
           "Protocol", "Sub-Protocol", "Instance", "VRF", "Ref Count");
    printf("%-15s %-20s %-12s %-8s %-10s\n",
           "--------", "------------", "--------", "---", "---------");

    /* Iterate through all NH protocol info */
    avltree_node_t *curr_node = NULL;
    ITERATE_AVL_TREE_BEGIN(&rtm->nh_proto_info_tree, curr_node) {
        
        rtm_nh_proto_t *nh_proto = avltree_container_of(curr_node, rtm_nh_proto_t, proto_glue);

        printf("%-15s %-20s %-12u %-8u %-10u\n",
               rtm_proto_to_string(nh_proto->proto),
               rtm_sub_proto_to_string(nh_proto->sub_proto),
               nh_proto->instance_no,
               nh_proto->vrf_id,
               nh_proto->ref_count);

    } ITERATE_AVL_TREE_END(&rtm->nh_proto_info_tree, curr_node);

    printf("\n");
}

/* Display general protocol information */
void rtm_show_proto_info(rtm_t *rtm) {
    if (!rtm) {
        printf("Error: NULL RTM pointer\n");
        return;
    }

    printf("\n========================================\n");
    printf("RTM Protocol Information\n");
    printf("========================================\n");
    printf("VRF: %u, AFI: %s, RTM ID: %u\n", 
           rtm->vrf, rtm_afi_to_string(rtm->afi), rtm->rtm_id);
    printf("========================================\n\n");

    bool found_any = false;

    /* Iterate through all protocol types */
    for (int proto = 0; proto < RTM_PROTO_MAX; proto++) {
        
        if (avltree_is_empty(&rtm->proto_info_tree[proto])) {
            continue;
        }

        if (!found_any) {
            printf("%-15s %-12s %-8s\n",
                   "Protocol", "Instance", "VRF");
            printf("%-15s %-12s %-8s\n",
                   "--------", "--------", "---");
            found_any = true;
        }

        /* Iterate through all instances of this protocol */
        avltree_node_t *curr_node = NULL;
        ITERATE_AVL_TREE_BEGIN(&rtm->proto_info_tree[proto], curr_node) {
            
            rtm_proto_info_t *proto_info = avltree_container_of(curr_node, rtm_proto_info_t, proto_glue);

            printf("%-15s %-12u %-8u\n",
                   rtm_proto_to_string(proto_info->proto),
                   proto_info->instance_no,
                   proto_info->vrf_id);

        } ITERATE_AVL_TREE_END(&rtm->proto_info_tree[proto], curr_node);
    }

    if (!found_any) {
        printf("  No protocol info registered\n");
    }

    printf("\n");
}

/* Display unresolvable nexthops */
void rtm_show_unresolvable_lnhs(rtm_t *rtm) {
    if (!rtm) {
        printf("Error: NULL RTM pointer\n");
        return;
    }

    printf("\n========================================\n");
    printf("RTM Unresolvable Nexthops\n");
    printf("========================================\n");
    printf("VRF: %u, AFI: %s, RTM ID: %u\n", 
           rtm->vrf, rtm_afi_to_string(rtm->afi), rtm->rtm_id);
    printf("========================================\n\n");

    if (IS_GLTHREAD_LIST_EMPTY(&rtm->unresolvable_lnhs)) {
        printf("  No unresolvable nexthops\n\n");
        return;
    }

    printf("%-15s %-20s %-40s %-10s\n",
           "Protocol", "Sub-Protocol", "Nexthop Prefix", "OIF");
    printf("%-15s %-20s %-40s %-10s\n",
           "--------", "------------", "--------------", "---");

    /* Iterate through unresolvable nexthops */
    glthread_t *curr_glthread = NULL;
    ITERATE_GLTHREAD_BEGIN(&rtm->unresolvable_lnhs, curr_glthread) {
        
        rtm_nh *nh = resolution_list_glue_to_rtm_nh(curr_glthread);
        char nh_prefix_str[128];
        rtm_format_nexthop(&nh->prefix, nh_prefix_str, sizeof(nh_prefix_str));

        printf("%-15s %-20s %-40s %-10u\n",
               rtm_proto_to_string(nh->proto),
               rtm_sub_proto_to_string(nh->sub_proto),
               nh_prefix_str,
               nh->outgoing_if);

    } ITERATE_GLTHREAD_END(&rtm->unresolvable_lnhs, curr_glthread);

    printf("\n");
}