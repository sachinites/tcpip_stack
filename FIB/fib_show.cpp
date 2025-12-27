#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include <ncurses.h>
#include "fib.h"
#include "fib_show.h"
#include "fib_route.h"
#include "fib_nh.h"
#include "../common/cmn_prefix.h"
#include "../mtrie/mtrie.h"
#include "../c-hashtable/hashtable.h"
#include "../c-hashtable/hashtable_itr.h"
#include "../common/mpls_lstack.h"
#include "../RTM/rtm_fib_common.h"
#include "../Interface/Interface.h"
#include "../utils.h"

extern int cprintf(const char *fmt, ...);

/* Helper function to format prefix for display */
static void
fib_format_prefix(cmn_prefix_t *prefix, char *buffer, size_t buf_size) {
    
    char addr_str[128] = {0};
    
    switch (prefix->afi) {
        case AF_IPV4:
            tcp_ip_covert_ip_n_to_p(prefix->u.v4_addr, (c_string)addr_str);
            snprintf(buffer, buf_size, "%s/%d", addr_str, prefix->prefix_len);
            break;
            
        case AF_IPV6:
            inet_ntop(AF_INET6, prefix->u.v6_addr, addr_str, sizeof(addr_str));
            snprintf(buffer, buf_size, "%s/%d", addr_str, prefix->prefix_len);
            break;
            
        case AF_LABEL:
            snprintf(buffer, buf_size, "Label %u", prefix->u.mpls_label);
            break;
            
        default:
            snprintf(buffer, buf_size, "Unknown");
            break;
    }
}

/* Helper function to format nexthop address for display */
static void
fib_format_nh_addr(cmn_prefix_t *nh_addr, char *buffer, size_t buf_size) {
    
    char addr_str[128] = {0};
    
    switch (nh_addr->afi) {
        case AF_IPV4:
            tcp_ip_covert_ip_n_to_p(nh_addr->u.v4_addr, (c_string)addr_str);
            snprintf(buffer, buf_size, "%s", addr_str);
            break;
            
        case AF_IPV6:
            inet_ntop(AF_INET6, nh_addr->u.v6_addr, addr_str, sizeof(addr_str));
            snprintf(buffer, buf_size, "%s", addr_str);
            break;
            
        case AF_LABEL:
            snprintf(buffer, buf_size, "Label %u", nh_addr->u.mpls_label);
            break;
            
        default:
            if (cmn_prefix_is_null(nh_addr)) {
                snprintf(buffer, buf_size, "0.0.0.0");
            } else {
                snprintf(buffer, buf_size, "Unknown");
            }
            break;
    }
}

/* Helper function to display label stack */
static void
fib_display_label_stack(mpls_lstack_t *label_stack) {
    
    if (!label_stack || 
        mpls_lstack_is_empty(label_stack)) {
        return;
    }
    
    cprintf("      Label Stack: ");

    for (int i = 0; i <= label_stack->curr_index; i++) {

        mpls_label_val_t label_val = mpls_label_get_value(label_stack->labels[i].label_val);
        
        switch (label_stack->labels[i].op) {
            case MPLS_OP_PUSH:
                cprintf("[PUSH %u]%s", label_val, 
                        mpls_label_is_stack_bottom(
                            label_stack->labels[i].label_val) ? "(S)":"");
                break;
            case MPLS_OP_POP:
                cprintf("[POP %u]%s", label_val,
                        mpls_label_is_stack_bottom(
                            label_stack->labels[i].label_val) ? "(S)":"");
                break;
            case MPLS_OP_SWAP:
                cprintf("[SWAP %u]%s", label_val,
                        mpls_label_is_stack_bottom(
                            label_stack->labels[i].label_val) ? "(S)":"");
                break;
            default:
                cprintf("[%u]", label_val);
                break;
        }
        
        if (i < label_stack->curr_index) {
            cprintf(" -> ");
        }
    }
    printw("\n");
}

/* Helper function to display segment list */
static void
fib_display_segment_list(uint8_t seg_list[][16], uint8_t count) {
    
    if (!seg_list || count == 0) {
        return;
    }
    
    cprintf("      SRv6 Segment List: ");
    for (int i = 0; i < count; i++) {
        char seg_str[128];
        inet_ntop(AF_INET6, seg_list[i], seg_str, sizeof(seg_str));
        cprintf("%s", seg_str);
        
        if (i < count - 1) {
            cprintf(" -> ");
        }
    }
    printw("\n");
}

/* Display FIB contents with all routes and nexthops */
void
fib_show_routes(fib_t *fib) {
        
    uint32_t route_count = 0;
    
    /* Iterate based on AFI type */
    if (fib->afi == AF_IPV4 || fib->afi == AF_IPV6) {
        
        /* LPM-based FIB - iterate through mtrie */
        if (!fib->u.lpm) {
            cprintf("No routes in FIB\n\n");
            return;
        }
        
        glthread_t *curr;
        ITERATE_GLTHREAD_BEGIN(&fib->u.lpm->list_head, curr) {
            
            mtrie_node_t *mnode = list_glue_to_mtrie_node(curr);
            if (!mnode || !mnode->data) {
                continue;
            }
            
            fib_route_t *route = (fib_route_t *)mnode->data;
            route_count++;
            
            /* Print route prefix */
            char prefix_str[128];
            fib_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str));
            cprintf("Route: %-40s\n", prefix_str);
            
            /* Count active nexthops */
            uint8_t active_nh_count = 0;
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                if (route->nhs[i]) {
                    active_nh_count++;
                }
            }
            
            if (active_nh_count == 0) {
                cprintf("  No nexthops\n\n");
                continue;
            }
            
            cprintf("  Nexthops (%u)%s:\n", active_nh_count, 
                   active_nh_count > 1 ? " [ECMP]" : "");
            
            /* Display all nexthops */
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                fib_nh_t *nh = route->nhs[i];
                if (!nh) continue;
                
                cprintf("    [%u] NH Idx: [%u|%u] (%p)\n", i + 1, 
                    route->nh_idx[i] >> 32, 
                    route->nh_idx[i] & 0x00000000FFFFFFFF, nh->fwd_info);
                
                /* Nexthop address */
                char nh_addr_str[128];
                fib_format_nh_addr(&nh->fwd_info->nh_addr, nh_addr_str, sizeof(nh_addr_str));
                cprintf("      Gateway: %s\n", nh_addr_str);
                
                /* Outgoing interface */
                if (nh->fwd_info->oif) {
                    cprintf("      OIF: %s\n", nh->fwd_info->oif->if_name.c_str());
                } else {
                    cprintf("      OIF: None\n");
                }
                
                /* Forwarding flags */
                #if 0
                cprintf("      Flags: 0x%04x ", nh->fwd_info->fwd_flags);
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV4) cprintf("[IPv4] ");
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV6) cprintf("[IPv6] ");
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) cprintf("[MPLS] ");
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) cprintf("[SRv6] ");
                printw("\n");
                #endif 
                
                /* Reference count and hit count */
                cprintf("      Ref Count: %u, Hit Count: %u\n", 
                       nh->ref_count, nh->hit_count);
                
                /* MPLS label stack */
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) {
                    fib_display_label_stack(&nh->fwd_info->u.mpls_fwd.label_stack);
                }
                
                /* SRv6 segment list */
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) {
                    cprintf("      SRv6 End Function: %u\n", 
                           nh->fwd_info->u.v6_fwd.endfn);
                    fib_display_segment_list(nh->fwd_info->u.v6_fwd.v6segment_lst, 
                                            nh->fwd_info->u.v6_fwd.n_segment_list);
                }
                
                printw("\n");
            }
            
        } ITERATE_GLTHREAD_END(&fib->u.lpm->list_head, curr);
        
    } else if (fib->afi == AF_LABEL) {
        
        if (!hashtable_count(fib->u.label_ht)) {
            cprintf("Total Routes: 0\n");
            return;
        }

        hashtable_itr *itr = hashtable_iterator(fib->u.label_ht);

        do {
            fib_route_t *route = (fib_route_t *)hashtable_iterator_value(itr);
            if (!route) break;
            
            route_count++;
            
            /* Print route prefix (label) */
            char prefix_str[128];
            fib_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str));
            cprintf("Route: %-40s\n", prefix_str);
            
            /* Count active nexthops */
            uint8_t active_nh_count = 0;
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                if (route->nhs[i]) {
                    active_nh_count++;
                }
            }
            
            if (active_nh_count == 0) {
                cprintf("  No nexthops\n\n");
                hashtable_iterator_advance(itr);
                continue;
            }
            
            cprintf("  Nexthops (%u)%s:\n", active_nh_count, 
                   active_nh_count > 1 ? " [ECMP]" : "");
            
            /* Display all nexthops */
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                fib_nh_t *nh = route->nhs[i];
                if (!nh) continue;
                
                cprintf("    [%u] NH Index: %u\n", i + 1, route->nh_idx[i]);
                
                /* Nexthop address */
                char nh_addr_str[128];
                fib_format_nh_addr(&nh->fwd_info->nh_addr, nh_addr_str, sizeof(nh_addr_str));
                cprintf("      Gateway: %s\n", nh_addr_str);
                
                /* Outgoing interface */
                if (nh->fwd_info->oif) {
                    cprintf("      OIF: %s\n", nh->fwd_info->oif->if_name.c_str());
                } else {
                    cprintf("      OIF: None\n");
                }
                
                /* Forwarding flags */
                #if 0
                cprintf("      Flags: 0x%04x ", nh->fwd_info->fwd_flags);
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV4) cprintf("[IPv4] ");
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV6) cprintf("[IPv6] ");
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) cprintf("[MPLS] ");
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) cprintf("[SRv6] ");
                printw("\n");
                #endif 
                
                /* Reference count and hit count */
                cprintf("      Ref Count: %u, Hit Count: %u\n", 
                       nh->ref_count, nh->hit_count);
                
                /* MPLS label stack */
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) {
                    fib_display_label_stack(&nh->fwd_info->u.mpls_fwd.label_stack);
                }
                
                /* SRv6 segment list */
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) {
                    cprintf("      SRv6 End Function: %u\n", 
                           nh->fwd_info->u.v6_fwd.endfn);
                    fib_display_segment_list(nh->fwd_info->u.v6_fwd.v6segment_lst, 
                                            nh->fwd_info->u.v6_fwd.n_segment_list);
                }
                
                printw("\n");
            }
            
        } while (hashtable_iterator_advance(itr));

        free(itr);
    }
    
    /* Print summary */
    cprintf("Total Routes: %u\n", route_count);
}

