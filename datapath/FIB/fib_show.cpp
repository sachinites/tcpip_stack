#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include <ncurses.h>
#include <stdlib.h>
#include "fib.h"
#include "fib_show.h"
#include "fib_route.h"
#include "fib_nh.h"
#include "../../libs/common/cmn_prefix.h"
#include "../../libs/mtrie/mtrie.h"
#include "../../libs/mtrie/atomic_mtrie.h"
#include "../../libs/c-hashtable/hashtable.h"
#include "../../libs/c-hashtable/hashtable_itr.h"
#include "../../libs/common/mpls_lstack.h"
#include "../../RTM/rtm_fib_common.h"
#include "../../utils.h"
#include "../../tcpconst.h"
#include "../../datapath/Interface/dp_intf.h"
#include "../../datapath/Vrfs/dp_vrf.h"
#include "../../datapath/dp_ctx.h"
#include "../../Layer3/SegmentRouting/SRv6/common/srv6_const.h"

extern int cprintf (const char* format, ...) ;

/* Helper function to format prefix for display */
static void
fib_format_prefix(cmn_prefix_t *prefix, char *buffer, size_t buf_size) {
    
    char addr_str[128] = {0};
    
    switch (prefix->afi) {
        case AF_IPV4:
            ip_ntop(prefix->u.v4_addr, (c_string)addr_str);
            snprintf(buffer, buf_size, "%s/%d", addr_str, prefix->prefix_len);
            break;
            
        case AF_IPV6:
            inet_ntop(AF_INET6, prefix->u.v6_addr, addr_str, sizeof(addr_str));
            snprintf(buffer, buf_size, "%s/%d", addr_str, prefix->prefix_len);
            break;
            
        case AF_LABEL:
            snprintf(buffer, buf_size, "Label %u",
                     mpls_label_get_value(prefix->u.mpls_label));
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
            ip_ntop(nh_addr->u.v4_addr, (c_string)addr_str);
            snprintf(buffer, buf_size, "%s", addr_str);
            break;
            
        case AF_IPV6:
            inet_ntop(AF_INET6, nh_addr->u.v6_addr, addr_str, sizeof(addr_str));
            snprintf(buffer, buf_size, "%s", addr_str);
            break;
            
        case AF_LABEL:
            snprintf(buffer, buf_size, "Label %u",
                     mpls_label_get_value(nh_addr->u.mpls_label));
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

/* VPNv4/BD steer OIF: print "vrf:<id>" / "bd:<name>", else normal gateway */
static void
fib_format_nh_gateway(dp_ctx_t *dp_ctx,
                      fib_nh_fwd_info_t *fi,
                      char *buffer,
                      size_t buf_size) {

    if (fi->oif &&
        (fi->oif->if_type == DP_INTF_TYPE_MPLS_TO_VRF_STEER ||
         fi->oif->if_type == DP_INTF_TYPE_SRV6_TO_VRF_STEER)) {
    
        snprintf(buffer, buf_size, "vrf:%u", fi->xconnect_id);
        return;
    }

    if (fi->oif &&
        (fi->oif->if_type == DP_INTF_TYPE_MPLS_TO_BD_STEER ||
         fi->oif->if_type == DP_INTF_TYPE_SRV6_TO_BD_STEER)) {

        dp_intf_t *bd_intf = dp_ctx->intf_table[fi->xconnect_id];
        snprintf(buffer, buf_size, "%s", bd_intf->if_name);
        return;
    }

    fib_format_nh_addr(&fi->nh_addr, buffer, buf_size);
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

/* Format label stack ops: "Pop", "Swap 17003", "Push 100 -> Push 17003".
 * Stack is printed bottom (innermost) -> top (outermost). */
static void
fib_format_label_stack_ops(fib_nh_fwd_info_t *fi, char *buf, size_t buf_size) {

    buf[0] = '\0';

    if (!(fi->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK)) {
        snprintf(buf, buf_size, "-");
        return;
    }

    mpls_lstack_t *ls = &fi->u.mpls_fwd.label_stack;
    if (!ls || mpls_lstack_is_empty(ls)) {
        snprintf(buf, buf_size, "-");
        return;
    }

    int off = 0;
    for (int i = 0; i <= ls->curr_index && off < (int)buf_size - 1; i++) {
        uint32_t val = mpls_label_get_value(ls->labels[i].label_val);
        const char *sep = (i > 0) ? " " : "";

        switch (ls->labels[i].op) {
            case MPLS_OP_POP:
                off += snprintf(buf + off, buf_size - off, "%sPop", sep);
                break;
            case MPLS_OP_SWAP:
                off += snprintf(buf + off, buf_size - off, "%sSw(%u)", sep, val);
                break;
            case MPLS_OP_PUSH:
                off += snprintf(buf + off, buf_size - off, "%sP(%u)", sep, val);
                break;
            default:
                off += snprintf(buf + off, buf_size - off, "%sOp(%u) %u",
                                sep, (unsigned)ls->labels[i].op, val);
                break;
        }
    }
}

/* Format SRv6 segment list into a compact inline string. */
static int
fib_format_seg_list_str(uint8_t seg_list[][16], uint8_t count,
                        char *buf, size_t buf_size) {

    int off = 0;
    for (int i = 0; i < count && off < (int)buf_size - 1; i++) {
        char addr[64];
        inet_ntop(AF_INET6, seg_list[i], addr, sizeof(addr));
        off += snprintf(buf + off, buf_size - off,
                        "%s%s", i > 0 ? " -> " : "", addr);
    }
    return off;
}

/* SRv6 / GRE under a brief NH row (label stack is inline on the NH line). */
static void
fib_show_nh_extra_encap(fib_nh_fwd_info_t *fi, const char *indent) {

    if (fi->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) {
        uint8_t  n      = fi->u.v6_fwd.n_segment_list;
        uint8_t  flavor = 0;
        Srv6_endpcode_t base_fn = srv6_split_endpcode(fi->u.v6_fwd.endfn, &flavor);
        cprintf("%sSRv6: endfn=%s", indent, srv6_end_fn_str(base_fn));
        if (flavor) {
            cprintf(" flavor=0x%x", flavor);
        }
        if (n > 0) {
            char sstr[512] = {0};
            fib_format_seg_list_str(fi->u.v6_fwd.v6segment_lst, n,
                                    sstr, sizeof(sstr));
            cprintf(" segs[%u]: %s", n, sstr);
        }
        cprintf("\n");
    }

    if (fib_nh_fwd_is_gre_encap(fi->fwd_flags)) {
        char src_str[48];
        char dst_str[48];
        cprintf("%sGre-Encap: S:%s D:%s\n", indent,
                cmn_prefix_to_string(&fi->u.gre_fwd.gre_tunnel_src, &src_str),
                cmn_prefix_to_string(&fi->u.gre_fwd.gre_tunnel_dst, &dst_str));
    }
}

/* Display FIB contents with all routes and nexthops */
void
fib_show_routes(dp_ctx_t *dp_ctx, fib_t *fib) {
        
    uint32_t route_count = 0;
    char ip_addr_str1[48];
    char ip_addr_str2[48];

    /* Iterate based on AFI type */
    if (fib->afi == AF_IPV4 || fib->afi == AF_IPV6) {
        
        /* LPM-based FIB - iterate through mtrie */
        if (!fib->u.rts.lpm) {
            cprintf("No routes in FIB\n\n");
            return;
        }
        
        glthread_t *curr;
        ITERATE_GLTHREAD_BEGIN(&fib->u.rts.rt_lst_head.head, curr) {
            
            fib_route_t *route = (fib_route_t *)fib_route_to_lst_glue(curr);
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
                fib_format_nh_gateway(dp_ctx, nh->fwd_info, nh_addr_str, sizeof(nh_addr_str));
                cprintf("      Gateway: %s\n", nh_addr_str);
                
                /* Outgoing interface */
                if (nh->fwd_info->oif) {
                    cprintf("      OIF: %s\n", nh->fwd_info->oif->if_name);
                } else {
                    cprintf("      OIF: None\n");
                }
                
                /* Forwarding flags */
                
                cprintf("      Flags: 0x%x\n", nh->fwd_info->fwd_flags);
                #if 0
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV4) cprintf("[IPv4] ");
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV6) cprintf("[IPv6] ");
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) cprintf("[MPLS] ");
                if (nh->fwd_info->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) cprintf("[SRv6] ");
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
                
                if (fib_nh_fwd_is_gre_encap(nh->fwd_info->fwd_flags)) {
                    cprintf("      GRE Tunnel Encap: S:%s D:%s\n", 
                        cmn_prefix_to_string(&nh->fwd_info->u.gre_fwd.gre_tunnel_src, &ip_addr_str1),
                        cmn_prefix_to_string(&nh->fwd_info->u.gre_fwd.gre_tunnel_dst, &ip_addr_str2));
                }

                printw("\n");
            }
            
        } ITERATE_GLTHREAD_END(&fib->u.rts.rt_lst_head.head, curr);
        
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
                fib_format_nh_gateway(dp_ctx, nh->fwd_info, nh_addr_str, sizeof(nh_addr_str));
                cprintf("      Gateway: %s\n", nh_addr_str);
                
                /* Outgoing interface */
                if (nh->fwd_info->oif) {
                    cprintf("      OIF: %s\n", nh->fwd_info->oif->if_name);
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

/* Brief/Compact route display - Cisco-like forwarding table format */
void
fib_show_routes_brief(dp_ctx_t *dp_ctx, fib_t *fib) {
    
    uint32_t route_count = 0;

    /* Column widths: use %-W.Ws so longer values truncate instead of shifting */
    /* ---- MPLS LFIB ---- */
    if (fib->afi == AF_LABEL) {

        cprintf("%-10s %-28s %-18s %-16s %-8s\n",
                "Local", "Label Stack", "Gateway", "OIF", "Bytes");
        cprintf("%-10s %-28s %-18s %-16s %-8s\n",
                "Label", "", "", "", "Switched");
        cprintf("%-10s %-28s %-18s %-16s %-8s\n",
                "----------", "----------------------------",
                "------------------", "----------------", "--------");

        if (!hashtable_count(fib->u.label_ht)) {
            cprintf("Total Labels: 0\n");
            return;
        }

        hashtable_itr *itr = hashtable_iterator(fib->u.label_ht);

        do {
            fib_route_t *route = (fib_route_t *)hashtable_iterator_value(itr);
            if (!route) break;

            route_count++;

            uint32_t local_label = mpls_label_get_value(route->prefix.u.mpls_label);

            uint8_t active_nh_count = 0;
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                if (route->nhs[i]) active_nh_count++;
            }

            if (active_nh_count == 0) {
                cprintf("%-10u %-28.28s %-18.18s %-16.16s %-8s\n",
                        local_label, "-", "-", "-", "-");
                hashtable_iterator_advance(itr);
                continue;
            }

            bool first = true;
            for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
                fib_nh_t *nh = route->nhs[i];
                if (!nh) continue;

                fib_nh_fwd_info_t *fi = nh->fwd_info;

                char nh_addr_str[48];
                fib_format_nh_gateway(dp_ctx, fi, nh_addr_str, sizeof(nh_addr_str));

                char stack_str[128];
                fib_format_label_stack_ops(fi, stack_str, sizeof(stack_str));

                const char *oif_name = fi->oif ? fi->oif->if_name : "-";

                if (first) {
                    cprintf("%-10u %-28.28s %-18.18s %-16.16s %-8u\n",
                            local_label, stack_str, nh_addr_str,
                            oif_name, nh->hit_count);
                    first = false;
                } else {
                    cprintf("%-10s %-28.28s %-18.18s %-16.16s %-8u\n",
                            "", stack_str, nh_addr_str,
                            oif_name, nh->hit_count);
                }

                fib_show_nh_extra_encap(fi, "           ");
            }

        } while (hashtable_iterator_advance(itr));

        free(itr);

        cprintf("%-10s %-28s %-18s %-16s %-8s\n",
                "----------", "----------------------------",
                "------------------", "----------------", "--------");
        cprintf("Total Labels: %u\n", route_count);
        return;
    }

    /* ---- IPv4 / IPv6 FIB ---- */
    cprintf("%-26s %-18s %-16s %-28s %-8s\n",
            "Prefix", "Gateway", "OIF", "Label Stack", "Hits");
    cprintf("%-26s %-18s %-16s %-28s %-8s\n",
            "--------------------------", "------------------", "----------------",
            "----------------------------", "--------");

    if (fib->afi != AF_IPV4 && fib->afi != AF_IPV6) {
        cprintf("Total Routes: 0\n");
        return;
    }

    if (!fib->u.rts.lpm) {
        cprintf("No routes in FIB\n");
        return;
    }

    glthread_t *curr;
    ITERATE_GLTHREAD_BEGIN(&fib->u.rts.rt_lst_head.head, curr) {

        fib_route_t *route = (fib_route_t *)fib_route_to_lst_glue(curr);
        route_count++;

        char prefix_str[48];
        fib_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str));

        uint8_t active_nh_count = 0;
        for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
            if (route->nhs[i]) active_nh_count++;
        }

        if (active_nh_count == 0) {
            cprintf("%-26.26s %-18.18s %-16.16s %-28.28s %-8s\n",
                    prefix_str, "-", "-", "-", "-");
            continue;
        }

        bool first = true;
        for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
            fib_nh_t *nh = route->nhs[i];
            if (!nh) continue;

            fib_nh_fwd_info_t *fi = nh->fwd_info;

            char nh_addr_str[48];
            fib_format_nh_gateway(dp_ctx, fi, nh_addr_str, sizeof(nh_addr_str));

            char stack_str[128];
            fib_format_label_stack_ops(fi, stack_str, sizeof(stack_str));

            const char *oif_name = fi->oif ? fi->oif->if_name : "-";

            if (first) {
                const char *ecmp = active_nh_count > 1 ? "*" : "";
                cprintf("%-26.26s %-18.18s %-16.16s %-28.28s %-8u %s\n",
                        prefix_str, nh_addr_str, oif_name,
                        stack_str, nh->hit_count, ecmp);
                first = false;
            } else {
                cprintf("%-26.26s %-18.18s %-16.16s %-28.28s %-8u\n",
                        "", nh_addr_str, oif_name,
                        stack_str, nh->hit_count);
            }

            fib_show_nh_extra_encap(fi, "                           ");
        }

    } ITERATE_GLTHREAD_END(&fib->u.rts.rt_lst_head.head, curr);

    cprintf("%-26s %-18s %-16s %-28s %-8s\n",
            "--------------------------", "------------------", "----------------",
            "----------------------------", "--------");
    cprintf("Total Routes: %u (* = ECMP)\n", route_count);
}

