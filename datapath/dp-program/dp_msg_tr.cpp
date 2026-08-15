#include <arpa/inet.h>
#include <cstdio>
#include <cstring>

#include "../dp_ctx.h"
#include "../../libs/Tracer/tracer.h"
#include "../../tcp_ip_trace.h"
#include "../../utils.h"
#include "../../libs/common/cmn_prefix.h"
#include "../../Layer3/SegmentRouting/SRv6/common/srv6_const.h"
#include "../Interface/intf_cons.h"

#include "dp-prog-struct.h"

static const char *
dp_component_type_str (DP_COMPONENT_TYPE_T t) {
    switch (t) {
        case MAC_TABLE:   return "MAC_TABLE";
        case PKT_BLOCK:   return "PKT_BLOCK";
        case FIB_TABLE:   return "FIB_TABLE";
        case INTF_TABLE:  return "INTF_TABLE";
        case VRF_TABLE:   return "VRF_TABLE";
        case DP_GENERICS: return "DP_GENERICS";
        case ARP_TABLE:   return "ARP_TABLE";
        default:          return "UNKNOWN";
    }
}

static const char *
dp_opr_type_str (DP_OPR_TYPE_T t) {
    switch (t) {
        case DP_CREATE:         return "DP_CREATE";
        case DP_DEL:            return "DP_DEL";
        case DP_UPDATE:         return "DP_UPDATE";
        case DP_READ:           return "DP_READ";
        case DP_L3_NORTHBOUND_IN: return "DP_L3_NORTHBOUND_IN";
        default:                return "UNKNOWN";
    }
}

static const char *
dp_intf_update_code_str (uint16_t code) {
    switch (code) {
        case CP2DP_CODE_INTF_PHYSICAL:    return "PHYSICAL";
        case CP2DP_CODE_INTF_IPV4_ADDR:  return "IPV4_ADDR";
        case CP2DP_CODE_INTF_IPV6_ADDR:  return "IPV6_ADDR";
        case CP2DP_CODE_INTF_VLAN_BIND:  return "VLAN_BIND";
        case CP2DP_CODE_INTF_ADMIN_DOWN: return "ADMIN_DOWN";
        case CP2DP_CODE_INTF_SW:         return "SWITCHPORT";
        case CP2DP_CODE_INTF_VLAN_VNI:    return "VLAN_VNI";
        case CP2DP_CODE_INTF_VLAN_GRP_BIND: return "VLAN_GRP_BIND";
        case CP2DP_CODE_INTF_GRP_VLAN_BIND: return "GRP_VLAN_BIND";
        case CP2DP_CODE_INTF_RMAC:       return "RMAC";
        case CP2DP_CODE_INTF_VLAN_FLOOD:  return "VLAN_FLOOD";
        case CP2DP_CODE_INTF_HOST_PATH:  return "HOST_PATH";
        case CP2DP_CODE_INTF_NVE:        return "NVE";
        case CP2DP_CODE_INTF_LOG_UPDATE: return "LOG_UPDATE";
        case CP2DP_CODE_INTF_GRE_TUNNEL: return "GRE_TUNNEL";
        case CP2DP_CODE_BD_AC_BIND:      return "BD_AC_BIND";
        case CP2DP_CODE_BD_AC_UNBIND:    return "BD_AC_UNBIND";
        case CP2DP_CODE_BD_AC_ENCAP_8021Q: return "BD_AC_ENCAP_8021Q";
        default:                          return "?";
    }
}

void
dp_uapi_trace_dp_msg ( dp_ctx_t *dp_ctx, dp_msg_t *dp_msg) {

    if (!dp_ctx || !dp_msg || !dp_ctx->dptr)
        return;

    tracer(dp_ctx->dptr, DCONF,
        "dp_msg: component=%s opr=%s data_size=%u flags=0x%x vrf_id=%u\n",
        dp_component_type_str(dp_msg->component_type),
        dp_opr_type_str(dp_msg->opr_type),
        dp_msg->data_size,
        (unsigned)dp_msg->flags,
        (unsigned)dp_msg->vrf_id);

    if (dp_msg->data_size == 0)
        return;

    switch (dp_msg->component_type) {

        case MAC_TABLE:
        {
            mac_update_msg_t *m = (mac_update_msg_t *)dp_msg->data;
            tracer(dp_ctx->dptr, DCONF,
                "  mac_msg: mac=%02x:%02x:%02x:%02x:%02x:%02x vlan_id=%u ifindex=%u flags=0x%x remote_dst_ip=0x%x\n",
                m->mac_addr[0], m->mac_addr[1], m->mac_addr[2],
                m->mac_addr[3], m->mac_addr[4], m->mac_addr[5],
                (unsigned)m->vlan_id, m->ifindex, (unsigned)m->flags,
                (unsigned)m->remote_dst_ip);
        }
        break;

        case PKT_BLOCK:
            tracer(dp_ctx->dptr, DCONF,
                "  payload: mbuf pointer (L3 northbound)\n");
            break;

        case FIB_TABLE:
        {
            fib_update_msg_t *f = (fib_update_msg_t *)dp_msg->data;
            char route_str[48];
            char nh_str[48];
            cmn_prefix_to_string(&f->prefix, &route_str);
            cmn_prefix_to_string(&f->fwd_info.nh_addr, &nh_str);
            tracer(dp_ctx->dptr, DCONF,
                "  fib_msg: target_vrf=%u target_afi=%u prefix=%s nhidx=%u inhidx=%u fwd_flags=0x%x oif=%u nh_addr=%s\n",
                (unsigned)f->target_fib_vrf_id, (unsigned)f->target_fib_afi,
                route_str, f->nhidx, f->inhidx, (unsigned)f->fwd_flags,
                f->fwd_info.oif, nh_str);
            /* fwd_info union: MPLS label stack or SRv6 */
            if (f->target_fib_afi == AF_LABEL) {
                mpls_lstack_t *stk = &f->fwd_info.u.mpls_fwd.label_stack;
                int n = stk->curr_index + 1;
                if (n > 0 && n <= (int)MAX_LBL_DEPTH) {
                    char lbl_buf[64];
                    int off = 0;
                    for (int i = 0; i < n && off < (int)sizeof(lbl_buf) - 16; i++)
                        off += snprintf(lbl_buf + off, sizeof(lbl_buf) - off, "%s%u", i ? "," : "", (unsigned)mpls_label_get_value(stk->labels[i].label_val));
                    tracer(dp_ctx->dptr, DCONF, "  fib_fwd: mpls_fwd curr_index=%d labels=%s\n", stk->curr_index, lbl_buf);
                }
            } else if (f->target_fib_afi == AF_IPV6) {
                const char *endfn_str = srv6_end_fn_str(f->fwd_info.u.v6_fwd.endfn);
                tracer(dp_ctx->dptr, DCONF,
                    "  fib_fwd: v6_fwd endfn=%s(%u) n_segment_list=%u\n",
                    endfn_str ? endfn_str : "?", (unsigned)f->fwd_info.u.v6_fwd.endfn,
                    (unsigned)f->fwd_info.u.v6_fwd.n_segment_list);
            }
        }
        break;

        case VRF_TABLE:
            if (dp_msg->opr_type == DP_UPDATE) {
                dp_vrf_intf_update_msg_t *v = (dp_vrf_intf_update_msg_t *)dp_msg->data;
                const char *op_str = (v->op_code == DP_VRF_INTF_OP_ADD) ? "ADD" :
                                    (v->op_code == DP_VRF_INTF_OP_DEL) ? "DEL" : "?";
                tracer(dp_ctx->dptr, DCONF,
                    "  vrf_intf_msg: op=%s vrf_id=%u ifindex=%u\n",
                    op_str, (unsigned)v->vrf_id, v->ifindex);
            } else {
                dp_vrf_create_msg_t *v = (dp_vrf_create_msg_t *)dp_msg->data;
                tracer(dp_ctx->dptr, DCONF,
                    "  vrf_msg: vrf_id=%u vrf_name=%s\n",
                    (unsigned)v->vrf_id, v->vrf_name);
            }
            break;

        case INTF_TABLE:
        {
            dp_intf_cp2dp_msg_hdr_t *h = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
            size_t hdr_sz = sizeof(dp_intf_cp2dp_msg_hdr_t);
            tracer(dp_ctx->dptr, DCONF,
                "  intf_msg: port_id=%u vlan_id=%u iftype=%u mac=%02x:%02x:%02x:%02x:%02x:%02x intf_name=%s update_code=%u (%s)\n",
                h->port_id, h->vlan_id, h->iftype,
                h->mac_addr[0], h->mac_addr[1], h->mac_addr[2],
                h->mac_addr[3], h->mac_addr[4], h->mac_addr[5],
                h->intf_name, (unsigned)h->update_code, dp_intf_update_code_str(h->update_code));
            /* Trace payload after header for DP_UPDATE */
            if (dp_msg->opr_type == DP_UPDATE && dp_msg->data_size > hdr_sz) {
                const void *payload = (const char *)dp_msg->data + hdr_sz;
                switch (h->update_code) {
                    case CP2DP_CODE_INTF_IPV4_ADDR:
                        if (dp_msg->data_size >= hdr_sz + sizeof(dp_intf_ipv4_addr_update_t)) {
                            const dp_intf_ipv4_addr_update_t *u = (const dp_intf_ipv4_addr_update_t *)payload;
                            char ip_str[INET_ADDRSTRLEN];
                            struct in_addr ia; ia.s_addr = htonl(u->ipv4_addr);
                            inet_ntop(AF_INET, &ia, ip_str, sizeof(ip_str));
                            tracer(dp_ctx->dptr, DCONF, "    intf_update: ipv4_addr=%s/%u\n", ip_str, (unsigned)u->mask);
                        }
                        break;
                    case CP2DP_CODE_INTF_IPV6_ADDR:
                        if (dp_msg->data_size >= hdr_sz + sizeof(dp_intf_ipv6_addr_update_t)) {
                            const dp_intf_ipv6_addr_update_t *u = (const dp_intf_ipv6_addr_update_t *)payload;
                            char ip6_str[INET6_ADDRSTRLEN];
                            inet_ntop(AF_INET6, u->ipv6_addr, ip6_str, sizeof(ip6_str));
                            tracer(dp_ctx->dptr, DCONF, "    intf_update: ipv6_addr=%s/%u\n", ip6_str, (unsigned)u->prefix_len);
                        }
                        break;
                    case CP2DP_CODE_INTF_VLAN_BIND:
                        if (dp_msg->data_size >= hdr_sz + sizeof(dp_intf_vlan_bind_t)) {
                            const dp_intf_vlan_bind_t *u = (const dp_intf_vlan_bind_t *)payload;
                            const char *mode_str = dp_intf_mode_str((DP_IntfL2Mode)u->l2_mode);
                            tracer(dp_ctx->dptr, DCONF, "    intf_update: vlan_bind vlan_port_id=%u port_id=%u l2_mode=%s add=%u\n",
                                u->vlan_port_id, u->port_id, mode_str ? mode_str : "?", (unsigned)u->add);
                        }
                        break;
                    case CP2DP_CODE_INTF_ADMIN_DOWN:
                        if (dp_msg->data_size >= hdr_sz + sizeof(dp_intf_admin_down_t)) {
                            const dp_intf_admin_down_t *u = (const dp_intf_admin_down_t *)payload;
                            tracer(dp_ctx->dptr, DCONF, "    intf_update: admin_down port_id=%u status=%s\n", u->port_id, u->status ? "DOWN" : "UP");
                        }
                        break;
                    case CP2DP_CODE_INTF_SW:
                        if (dp_msg->data_size >= hdr_sz + sizeof(dp_intf_boolean_property_t)) {
                            const dp_intf_boolean_property_t *u = (const dp_intf_boolean_property_t *)payload;
                            tracer(dp_ctx->dptr, DCONF, "    intf_update: switchport port_id=%u enable=%u\n", u->port_id, (unsigned)u->enable);
                        }
                        break;
                    case CP2DP_CODE_INTF_VLAN_VNI:
                        if (dp_msg->data_size >= hdr_sz + sizeof(dp_intf_vlan_vni_t)) {
                            const dp_intf_vlan_vni_t *u = (const dp_intf_vlan_vni_t *)payload;
                            tracer(dp_ctx->dptr, DCONF, "    intf_update: vlan_vni vni_id=%u add=%u\n", u->vni_id, (unsigned)u->add);
                        }
                        break;
                    case CP2DP_CODE_INTF_VLAN_GRP_BIND:
                        if (dp_msg->data_size >= hdr_sz + sizeof(dp_intf_vlan_grp_bind_t)) {
                            const dp_intf_vlan_grp_bind_t *u = (const dp_intf_vlan_grp_bind_t *)payload;
                            tracer(dp_ctx->dptr, DCONF, "    intf_update: vlan_grp_bind add=%u vlan_bitmapp[%zu bytes]\n",
                                (unsigned)u->add, sizeof(u->vlan_bitmapp));
                        }
                        break;
                    case CP2DP_CODE_INTF_GRP_VLAN_BIND:
                        if (dp_msg->data_size >= hdr_sz + sizeof(dp_intf_grp_bind_t)) {
                            const dp_intf_grp_bind_t *u = (const dp_intf_grp_bind_t *)payload;
                            tracer(dp_ctx->dptr, DCONF, "    intf_update: grp_vlan_bind add=%u if_bitmapp[%zu bytes]\n",
                                (unsigned)u->add, sizeof(u->if_bitmapp));
                        }
                        break;
                    case CP2DP_CODE_INTF_LOG_UPDATE:
                        if (dp_msg->data_size >= hdr_sz + sizeof(dp_intf_log_update_t)) {
                            tracer(dp_ctx->dptr, DCONF, "    intf_update: log_update\n");
                        }
                        break;
                    case CP2DP_CODE_INTF_GRE_TUNNEL:
                        if (dp_msg->data_size >= hdr_sz + sizeof(dp_intf_gre_tunnel_update_t)) {
                            const dp_intf_gre_tunnel_update_t *u =
                                (const dp_intf_gre_tunnel_update_t *)payload;
                            char lcl_str[INET_ADDRSTRLEN];
                            char src_str[INET_ADDRSTRLEN];
                            char dst_str[INET_ADDRSTRLEN];

                            tcp_ip_covert_ip_n_to_p(u->lcl_ip, (c_string)lcl_str);
                            tcp_ip_covert_ip_n_to_p(u->tunnel_src_ip, (c_string)src_str);
                            tcp_ip_covert_ip_n_to_p(u->tunnel_dst_ip, (c_string)dst_str);

                            tracer(dp_ctx->dptr, DCONF,
                                "    intf_update: gre_tunnel lcl=%s/%u src=%s dst=%s up=%u\n",
                                lcl_str, (unsigned)u->mask, src_str, dst_str,
                                (unsigned)u->tunnel_up);
                        }
                        break;
                    case CP2DP_CODE_BD_AC_BIND:
                    case CP2DP_CODE_BD_AC_UNBIND:
                        if (dp_msg->data_size >= hdr_sz + sizeof(dp_intf_bd_ac_bind_t)) {
                            const dp_intf_bd_ac_bind_t *u =
                                (const dp_intf_bd_ac_bind_t *)payload;
                            tracer(dp_ctx->dptr, DCONF,
                                "    intf_update: bd_ac_bind bd_port_id=%u ac_port_id=%u\n",
                                u->bd_port_id, u->ac_port_id);
                        }
                        break;
                    case CP2DP_CODE_BD_AC_ENCAP_8021Q:
                        if (dp_msg->data_size >=
                            hdr_sz + sizeof(dp_intf_bd_ac_encap_8021q_t)) {
                            const dp_intf_bd_ac_encap_8021q_t *u =
                                (const dp_intf_bd_ac_encap_8021q_t *)payload;
                            tracer(dp_ctx->dptr, DCONF,
                                "    intf_update: bd_ac_encap_8021q "
                                "ac_port_id=%u tag=%u\n",
                                u->ac_port_id, u->encap_8021q_tag);
                        }
                        break;
                    default:
                        break;
                }
            }
        }
        break;

        case DP_GENERICS:
        {
            if (dp_msg->data_size < sizeof(dp_generic_msg_t))
                break;

            dp_generic_msg_t *g = (dp_generic_msg_t *)dp_msg->data;

            const char *opcode_str =
                (g->opcode == DP_GENERIC_RMAC)   ? "RMAC"   :
                (g->opcode == DP_GENERIC_RTR_ID) ? "RTR_ID" : "?";

            tracer(dp_ctx->dptr, DCONF,
                "  generic_msg: opcode=%s(%u)\n",
                opcode_str, (unsigned)g->opcode);

            switch (g->opcode) {
                case DP_GENERIC_RMAC:
                    tracer(dp_ctx->dptr, DCONF,
                        "  generic_rmac: mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                        g->u.mac_addr[0], g->u.mac_addr[1], g->u.mac_addr[2],
                        g->u.mac_addr[3], g->u.mac_addr[4], g->u.mac_addr[5]);
                    break;
                case DP_GENERIC_RTR_ID:
                    break;
                default:
                    break;
            }
        }
        break;


        default:
            tracer(dp_ctx->dptr, DCONF,
                "  payload: %u bytes (raw)\n", dp_msg->data_size);
            break;
    }
}
