/*
 * =============================================================================
 * File: dp_cli.cpp
 * Description: CLI for datapath: show VRF table, interface table, FIB.
 * =============================================================================
 *
 * Design:
 *   - Registers "show node <node-name> data-path ..." commands (VRF table,
 *     interface table [brief] [intf-name], fib <fib-name>).
 *   - dp_show_handler() dispatches by cmdcode and prints from node->dp_ctx
 *     (hashtables, special interfaces). FIB display is stubbed.
 *   - dp_print_interface() / dp_print_interface_brief() format one interface
 *     (L2/L3 config, stats, tunnel, member ports, etc.).
 * =============================================================================
 */

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"
#include "../cmdcodes.h"
#include "../utils.h"
#include "Interface/dp_intf.h"
#include "Interface/dp_intf_store.h"
#include "Vrfs/dp_vrf.h"
#include "FIB/fib.h"
#include "FIB/fib_show.h"
#include "Layer2/arp/arp.h"
#include "../libs/c-hashtable/hashtable.h"
#include "../libs/c-hashtable/hashtable_itr.h"
#include "../libs/mtrie/atomic_mtrie.h"
#include "../libs/BitOp/bitmap.h"
#include "../router_init.h"
#include "dp_ctx.h"
#include "dp_uapi.h"
#include "../tcpconst.h"
#include "../libs/common/protoIds.h"
#include "classifier/pkt_classifier.h"
#include "Layer2/switching/mac_table.h"
#include "Layer2/MacNexthop/L2FwdObject.h"
#include "../libs/Tree/libtree.h"
#include "../libs/common/mpls_lstack.h"

extern graph_t *topo;

/* Command codes for show data-path subcommands */
#define CMDCODE_SHOW_DP_VRF_TABLE        1
#define CMDCODE_SHOW_DP_INTF_TABLE       2
#define CMDCODE_SHOW_DP_INTF_TABLE_BRIEF 3
#define CMDCODE_SHOW_DP_FIB              4
#define CMDCODE_SHOW_DP_ARP              5
#define CMDCODE_DEBUG_DP_MEMPOOL         6
#define CMDCODE_DEBUG_DP_CLASSIFIERS     7
#define CMDCODE_SHOW_BD_MAC              8
#define CMDCODE_DEBUG_DP_L2_FWD_OBJ_DB   9

/* -----  Interface display helpers  ----- */

static void
rte_mempool_custom_dump(struct rte_mempool *mp)
{
    struct rte_mempool_memhdr *memhdr;
    struct rte_mempool_ops *ops;
    unsigned common_count;
    unsigned cache_count;
    size_t mem_len = 0;

    RTE_ASSERT(mp != NULL);

    cprintf("mempool <%s>@%p\n", mp->name, mp);
    cprintf("  flags=%x\n", mp->flags);
    cprintf("  socket_id=%d\n", mp->socket_id);
    cprintf("  pool=%p\n", mp->pool_data);
    cprintf("  iova=0x%" PRIx64 "\n", mp->mz->iova);
    cprintf("  nb_mem_chunks=%u\n", mp->nb_mem_chunks);
    cprintf("  size=%" PRIu32 "\n", mp->size);
    cprintf("  populated_size=%" PRIu32 "\n", mp->populated_size);
    cprintf("  header_size=%" PRIu32 "\n", mp->header_size);
    cprintf("  elt_size=%" PRIu32 "\n", mp->elt_size);
    cprintf("  trailer_size=%" PRIu32 "\n", mp->trailer_size);
    cprintf("  total_obj_size=%" PRIu32 "\n",
            mp->header_size + mp->elt_size + mp->trailer_size);

    cprintf("  private_data_size=%" PRIu32 "\n", mp->private_data_size);

    cprintf("  ops_index=%d\n", mp->ops_index);
    ops = rte_mempool_get_ops(mp->ops_index);
    cprintf("  ops_name: <%s>\n", (ops != NULL) ? ops->name : "NA");
    
    unsigned avail = rte_mempool_avail_count(mp);
    unsigned inuse = rte_mempool_in_use_count(mp);
    cprintf("  avail=%u inuse=%u\n", avail, inuse);

    STAILQ_FOREACH(memhdr, &mp->mem_list, next)
    {
        cprintf("  memory chunk at %p, addr=%p, iova=0x%" PRIx64 ", len=%zu\n",
                memhdr, memhdr->addr, memhdr->iova, memhdr->len);
        mem_len += memhdr->len;
    }
    if (mem_len != 0)
    {
        cprintf("  avg bytes/object=%#Lf\n",
                (long double)mem_len / mp->size);
    }
}

static void
dp_print_interface_brief(dp_intf_t *intf)
{
    char ipv4_str[32];
    char ipv6_str[64];

    if (!intf) return;

    if (intf->ip_addr) {
        tcp_ip_covert_ip_n_to_p(intf->ip_addr, (c_string)ipv4_str);
        snprintf(ipv4_str + strlen(ipv4_str),
                 sizeof(ipv4_str) - strlen(ipv4_str),
                 "/%u", intf->mask);
    } else {
        strcpy(ipv4_str, "N/A");
    }

    if (intf->v6addr[0] || intf->v6addr[15]) {
        inet_ntop(AF_INET6, intf->v6addr, ipv6_str, sizeof(ipv6_str));
    } else {
        strcpy(ipv6_str, "N/A");
    }

    const char *l2l3_str = "L3";
    if (intf->switchport) {
        l2l3_str = "L2";
    } else if (intf->if_type == DP_INTF_TYPE_VLAN_FLOOD ||
               intf->if_type == DP_INTF_TYPE_BD_FLOOD) {
        l2l3_str = "L2";
    }

    /* Width+precision keeps columns aligned even if a field is long. */
    cprintf("%-16.16s %-12.12s %-18.18s %-22.22s %-4.4s %-14.14s %10u %10u\n",
            intf->if_name[0] ? intf->if_name : "N/A",
            intf->vrf ? intf->vrf->vrf_name : "N/A",
            ipv4_str,
            ipv6_str,
            l2l3_str,
            dp_intf_type_str(intf->if_type),
            intf->pkt_recv,
            intf->pkt_sent);
}

static void
dp_print_interface(dp_intf_t *intf)
{
    char ipv4_str[32];
    char ipv6_str[64];
    char ipv6_ll_str[64];
    char mac_str[32];

    if (!intf) return;

    /* IPv4 */
    if (intf->ip_addr) {
        tcp_ip_covert_ip_n_to_p(intf->ip_addr, (c_string)ipv4_str);
        snprintf(ipv4_str + strlen(ipv4_str),
                 sizeof(ipv4_str) - strlen(ipv4_str), "/%u", intf->mask);
    } else {
        strcpy(ipv4_str, "N/A");
    }

    /* IPv6 global */
    if (intf->v6addr[0] || intf->v6addr[15]) {
        inet_ntop(AF_INET6, intf->v6addr, ipv6_str, sizeof(ipv6_str));
        snprintf(ipv6_str + strlen(ipv6_str),
                 sizeof(ipv6_str) - strlen(ipv6_str), "/%u", intf->v6mask);
    } else {
        strcpy(ipv6_str, "N/A");
    }

    /* IPv6 link-local */
    if (intf->v6addr_link_local[0] || intf->v6addr_link_local[15]) {
        inet_ntop(AF_INET6, intf->v6addr_link_local, ipv6_ll_str, sizeof(ipv6_ll_str));
    } else {
        strcpy(ipv6_ll_str, "N/A");
    }

    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
            intf->mac_add.mac[0], intf->mac_add.mac[1], intf->mac_add.mac[2],
            intf->mac_add.mac[3], intf->mac_add.mac[4], intf->mac_add.mac[5]);

    const char *l2_mode_str = "None";
    switch (intf->l2_mode) {
        case DP_LAN_MODE_NONE:        l2_mode_str = "None";   break;
        case DP_LAN_ACCESS_MODE:      l2_mode_str = "Access"; break;
        case DP_LAN_TRUNK_MODE:       l2_mode_str = "Trunk";  break;
        default:                      l2_mode_str = "Unknown"; break;
    }

    /* Header and basic info */
    cprintf("\nInterface: %s (Port ID: %u)\n",
            intf->if_name[0] ? intf->if_name : "N/A", intf->port_id);
    cprintf("  Type: %-20s  Status: %s\n",
            dp_intf_type_str(intf->if_type), intf->is_up ? "Up" : "Down");
    cprintf("  VRF: %s\n", intf->vrf ? intf->vrf->vrf_name : "N/A");
    cprintf("  MAC Address: %s\n", mac_str);

    /* Layer 3 */
    cprintf("\n  Layer 3 Configuration:\n");
    cprintf("    IPv4 Address    : %s\n", ipv4_str);
    cprintf("    IPv6 Address    : %s\n", ipv6_str);
    cprintf("    IPv6 Link-Local : %s\n", ipv6_ll_str);

    if (intf->l3_acl_ingress.load(std::memory_order_acquire)) {

        cprintf("    L3 Ingress ACL Applied\n",
            intf->l3_acl_ingress.load(std::memory_order_acquire) ? "Yes" : "No");
    }
    if (intf->l3_acl_egress.load(std::memory_order_acquire)) {

        cprintf("    L3 Eggress ACL Applied\n",
            intf->l3_acl_egress.load(std::memory_order_acquire) ? "Yes" : "No");
    } 

    /* Layer 2 */
    cprintf("\n  Layer 2 Configuration:\n");
    cprintf("    Switchport      : %s\n", intf->switchport ? "Yes" : "No");
    cprintf("    L2 Mode         : %s\n", l2_mode_str);
    cprintf("    VLAN ID         : %u\n", intf->vlan_id);
    cprintf("    VNI ID          : %u\n", intf->vni_id);
    if (intf->vlan_intf) {
        cprintf("    Parent VLAN     : %u\n", intf->vlan_intf->vlan_id);
    }

    /* Member ACs (Bridge Domain) or member ports (VLAN SVI) */
    if (intf->if_type == DP_INTF_TYPE_BD) {
        bool has_acs = false;
        for (int i = 0; i < MAX_BD_MEMBER_PORTS; i++) {
            if (!intf->mports[i])
                continue;
            if (!has_acs) {
                cprintf("    Member ACs       : ");
                has_acs = true;
            } else {
                cprintf(", ");
            }
            cprintf("%s", intf->mports[i]->if_name[0] ?
                    intf->mports[i]->if_name : "N/A");
        }
        if (has_acs)
            cprintf("\n");
        else
            cprintf("    Member ACs       : None\n");
    } else {
        bool has_members = false;
        for (int i = 0; i < MAX_VLAN_MEMBER_PORTS; i++) {
            if (intf->mports[i]) {
                if (!has_members) {
                    cprintf("    Member Ports     : ");
                    has_members = true;
                } else {
                    cprintf(", ");
                }
                cprintf("%s", intf->mports[i]->if_name);
            }
        }
        if (has_members) printw("\n");
    }

    if (intf->bd_intf) {
        cprintf("    Parent BD        : %s\n",
                intf->bd_intf->if_name[0] ? intf->bd_intf->if_name : "N/A");
    }

    /* Trunk VLAN bitmap */
    if (intf->vlan_bitmap && intf->l2_mode == DP_LAN_TRUNK_MODE) {
        cprintf("    Trunk VLANs      : ");
        bool first_vlan = true;
        int vlan_count = 0;
        for (uint16_t vlan = 0; vlan < intf->vlan_bitmap->tsize && vlan < DP_MAX_VLAN_SUPORT; vlan++) {
            if (bitmap_at(intf->vlan_bitmap, vlan)) {
                if (!first_vlan) cprintf(", ");
                cprintf("%u", vlan);
                first_vlan = false;
                vlan_count++;
                if (vlan_count >= 20) {
                    cprintf(", ...");
                    break;
                }
            }
        }
        if (vlan_count == 0) cprintf("None");
        printw("\n");
    }

    if (intf->l2_acl_ingress.load(std::memory_order_acquire)) {

        cprintf("    L2 Ingress ACL Applied\n",
            intf->l2_acl_ingress.load(std::memory_order_acquire) ? "Yes" : "No");
    }
    if (intf->l2_acl_egress.load(std::memory_order_acquire)) {

        cprintf("    L2 Eggress ACL Applied\n",
            intf->l2_acl_egress.load(std::memory_order_acquire) ? "Yes" : "No");
    } 

    /* Tunnel / overlay */
    if (intf->if_type == DP_INTF_TYPE_GRE_TUNNEL) {

        char tunnel_src_str[32];
        char tunnel_dst_str[32];
        tcp_ip_covert_ip_n_to_p(intf->gre_tunnel_src_ip, (c_string)tunnel_src_str);
        tcp_ip_covert_ip_n_to_p(intf->gre_tunnel_dst_ip, (c_string)tunnel_dst_str);
        cprintf("\n  Tunnel Configuration:\n");
        cprintf("    GRE Tunnel End Point  : [%s %s]\n", tunnel_src_str, tunnel_dst_str);
        cprintf("    Is Active ? %s", intf->is_tunnel_up ? "Y" : "N");
    }

    if (intf->olay_tunnel_intf) {
        if (!intf->gre_tunnel_dst_ip) {
            cprintf("\n  Tunnel Configuration:\n");
        }
        cprintf("    Overlay Tunnel   : Port %u (%s)\n",
                intf->olay_tunnel_intf->port_id,
                intf->olay_tunnel_intf->if_name[0] ? intf->olay_tunnel_intf->if_name : "N/A");
    }

    /* Stats */
    cprintf("\n  Packet Statistics:\n");
    cprintf("    RX Packets       : %-12u  TX Packets       : %u\n",
            intf->pkt_recv, intf->pkt_sent);
    cprintf("    RX Dropped       : %-12u  TX Dropped       : %u\n",
            intf->recvd_pkt_dropped, intf->xmit_pkt_dropped);

    cprintf("--------------------------------------------------------------------------------\n");
}

/* -----  Classifier display helper  ----- */

static void
dp_show_intf_classifiers(dp_intf_t *intf)
{
    cprintf("\nInterface: %s\n", intf->if_name[0] ? intf->if_name : "<unnamed>");
    cprintf("  %-6s  %-20s  %-10s  %-14s  %-10s  %s\n",
            "ID", "Protocol", "trap_fn", "trap_app_cbk", "ev_dis/pkt_q", "count");
    cprintf("  %-6s  %-20s  %-10s  %-14s  %-10s  %s\n",
            "------", "--------------------", "----------",
            "--------------", "----------", "-------");

    int total = 0;
    for (int i = 0; i < (int)PROTO_IDX_MAX; i++) {
        trap_rule_t *rule = intf->trap_rule_table[i];
        while (rule) {
            cprintf("  %-6u  %-20s  %-10s  %-14s  %-10s  %u\n",
                    rule->id,
                    proto_id_str(rule->proto),
                    rule->trap_fn       ? "set"     : "not-set",
                    rule->trap_app_cbk  ? "set"     : "not-set",
                    (rule->ev_dis && rule->pkt_q) ? "set" : "not-set",
                    rule->trap_count);
            total++;
            rule = rule->next;
        }
    }

    if (total == 0)
        cprintf("  (no trap rules installed)\n");
}

/* -----  L2 forwarding object database dump  ----- */

static const char *
l2_fwd_type_str(L2_FWD_TYPE_T fwd_type)
{
    switch (fwd_type) {
        case L2_FWD_PORT:        return "PORT";
        case L2_FWD_RMAC:        return "RMAC";
        case L2_FWD_FLOODING:    return "FLOODING";
        case L2_FWD_MPLS_TUNNEL: return "MPLS_TUNNEL";
        case L2_FWD_SRv6_TUNNEL: return "SRv6_TUNNEL";
        case L2_FWD_VxLAN:       return "VxLAN";
        case L2_FWD_STEERING:    return "STEERING";
        case L2_FWD_MAX:
        default:                 return "UNKNOWN";
    }
}

static void
dp_print_l2_fwd_object(dp_ctx_t *dp_ctx, mac_fwd_object_t *obj)
{
    cprintf("  obj=%p  idx=%u  ref=%u  ",
            (void *)obj, obj->idx, obj->ref_count);

    switch (obj->fwd_type) {

        case L2_FWD_PORT: {
            dp_intf_t *oif = (obj->u.dp_intf < DP_MAX_INTF) ?
                dp_ctx->intf_table[obj->u.dp_intf] : NULL;
            cprintf("ifindex=%u (%s)",
                    obj->u.dp_intf,
                    oif && oif->if_name[0] ? oif->if_name : "-");
            break;
        }

        case L2_FWD_RMAC:
            cprintf("rmac");
            break;

        case L2_FWD_FLOODING: {
            dp_intf_t *vfif = obj->u.l2_flood.vfif;
            dp_intf_t *vlan_bd = obj->u.l2_flood.vlan_bd_port ?
                ((obj->u.l2_flood.vlan_bd_port < DP_MAX_INTF) ?
                    dp_ctx->intf_table[obj->u.l2_flood.vlan_bd_port] : NULL) :
                NULL;
            cprintf("vfif=%s  vlan_bd_port=%u (%s)",
                    vfif && vfif->if_name[0] ? vfif->if_name : "-",
                    obj->u.l2_flood.vlan_bd_port,
                    vlan_bd && vlan_bd->if_name[0] ? vlan_bd->if_name : "-");
            break;
        }

        case L2_FWD_MPLS_TUNNEL: {
            mpls_lstack_t *st = obj->u.lbl_stk;
            cprintf("lbl_stk=%p", (void *)st);
            if (st && st->curr_index >= 0) {
                cprintf("  labels=");
                for (int i = 0; i <= st->curr_index; i++) {
                    cprintf("%s%u/%s",
                            i ? "," : "",
                            mpls_label_get_value(st->labels[i].label_val),
                            mpls_op_tostring(st->labels[i].op));
                }
            }
            break;
        }

        case L2_FWD_SRv6_TUNNEL: {
            cprintf("seg_cnt=%u", obj->u.srv6.seg_lst_cnt);
            if (obj->u.srv6.seg_lst) {
                for (uint8_t i = 0; i < obj->u.srv6.seg_lst_cnt; i++) {
                    char sid[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, (*obj->u.srv6.seg_lst)[i],
                              sid, sizeof(sid));
                    cprintf("  sid[%u]=%s", i, sid);
                }
            }
            break;
        }

        case L2_FWD_VxLAN: {
            char vtep[IPV4_ADDR_LEN_STR];
            tcp_ip_covert_ip_n_to_p(obj->u.vxlan.vtep_ip, (c_string)vtep);
            cprintf("vni=%u  vtep=%s",
                    obj->u.vxlan.l2vni, vtep);
            break;
        }

        case L2_FWD_STEERING:
            cprintf("steer=%s  obj_ifindex=%u",
                    obj->u.steering.steering_type == STEER_INTO_VRF ? "vrf" :
                    obj->u.steering.steering_type == STEER_INTO_BD  ? "bd"  :
                    "unknown",
                    obj->u.steering.u_steer.steered_obj_ifindex);
            break;

        default:
            cprintf("type=%u", (unsigned)obj->fwd_type);
            break;
    }

    cprintf("\n");
}

static void
dp_show_l2_fwd_object_db(dp_ctx_t *dp_ctx, const char *node_name)
{
    uint32_t total = 0;
    avltree_node_t *avl_node;

    printw("\n");
    cprintf("Node: %s - L2 Forwarding Object Database\n", node_name);
    cprintf("================================================================================\n");

    for (int t = 0; t < L2_FWD_MAX; t++) {
        avltree_t *tree = dp_ctx->l2_fwd_obj_tree[t];
        uint32_t count = 0;

        cprintf("\nType: %-12s  tree=%p\n",
                l2_fwd_type_str((L2_FWD_TYPE_T)t), (void *)tree);

        if (!tree) {
            cprintf("  (not initialized)\n");
            continue;
        }

        ITERATE_AVL_TREE_BEGIN(tree, avl_node) {
            mac_fwd_object_t *obj =
                avltree_container_of(avl_node, mac_fwd_object_t, glue);
            dp_print_l2_fwd_object(dp_ctx, obj);
            count++;
        } ITERATE_AVL_TREE_END;

        if (!count)
            cprintf("  (empty)\n");
        cprintf("  objects: %u\n", count);
        total += count;
    }

    cprintf("================================================================================\n");
    cprintf("Total interned objects: %u\n", total);
}

/* -----  Show command handler  ----- */

static int
dp_show_handler(int64_t cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable)
{
    node_t *node = NULL;
    dp_ctx_t *dp_ctx;
    c_string node_name = NULL;
    c_string fib_name = NULL;
    c_string intf_name_filter = NULL;
    c_string vrf_name = NULL;
    int numa_id = 0;
    uint16_t bd_id = 0;
    tlv_struct_t *tlv;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "fib-name"))
            fib_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "intf-name"))
            intf_name_filter = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "vrf-name"))
            vrf_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "numaid"))
            numa_id = atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "bd-id"))
            bd_id = (uint16_t)atoi((const char *)tlv->value);
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    dp_ctx = node->dp_ctx;

    switch (cmdcode) {

    case CMDCODE_SHOW_DP_VRF_TABLE: {
        hashtable_t *vrf_ht = node->dp_ctx->dp_vrf_ht;

        if (!vrf_ht) {
            cprintf("Node %s: Datapath VRF table not initialized\n", node_name);
            return 0;
        }

        printw("\n");
        cprintf("====================================\n");
        cprintf("Node: %s - Datapath VRF Table\n", node_name);
        cprintf("====================================\n");
        cprintf("%-10s %-20s %-15s %-15s\n",
                "VRF ID", "VRF Name", "IPv4 FIB", "IPv6 FIB");
        cprintf("------------------------------------------------------------\n");

        struct hashtable_itr *itr = hashtable_iterator(vrf_ht);

        if (hashtable_count(vrf_ht) > 0) {
            do {
                dp_vrf_t *vrf = (dp_vrf_t *)hashtable_iterator_value(itr);
                if (vrf) {
                    cprintf("%-10u %-20s %-15s %-15s\n",
                            vrf->vrf_id,
                            vrf->vrf_name[0] ? vrf->vrf_name : "<unnamed>",
                            vrf->fib_inet0 ? "Initialized" : "Not Init",
                            vrf->fib_inet6 ? "Initialized" : "Not Init");
                }
            } while (hashtable_iterator_advance(itr));
        } else {
            cprintf("No VRFs configured\n");
        }

        free(itr);
        printw("\n");
        break;
    }

    case CMDCODE_SHOW_DP_INTF_TABLE: {
        printw("\n");
        cprintf("Node: %s - Datapath Interface Table", node_name);
        if (intf_name_filter) {
            cprintf(" (Filter: %s)", intf_name_filter);
        }
        printw("\n");
        cprintf("================================================================================\n");

        int count = 0;
        for (int _i = 0; _i < DP_MAX_INTF; _i++) {
            dp_intf_t *intf = node->dp_ctx->intf_table[_i];
            if (!intf) continue;
            if (intf_name_filter && intf->if_name[0]) {
                if (strcmp(intf->if_name, (const char *)intf_name_filter) != 0) continue;
            }
            count++;
            dp_print_interface(intf);
        }
        if (count == 0) {
            cprintf("No interfaces configured\n");
        }

        cprintf("================================================================================\n");
        printw("\n");
        break;
    }

    case CMDCODE_SHOW_DP_INTF_TABLE_BRIEF: {
        printw("\n");
        cprintf("Node: %s - Datapath Interface Table (brief)\n", node_name);
        cprintf("%-16s %-12s %-18s %-22s %-4s %-14s %10s %10s\n",
                "IfName", "VRF", "IPv4", "IPv6", "Mode", "Type", "RX", "TX");
        cprintf("---------------------------------------------------------------------------------------------------------------\n");

        for (int _i = 0; _i < DP_MAX_INTF; _i++) {
            dp_intf_t *intf = node->dp_ctx->intf_table[_i];
            if (intf) dp_print_interface_brief(intf);
        }
        printw("\n");
        break;
    }

    case CMDCODE_SHOW_DP_FIB:
    {
        fib_t *fib = fib_get_by_name(dp_ctx, (char *)fib_name);

        if (!fib) {
            cprintf("Error: FIB '%s' not initialized\n", fib_name);
            return -1;
        }

        {
            #if 0
            atomic_mtrie_traverse(
                fib_get(node->dp_ctx, AF_IPV4, 0)->u.rts.lpm,
                atomic_mtrie_print_node, NULL);
            #endif
        }

        fib_show_routes_brief(fib);
        break;
    }

    case CMDCODE_SHOW_DP_ARP:
    {
        const char *arp_vrf = vrf_name ? (const char *)vrf_name : DEF_VRF_NAME;

        arp_table_t *arp_table = dp_vrf_get_arp_cache(dp_ctx, (char *)arp_vrf);
        
        if (!arp_table) {
            cprintf("Error: ARP cache not found for VRF '%s'\n", arp_vrf);
            return -1;
        }

        /* Route through dp_ev_dis for consistent view (no races with hash writers) */
        dp_show_arp_table_sync(dp_ctx, (void *)arp_table);
        break;
    }


    case CMDCODE_DEBUG_DP_MEMPOOL:
    {
        char mpool_name[64];
        memset (mpool_name, 0, sizeof (mpool_name));
        snprintf (mpool_name, sizeof (mpool_name), 
            "MP_%s_%u", node->dp_ctx->ctx_name, numa_id);
        
        struct rte_mempool *mpool = rte_mempool_lookup((const char *)mpool_name);
        if (!mpool) {
            cprintf ("Mpool Not found\n");
            break;
        }

        rte_mempool_custom_dump(mpool);
    }
    break;

    case CMDCODE_DEBUG_DP_CLASSIFIERS:
    {
        if (intf_name_filter) {
            /* Show classifiers for a single named interface */
            bool found = false;
            for (int _i = 0; _i < DP_MAX_INTF; _i++) {
                dp_intf_t *intf = dp_ctx->intf_table[_i];
                if (!intf) continue;
                if (strcmp(intf->if_name, (const char *)intf_name_filter) != 0) continue;
                dp_show_intf_classifiers(intf);
                found = true;
                break;
            }
            if (!found) {
                cprintf("Error: Interface '%s' not found\n", intf_name_filter);
                return -1;
            }
        } else {
            /* Show classifiers for all interfaces */
            cprintf("Node: %s - Interface Classifier (Trap Rules)\n", node_name);
            cprintf("================================================================================\n");
            int count = 0;
            for (int _i = 0; _i < DP_MAX_INTF; _i++) {
                dp_intf_t *intf = dp_ctx->intf_table[_i];
                if (!intf) continue;
                dp_show_intf_classifiers(intf);
                count++;
            }
            if (count == 0)
                cprintf("No interfaces configured\n");
            cprintf("================================================================================\n");
        }
    }
    break;

    case CMDCODE_SHOW_BD_MAC:
    {
        char bd_name[DP_INTF_NAME];
        snprintf(bd_name, sizeof(bd_name), "bd%u", bd_id);

        dp_intf_t *bd_intf = NULL;
        for (int _i = 0; _i < DP_MAX_INTF; _i++) {
            dp_intf_t *intf = dp_ctx->intf_table[_i];
            if (!intf || intf->if_type != DP_INTF_TYPE_BD)
                continue;
            if (strcmp(intf->if_name, bd_name) == 0) {
                bd_intf = intf;
                break;
            }
        }

        if (!bd_intf) {
            cprintf("Error: Bridge-domain %s not found\n", bd_name);
            return -1;
        }

        cprintf("Bridge-domain %u MAC Address Table\n", bd_id, bd_intf->if_name);
        show_mac_table(dp_ctx, bd_intf->mac_table, 0);
        break;
    }

    case CMDCODE_DEBUG_DP_L2_FWD_OBJ_DB:
        dp_show_l2_fwd_object_db(dp_ctx, (const char *)node_name);
        break;

    default:
        break;
    }

    return 0;
}

/* -----  CLI tree registration  ----- */

/**
 * Build CLI: show node <node-name> data-path { vrf-table | interface-table [brief] [intf-name] | fib <fib-name> }
 */
void
dp_build_dp_show_cli_tree(param_t *node_name)
{
    static param_t data_path;
    init_param(&data_path, CMD, "data-path", NULL, NULL, INVALID, NULL, "Datapath information");
    libcli_register_param(node_name, &data_path);

    {
        static param_t vrf_table;
        init_param(&vrf_table, CMD, "vrf-table", dp_show_handler, NULL, INVALID, NULL, "Show datapath VRF table");
        libcli_register_param(&data_path, &vrf_table);
        libcli_set_param_cmd_code(&vrf_table, CMDCODE_SHOW_DP_VRF_TABLE);
        libcli_set_user_flag(&vrf_table, CLI_F_DATA_PLANE);
    }

    {
        static param_t intf_table;
        init_param(&intf_table, CMD, "interface-table", dp_show_handler, NULL, INVALID, NULL, "Show datapath interface table");
        libcli_register_param(&data_path, &intf_table);
        libcli_set_param_cmd_code(&intf_table, CMDCODE_SHOW_DP_INTF_TABLE);
        libcli_set_user_flag(&intf_table, CLI_F_DATA_PLANE);

        {
            static param_t intf_name;
            init_param(&intf_name, LEAF, NULL, dp_show_handler, NULL, STRING, "intf-name", "Interface name filter (optional)");
            libcli_register_param(&intf_table, &intf_name);
            libcli_set_param_cmd_code(&intf_name, CMDCODE_SHOW_DP_INTF_TABLE);
            libcli_set_user_flag(&intf_name, CLI_F_DATA_PLANE);
        }

        {
            static param_t brief;
            init_param(&brief, CMD, "brief", dp_show_handler, NULL, INVALID, NULL, "Show datapath interface table (brief)");
            libcli_register_param(&intf_table, &brief);
            libcli_set_param_cmd_code(&brief, CMDCODE_SHOW_DP_INTF_TABLE_BRIEF);
            libcli_set_user_flag(&brief, CLI_F_DATA_PLANE);
        }
    }

    {
        static param_t fib;
        init_param(&fib, CMD, "fib", NULL, NULL, INVALID, NULL, "Show datapath FIB");
        libcli_register_param(&data_path, &fib);

        {
            static param_t fib_name;
            init_param(&fib_name, LEAF, NULL, dp_show_handler, NULL, STRING, "fib-name", "FIB name (format :  <vrf-name>.inet[6]");
            libcli_register_param(&fib, &fib_name);
            libcli_set_param_cmd_code(&fib_name, CMDCODE_SHOW_DP_FIB);
            libcli_set_user_flag(&fib_name, CLI_F_DATA_PLANE);
        }
    }

    {
        static param_t arp;
        init_param(&arp, CMD, "arp", dp_show_handler, NULL, INVALID, NULL, "Show ARP cache");
        libcli_register_param(&data_path, &arp);
        libcli_set_param_cmd_code(&arp, CMDCODE_SHOW_DP_ARP);
        libcli_set_user_flag(&arp, CLI_F_DATA_PLANE);
        {
            static param_t vrf_name;
            init_param(&vrf_name, LEAF, NULL, dp_show_handler, NULL, STRING, "vrf-name", "VRF name");
            libcli_register_param(&arp, &vrf_name);
            libcli_set_param_cmd_code(&vrf_name, CMDCODE_SHOW_DP_ARP);
            libcli_set_user_flag(&vrf_name, CLI_F_DATA_PLANE);
        }
    }

    
    {
        static param_t bd;
        init_param(&bd, CMD, "bridge-domain", 0, 0, INVALID, 0, "bridge-domain");
        libcli_register_param(&data_path, &bd);
        {
            static param_t bd_id;
            init_param(&bd_id, LEAF, NULL, NULL, 0, INT, "bd-id", "bridge-domain id");
            libcli_register_param(&bd, &bd_id);

            /* MAC Address Table of BD */
            {
                static param_t bd_mac;
                init_param(&bd_mac, CMD, "mac-address-table", dp_show_handler, 0, INVALID, 0, "mac-address-table");
                libcli_register_param(&bd_id, &bd_mac);
                libcli_set_param_cmd_code(&bd_mac, CMDCODE_SHOW_BD_MAC);
                libcli_set_user_flag(&bd_mac, CLI_F_DATA_PLANE);
            }
        }
    }

}

void
dp_build_dp_debug_cli_tree(param_t *node_name, param_t *show) 
{
    /* debug node <node-name> show mpools <numa-id>*/
    {
        {
            /* mpool ....*/
            static param_t mpool;
            init_param(&mpool, CMD, "mpool", NULL, NULL, INVALID, NULL, "Memory Pool");
            libcli_register_param(show, &mpool);
            {
                /* show mpool <numa-id>*/
                static param_t mpool_name;
                init_param(&mpool_name, LEAF, NULL, dp_show_handler, NULL, INT, "numaid", "Numa Node number");
                libcli_register_param(&mpool, &mpool_name);
                libcli_set_param_cmd_code(&mpool_name, CMDCODE_DEBUG_DP_MEMPOOL);
                libcli_set_user_flag(&mpool_name, CLI_F_DATA_PLANE);
            }
        }

        {
            /* classifiers */
            static param_t classifiers;
            init_param(&classifiers, CMD, "classifiers", dp_show_handler, NULL, INVALID, NULL, "Interface Classifiers");
            libcli_register_param(show, &classifiers);
            libcli_set_param_cmd_code(&classifiers, CMDCODE_DEBUG_DP_CLASSIFIERS);
            libcli_set_user_flag(&classifiers, CLI_F_DATA_PLANE);
            {
                /* classifiers <intf-name>*/
                static param_t intf_name;
                init_param(&intf_name, LEAF, NULL, dp_show_handler, NULL, STRING, "intf-name", "Interface name");
                libcli_register_param(&classifiers, &intf_name);
                libcli_set_param_cmd_code(&intf_name, CMDCODE_DEBUG_DP_CLASSIFIERS);
                libcli_set_user_flag(&intf_name, CLI_F_DATA_PLANE);
            }
        }
    }

    /* debug node <node-name> l2-fwd-object database */
    {
        static param_t l2_fwd_object;
        init_param(&l2_fwd_object, CMD, "l2-fwd-object", NULL, NULL, INVALID, NULL,
                   "L2 forwarding objects");
        libcli_register_param(node_name, &l2_fwd_object);
        {
            static param_t database;
            init_param(&database, CMD, "database", dp_show_handler, NULL, INVALID, NULL,
                       "Dump L2 forwarding object database");
            libcli_register_param(&l2_fwd_object, &database);
            libcli_set_param_cmd_code(&database, CMDCODE_DEBUG_DP_L2_FWD_OBJ_DB);
            libcli_set_user_flag(&database, CLI_F_DATA_PLANE);
        }
    }

}
