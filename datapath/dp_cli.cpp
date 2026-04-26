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
#include "../tcpconst.h"

extern graph_t *topo;

/* Command codes for show data-path subcommands */
#define CMDCODE_SHOW_DP_VRF_TABLE        1
#define CMDCODE_SHOW_DP_INTF_TABLE       2
#define CMDCODE_SHOW_DP_INTF_TABLE_BRIEF 3
#define CMDCODE_SHOW_DP_FIB              4
#define CMDCODE_SHOW_DP_ARP              5

/* -----  Interface display helpers  ----- */

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
    }

    cprintf("%-10s  %-12s  %-20s  %-32s  %-6s  %s\n",
            intf->if_name[0] ? intf->if_name : "N/A",
            intf->vrf ? intf->vrf->vrf_name : "N/A",
            ipv4_str,
            ipv6_str,
            l2l3_str,
            dp_intf_type_str(intf->if_type));
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

    /* Layer 2 */
    cprintf("\n  Layer 2 Configuration:\n");
    cprintf("    Switchport      : %s\n", intf->switchport ? "Yes" : "No");
    cprintf("    L2 Mode         : %s\n", l2_mode_str);
    cprintf("    VLAN ID         : %u\n", intf->vlan_id);
    cprintf("    VNI ID          : %u\n", intf->vni_id);
    if (intf->vlan_intf) {
        cprintf("    Parent VLAN     : %u\n", intf->vlan_intf->vlan_id);
    }

    /* Member ports (VLAN SVI) */
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

    /* Tunnel / overlay */
    if (intf->gre_tunnel_dst_ip) {
        struct in_addr tunnel_addr;
        tunnel_addr.s_addr = intf->gre_tunnel_dst_ip;
        char tunnel_str[32];
        inet_ntop(AF_INET, &tunnel_addr, tunnel_str, sizeof(tunnel_str));
        cprintf("\n  Tunnel Configuration:\n");
        cprintf("    GRE Tunnel Dest  : %s\n", tunnel_str);
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

/* -----  Show command handler  ----- */

static int
dp_show_handler(int cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable)
{
    node_t *node = NULL;
    dp_ctx_t *dp_ctx;
    c_string node_name = NULL;
    c_string fib_name = NULL;
    c_string intf_name_filter = NULL;
    c_string vrf_name = NULL;
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
        hashtable_t *intf_ht = node->dp_ctx->dp_intf_ht;

        if (!intf_ht) {
            cprintf("Node %s: Datapath interface table not initialized\n", node_name);
            return 0;
        }

        printw("\n");
        cprintf("Node: %s - Datapath Interface Table", node_name);
        if (intf_name_filter) {
            cprintf(" (Filter: %s)", intf_name_filter);
        }
        printw("\n");
        cprintf("================================================================================\n");

        struct hashtable_itr *itr = hashtable_iterator(intf_ht);

        if (hashtable_count(intf_ht) > 0) {
            int count = 0;
            do {
                dp_intf_t *intf = (dp_intf_t *)hashtable_iterator_value(itr);
                if (intf) {
                    if (intf_name_filter && intf->if_name[0]) {
                        if (strcmp(intf->if_name, (const char *)intf_name_filter) != 0) {
                            continue;
                        }
                    }
                    count++;
                    dp_print_interface(intf);
                }
            } while (hashtable_iterator_advance(itr));

            if (count == 0) {
                cprintf("No interfaces match the filter\n");
            }
        } else {
            cprintf("No interfaces configured\n");
        }

        free(itr);
        cprintf("================================================================================\n");
        printw("\n");
        break;
    }

    case CMDCODE_SHOW_DP_INTF_TABLE_BRIEF: {
        hashtable_t *intf_ht = node->dp_ctx->dp_intf_ht;

        if (!intf_ht) {
            cprintf("Node %s: Datapath interface table not initialized\n", node_name);
            return 0;
        }

        printw("\n");
        cprintf("Node: %s - Datapath Interface Table (brief)\n", node_name);
        cprintf("%-10s  %-12s  %-20s  %-32s  %-6s  %s\n",
                "IfName", "VRF", "IPv4", "IPv6", "Mode", "Type");
        cprintf("-----------------------------------------------------------------------------------------------------\n");

        struct hashtable_itr *itr = hashtable_iterator(intf_ht);

        if (hashtable_count(intf_ht) > 0) {
            do {
                dp_intf_t *intf = (dp_intf_t *)hashtable_iterator_value(itr);
                if (intf) {
                    dp_print_interface_brief(intf);
                }
            } while (hashtable_iterator_advance(itr));
        }
        free(itr);
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

        show_arp_table(arp_table);
        break;
    }

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

}

