
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"
#include "../cmdcodes.h"
#include "../router_init.h"
#include "../utils.h"
#include "Interface/dp_intf.h"
#include "Interface/dp_intf_store.h"
#include "Vrfs/dp_vrf.h"
#include "../c-hashtable/hashtable.h"
#include "../c-hashtable/hashtable_itr.h"
#include "../BitOp/bitmap.h"

extern graph_t *topo;

/* Datapath show commands */
#define CMDCODE_SHOW_DP_VRF_TABLE 1
#define CMDCODE_SHOW_DP_INTF_TABLE 2
#define CMDCODE_SHOW_DP_FIB 3


/* Handler for datapath show commands */
static int
dp_show_handler(int cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable) {

    node_t *node = NULL;
    c_string node_name = NULL;
    c_string fib_name = NULL;
    c_string intf_name_filter = NULL;
    tlv_struct_t *tlv;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "fib-name"))
            fib_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "intf-name"))
            intf_name_filter = tlv->value;
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    
    if (!node) {
        cprintf("Error: Node %s not found\n", node_name);
        return -1;
    }

    switch (cmdcode) {

        case CMDCODE_SHOW_DP_VRF_TABLE:
        {
            hashtable_t *vrf_ht = node->dp_vrf_ht;
            
            if (!vrf_ht) {
                cprintf("Node %s: Datapath VRF table not initialized\n", node_name);
                return 0;
            }

            cprintf("\n");
            cprintf("====================================\n");
            cprintf("Node: %s - Datapath VRF Table\n", node_name);
            cprintf("====================================\n");
            cprintf("%-10s %-20s %-15s %-15s\n", 
                    "VRF ID", "VRF Name", "IPv4 FIB", "IPv6 FIB");
            cprintf("------------------------------------------------------------\n");

            /* Iterate through hashtable */
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
            cprintf("\n");
        }
        break;

        case CMDCODE_SHOW_DP_INTF_TABLE:
        {
            hashtable_t *intf_ht = node->dp_intf_ht;
            char ipv4_str[32];
            char ipv6_str[64];
            char ipv6_ll_str[64];
            char mac_str[32];
            
            if (!intf_ht) {
                cprintf("Node %s: Datapath interface table not initialized\n", node_name);
                return 0;
            }

            cprintf("\n");
            cprintf("Node: %s - Datapath Interface Table", node_name);
            if (intf_name_filter) {
                cprintf(" (Filter: %s)", intf_name_filter);
            }
            cprintf("\n");
            cprintf("================================================================================\n");

            /* Iterate through hashtable */
            struct hashtable_itr *itr = hashtable_iterator(intf_ht);
            
            if (hashtable_count(intf_ht) > 0) {
                int count = 0;
                do {
                    dp_intf_t *intf = (dp_intf_t *)hashtable_iterator_value(itr);
                    if (intf) {
                        /* Apply filter if specified */
                        if (intf_name_filter && intf->if_name[0]) {
                            if (strcmp(intf->if_name, intf_name_filter) != 0) {
                                continue;
                            }
                        }
                        
                        count++;
                        
                        /* Format IP addresses and MAC */
                        if (intf->ip_addr) {                          
                            tcp_ip_covert_ip_n_to_p(intf->ip_addr, (c_string)ipv4_str);                      
                            snprintf(ipv4_str + strlen(ipv4_str), sizeof(ipv4_str) - strlen(ipv4_str), "/%u", intf->mask);
                        } else {
                            strcpy(ipv4_str, "N/A");
                        }
                        
                        if (intf->v6addr[0] || intf->v6addr[15]) {
                            inet_ntop(AF_INET6, intf->v6addr, ipv6_str, sizeof(ipv6_str));
                            snprintf(ipv6_str + strlen(ipv6_str), sizeof(ipv6_str) - strlen(ipv6_str), "/%u", intf->v6mask);
                        } else {
                            strcpy(ipv6_str, "N/A");
                        }
                        
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
                            case DP_LAN_MODE_NONE: l2_mode_str = "None"; break;
                            case DP_LAN_ACCESS_MODE: l2_mode_str = "Access"; break;
                            case DP_LAN_TRUNK_MODE: l2_mode_str = "Trunk"; break;
                            default: l2_mode_str = "Unknown"; break;
                        }
                        
                        /* Display interface details */
                        cprintf("\nInterface: %s (Port ID: %u)\n", 
                                intf->if_name[0] ? intf->if_name : "N/A", intf->port_id);
                        cprintf("  Type: %-20s  Status: %s\n", 
                                dp_intf_type_str(intf->if_type), intf->is_up ? "Up" : "Down");
                        cprintf("  VRF: %s\n", intf->vrf ? intf->vrf->vrf_name : "N/A");
                        cprintf("  MAC Address: %s\n", mac_str);
                        
                        cprintf("\n  Layer 3 Configuration:\n");
                        cprintf("    IPv4 Address    : %s\n", ipv4_str);
                        cprintf("    IPv6 Address    : %s\n", ipv6_str);
                        cprintf("    IPv6 Link-Local : %s\n", ipv6_ll_str);
                        
                        cprintf("\n  Layer 2 Configuration:\n");
                        cprintf("    Switchport      : %s\n", intf->switchport ? "Yes" : "No");
                        cprintf("    L2 Mode         : %s\n", l2_mode_str);
                        cprintf("    VLAN ID         : %u\n", intf->vlan_id);
                        cprintf("    VNI ID          : %u\n", intf->vni_id);
                        if (intf->vlan_intf) {
                            cprintf("    Parent VLAN  : %u\n", intf->vlan_intf->vlan_id);
                        }
                        
                        /* Display member ports if it's a VLAN interface */
                        bool has_members = false;
                        for (int i = 0; i < MAX_VLAN_MEMBER_PORTS; i++) {
                            if (intf->mports[i]) {
                                if (!has_members) {
                                    cprintf("    Member Ports    : ");
                                    has_members = true;
                                } else {
                                    cprintf(", ");
                                }
                                cprintf("%s", intf->mports[i]->if_name);
                            }
                        }
                        if (has_members) cprintf("\n");
                        
                        /* Display VLAN bitmap for trunk interfaces */
                        if (intf->vlan_bitmap && intf->l2_mode == DP_LAN_TRUNK_MODE) {
                            cprintf("    Trunk VLANs     : ");
                            bool first_vlan = true;
                            int vlan_count = 0;
                            for (uint16_t vlan = 0; vlan < intf->vlan_bitmap->tsize && vlan < 4096; vlan++) {
                                if (bitmap_at(intf->vlan_bitmap, vlan)) {
                                    if (!first_vlan) cprintf(", ");
                                    cprintf("%u", vlan);
                                    first_vlan = false;
                                    vlan_count++;
                                    /* Limit display to avoid excessive output */
                                    if (vlan_count >= 20) {
                                        cprintf(", ...");
                                        break;
                                    }
                                }
                            }
                            if (vlan_count == 0) cprintf("None");
                            cprintf("\n");
                        }
                        
                        /* Display tunnel/overlay information */
                        if (intf->gre_tunnel_dst_ip) {
                            struct in_addr tunnel_addr;
                            tunnel_addr.s_addr = intf->gre_tunnel_dst_ip;
                            char tunnel_str[32];
                            inet_ntop(AF_INET, &tunnel_addr, tunnel_str, sizeof(tunnel_str));
                            cprintf("\n  Tunnel Configuration:\n");
                            cprintf("    GRE Tunnel Dest : %s\n", tunnel_str);
                        }
                        
                        if (intf->olay_tunnel_intf) {
                            if (!intf->gre_tunnel_dst_ip) {
                                cprintf("\n  Tunnel Configuration:\n");
                            }
                            cprintf("    Overlay Tunnel  : Port %u (%s)\n", 
                                    intf->olay_tunnel_intf->port_id,
                                    intf->olay_tunnel_intf->if_name[0] ? intf->olay_tunnel_intf->if_name : "N/A");
                        }
                        
                        cprintf("\n  Packet Statistics:\n");
                        cprintf("    RX Packets      : %-12u  TX Packets      : %u\n", 
                                intf->pkt_recv, intf->pkt_sent);
                        cprintf("    RX Dropped      : %-12u  TX Dropped      : %u\n", 
                                intf->recvd_pkt_dropped, intf->xmit_pkt_dropped);
                        
                        cprintf("--------------------------------------------------------------------------------\n");
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
            cprintf("\n");
        }
        break;

        case CMDCODE_SHOW_DP_FIB:
        {
            cprintf("\n");
            cprintf("Node: %s - Datapath FIB: %s\n", node_name, fib_name);
            cprintf("FIB display not yet implemented\n");
            cprintf("\n");
        }
        break;

        default:
            break;
    }

    return 0;
}

/* Construct the following CLI tree : 

CLI : 
    show node <node-name> data-path vrf-table 
    show node <node-name> data-path interface-table [<intf-name>]
    show node <node-name> data-path fib <fib-name>
*/
void 
dp_build_dp_show_cli_tree (param_t *node_name) {

    /* show node <node-name> data-path ... */
    static param_t data_path;
    init_param(&data_path, CMD, "data-path", NULL, NULL, INVALID, NULL, "Datapath information");
    libcli_register_param(node_name, &data_path);

    {
        /* show node <node-name> data-path vrf-table */
        static param_t vrf_table;
        init_param(&vrf_table, CMD, "vrf-table", dp_show_handler, NULL, INVALID, NULL, "Show datapath VRF table");
        libcli_register_param(&data_path, &vrf_table);
        libcli_set_param_cmd_code(&vrf_table, CMDCODE_SHOW_DP_VRF_TABLE);
    }

    {
        /* show node <node-name> data-path interface-table [<intf-name>] */
        static param_t intf_table;
        init_param(&intf_table, CMD, "interface-table", dp_show_handler, NULL, INVALID, NULL, "Show datapath interface table");
        libcli_register_param(&data_path, &intf_table);
        libcli_set_param_cmd_code(&intf_table, CMDCODE_SHOW_DP_INTF_TABLE);
        
        {
            /* Optional interface name filter */
            static param_t intf_name;
            init_param(&intf_name, LEAF, NULL, dp_show_handler, NULL, STRING, "intf-name", "Interface name filter (optional)");
            libcli_register_param(&intf_table, &intf_name);
            libcli_set_param_cmd_code(&intf_name, CMDCODE_SHOW_DP_INTF_TABLE);
        }
    }

    {
        /* show node <node-name> data-path fib ... */
        static param_t fib;
        init_param(&fib, CMD, "fib", NULL, NULL, INVALID, NULL, "Show datapath FIB");
        libcli_register_param(&data_path, &fib);

        {
            /* show node <node-name> data-path fib <fib-name> */
            static param_t fib_name;
            init_param(&fib_name, LEAF, NULL, dp_show_handler, NULL, STRING, "fib-name", "FIB name (e.g., inet.0, inet6.0)");
            libcli_register_param(&fib, &fib_name);
            libcli_set_param_cmd_code(&fib_name, CMDCODE_SHOW_DP_FIB);
        }
    }
}
