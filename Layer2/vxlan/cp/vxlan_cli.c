#include "../../../graph.h"
#include "../../mac_table.h"
#include "../../../tcpconst.h"
#include "../../../cmdcodes.h"
#include "../../../utils.h"
#include "../../../common/cp2dp.h"
#include "../../../CLIBuilder/libcli.h"
#include "../../../CLIBuilder/cmdtlv.h"
#include "../../../Interface/Interface.h"

extern graph_t *topo;

int
mac_table_config_handler (int cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable) {

    node_t *node;
    c_string if_name = NULL;
    c_string node_name = NULL;
    c_string mac_address = NULL;
    c_string remote_vtep_ip = NULL;
    vlan_id_t vlan_id = 0;
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {
        
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "vlan-id"))
            vlan_id = atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "mac-addr"))
            mac_address = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "remote-vtep"))
            remote_vtep_ip = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "oif"))
            if_name = tlv->value;

    } TLV_LOOP_END;
    
    node = node_get_node_by_name(topo, node_name);
    
    uint32_t vtep_ip = remote_vtep_ip ? tcp_ip_convert_ip_p_to_n(remote_vtep_ip) : 0;
    
    switch (enable_or_disable) {

        case CONFIG_ENABLE:
        {
            mac_addr_t mac_addr;
            if (sscanf((const char *)mac_address, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                      &mac_addr.mac[0], &mac_addr.mac[1], &mac_addr.mac[2],
                      &mac_addr.mac[3], &mac_addr.mac[4], &mac_addr.mac[5]) != 6) {
                cprintf("Error: Failed to parse MAC address %s\n", mac_address);
                return -1;
            }

            Interface *intf = node_get_intf_by_name (node, if_name);

            if (!intf) {
                cprintf ("Error : Interface %s not found\n", if_name);
                return -1;
            }

            cp2dp_mac_table_entry_add (node, (uint8_t *)mac_addr.mac, vlan_id,
                       intf->ifindex,  MAC_STATIC, true, vtep_ip);
            break;
        }
        case CONFIG_DISABLE:
        {
            mac_addr_t mac_addr;
            if (sscanf((const char *)mac_address, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                      &mac_addr.mac[0], &mac_addr.mac[1], &mac_addr.mac[2],
                      &mac_addr.mac[3], &mac_addr.mac[4], &mac_addr.mac[5]) != 6) {
                cprintf("Error: Failed to parse MAC address %s\n", mac_address);
                return -1;
            }
            
            Interface *intf = node_get_intf_by_name (node, if_name);

            if (!intf) {
                cprintf ("Error : Interface %s not found\n", if_name);
                return -1;
            }

           cp2dp_mac_table_entry_del (node, (uint8_t *)mac_addr.mac, vlan_id, 
                        intf->ifindex, true, vtep_ip);            
            break;
        }
        
        default:
            break;
    }
    
    return 0;
}