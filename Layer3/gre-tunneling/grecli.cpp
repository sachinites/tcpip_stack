#include "../../utils.h"
#include "../../CLIBuilder/libcli.h"
#include "grecmdcodes.h"
#include "../../router_init.h"
#include "../../Interface/InterfaceUApi.h"
#include "greuapi.h"
#include "../../dpal/cp2dp.h"
#include "../../cmdcodes.h"
#include "../../libs/BitOp/bitsop.h"

extern graph_t *topo;

extern int
validate_mask_value(Stack_t *tlv_stack, c_string mask_str);

static int
gre_tunnel_config_handler (int64_t cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable){

    node_t *node = NULL;
    uint32_t gre_tun_id = 0;
    uint32_t ip_addr_lcl;
    c_string if_up_down = NULL;
    c_string node_name = NULL;
    Interface *gre_tunnel = NULL;
    tlv_struct_t *tlv;
    c_string src_addr = NULL;
    c_string dst_addr = NULL;
    c_string intf_ip_addr = NULL;
    uint8_t mask = 0;
    c_string if_name = NULL;
    Interface *tunnel;
    char intf_name[IF_NAME_SIZE];

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if  (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "tunnel-id"))
            gre_tun_id = atoi((const char *)tlv->value);
        else if  (parser_match_leaf_id (tlv->leaf_id, "tunnel-src-ip"))
            src_addr = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "tunnel-dst-ip"))
            dst_addr = tlv->value;     
        else if  (parser_match_leaf_id (tlv->leaf_id, "intf-ip-address"))
            intf_ip_addr = tlv->value;                     
        else if  (parser_match_leaf_id (tlv->leaf_id, "mask"))
            mask = atoi((const char *)tlv->value);                     
        else if  (parser_match_leaf_id (tlv->leaf_id, "if-name"))
            if_name = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "if-up-down"))
            if_up_down = tlv->value; 

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    if (if_name) {
        tunnel = node_interface_lookup_by_name(node, (const char *)if_name);
    }
    else {
        snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", gre_tun_id);
        tunnel = node_interface_lookup_by_name(node, (const char *)intf_name);
    }

    switch (cmdcode) {

        case GRE_CONFIG_CREATE_TUNNEL_INTF:

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    if (!gre_tunnel_create (node, gre_tun_id)) return -1;
                    break;
                case CONFIG_DISABLE:
                    if (!gre_tunnel_destroy (node, gre_tun_id)) return -1;
                    break;
            }
        break;

        case GRE_CONFIG_TUNNEL_SOURCE_IPADDR:

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    gre_tunnel_set_src_addr (node, gre_tun_id, src_addr);
                    break;
                case CONFIG_DISABLE:
                    gre_tunnel_set_src_addr (node, gre_tun_id, NULL);
                    break;
                default: ;
            }
        break;

        case GRE_CONFIG_TUNNEL_SOURCE_INTF:

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    if (!gre_tunnel_set_src_interface (node, gre_tun_id, if_name)) return -1;
                    break;
                case CONFIG_DISABLE:
                    if (!gre_tunnel_set_src_interface (node, gre_tun_id, NULL)) {
                        return -1;
                    }
                    break;
                default: ;
            }
        break;
     
        case GRE_CONFIG_TUNNEL_DESTINATION:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    gre_tunnel_set_dst_addr (node, gre_tun_id, dst_addr);
                    break;
                case CONFIG_DISABLE:
                    gre_tunnel_set_dst_addr (node, gre_tun_id, NULL);
                    break;
                default:
                    ;
            }    
        break;  

        case GRE_CONFIG_TUNNEL_LOCAL_IP:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    gre_tunnel_set_lcl_ip_addr(node, gre_tun_id, intf_ip_addr, mask);
                    break;
                case CONFIG_DISABLE:
                    gre_tunnel_set_lcl_ip_addr(node, gre_tun_id, NULL, 0);
                    break;
                default:
                    ;
            }
        break;             

        case CMDCODE_CONF_INTF_UP_DOWN:
        {
            ipc_interface_t *update_data;
            uint32_t minor_code = 0;

            if (string_compare(if_up_down, "up", strlen("up")) == 0){

                if (tunnel->is_up == true) return 0;

                update_data = new ipc_interface_t;
                update_data->intf = tunnel->GetSharedPtr();
                SET_BIT(minor_code, IPC_INTERFACE_ADMIN_STATE_UP);
                update_data->up_status = false;
                tunnel->is_up = true;
                GRETunnelInterface *tunnel_intf = dynamic_cast<GRETunnelInterface *>(tunnel);
                tunnel_intf->gre_tunnel_check_and_activate_tunnel();
                cp_ips_send (node, IPC_INTERFACE, minor_code, 
                    update_data, sizeof (*update_data), true,  ips_free_ipc_interface_cbk);
            }
            else if (string_compare(if_up_down, "down", strlen("down")) == 0)
            {
                if (tunnel->is_up == false) return 0;

                update_data = new ipc_interface_t;
                SET_BIT(minor_code, IPC_INTERFACE_ADMIN_STATE_DOWN);
                update_data->up_status = true;
                update_data->intf = tunnel->GetSharedPtr();
                cp2dp_send_intf_admin_status_update(node, tunnel->ifindex, true);
                tunnel->is_up = true;
                GRETunnelInterface *tunnel_intf = dynamic_cast<GRETunnelInterface *>(tunnel);
                tunnel_intf->gre_deactivate_tunnel();
                cp_ips_send (node, IPC_INTERFACE, minor_code, 
                    update_data, sizeof (*update_data), true,  ips_free_ipc_interface_cbk);
            }
        }
        break;

    }
    return 0;
}

extern  void
Interface_config_cli_common_subtree (param_t *if_name, 
                int (*cbk) (int , Stack_t *, op_mode ), 
                uint64_t unsupported_configs);

/* conf node <node-name> interface ...*/
void
gre_cli_config_tree (param_t *interface) {

    {
        /* ... tunnel ... */
        static param_t tunnel;
        init_param (&tunnel, CMD, "tunnel", NULL, NULL, INVALID, NULL, "Config GRE Tunnel");
        libcli_register_param(interface, &tunnel);
        {
             /* ... tunnel <tunnel-id> */
             static param_t tunnel_id;
             init_param(&tunnel_id, LEAF, NULL, gre_tunnel_config_handler, NULL, INT, "tunnel-id", "Config GRE Tunnel ID");
             libcli_register_param(&tunnel, &tunnel_id);
             libcli_set_param_cmd_code (&tunnel_id, GRE_CONFIG_CREATE_TUNNEL_INTF);
             {
                 /* ... tunnel <tunnel-id> tunnel-source ...*/
                 static param_t tunnelsrc;
                 init_param(&tunnelsrc, CMD, "tunnel-source", NULL, NULL, INVALID, NULL, "Config GRE Tunnel Source Point");
                 libcli_register_param(&tunnel_id, &tunnelsrc);
                 {
                     /* ... tunnel <tunnel-id> tunnel-source <ip-address>*/
                     static param_t src_ip;
                     init_param(&src_ip, LEAF, 0, gre_tunnel_config_handler, 0, IPV4, "tunnel-src-ip", "specify Tunnel Src IPV4 Address");
                     libcli_register_param(&tunnelsrc, &src_ip);
                     libcli_set_param_cmd_code(&src_ip, GRE_CONFIG_TUNNEL_SOURCE_IPADDR);
                 }
                 {
                    /* ... tunnel <tunnel-id> tunnel-source interface ....*/
                    static param_t interface;
                    init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "specify Src Tunnel Interface");
                    libcli_register_param(&tunnelsrc, &interface);
                    {
                        /* ... tunnel <tunnel-id> tunnel-source interface <if-name>*/
                        static param_t if_name;
                        init_param(&if_name, LEAF, 0, gre_tunnel_config_handler, 0, STRING, "if-name", "Interface Name");
                        libcli_register_param(&interface, &if_name);
                        libcli_set_param_cmd_code(&if_name, GRE_CONFIG_TUNNEL_SOURCE_INTF);
                    }
                 }
             }
             {
                 /* ... tunnel <tunnel-id> tunnel-destination ...*/
                 static param_t tunneldst;
                 init_param(&tunneldst, CMD, "tunnel-destination", NULL, NULL, INVALID, NULL, "Config GRE Tunnel Destination Point");
                 libcli_register_param(&tunnel_id, &tunneldst);
                 {
                    /* ... tunnel <tunnel-id> tunnel-destination <ip-addr>*/
                    static param_t dst_ip;
                    init_param(&dst_ip, LEAF, 0, gre_tunnel_config_handler, 0, IPV4, "tunnel-dst-ip", "specify Tunnel Dst IPV4 Address");
                    libcli_register_param(&tunneldst, &dst_ip);
                    libcli_set_param_cmd_code(&dst_ip, GRE_CONFIG_TUNNEL_DESTINATION);
                 }
             }
             {
                 /* ... tunnel <tunnel-id> ip-address <ip-addr> <mask> */
                 static param_t ip_addr;
                 init_param(&ip_addr, CMD, "ip-address", 0, 0, INVALID, 0, "Tunnel Intf IP Address");
                 libcli_register_param(&tunnel_id, &ip_addr);
                 {
                     static param_t ip_addr_val;
                     init_param(&ip_addr_val, LEAF, 0, 0, 0, IPV4, "intf-ip-address", "IPV4 address");
                     libcli_register_param(&ip_addr, &ip_addr_val);
                     {
                         static param_t mask;
                         init_param(&mask, LEAF, 0, gre_tunnel_config_handler, validate_mask_value, INT, "mask", "mask [0-32]");
                         libcli_register_param(&ip_addr_val, &mask);
                         libcli_set_param_cmd_code(&mask, GRE_CONFIG_TUNNEL_LOCAL_IP);
                     }
                 }
             }

             /* Following configs are not supported on GRE interfaces*/
             uint64_t unsupported_configs = 0;
             unsupported_configs |= INTF_CONFIG_NOT_SUPPORTED_TSP;
             unsupported_configs |= INTF_CONFIG_NOT_SUPPORTED_SWITCHPORT;
             unsupported_configs |= INTF_CONFIG_NOT_SUPPORTED_VLAN;
             unsupported_configs |= INTF_CONFIG_NOT_SUPPORTED_IP_ADDRESS;
             unsupported_configs |= INTF_CONFIG_NOT_SUPPORTED_OVERLAY_TUNNEL;
             Interface_config_cli_common_subtree(&tunnel_id, 
                    gre_tunnel_config_handler, 
                    unsupported_configs);
             libcli_support_cmd_negation(&tunnel_id);
        }
    }

}
