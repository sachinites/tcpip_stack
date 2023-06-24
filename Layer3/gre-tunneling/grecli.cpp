#include "../../utils.h"
#include "../../CLIBuilder/libcli.h"
#include "grecmdcodes.h"
#include "../../graph.h"
#include "../../Interface/InterfaceUApi.h"
#include "greuapi.h"

extern graph_t *topo;

extern int
validate_mask_value(Stack_t *tlv_stack, c_string mask_str);

static int
gre_tunnel_config_handler (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable){

    node_t *node = NULL;
    uint16_t gre_tun_id;
    c_string node_name = NULL;
    Interface *gre_tunnel = NULL;
    tlv_struct_t *tlv;
    c_string src_addr = NULL;
    c_string dst_addr = NULL;
    c_string intf_ip_addr = NULL;
    uint8_t mask = 0;
    c_string if_name = NULL;

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
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {

        case GRE_CONFIG_CREATE_TUNNEL_INTF:

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    gre_tunnel_create (node, gre_tun_id);
                    break;
                case CONFIG_DISABLE:
                    gre_tunnel_destroy (node, gre_tun_id);
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
                    gre_tunnel_set_src_interface (node, gre_tun_id, if_name);
                    break;
                case CONFIG_DISABLE:
                    gre_tunnel_set_src_interface (node, gre_tun_id, NULL);
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

    }
    return 0;
}

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
        }
    }
}
