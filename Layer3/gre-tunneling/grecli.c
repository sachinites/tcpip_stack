#include "../../utils.h"
#include "../../CommandParser/cmdtlv.h"
#include "../../CommandParser/libcli.h"
#include "grecmdcodes.h"

extern int
validate_mask_value(c_string mask_str);

static int
gre_tunnel_config_handler(param_t *param, 
                    ser_buff_t *tlv_buf,
                    op_mode enable_or_disable){

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
             set_param_cmd_code (&tunnel_id, GRE_CONFIG_CREATE_TUNNEL_INTF);
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
                     set_param_cmd_code(&src_ip, GRE_CONFIG_TUNNEL_SOURCE_IPADDR);
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
                        set_param_cmd_code(&if_name, GRE_CONFIG_TUNNEL_SOURCE_INTF);
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
                    set_param_cmd_code(&dst_ip, GRE_CONFIG_TUNNEL_DESTINATION);
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
                         set_param_cmd_code(&mask, GRE_CONFIG_TUNNEL_LOCA_IP);
                     }
                 }
             }
        }
    }
}
