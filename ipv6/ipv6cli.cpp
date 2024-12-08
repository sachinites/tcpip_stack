#include "../CLIBuilder/libcli.h"
#include "../graph.h"
#include "../Interface/InterfaceUApi.h"

extern graph_t *topo;
extern void  srv6_build_cli_tree (param_t *root);
extern void display_node_interfaces (param_t *param, Stack_t *tlv_stack);


/* config node <node-name> [no] ipv6 route <ipv6-address> <mask> <nexthop ip> <oif-name>*/
#define IPV6_RT_CONFIG  1


static int
ipv6_config_handler 
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    return 0;
}


void 
ipv6_build_cli_tree (param_t *root)
{
    {
        static param_t ipv6;
        init_param(&ipv6, CMD, "ipv6", NULL, NULL, INVALID, NULL, "Configure IPv6");
        libcli_register_param(root, &ipv6);
        {
            static param_t route;
            init_param(&route, CMD, "route", NULL, NULL, INVALID, NULL, "Configure IPv6 Route");
            libcli_register_param(&ipv6, &route);
            {
                static param_t ipv6_addr;
                init_param(&ipv6_addr, LEAF, NULL, NULL, NULL, STRING, "ipv6-address", "IPv6 Address");
                libcli_register_param(&route, &ipv6_addr);
                {
                    static param_t mask;
                    init_param(&mask, LEAF, NULL, NULL, NULL, INT, "mask", "IPv6 Mask [0-128]");
                    libcli_register_param(&ipv6_addr, &mask);
                    
                    srv6_build_cli_tree (&mask);

                    {
                        static param_t nexthop;
                        init_param(&nexthop, LEAF, NULL, NULL, NULL, STRING, "nexthop", "IPv6 Next Hop");
                        libcli_register_param(&mask, &nexthop);
                        {
                            static param_t oif;
                            init_param(&oif, LEAF, NULL, ipv6_config_handler , 
                                NULL, STRING, "oif-name", " Interface Name");
                            libcli_register_param(&nexthop, &oif);
                            libcli_set_param_cmd_code(&oif,  IPV6_RT_CONFIG);                            
                            libcli_register_display_callback(&oif, display_node_interfaces);
                        }
                    }
                }
            }
        }
    }
}
