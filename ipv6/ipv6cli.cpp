#include "../CLIBuilder/libcli.h"
#include "../graph.h"
#include "../Interface/InterfaceUApi.h"
#include "ipv6_hdrs.h"
#include "ipv6_utils.h"
#include "ipv6_route.h"
#include "../common/cp2dp.h"

extern graph_t *topo;
extern void  srv6_build_cli_tree (param_t *root);
extern void display_node_interfaces (param_t *param, Stack_t *tlv_stack);
extern void srv6_build_cli_run_tree (param_t *root);

/* config node <node-name> [no] ipv6 route <ipv6-address> <mask> <nexthop ip> <oif-name>*/
#define IPV6_RT_CONFIG  1
#define CMDCODE_PING6 2


static int
ipv6_config_handler 
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    tlv_struct_t *tlv;
    uint8_t prefix_len = 0;
    node_t *node = NULL;
    c_string gw_ip = NULL;
    c_string oif_name = NULL;
    c_string ipv6_addr = NULL;
    c_string node_name = NULL;
     Interface *intf = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if  (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "ipv6-address"))
            ipv6_addr = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "mask"))
            prefix_len = atoi((const char *)tlv->value);
        else if  (parser_match_leaf_id (tlv->leaf_id, "nexthop"))
            gw_ip = tlv->value;
        else if  (parser_match_leaf_id (tlv->leaf_id, "oif-name"))
            oif_name = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    if (oif_name) {

        intf = node_get_intf_by_name(node, (const char *)oif_name);

        if (!intf) {
            cprintf ("Error : Interface %s not found\n", oif_name);
            return -1;
        }
    }

    switch (cmdcode) {

        case IPV6_RT_CONFIG:
        {
            switch (enable_or_disable ) {

                case CONFIG_ENABLE:
                {
                    ipv6_addr_t prefix;
                    ipv6_addr_t gw = {0};
                    inet_pton6 ((char *)ipv6_addr, &prefix);
                    if (gw_ip) inet_pton6 ((char *)gw_ip, &gw);
                    dp_ipv6_route_install (node, 
                                                    &prefix,
                                                    prefix_len,
                                                    0,
                                                    &gw,
                                                    intf,
                                                    0, (Srv6_endpcode_t)0, 0,
                                                    PROTO_STATIC);
                }
                break;

                case CONFIG_DISABLE:
                {
                    ipv6_addr_t prefix;
                    ipv6_addr_t gw = {0};
                    inet_pton6 ((char *)ipv6_addr, &prefix);
                    if (gw_ip) inet_pton6 ((char *)gw_ip, &gw);
                    dp_ipv6_route_uninstall (node, 
                                                    &prefix,
                                                    prefix_len,
                                                    &gw,
                                                    intf,
                                                    PROTO_STATIC);
                }
                break;
            }
        }
    }
    return 0;
}

void 
show_rt6_handler(int cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable) {

    node_t *node;
    c_string node_name;
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    v6_rt_table_show(NODE_V6RT_TABLE(node));
}

static int
ping6_handler(int cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable) {

    node_t *node;
    c_string node_name;
    c_string ipv6_addr;
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "ipv6-address"))
            ipv6_addr = tlv->value;
 
    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    if (!node) {
        cprintf("Error : Node %s not found\n", node_name);
        return -1;
    }

    ipv6_addr_t dst_addr;
    inet_pton6((char *)ipv6_addr, &dst_addr);

    cp2dp_send_ip6_data (node, NULL, dst_addr, ICMP6_PROTO);
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
                init_param(&ipv6_addr, LEAF, NULL, NULL, NULL, IPV6, "ipv6-address", "IPv6 Address");
                libcli_register_param(&route, &ipv6_addr);
                {
                    static param_t mask;
                    init_param(&mask, LEAF, NULL, ipv6_config_handler, NULL, INT, "mask", "IPv6 Mask [0-128]");
                    libcli_register_param(&ipv6_addr, &mask);
                    libcli_set_param_cmd_code(&mask,  IPV6_RT_CONFIG);       

                    /* Mount SRV6 CLIs here*/
                    srv6_build_cli_tree (&mask);

                    {
                        static param_t nexthop;
                        init_param(&nexthop, CMD, "nexthop", NULL, NULL, INVALID, NULL, "IPv6 Next Hop");
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

void 
ipv6_build_cli_run_tree (param_t *root) 
{

    {
        /*run node <node-name> ping6 */
        static param_t ping6;
        init_param(&ping6, CMD, "ping6", 0, 0, INVALID, 0, "ipv6 Ping utility");
        libcli_register_param(root, &ping6);
        {
            /*run node <node-name> ping6 <ipv6-address>*/
            static param_t ipv6_addr;
            init_param(&ipv6_addr, LEAF, 0, ping6_handler, 0, IPV6, "ipv6-address", "Ipv6 Address");
            libcli_register_param(&ping6, &ipv6_addr);
            libcli_set_param_cmd_code(&ipv6_addr, CMDCODE_PING6);
        }

        /* Mount SRV6 ping */
        srv6_build_cli_run_tree (&ping6);
        
    }
    
}