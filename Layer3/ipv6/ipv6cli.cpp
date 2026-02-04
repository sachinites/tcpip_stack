#include <arpa/inet.h>
#include "../../CLIBuilder/libcli.h"
#include "../../router_init.h"
#include "../../Interface/InterfaceUApi.h"
#include "ipv6_hdrs.h"
#include "ipv6_utils.h"
#include "ipv6_route.h"
#include "../../common/cp2dp.h"
#include "../../RTM/rtm.h"
#include "../../RTM/rtm_nb_integ.h"
#include "../../common/cmn_prefix.h"
#include "../../vrf/vrf.h"

extern graph_t *topo;
extern void display_node_interfaces (param_t *param, Stack_t *tlv_stack);
extern void srv6_build_cli_run_tree (param_t *root);
extern uint8_t 
srv6_route_flag (node_t *node, uint8_t (*prefix)[16]) ;

/* config node <node-name> [no] ipv6 route <ipv6-address> <mask> <nexthop ip> <oif-name>*/
#define IPV6_RT_CONFIG  1
#define CMDCODE_PING6 2
#define CMDCODE_BINDING_SID_CONFIG 3

/**
 * @brief IPv6 route configuration handler
 * 
 * Handles installation and uninstallation of IPv6 static routes using the new RTM API.
 * Replaces legacy ipv6_route_install/uninstall with cp_rtm_install_static_route/cp_rtm_uninstall_static_route.
 * 
 * @param cmdcode Command code identifying the operation
 * @param tlv_stack Stack of TLV parameters from CLI
 * @param enable_or_disable CONFIG_ENABLE to install, CONFIG_DISABLE to uninstall
 * @return 0 on success, -1 on error
 */
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

        intf = node_interface_lookup_by_name(node, (const char *)oif_name);

        if (!intf) {
            cprintf ("Error : Interface %s not found\n", oif_name);
            return -1;
        }
    }

    switch (cmdcode) {

        case IPV6_RT_CONFIG:
        {
            rtm_t *rtm;
            uint32_t rc;
            cmn_prefix_t prefix_key, gateway;
            ipv6_addr_t ipv6_prefix, ipv6_gw;
            
            /* Get the RTM instance for IPv6 default VRF */
            rtm = rtm_get(node, RTM_DEFAULT_VRF, AF_IPV6, 0);
            if (!rtm) {
                cprintf("Error: RTM not found for node %s\n", node->node_name);
                return -1;
            }

            /* Parse IPv6 addresses */
            memset(&ipv6_prefix, 0, sizeof(ipv6_prefix));
            memset(&ipv6_gw, 0, sizeof(ipv6_gw));
            inet_pton6((char *)ipv6_addr, &ipv6_prefix);
            if (gw_ip) {
                inet_pton6((char *)gw_ip, &ipv6_gw);
            }

            /* Convert to common prefix format */
            cmn_prefix_initialize_v6(&prefix_key, &ipv6_prefix.addr, prefix_len);
            if (gw_ip && !is_ipv6_addr_unspecified(&ipv6_gw.addr)) {
                cmn_prefix_initialize_v6(&gateway, &ipv6_gw.addr, 128);
            } else {
                memset(&gateway, 0, sizeof(gateway));
            }

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                {
                    /* Install static route using new RTM API */
                    rc = cp_rtm_install_static_route(
                        rtm,
                        &prefix_key,
                        gw_ip ? &gateway : NULL,
                        intf ? intf->GetSharedPtr() : nullptr,
                        0  /* default cost */
                    );

                    if (rc != RTM_SUCCESS) {
                        cprintf("Error: Failed to install IPv6 route %s/%d\n", 
                               ipv6_addr, prefix_len);
                        return -1;
                    }
                }
                break;

                case CONFIG_DISABLE:
                {
                    /* Uninstall static route using new RTM API */
                    rc = cp_rtm_uninstall_static_route(
                        rtm,
                        &prefix_key,
                        gw_ip ? &gateway : NULL,
                        intf ? intf->GetSharedPtr() : nullptr,
                        0  /* default cost */
                    );

                    if (rc != RTM_SUCCESS) {
                        cprintf("Error: Failed to uninstall IPv6 route %s/%d\n", 
                               ipv6_addr, prefix_len);
                        return -1;
                    }
                }
                break;
            }
        }
        break;
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

    ipv6_addr_t dst_addr;
    inet_pton6((char *)ipv6_addr, &dst_addr);

    cp2dp_send_ip6_data (node, NULL, dst_addr, ICMP6_PROTO);
    return 0;
}

static int
ipv6_binding_sid_config_handler (int cmdcode, 
                                                        Stack_t *tlv_stack, 
                                                        op_mode enable_or_disable) {

    node_t *node;
    c_string node_name;
    c_string bsid_addr;
    c_string ipv6_route_str;
    tlv_struct_t *tlv = NULL;
    uint8_t prefix_len = 0;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "ipv6-address"))
            ipv6_route_str = tlv->value;
         else if(parser_match_leaf_id(tlv->leaf_id, "bsid-address"))
            bsid_addr = tlv->value;
         else if(parser_match_leaf_id(tlv->leaf_id, "mask"))
            prefix_len = atoi( (const char *) tlv->value);

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    ipv6_addr_t route, gw;
    inet_pton6((char *)ipv6_route_str, &route);
    inet_pton6((char *)bsid_addr, &gw);

    switch (enable_or_disable) {

        case CONFIG_ENABLE:
    
            ipv6_route_install (node,
                                            &route,
                                            prefix_len,
                                            FIB_NH_FWD_F_TUNNEL,
                                            &gw,
                                            NULL,
                                            NULL,
                                            0,
                                            (Srv6_endpcode_t )0,
                                            PROTO_SRv6) ;
        break;

        case CONFIG_DISABLE:

        break;
    }

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

                    /* Mount SRV6 static route CLIs here*/

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

                    {
                        /* . . . binding-sid <ipv6-address> */
                        static param_t bsid;
                        init_param(&bsid, CMD, "binding-sid", NULL, NULL, INVALID, NULL, "Binding Sid");
                        libcli_register_param(&mask, &bsid);
                        {
                            static param_t ipv6_addr;
                            init_param(&ipv6_addr, LEAF, NULL, ipv6_binding_sid_config_handler, NULL, IPV6, "bsid-address", "IPv6 Address");
                            libcli_register_param(&bsid, &ipv6_addr);                            
                            libcli_set_param_cmd_code(&ipv6_addr,  CMDCODE_BINDING_SID_CONFIG);                  
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
