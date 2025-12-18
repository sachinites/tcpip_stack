#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"
#include "../cmdcodes.h"
#include "../graph.h"
#include "mpls_fwd.h"
#include "rt_table/nexthop.h"
#include "../utils.h"
#include "../Interface/InterfaceUApi.h"
#include "../common/cp2dp.h"

extern graph_t *topo;
extern int cprintf (const char* format, ...) ;

/* Forward declarations of cp2dp APIs */
extern void
cp2dp_mpls_route_install (node_t *node, 
                         mpls_label_val_t in_label,
                         c_string gw_ip,
                         uint32_t ifindex,
                         mpls_label_val_t (*label_stack)[MAX_LBL_DEPTH],
                         uint8_t label_stack_count);

extern void
cp2dp_mpls_route_delete (node_t *node, mpls_label_val_t in_label);

extern void
cp2dp_mpls_nexthop_delete (node_t *node,
                          mpls_label_val_t in_label,
                          c_string gw_ip,
                          uint32_t ifindex,
                          mpls_label_val_t (*label_stack)[MAX_LBL_DEPTH],
                          uint8_t label_stack_count);

extern void
cp2dp_ipv4_mpls_route_install (node_t *node,
                               c_string prefix,
                               uint8_t mask,
                               c_string gw_ip,
                               uint32_t ifindex,
                               mpls_label_val_t (*label_stack)[MAX_LBL_DEPTH],
                               uint8_t label_stack_count);

extern void
cp2dp_ipv4_mpls_route_delete (node_t *node,
                              c_string prefix,
                              uint8_t mask);

extern void
cp2dp_ipv4_mpls_nexthop_delete (node_t *node,
                                c_string prefix,
                                uint8_t mask,
                                c_string gw_ip,
                                uint32_t ifindex,
                                mpls_label_val_t (*label_stack)[MAX_LBL_DEPTH],
                                uint8_t label_stack_count);

/* MPLS Route Configuration Handler */
static int
mpls_route_config_handler(int cmdcode, 
                         Stack_t *tlv_stack,
                         op_mode enable_or_disable) {
    
    node_t *node;
    tlv_struct_t *tlv;
    
    c_string node_name = NULL;
    c_string gw_ip = NULL;
    c_string if_name = NULL;
    c_string prefix_mask = NULL;
    mpls_label_val_t in_label = 0;
    mpls_label_val_t label_stack[MAX_LBL_DEPTH] = {0};
    uint8_t label_stack_count = 0;
    Interface *oif = NULL;
    
    /* Parse TLVs from CLI input */
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {
        
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "in-label")) {
            uint32_t label_value = atoi((const char *)tlv->value);
            mpls_label_set_value(&in_label, label_value);
        }
        else if (parser_match_leaf_id(tlv->leaf_id, "prefix-mask"))
            prefix_mask = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "gw-ip"))
            gw_ip = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "if-name"))
            if_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "label-list")) {
            uint32_t label_value = atoi((const char *)tlv->value);
            mpls_label_set_value(&label_stack[label_stack_count], label_value);
            label_stack_count++;
        }
            
    } TLV_LOOP_END;
    
    /* Get the node */
    node = node_get_node_by_name(topo, node_name);
    
    switch (cmdcode) {
        
        case CMDCODE_CONFIG_MPLS_ROUTE:
            
            switch (enable_or_disable) {
                
                case CONFIG_ENABLE:
                {
                    /* Validate inputs */
                    if (mpls_label_get_value(in_label) == 0) {
                        cprintf("Error: Invalid incoming label\n");
                        return -1;
                    }
                    
                    if (!gw_ip) {
                        cprintf("Error: Gateway IP is required\n");
                        return -1;
                    }
                    
                    if (!if_name) {
                        cprintf("Error: Interface name is required\n");
                        return -1;
                    }
                    
                    /* Get the interface */
                    oif = node_get_intf_by_name(node, (const char *)if_name);
                    if (!oif) {
                        cprintf("Error: Interface %s not found on node %s\n", 
                               if_name, node_name);
                        return -1;
                    }
                    
                    /* Check if interface is L3 mode */
                    if (!oif->IsIpConfigured()) {
                        cprintf("Error: Interface %s is not configured in L3 mode\n", 
                               if_name);
                        return -1;
                    }
                    
                    /* Install MPLS route using cp2dp asynchronous API */
                    cp2dp_mpls_route_install(node, 
                                            in_label,
                                            gw_ip,
                                            oif->ifindex,
                                            &label_stack,
                                            label_stack_count);
                }
                break;
                
                case CONFIG_DISABLE:
                {
                    /* Validate in-label */
                    if (mpls_label_get_value(in_label) == 0) {
                        cprintf("Error: Invalid incoming label\n");
                        return -1;
                    }
                    
                    /* Check if specific nexthop deletion or entire route deletion */
                    if (gw_ip && if_name) {
                        /* Specific nexthop deletion */
                        oif = node_get_intf_by_name(node, (const char *)if_name);
                        if (!oif) {
                            cprintf("Error: Interface %s not found on node %s\n", 
                                   if_name, node_name);
                            return -1;
                        }
                        
                        /* Delete specific nexthop using cp2dp asynchronous API */
                        cp2dp_mpls_nexthop_delete(node, 
                                                 in_label,
                                                 gw_ip,
                                                 oif->ifindex,
                                                 &label_stack,
                                                 label_stack_count);
                    } else {
                        /* Delete entire route (all nexthops) */
                        cp2dp_mpls_route_delete(node, in_label);
                    }
                }
                break;
                    
                default:
                    ;
            }
            break;
            
        case CMDCODE_CONFIG_IPV4_MPLS_ROUTE:
            
            switch (enable_or_disable) {
                
                case CONFIG_ENABLE:
                {
                    /* Parse prefix/mask */
                    char prefix_str[16];
                    uint8_t mask;
                    
                    if (!prefix_mask) {
                        cprintf("Error: IPv4 prefix/mask is required\n");
                        return -1;
                    }
                    
                    /* Parse prefix/mask format (e.g., "192.168.1.0/24") */
                    if (sscanf((const char *)prefix_mask, "%[^/]/%hhu", prefix_str, &mask) != 2) {
                        cprintf("Error: Invalid prefix/mask format. Use: <ip>/<mask>\n");
                        return -1;
                    }
                    
                    if (mask > 32) {
                        cprintf("Error: Invalid mask value. Must be 0-32\n");
                        return -1;
                    }
                    
                    /* Validate inputs */
                    if (!gw_ip) {
                        cprintf("Error: Gateway IP is required\n");
                        return -1;
                    }
                    
                    if (!if_name) {
                        cprintf("Error: Interface name is required\n");
                        return -1;
                    }
                    
                    /* Get the interface */
                    oif = node_get_intf_by_name(node, (const char *)if_name);
                    if (!oif) {
                        cprintf("Error: Interface %s not found on node %s\n", 
                               if_name, node_name);
                        return -1;
                    }
                    
                    /* Check if interface is L3 mode */
                    if (!oif->IsIpConfigured()) {
                        cprintf("Error: Interface %s is not configured in L3 mode\n", 
                               if_name);
                        return -1;
                    }
                    
                    /* Install IPv4 MPLS route using cp2dp asynchronous API */
                    cp2dp_ipv4_mpls_route_install(node, 
                                                  (c_string)prefix_str,
                                                  mask,
                                                  gw_ip,
                                                  oif->ifindex,
                                                  &label_stack,
                                                  label_stack_count);
                }
                break;
                
                case CONFIG_DISABLE:
                {
                    /* Parse prefix/mask */
                    char prefix_str[16];
                    uint8_t mask;
                    
                    if (!prefix_mask) {
                        cprintf("Error: IPv4 prefix/mask is required\n");
                        return -1;
                    }
                    
                    /* Parse prefix/mask format */
                    if (sscanf((const char *)prefix_mask, "%[^/]/%hhu", prefix_str, &mask) != 2) {
                        cprintf("Error: Invalid prefix/mask format. Use: <ip>/<mask>\n");
                        return -1;
                    }
                    
                    if (mask > 32) {
                        cprintf("Error: Invalid mask value. Must be 0-32\n");
                        return -1;
                    }
                    
                    /* Check if specific nexthop deletion or entire route deletion */
                    if (gw_ip && if_name) {
                        /* Specific nexthop deletion */
                        oif = node_get_intf_by_name(node, (const char *)if_name);
                        if (!oif) {
                            cprintf("Error: Interface %s not found on node %s\n", 
                                   if_name, node_name);
                            return -1;
                        }
                        
                        /* Delete specific nexthop using cp2dp asynchronous API */
                        cp2dp_ipv4_mpls_nexthop_delete(node, 
                                                       (c_string)prefix_str,
                                                       mask,
                                                       gw_ip,
                                                       oif->ifindex,
                                                       &label_stack,
                                                       label_stack_count);
                    } else {
                        /* Delete entire route (all nexthops) */
                        cp2dp_ipv4_mpls_route_delete(node, (c_string)prefix_str, mask);
                    }
                }
                break;
                    
                default:
                    ;
            }
            break;
            
        default:
            ;
    }
    
    return 0;
}

/* MPLS Show Handler */
static int
mpls_show_handler(int cmdcode, 
                 Stack_t *tlv_stack,
                 op_mode enable_or_disable) {
    
    node_t *node;
    tlv_struct_t *tlv;
    c_string node_name = NULL;
    
    printw("\n\r");
    
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {
        
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
            
    } TLV_LOOP_END;
    
    node = node_get_node_by_name(topo, node_name);
    
    switch (cmdcode) {
        
        case CMDCODE_SHOW_MPLS_TABLE:
            cprintf("MPLS Routing Table:\n");
            cprintf("===================\n");
            mpls_display_routing_table(node);
            break;
            
        case CMDCODE_SHOW_IPV4_MPLS_TABLE:
            cprintf("IPv4 MPLS Routing Table:\n");
            cprintf("========================\n");
            ipv4_mpls_display_routing_table(node);
            break;


        default:
            ;
    }
    
    return 0;
}

/* Build MPLS Config CLI Tree */
int
mpls_build_config_cli_tree(param_t *node_name_param) {
    
    {
        /* config node <node-name> mpls */
        static param_t mpls;
        init_param(&mpls, CMD, "mpls", 0, 0, INVALID, 0, "MPLS Configuration");
        libcli_register_param(node_name_param, &mpls);
        {
            /* config node <node-name> mpls label-route */
            static param_t label_route;
            init_param(&label_route, CMD, "label-route", 0, 0, INVALID, 0, "MPLS Label-based Route");
            libcli_register_param(&mpls, &label_route);
            {
                /* config node <node-name> mpls label-route <in-label> */
                static param_t in_label;
                init_param(&in_label, LEAF, 0, 0, 0, INT, "in-label", "Incoming Label");
                libcli_register_param(&label_route, &in_label);
                {
                    /* config node <node-name> mpls route <in-label> gateway */
                    static param_t gateway;
                    init_param(&gateway, CMD, "gateway", 0, 0, INVALID, 0, "Gateway");
                    libcli_register_param(&in_label, &gateway);
                    {
                        /* config node <node-name> mpls route <in-label> gateway <gw-ip> */
                        static param_t gw_ip;
                        init_param(&gw_ip, LEAF, 0, 0, 0, IPV4, "gw-ip", "Gateway IP Address");
                        libcli_register_param(&gateway, &gw_ip);
                        {
                            /* config node <node-name> mpls route <in-label> gateway <gw-ip> interface */
                            static param_t interface;
                            init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "Interface");
                            libcli_register_param(&gw_ip, &interface);
                            {
                                /* config node <node-name> mpls route <in-label> gateway <gw-ip> interface <if-name> */
                                static param_t if_name;
                                init_param(&if_name, LEAF, 0, mpls_route_config_handler, 0, STRING, 
                                          "if-name", "Interface Name");
                                libcli_register_param(&interface, &if_name);
                                libcli_set_param_cmd_code(&if_name, CMDCODE_CONFIG_MPLS_ROUTE);
                                {
                                    /* config node <node-name> mpls route <in-label> gateway <gw-ip> interface <if-name> label-stack */
                                    static param_t label_stack;
                                    init_param(&label_stack, CMD, "label-stack", 0, 0, INVALID, 0, 
                                              "Label Stack");
                                    libcli_register_param(&if_name, &label_stack);
                                    {
                                        /* config node <node-name> mpls route <in-label> gateway <gw-ip> interface <if-name> label-stack <label-list> */
                                        static param_t label_list;
                                        init_param(&label_list, LEAF, 0, mpls_route_config_handler, 0, 
                                                  STRING, "label-list", "Space separated label values");
                                        libcli_register_param(&label_stack, &label_list);
                                        libcli_param_recursive (&label_list );
                                        libcli_set_param_cmd_code(&label_list, CMDCODE_CONFIG_MPLS_ROUTE);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        {
            /* config node <node-name> mpls ipv4-route */
            static param_t ipv4_route;
            init_param(&ipv4_route, CMD, "ipv4-route", 0, 0, INVALID, 0, "MPLS IPv4 Prefix-based Route");
            libcli_register_param(&mpls, &ipv4_route);
            {
                /* config node <node-name> mpls ipv4-route <prefix/mask> */
                static param_t pfx_mask;
                init_param(&pfx_mask, LEAF, 0, 0, 0, STRING, "prefix-mask", "ipv4/mask Route");
                libcli_register_param(&ipv4_route, &pfx_mask);
                {
                    /* config node <node-name> mpls route <prefix/mask> gateway */
                    static param_t gateway2;
                    init_param(&gateway2, CMD, "gateway", 0, 0, INVALID, 0, "Gateway");
                    libcli_register_param(&pfx_mask, &gateway2);
                    {
                        /* config node <node-name> mpls route <prefix/mask> gateway <gw-ip> */
                        static param_t gw_ip2;
                        init_param(&gw_ip2, LEAF, 0, 0, 0, IPV4, "gw-ip", "Gateway IP Address");
                        libcli_register_param(&gateway2, &gw_ip2);
                        {
                            /* config node <node-name> mpls route <prefix/mask> gateway <gw-ip> interface */
                            static param_t interface2;
                            init_param(&interface2, CMD, "interface", 0, 0, INVALID, 0, "Interface");
                            libcli_register_param(&gw_ip2, &interface2);
                            {
                                /* config node <node-name> mpls route <prefix/mask> gateway <gw-ip> interface <if-name> */
                                static param_t if_name2;
                                init_param(&if_name2, LEAF, 0, mpls_route_config_handler, 0, STRING, 
                                          "if-name", "Interface Name");
                                libcli_register_param(&interface2, &if_name2);
                                libcli_set_param_cmd_code(&if_name2, CMDCODE_CONFIG_IPV4_MPLS_ROUTE);
                                {
                                    /* config node <node-name> mpls route <prefix/mask> gateway <gw-ip> interface <if-name> label-stack */
                                    static param_t label_stack2;
                                    init_param(&label_stack2, CMD, "label-stack", 0, 0, INVALID, 0, 
                                              "Label Stack");
                                    libcli_register_param(&if_name2, &label_stack2);
                                    {
                                        /* config node <node-name> mpls route <prefix/mask> gateway <gw-ip> interface <if-name> label-stack <label-list> */
                                        static param_t label_list2;
                                        init_param(&label_list2, LEAF, 0, mpls_route_config_handler, 0, 
                                                  STRING, "label-list", "Space separated label values");
                                        libcli_register_param(&label_stack2, &label_list2);
                                        libcli_param_recursive (&label_list2);
                                        libcli_set_param_cmd_code(&label_list2, CMDCODE_CONFIG_IPV4_MPLS_ROUTE);
                                    }
                                }
                            }
                        }
                    }
                }
            }



        }
    }
    return 0;
}

/* Build MPLS Show CLI Tree */
int
mpls_build_show_cli_tree(param_t *node_name_param) {
    
    {
        /* show node <node-name> mpls-table */
        static param_t mpls_table;
        init_param(&mpls_table, CMD, "mpls-table", mpls_show_handler, 0, INVALID, 0, 
                  "Show MPLS RT Table");
        libcli_register_param(node_name_param, &mpls_table);
        libcli_set_param_cmd_code(&mpls_table, CMDCODE_SHOW_MPLS_TABLE);
    }
    {
        /* show node <node-name> ipv4-mpls-table */
        static param_t ipv4_mpls_table;
        init_param(&ipv4_mpls_table, CMD, "ipv4-mpls-table", mpls_show_handler, 0, INVALID, 0, 
                  "Show IPV4 MPLS RT Table");
        libcli_register_param(node_name_param, &ipv4_mpls_table);
        libcli_set_param_cmd_code(&ipv4_mpls_table, CMDCODE_SHOW_IPV4_MPLS_TABLE);        
    }
    return 0;
}

