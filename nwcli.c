/*
 * =====================================================================================
 *
 *       Filename:  nwcli.c
 *
 *    Description:  This file implements CLI commands to interact with the project
 *
 *        Version:  1.0
 *        Created:  Friday 20 September 2019 06:36:26  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *        
 *        This file is part of the NetworkGraph distribution (https://github.com/sachinites).
 *        Copyright (c) 2017 Abhishek Sagar.
 *        This program is free software: you can redistribute it and/or modify
 *        it under the terms of the GNU General Public License as published by  
 *        the Free Software Foundation, version 3.
 *
 *        This program is distributed in the hope that it will be useful, but 
 *        WITHOUT ANY WARRANTY; without even the implied warranty of 
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *        General Public License for more details.
 *
 *        You should have received a copy of the GNU General Public License 
 *        along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdint.h>
#include "graph.h"
#include "CLIBuilder/libcli.h"
#include "CLIBuilder/cmdtlv.h"
#include "cmdcodes.h"
#include "libtimer/WheelTimer.h"
#include "Layer5/app_handlers.h"
#include "BitOp/bitsop.h"
#include "tcpip_notif.h"
#include "Layer3/rt_table/nexthop.h"
#include "Layer3/layer3.h"
#include "LinuxMemoryManager/uapi_mm.h"
#include "prefix-list/prefixlst.h"
#include "tcpconst.h"
#include "Layer2/mac_table.h"
#include "RTM/rtm_nb_integ.h"
#include "RTM/rtm_show.h"
#include "RTM/rtm_priv_api.h"

extern graph_t *topo;
class Interface;

extern int traceoptions_handler(int cmdcode,
                                Stack_t *tlv_stack,
                                op_mode enable_or_disable);
extern void tcp_ip_traceoptions_cli(param_t *node_name_param, 
                                 param_t *intf_name_param);
extern param_t * policy_config_cli_tree () ;
extern void acl_build_config_cli(param_t *root) ;
extern void acl_build_show_cli(param_t *root) ;
extern void prefix_list_cli_config_tree (param_t *param);
extern void network_object_build_config_cli (param_t *root) ;
extern void object_group_build_config_cli (param_t *root) ;
extern void network_object_build_show_cli (param_t *root) ;
extern void object_group_build_show_cli (param_t *root) ;
extern void prefix_list_cli_show_tree(param_t *param) ;
extern void time_range_config_cli_tree (param_t *root) ;
extern void Interface_config_cli_tree (param_t *root);
extern void access_list_print_bitmap(node_t *node, c_string access_list_name);
extern void config_node_build_transport_svc_cli_tree (param_t *param) ;
extern void show_node_transport_svc_cli_tree (param_t *param) ;
extern void tcp_ip_build_debug_cli_tree (param_t *root);
extern void ipv6_build_cli_tree (param_t *root);
extern void show_rt6_handler(int cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable);
extern int isis_show_handler (int cmdcode,
                  Stack_t *tlv_stack,
                  op_mode enable_or_disable);

extern int
config_rtm_route_cli_handler(int cmdcode,
                              Stack_t *tlv_stack,
                              op_mode enable_or_disable) ;

extern void sql_build_cli_tree (param_t *root) ;

extern void 
ipv6_build_cli_run_tree (param_t *root) ;

extern int ip_traffic_generate_handler(int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable);
extern int mac_table_config_handler(
    int cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable);

static int
display_mem_usage(int cmdcode, Stack_t *tlv_stack,
                    op_mode enable_or_disable){

    tlv_struct_t *tlv = NULL;
    c_string struct_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "struct-name"))
            struct_name =  tlv->value;
    } TLV_LOOP_END;

    printw("\n\r");

    switch(cmdcode){
        case CMDCODE_DEBUG_SHOW_MEMORY_USAGE:
            mm_print_block_usage(0);
            break;
        case CMDCODE_DEBUG_SHOW_MEMORY_USAGE_DETAIL:
            mm_print_memory_usage(0, struct_name);
            break;
        default:
            ;
    }
    return 0;
}

/*
 * In the CLI hierarchy, it is very common to hook up new CLIs (config and show)
 * at node and interface level. Provided the mechanism where App developer can 
 * write CLI trees in application folder and simply hooks up those functions here
 * after declaring the function prototypes in Layer5/app_handler.h. NO need to mess
 * with CLI hierarchy tree implemented in nw_init_cli () unless app developer wants
 * to develop a CLI under a non-trivial hook point in a CLI tree.
 */

/* config node <node-name> protocol .... */
typedef int (*cli_register_cb)(param_t *);
static cli_register_cb
	cli_register_cb_arr_config_node_node_name_protocol_level[] =
	{
		//ddcp_config_cli_tree,
		//nmp_config_cli_tree,
        isis_config_cli_tree,
        srv6_build_global_config_cli_tree,
        lfa_config_cli_tree,

        /*  Add more CB here */
        
        0 /* Last member must be NULL */
	};

/* show node <node-name> protocol ... */
static cli_register_cb
	cli_register_cb_arr_show_node_node_name_protcol_level[] =
	{
		//ddcp_show_cli_tree,
		//nmp_show_cli_tree,
        isis_show_cli_tree,
        srv6_build_cli_show_tree,
        lfa_show_cli_tree,

        /* Add more CB here */

        0 /*  Last member must be NULL */
	};

/* clear node <node-name> protocol ... */
static cli_register_cb
	cli_register_cb_arr_clear_node_node_name_protcol_level[] =
	{
        isis_clear_cli_tree,
		
        /* Add more CB here */

        0 /*  Last member must be NULL */
	};

/* run node <node-name> protocol .... */
static cli_register_cb
	cli_register_cb_arr_run_node_node_name_protocol_level[] =
	{
		isis_run_cli_tree,
		0
		/* Add more CB here */
	};

/* debug node <node-name> protocol .... */
static cli_register_cb
	cli_register_cb_arr_debug_node_node_name_protocol_level[] =
	{
		isis_debug_cli_tree,
		0
		/* Add more CB here */
	};


static void
cli_register_application_cli_trees(param_t *param,
			cli_register_cb *cli_register_cb_arr){

	int i = 0;
	while(cli_register_cb_arr[i]) {
		(cli_register_cb_arr[i])(param);
		i++;
	}
}

/* Display functions when user presses ?*/
void
display_graph_nodes(param_t *param, Stack_t *tlv_stack){

    node_t *node;
    glthread_t *curr;

    ITERATE_GLTHREAD_BEGIN(&topo->node_list, curr){

        node = graph_glue_to_node(curr);
        cprintf("%s\n", node->node_name);
    } ITERATE_GLTHREAD_END(&topo->node_list, curr);
}


static int
validate_node_extistence(Stack_t *tlv_stack, c_string node_name){

    node_t *node = node_get_node_by_name(topo, node_name);
    if(node)
        return LEAF_VALIDATION_SUCCESS;
    return LEAF_VALIDATION_FAILED;
}

static int
validate_vlan_id(Stack_t *tlv_stack, c_string vlan_value){

    uint32_t vlan = atoi((const char *)vlan_value);
    if(!vlan){
        return LEAF_VALIDATION_FAILED;
    }
    if(vlan >= 1 && vlan <= 4095)
        return LEAF_VALIDATION_SUCCESS;

    return LEAF_VALIDATION_FAILED;
}

static int
validate_l2_mode_value(Stack_t *tlv_stack, c_string l2_mode_value){
        return LEAF_VALIDATION_SUCCESS;
    return LEAF_VALIDATION_FAILED;
}

static int
validate_vrf_id(Stack_t *tlv_stack, c_string vrf_value){

    int vrf = atoi((const char *)vrf_value);
    if(vrf >= 0 && vrf <= 255)
        return LEAF_VALIDATION_SUCCESS;
    return LEAF_VALIDATION_FAILED;
}

static int
validate_rtm_table_id(Stack_t *tlv_stack, c_string table_value){

    int table_id = atoi((const char *)table_value);
    if(table_id >= 0 && table_id <= 255)
        return LEAF_VALIDATION_SUCCESS;
    return LEAF_VALIDATION_FAILED;
}

int
validate_mask_value(Stack_t *tlv_stack, c_string mask_str);

int
validate_mask_value(Stack_t *tlv_stack, c_string mask_str){

    int mask = atoi((const char *)mask_str);
    if(mask >= 0 && mask <= 32)
        return LEAF_VALIDATION_SUCCESS;
    return LEAF_VALIDATION_FAILED;
}


/*Generic Topology Commands*/
static int
show_nw_topology_handler(int cmdcode,
                         Stack_t *tlv_stack,
                         op_mode enable_or_disable){

    node_t *node = NULL;
    c_string node_name = NULL;;
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){
        
        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
    } TLV_LOOP_END;

    if(node_name)
        node = node_get_node_by_name(topo, node_name);

    printw ("\n\r");
    
    switch(cmdcode){

        case CMDCODE_SHOW_NW_TOPOLOGY:
            dump_nw_graph(topo, node);
            break;
        default:
            ;
    }
    return 0;
}

extern void
tcp_ip_refresh_tcp_log_file(node_t *);

static int
clear_topology_handler(int cmdcode,
                       Stack_t *tlv_stack,
                       op_mode enable_or_disable){

    node_t *node;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch(cmdcode) {
        case CMDCODE_CLEAR_LOG_FILE:
            tcp_ip_refresh_tcp_log_file(node);
            break;
        default: ;
    }
    return 0;
}

/*Layer 2 Commands*/

typedef struct arp_table_ arp_table_t;
extern void
show_arp_table(arp_table_t *arp_table);

static int
show_arp_handler(int cmdcode, Stack_t *tlv_stack, 
                    op_mode enable_or_disable){

    node_t *node;
    c_string node_name;
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    show_arp_table(NODE_ARP_TABLE(node));
    return 0;
}

extern 
void dump_node_interface_stats(node_t *node);

typedef struct mac_table_ mac_table_t;
extern void show_mac_table(mac_table_t *mac_table, vlan_id_t vlan_id);
extern vlan_id_t vni_to_vlan_lookup(node_t *node, uint32_t vni_id);

static int
show_mac_handler(int cmdcode, Stack_t *tlv_stack,
                    op_mode enable_or_disable){

    node_t *node;
    c_string node_name;
    uint32_t vni_id = 0;
    vlan_id_t vlan_id = 0;
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

        else if (parser_match_leaf_id(tlv->leaf_id, "vni-id")) {

            vni_id = atoi(tlv->value);
            if (vni_id == 0) {
                cprintf ("Error : Invalid vni\n");
                return -1;
            }
        }

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    vlan_id = vni_to_vlan_lookup(node, vni_id);

    if (vni_id && vlan_id ==0) {
        cprintf ("Error : No VLAN associated with VNI %d\n", vni_id);
        return -1;
    }

    show_mac_table(NODE_MAC_TABLE (node), vlan_id);
    return 0;
}

extern void
send_arp_broadcast_request(node_t *node,
                           Interface *oif,
                           c_string ip_addr);
static int
arp_handler(int cmdcode, Stack_t *tlv_stack,
                op_mode enable_or_disable){

    node_t *node;
    c_string node_name;
    c_string ip_addr;
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "ip-address"))
            ip_addr = tlv->value;
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    send_arp_broadcast_request(node, NULL, ip_addr);
    return 0;
}


/*Layer 3 Commands*/
extern void
layer3_ping_fn(node_t *node, c_string dst_ip_addr, uint32_t count);
extern void
layer3_ero_ping_fn(node_t *node, c_string dst_ip_addr,
                            c_string ero_ip_address);

static int
ping_handler(int cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable){

    node_t *node;
    uint32_t count = 1;
    c_string ip_addr = NULL;
    c_string ero_ip_addr = NULL;
    c_string node_name = NULL;

    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "ip-address"))
            ip_addr = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "ero-ip-address"))
            ero_ip_addr = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "count"))
            count = atoi(tlv->value);
    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch(cmdcode){

        case CMDCODE_PING:
            layer3_ping_fn(node, ip_addr, count);
            break;
        case CMDCODE_ERO_PING:
            layer3_ero_ping_fn(node, ip_addr, ero_ip_addr);
        default:
            ;
    }

    return 0;
}


typedef struct rt_table_ rt_table_t;
extern void
dump_rt_table(rt_table_t *rt_table);
static int
show_rt_handler(int cmdcode, Stack_t *tlv_stack,
                    op_mode enable_or_disable){

    node_t *node;
    c_string node_name;
    tlv_struct_t *tlv = NULL;
    
    printw ("\n\r");
    
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    dump_rt_table(NODE_RT_TABLE(node));
    return 0;
}

static int
show_rtm_route_cli_handler(int cmdcode,
                           Stack_t *tlv_stack,
                           op_mode enable_or_disable){

    uint32_t table_id = 0;
    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    c_string rib_name = NULL;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "rib-name"))
            rib_name = tlv->value;

    }TLV_LOOP_END;

    if(!node_name){
        cprintf("Error : node-name missing\n");
        return -1;
    }

    node = node_get_node_by_name(topo, node_name);

    rtm_t *rtm = rtm_get_by_name (node, rib_name);

    if(!rtm){
        cprintf("Error : RTM %s not found\n", rib_name); 
        return -1;
    }

    switch (cmdcode) {
        case CMDCODE_SHOW_NODE_RTM_ROUTE:
            rtm_show_rib(rtm);
            break;
        case CMDCODE_SHOW_NODE_RTM_ROUTE_DETAIL:
            rtm_show_rib_detail(rtm);
            break;
        default:
            ;
    }
    return 0;
}

static int
show_rtm_protocol_subscriptions_handler(int cmdcode, Stack_t *tlv_stack,
                    op_mode enable_or_disable){

    node_t *node;
    c_string node_name = NULL;
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    }TLV_LOOP_END;

    if(!node_name){
        cprintf("Error : node-name missing\n");
        return -1;
    }

    node = node_get_node_by_name(topo, node_name);
    if(!node){
        cprintf("Error : Node %s not found\n", node_name);
        return -1;
    }

    /* Get default RTM: VRF=0, AFI=IPv4, RTM ID=0 */
    rtm_t *rtm = rtm_get(node, 0, RTM_AF_IPV4, 0);
    if(!rtm){
        cprintf("Error : Default RTM not found for node %s\n", node_name);
        return -1;
    }

    rtm_show_protocol_subscriptions(rtm);
    return 0;
}

extern void
clear_rt_table(rt_table_t *rt_table, uint16_t proto_id);
static int
clear_rt_handler(int cmdcode, Stack_t *tlv_stack,
                    op_mode enable_or_disable){

    node_t *node;
    c_string node_name;
    c_string rib_name;
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        if(parser_match_leaf_id(tlv->leaf_id, "rib-name"))
            rib_name = tlv->value;
    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    clear_rt_table(NODE_RT_TABLE(node), PROTO_ISIS);
    return 0;
}


static int
l3_config_handler(int cmdcode, Stack_t *tlv_stack, op_mode enable_or_disable){

    node_t *node = NULL;
    c_string node_name = NULL;
    c_string intf_name = NULL;
    c_string gwip = NULL;
    c_string mask_str = NULL;
    c_string dest = NULL;
    c_string rib_name = NULL;
    c_string prefix_lst_name = NULL;
    
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "ip-address"))
            dest = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "gw-ip"))
            gwip = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "mask"))
            mask_str = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "oif"))
            intf_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "rib-name"))
            rib_name = tlv->value;        
        else if(parser_match_leaf_id(tlv->leaf_id, "prefix-lst-name"))
            prefix_lst_name = tlv->value;                   
    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    char mask;
    if(mask_str){
        mask = atoi((const char *)(const char *)mask_str);
    }

    uint32_t gw_ip_int = 0;

    switch(cmdcode){
        case CMDCODE_CONF_NODE_L3ROUTE:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                {
                    Interface *intf = NULL;
                    if(intf_name){
                        intf = node_get_intf_by_name(node, (const char *)intf_name);
                        if(!intf){
                            cprintf("Config Error : Non-Existing Interface : %s\n", intf_name);
                            return -1;
                        }
                        if (!intf->IsIpConfigured()) {
                            cprintf("Config Error : Not L3 Mode Interface : %s\n", intf_name);
                            return -1;
                        }
                    }

                    if (gwip) {
                        gw_ip_int =  tcp_ip_convert_ip_p_to_n (gwip);
                    }

                    /* If Gw and OIF is specified, then Gw must belong to subnet 
                        configured on an interface */
                    if (gw_ip_int && intf) {

                        if (!intf->IsSameSubnet(gw_ip_int)) {
                            cprintf("Config Error : Gateway IP %s not in subnet of Interface %s\n",
                                    gwip, intf_name);
                            return -1;
                        }
                    }

                    rt_ipv4_route_add (node, 
                        tcp_ip_convert_ip_p_to_n(dest), mask, 
                            gwip ? gw_ip_int : 0, 
                            intf, 0, PROTO_STATIC, true);

                    /* New RTM*/
                    rtm_prefix_t  prefix, gateway;
                    rtm_prefix_initialize_v4 (&prefix, tcp_ip_convert_ip_p_to_n(dest), mask);
                    rtm_prefix_initialize_v4 (&gateway, 0, 32);

                    if (gwip) {
                        gw_ip_int =  tcp_ip_convert_ip_p_to_n (gwip);
                        rtm_prefix_initialize_v4 (&gateway, gw_ip_int, 32);
                    }
                    
                    uint32_t rc = cp_rtm_install_static_route (
                        rtm_get(node,  intf->GetVRF(), RTM_AF_IPV4, 0), 
                        &prefix,  &gateway, intf->GetSharedPtr(), 0);

                    if (!rc) {
                        cprintf("Error : Failed to install static route\n");
                        return -1;
                    }

                }
                break;
                case CONFIG_DISABLE:
                {      
                    Interface *intf = NULL;
                    if(intf_name){
                        intf = node_get_intf_by_name(node, (const char *)intf_name);
                        if(!intf){
                            cprintf("Config Error : Non-Existing Interface : %s\n", intf_name);
                            return -1;
                        }
                        if (!intf->IsIpConfigured()) {
                            cprintf("Config Error : Not L3 Mode Interface : %s\n", intf_name);
                            return -1;
                        }
                    }

                    rt_ipv4_route_del (node, 
                            tcp_ip_convert_ip_p_to_n(dest), 
                            mask, PROTO_STATIC, true);

                    /* New RTM*/
                    rtm_prefix_t  prefix, gateway;
                    rtm_prefix_initialize_v4 (&prefix, tcp_ip_convert_ip_p_to_n(dest), mask);
                    rtm_prefix_initialize_v4 (&gateway, 0, 32);

                    if (!gwip) return -1;

                    if (gwip) {
                        gw_ip_int =  tcp_ip_convert_ip_p_to_n (gwip);
                        rtm_prefix_initialize_v4 (&gateway, gw_ip_int, 32);
                    }
                    
                    rtm_error_t rc = cp_rtm_uninstall_static_route (
                        rtm_get(node,  intf->GetVRF(), RTM_AF_IPV4, 0), 
                        &prefix,  &gateway, intf->GetSharedPtr(), 0);

                    if (rc != RTM_SUCCESS) {
                        cprintf("Error : Failed to uninstall static route\n");
                        return -1;
                    }
                }
                break;
                default: ;
            }
            break;

        case CMDCODE_CONF_RIB_IMPORT_POLICY:
        {
            if (string_compare(rib_name, "inet.0", 6) == 0) {
                rt_table_t *rt_table = NODE_RT_TABLE(node);
                prefix_list_t *prefix_lst = prefix_lst_lookup_by_name(&node->prefix_lst_db, prefix_lst_name);
                if (!prefix_lst) {
                    cprintf ("Error : Prefix List do not Exist\n");
                    return -1;
                }
                switch (enable_or_disable) {
                    case CONFIG_ENABLE:
                        if (rt_table->import_policy == prefix_lst) return 0;
                        if (rt_table->import_policy) {
                            prefix_list_dereference(rt_table->import_policy);
                            rt_table->import_policy = NULL;
                        }
                        rt_table->import_policy = prefix_lst;
                        prefix_list_reference(prefix_lst);
                        break;
                    case CONFIG_DISABLE:
                        if (rt_table->import_policy != prefix_lst) return 0;
                        if (!rt_table->import_policy) return 0;
                        prefix_list_dereference(rt_table->import_policy);
                        rt_table->import_policy = NULL;
                        break;
                    default:;
                }
            }
            else {
                cprintf ("Error : Routing Table Support is inet.0\n");
                return -1;
            }
        }
        break;
        default:
            break;
    }
    return 0;
}

/*Layer 4 Commands*/



/*Layer 5 Commands*/




extern bool
schedule_hello_on_interface(Interface *intf,
                            int interval_sec,
                            bool is_repeat);
extern void
stop_interface_hellos(Interface *interface);

/*Miscellaneous Commands*/


static int
debug_show_node_handler(int cmdcode, Stack_t *tlv_stack,
                         op_mode enable_or_disable){

   node_t *node;
   c_string node_name;
   tlv_struct_t *tlv = NULL;
   c_string access_list_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){
        
        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if   (parser_match_leaf_id(tlv->leaf_id, "access-list-name"))
            access_list_name = tlv->value;
    }TLV_LOOP_END;

   node = node_get_node_by_name(topo, node_name);

   printw ("\n\r");

   switch(cmdcode){
        case CMDCODE_DEBUG_SHOW_NODE_TIMER:
            print_wheel_timer(CP_TIMER(node));         
            break;
		case CMDCODE_DEBUG_SHOW_NODE_TIMER_LOGGING:
			wt_enable_logging(CP_TIMER(node));
            break;
        case CMDCODE_DEBUG_SHOW_NODE_MTRIE_RT:
            mtrie_longest_prefix_first_traverse(
                    &NODE_RT_TABLE(node)->route_list,
                    mtrie_print_node, NULL);
            break;
        case CMDCODE_DEBUG_SHOW_NODE_MTRIE_RT6:
            mtrie_longest_prefix_first_traverse(
                    &NODE_V6RT_TABLE(node)->route_list,
                    mtrie_print_node, NULL);
            break;
        case CMDCODE_DEBUG_SHOW_NODE_MTRIE_ACL:
             access_list_print_bitmap(node, access_list_name);
            break;
        default:
        break;
   }
   return 0;
}

static int 
show_interface_handler(int cmdcode, Stack_t *tlv_stack,
                       op_mode enable_or_disable){
    
    node_t *node;
    c_string node_name;
    c_string protocol_name = NULL;

    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "protocol-name"))
            protocol_name = tlv->value;        
    } TLV_LOOP_END;
   
    node = node_get_node_by_name(topo, node_name);

    printw ("\n\r");

    switch(cmdcode){

        case CMDCODE_SHOW_INTF_STATS:
            dump_node_interface_stats(node);
            break;
        default:
            ;
    }
    return 0;
}

void
nw_init_cli(){

    cli_register_ctrlC_handler(tcp_ip_toggle_global_console_logging);

    param_t *show   = libcli_get_show_hook();
    param_t *debug  = libcli_get_debug_hook();
    param_t *config = libcli_get_config_hook();
    param_t *run    = libcli_get_run_hook();
    param_t *clear    = libcli_get_clear_hook();
    param_t *root = libcli_get_root_hook();

    {
        /* debug mem-usage*/
        static param_t mem_usage;
        init_param(&mem_usage, CMD, "mem-usage", display_mem_usage, 0, INVALID, 0, "Memory Usage");
        libcli_register_param(debug, &mem_usage);
        libcli_set_param_cmd_code(&mem_usage, CMDCODE_DEBUG_SHOW_MEMORY_USAGE);
        {
            /* debug mem-usage detail*/
            static param_t detail;
            init_param(&detail, CMD, "detail", display_mem_usage, 0, INVALID, 0, "Memory Usage Detail");
            libcli_register_param(&mem_usage, &detail);
            libcli_set_param_cmd_code(&detail, CMDCODE_DEBUG_SHOW_MEMORY_USAGE_DETAIL);
            {
                /*  debug mem-usage detail <struct-name> */
                static param_t struct_name;
                init_param(&struct_name, LEAF, 0, display_mem_usage, 0, STRING, "struct-name", "Structure Name Filter");
                libcli_register_param(&detail, &struct_name);
                libcli_set_param_cmd_code(&struct_name, CMDCODE_DEBUG_SHOW_MEMORY_USAGE_DETAIL);
            }
        }
    }

    /* Debug commands */
    {
        static param_t node;
        init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
        libcli_register_param(debug, &node);
        {
            /* debug node <node-name> . . .*/
            static param_t node_name;
            init_param(&node_name, LEAF, 0, 0, validate_node_extistence, STRING, "node-name", "Node Name");
            libcli_register_param(&node, &node_name);
            libcli_register_display_callback(&node_name, display_graph_nodes);
            {
                /*debug node <node-name> access-list...*/
                static param_t access_lst;
                init_param(&access_lst, CMD, "access-list", 0, 0, INVALID, 0, "Access List");
                libcli_register_param(&node_name, &access_lst);
                {
                    /*debug node <node-name> access-list <access-list-name> ...*/
                    static param_t access_list_name;
                    init_param(&access_list_name, LEAF, 0, 0, 0, STRING, "access-list-name", "Access List Name");
                    libcli_register_param(&access_lst, &access_list_name);
                    {
                        static param_t tcam;
                        init_param(&tcam, CMD, "tcam", debug_show_node_handler, 0, INVALID, 0, "Tcam format");
                        libcli_register_param(&access_list_name, &tcam);
                        libcli_set_param_cmd_code(&tcam, CMDCODE_DEBUG_SHOW_NODE_MTRIE_ACL);
                    }
                }
            }
             {
                 /*debug node <node-name> mtrie ...*/
                static param_t mtrie;
                init_param(&mtrie, CMD, "mtrie", 0, 0, INVALID, 0, "mtrie");
                libcli_register_param(&node_name, &mtrie);
                {
                    static param_t rt;
                    init_param(&rt, CMD, "rt", debug_show_node_handler, 0, INVALID, 0, "Routing Table");
                    libcli_register_param(&mtrie, &rt);
                    libcli_set_param_cmd_code(&rt, CMDCODE_DEBUG_SHOW_NODE_MTRIE_RT);
                }
                {
                    static param_t rt6;
                    init_param(&rt6, CMD, "rt6", debug_show_node_handler, 0, INVALID, 0, "ipv6 Routing Table");
                    libcli_register_param(&mtrie, &rt6);
                    libcli_set_param_cmd_code(&rt6, CMDCODE_DEBUG_SHOW_NODE_MTRIE_RT6);
                }                
            }
            {
                /*debug node <node-name> timer*/
                static param_t timer;
                init_param(&timer, CMD, "timer", debug_show_node_handler, 0, INVALID, 0, "Timer State");
                libcli_register_param(&node_name, &timer);
                libcli_set_param_cmd_code(&timer, CMDCODE_DEBUG_SHOW_NODE_TIMER);
				{
					/*debug show node <node-name> timer logs*/
					static param_t logs;
					init_param(&logs, CMD, "logging", debug_show_node_handler, 0, INVALID, 0, "Timer Logging");
					libcli_register_param(&timer, &logs);
					libcli_set_param_cmd_code(&logs, CMDCODE_DEBUG_SHOW_NODE_TIMER_LOGGING);
				}
            }
		    {
			    /* debug node <node-name> protocol */
				static param_t protocol;
				init_param(&protocol, CMD, "protocol", 0, 0, INVALID, 0, "App protocol");
				libcli_register_param(&node_name, &protocol);

				/* debug node <node-name> protocol ...*/
				cli_register_application_cli_trees(&protocol, 
							 cli_register_cb_arr_debug_node_node_name_protocol_level);
			}            
        }
    }


    /* clear commands */
    {
        {
            /* clear log */
            static param_t log_file;
            init_param(&log_file, CMD, "log-file", clear_topology_handler, 0, INVALID, 0, "clear log-file");
            libcli_register_param(clear, &log_file);
            libcli_set_param_cmd_code(&log_file, CMDCODE_CLEAR_LOG_FILE);
        }
        /*clear node ...*/    
        static param_t node;
        init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
        libcli_register_param(clear, &node);
        {
            /*clear node <node-name>*/ 
            static param_t node_name;
            init_param(&node_name, LEAF, 0, 0, validate_node_extistence, STRING, "node-name", "Node Name");
            libcli_register_param(&node, &node_name);	
            libcli_register_display_callback(&node_name, display_graph_nodes);
		    {
			    /* clear node <node-name> protocol */
				static param_t protocol;
				init_param(&protocol, CMD, "protocol", 0, 0, INVALID, 0, "App protocol");
				libcli_register_param(&node_name, &protocol);

				/* show node <node-name> protocol ...*/
				cli_register_application_cli_trees(&protocol, 
							 cli_register_cb_arr_clear_node_node_name_protcol_level);
			}
            {
                static param_t rib;
                init_param(&rib, CMD, "rib", 0, 0, INVALID, 0, "Routing Information Base rib");
                libcli_register_param(&node_name, &rib);
                {
                    static param_t rib_name;
                    init_param(&rib_name, LEAF, 0, clear_rt_handler, NULL, STRING, "rib-name", "Routing Table Name");
                    libcli_register_param(&rib, &rib_name);
                    libcli_set_param_cmd_code(&rib_name, CMDCODE_CLEAR_RT_TABLE);
                }
            }
        }
    }


    {
        /*show topology*/
         static param_t topology;
         init_param(&topology, CMD, "topology", show_nw_topology_handler, 0, INVALID, 0, "Dump Complete Network Topology");
         libcli_register_param(show, &topology);
         libcli_set_param_cmd_code(&topology, CMDCODE_SHOW_NW_TOPOLOGY);
         {
             /*show topology node*/ 
             static param_t node;
             init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
             libcli_register_param(&topology, &node);
             {
                /*show topology node <node-name>*/ 
                 static param_t node_name;
                 init_param(&node_name, LEAF, 0, show_nw_topology_handler, validate_node_extistence, STRING, "node-name", "Node Name");
                 libcli_register_display_callback(&node_name, display_graph_nodes);
                 libcli_register_param(&node, &node_name);
                 libcli_set_param_cmd_code(&node_name, CMDCODE_SHOW_NW_TOPOLOGY);
             }
         }
         
         {
            /*show node*/    
             static param_t node;
             init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
             libcli_register_param(show, &node);
             {
                /*show node <node-name>*/ 
                 static param_t node_name;
                 init_param(&node_name, LEAF, 0, 0, validate_node_extistence, STRING, "node-name", "Node Name");
                 libcli_register_param(&node, &node_name);
				libcli_register_display_callback(&node_name, display_graph_nodes);
                 {
                     /* show CLIs for Access list mounted here */
                     acl_build_show_cli(&node_name);
                     /* show CLIs for Prefix List are mounted here */
                     prefix_list_cli_show_tree(&node_name);
                    /* Network Object Show CLIs */
                     network_object_build_show_cli (&node_name);
                     /* Object Group Show CLIs*/
                     object_group_build_show_cli (&node_name);
                     /* show CLIs for TSPs*/
                     show_node_transport_svc_cli_tree(&node_name);
                 }

				 {
					 /* show node <node-name> protocol */
					 static param_t protocol;
					 init_param(&protocol, CMD, "protocol", 0, 0, INVALID, 0, "App protocol");
					 libcli_register_param(&node_name, &protocol);

					 /* show node <node-name> protocol ...*/
					 cli_register_application_cli_trees(&protocol, 
							 cli_register_cb_arr_show_node_node_name_protcol_level);
				 }

                 {
                     static param_t log_status;
                     init_param(&log_status, CMD, "log-status", traceoptions_handler, 0, INVALID, 0, "log-status");
                     libcli_register_param(&node_name, &log_status);
                     libcli_set_param_cmd_code(&log_status, CMDCODE_DEBUG_SHOW_LOG_STATUS);
                 }
                 {
                    #if 0
                    /*show node <node-name> spf-result*/
                    static param_t spf_result;
                    init_param(&spf_result, CMD, "spf-result", spf_algo_handler, 0, INVALID, 0, "SPF Results");
                    libcli_register_param(&node_name, &spf_result);
                    libcli_set_param_cmd_code(&spf_result, CMDCODE_SHOW_SPF_RESULTS);
                    #endif
                 }
                 {
                    /*show node <node-name> arp*/
                    static param_t arp;
                    init_param(&arp, CMD, "arp", show_arp_handler, 0, INVALID, 0, "Dump Arp Table");
                    libcli_register_param(&node_name, &arp);
                    libcli_set_param_cmd_code(&arp, CMDCODE_SHOW_NODE_ARP_TABLE);
                 }
                 {
                    /*show node <node-name> mac*/
                    static param_t mac;
                    init_param(&mac, CMD, "mac", show_mac_handler, 0, INVALID, 0, "Dump Mac Table");
                    libcli_register_param(&node_name, &mac);
                    libcli_set_param_cmd_code(&mac, CMDCODE_SHOW_NODE_MAC_TABLE);
                    {
                        /* Keyword 'vni' . . .*/
                        static param_t vni;
                        init_param(&vni, CMD, "vni", 0, 0, INVALID, 0, "Show Mac Table for VNI");
                        libcli_register_param(&mac, &vni);
                        libcli_param_list(&vni);
                        {
                            /* Value of vni */
                            static param_t vni_id;
                            init_param(&vni_id, LEAF, 0, show_mac_handler, 0, INT, "vni-id", "vni id(1-16777215)");
                            libcli_register_param(&vni, &vni_id);
                            libcli_set_param_cmd_code(&vni_id, CMDCODE_SHOW_NODE_MAC_VNI_TABLE);
                        }
                    }
                 }
                 {
                    /*show node <node-name> rt*/
                    static param_t rt;
                    init_param(&rt, CMD, "rt", show_rt_handler, 0, INVALID, 0, "Dump L3 Routing table");
                    libcli_register_param(&node_name, &rt);
                    libcli_set_param_cmd_code(&rt, CMDCODE_SHOW_NODE_RT_TABLE);
                    {
                         /*show node <node-name> rt <Rib name> */
                        static param_t rib_name;
                        init_param(&rib_name, LEAF, 0, show_rtm_route_cli_handler, 0, INVALID, "rib-name", "Show RTM table");
                        libcli_register_param(&rt, &rib_name);
                        libcli_set_param_cmd_code(&rib_name, CMDCODE_SHOW_NODE_RTM_ROUTE);
                        {
                             /*show node <node-name> rt <Rib name> detail*/
                             static param_t detail;
                             init_param(&detail, CMD, "detail", show_rtm_route_cli_handler, 0, INVALID, 0, "Show RTM table detail");
                             libcli_register_param(&rib_name, &detail);
                             libcli_set_param_cmd_code(&detail, CMDCODE_SHOW_NODE_RTM_ROUTE_DETAIL);    
                        }
                    }
                 }

                 {
                    /* Mount MPLS show CLI here */
                    mpls_build_show_cli_tree(&node_name);
                 }

                 {
                    /*show node <node-name> rt6*/
                    static param_t rt6;
                    init_param(&rt6, CMD, "rt6", show_rt6_handler, 0, INVALID, 0, "Dump L3 V6 Routing table");
                    libcli_register_param(&node_name, &rt6);
                    libcli_set_param_cmd_code(&rt6, CMDCODE_SHOW_NODE_RT6_TABLE);
                 }

                 {
                    /*show node <node-name> rtm protocol-subscriptions*/
                    static param_t rtm;
                    init_param(&rtm, CMD, "rtm", 0, 0, INVALID, 0, "RTM information");
                    libcli_register_param(&node_name, &rtm);
                    {
                        static param_t protocol_subscriptions;
                        init_param(&protocol_subscriptions, CMD, "protocol-subscriptions", 
                                   show_rtm_protocol_subscriptions_handler, 0, INVALID, 0, 
                                   "Display protocol subscription database");
                        libcli_register_param(&rtm, &protocol_subscriptions);
                        libcli_set_param_cmd_code(&protocol_subscriptions, CMDCODE_SHOW_NODE_RTM_PROTOCOL_SUBSCRIPTIONS);
                    }
                 }

                 {
                    /*show node <node-name> interface*/
                    static param_t interface;
                    init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "\"interface\" keyword");
                    libcli_register_param(&node_name, &interface);

                    {
                        /*show node <node-name> interface statistics*/
                        static param_t stats;
                        init_param(&stats, CMD, "statistics", show_interface_handler, 0, INVALID, 0, "Interface Statistics");
                        libcli_register_param(&interface, &stats);
                        libcli_set_param_cmd_code(&stats, CMDCODE_SHOW_INTF_STATS);
                    }
                 }

             }
         } 
    }
   

    {
        /*run spf*/ 
        static param_t spf;
        init_param(&spf, CMD, "spf", 0, 0, INVALID, 0, "Shortest SPF Path");
        libcli_register_param(run, &spf);
        {
            #if 0
            /*run spf all*/
            static param_t all;
            init_param(&all, CMD, "all" , spf_algo_handler, 0, INVALID, 0, "All nodes");
            libcli_register_param(&spf, &all);
            libcli_set_param_cmd_code(&all, CMDCODE_RUN_SPF_ALL);
            #endif
        }
    }

    {
        /*run node*/
        static param_t node;
        init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
        libcli_register_param(run, &node);
        {
            /*run node <node-name>*/
            static param_t node_name;
            init_param(&node_name, LEAF, 0, 0, validate_node_extistence, STRING, "node-name", "Node Name");
            libcli_register_param(&node, &node_name);
            libcli_register_display_callback(&node_name, display_graph_nodes);
			{
				/* run node <node-name> protocol */	
				static param_t protocol;
				init_param(&protocol, CMD, "protocol", 0, 0, INVALID, 0, "App Protocol");
				libcli_register_param(&node_name, &protocol);		

				/* run node <node-name> protocol ... */
				cli_register_application_cli_trees(&protocol, 
						cli_register_cb_arr_run_node_node_name_protocol_level);
			}

            /* Mount ping6 CLI here*/
            ipv6_build_cli_run_tree (&node_name);
            
            /* Mount SQL Query CLI */
            sql_build_cli_tree (&node_name);

            {
                /*run node <node-name> ping */
                static param_t ping;
                init_param(&ping, CMD, "ping" , 0, 0, INVALID, 0, "Ping utility");
                libcli_register_param(&node_name, &ping);
                {
                    /*run node <node-name> ping <ip-address>*/    
                    static param_t ip_addr;
                    init_param(&ip_addr, LEAF, 0, ping_handler, 0, IPV4, "ip-address", "Ipv4 Address");
                    libcli_register_param(&ping, &ip_addr);
                    libcli_set_param_cmd_code(&ip_addr, CMDCODE_PING);
                    libcli_param_synchronous  (&ip_addr);
                    {
                        /*run node <node-name> ping <ip-address> -c */
                            static param_t _c;
                            init_param(&_c, CMD, "-c", 0, 0, INVALID, 0, "-c count switch");
                            libcli_register_param(&ip_addr, &_c);
                            {
                                 static param_t count;
                                 init_param(&count, LEAF, 0, ping_handler, 0, INT, "count", "No of Pings to send");
                                 libcli_register_param(&_c, &count);
                                 libcli_set_param_cmd_code(&count, CMDCODE_PING);
                            }
                    }
                    {
                        static param_t ero;
                        init_param(&ero, CMD, "ero", 0, 0, INVALID, 0, "ERO(Explicit Route Object)");
                        libcli_register_param(&ip_addr, &ero);
                        {
                            static param_t ero_ip_addr;
                            init_param(&ero_ip_addr, LEAF, 0, ping_handler, 0, IPV4, "ero-ip-address", "ERO Ipv4 Address");
                            libcli_register_param(&ero, &ero_ip_addr);
                            libcli_set_param_cmd_code(&ero_ip_addr, CMDCODE_ERO_PING);
                            libcli_param_synchronous  (&ero_ip_addr);
                        }
                    }
                }
            }

            {
                /*run node <node-name> resolve-arp*/    
                static param_t resolve_arp;
                init_param(&resolve_arp, CMD, "resolve-arp", 0, 0, INVALID, 0, "Resolve ARP");
                libcli_register_param(&node_name, &resolve_arp);
                {
                    /*run node <node-name> resolve-arp <ip-address>*/    
                    static param_t ip_addr;
                    init_param(&ip_addr, LEAF, 0, arp_handler, 0, IPV4, "ip-address", "Nbr IPv4 Address");
                    libcli_register_param(&resolve_arp, &ip_addr);
                    libcli_set_param_cmd_code(&ip_addr, CMDCODE_RUN_ARP);
                }
            }
            {
                /*run node <node-name> spf*/
                static param_t spf;
                init_param(&spf, CMD, "spf", isis_show_handler, 0, INVALID, 0, "Trigger SPF");
                libcli_register_param(&node_name, &spf);
                libcli_set_param_cmd_code(&spf, CMDCODE_RUN_SPF);
            }
        }
    }

    {
        /*config global*/
        static param_t global;
        init_param(&global, CMD, "global", 0, 0, INVALID, 0, "global network-wide config");
        libcli_register_param(config, &global);
        {
            /*config global stdout*/
            static param_t _stdout;
            init_param(&_stdout, CMD, "stdout", traceoptions_handler, 0, INVALID, 0, "Turn on stdio logging");
            libcli_register_param(&global, &_stdout);
            libcli_set_param_cmd_code(&_stdout, CMDCODE_DEBUG_GLOBAL_STDOUT);
        }
        {
            /*config global no-stdout*/
            static param_t _no_stdout;
            init_param(&_no_stdout, CMD, "no-stdout", traceoptions_handler, 0, INVALID, 0, "Turn off stdio logging");
            libcli_register_param(&global, &_no_stdout);
            libcli_set_param_cmd_code(&_no_stdout, CMDCODE_DEBUG_GLOBAL_NO_STDOUT);
        }
    }
    {
      /*config node*/
      static param_t node;
      init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
      libcli_register_param(config, &node);  
      {
        /*config node <node-name>*/
        static param_t node_name;
        init_param(&node_name, LEAF, 0, 0, validate_node_extistence, STRING, "node-name", "Node Name");
        libcli_register_param(&node, &node_name);
        libcli_register_display_callback(&node_name, display_graph_nodes);
        {
            /* ACL CLIs are loaded */
            acl_build_config_cli (&node_name);

            /* Prefix List CLI loaded */
            prefix_list_cli_config_tree (&node_name);

            /* Object Network Config CLIs */
            network_object_build_config_cli (&node_name);

            /*Object Group Config CLIs */
            object_group_build_config_cli (&node_name);

            /* Timer Range CLIs */
            time_range_config_cli_tree (&node_name);

            /* Interface CLIs */
            Interface_config_cli_tree (&node_name);

            /* Transport Svc Profile CLIs*/
            config_node_build_transport_svc_cli_tree (&node_name);

            /* Debug options */
            tcp_ip_build_debug_cli_tree (&node_name);

            /* Mount ipv6 CLIs*/
            ipv6_build_cli_tree (&node_name);
            
            /* Mount MPLS Config CLIs*/
            mpls_build_config_cli_tree (&node_name);
        }

        {
            /* config node <node-name> rtm-route */
            static param_t rtm_route;
            init_param(&rtm_route, CMD, "rtm-route", 0, 0, INVALID, 0, "RTM Route Configuration");
            libcli_register_param(&node_name, &rtm_route);
            {
                /* config node <node-name> rtm-route prefix */
                static param_t prefix;
                init_param(&prefix, CMD, "prefix", 0, 0, INVALID, 0, "Route prefix");
                libcli_register_param(&rtm_route, &prefix);
                {
                    /* config node <node-name> rtm-route prefix <prefix/mask> */
                    static param_t prefix_mask;
                    init_param(&prefix_mask, LEAF, 0, 0, 0, STRING, "prefix-mask", "IP prefix/mask (10.0.0.0/24) or MPLS label (100 or Label:100)");
                    libcli_register_param(&prefix, &prefix_mask);
                    {
                        /* config node <node-name> rtm-route prefix <prefix/mask> <proto-id> */
                        static param_t proto_id;
                        init_param(&proto_id, LEAF, 0, 0, 0, INT, "proto-id", "Protocol ID (0-9)");
                        libcli_register_param(&prefix_mask, &proto_id);
                        {
                            /* <sub-proto-id> */
                            static param_t sub_proto_id;
                            init_param(&sub_proto_id, LEAF, 0, 0, 0, INT, "sub-proto-id", "Sub-protocol ID");
                            libcli_register_param(&proto_id, &sub_proto_id);
                            {
                                /* <instance-no> */
                                static param_t instance_no;
                                init_param(&instance_no, LEAF, 0, 0, 0, INT, "instance-no", "Instance number");
                                libcli_register_param(&sub_proto_id, &instance_no);
                                {
                                    /* <action-id> */
                                    static param_t action_id;
                                    init_param(&action_id, LEAF, 0, 0, 0, INT, "action-id", "Action ID (0-5)");
                                    libcli_register_param(&instance_no, &action_id);
                                    {
                                        /* <metric> */
                                        static param_t metric;
                                        init_param(&metric, LEAF, 0, 0, 0, INT, "metric", "Route metric");
                                        libcli_register_param(&action_id, &metric);
                                        {
                                            /* gateway */
                                            static param_t gateway;
                                            init_param(&gateway, CMD, "gateway", 0, 0, INVALID, 0, "Gateway IP");
                                            libcli_register_param(&metric, &gateway);
                                            {
                                                /* gateway <gw-ip> */
                                                static param_t gw_ip;
                                                init_param(&gw_ip, LEAF, 0, 0, 0, STRING, "gw-ip", "Gateway IP address (IPv4 or IPv6)");
                                                libcli_register_param(&gateway, &gw_ip);
                                                {
                                                    /* interface */
                                                    static param_t interface;
                                                    init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "Outgoing interface");
                                                    libcli_register_param(&gw_ip, &interface);
                                                    {
                                                        /* interface <if-name> */
                                                        static param_t if_name;
                                                        init_param(&if_name, LEAF, 0, config_rtm_route_cli_handler, 0, STRING, "if-name", "Interface name");
                                                        libcli_register_param(&interface, &if_name);
                                                        libcli_set_param_cmd_code(&if_name, CMDCODE_CONFIG_RTM_ROUTE_IP);
                                                        {
                                                            /* label-stack */
                                                            static param_t label_stack;
                                                            init_param(&label_stack, CMD, "label-stack", 0, 0, INVALID, 0, "MPLS label stack");
                                                            libcli_register_param(&if_name, &label_stack);
                                                            {
                                                                /* label-stack <label-list> */
                                                                static param_t label_list;
                                                                init_param(&label_list, LEAF, 0, config_rtm_route_cli_handler, 0, STRING, "label-list", "Space-separated label values");
                                                                libcli_register_param(&label_stack, &label_list);
                                                                libcli_param_recursive(&label_list);
                                                                libcli_set_param_cmd_code(&label_list, CMDCODE_CONFIG_RTM_ROUTE_IP);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        {
            /* config node <node-name> ip-traffic <src-addr> <dst-addr> <protocol>*/
            static param_t traffic;
            init_param(&traffic, CMD, "ip-traffic", 0, 0, INVALID, 0, "IP Traffic Generator");
            libcli_register_param(&node_name, &traffic);
            {
                static param_t src_addr;
                init_param(&src_addr, LEAF, 0, 0, 0, IPV4, "src-addr", "Source Address");
                libcli_register_param(&traffic, &src_addr);
                {
                    static param_t dst_addr;
                    init_param(&dst_addr, LEAF, 0, 0, 0, IPV4, "dst-addr", "Destination Address");
                    libcli_register_param(&src_addr, &dst_addr);
                    {
                        static param_t protocol;
                        init_param(&protocol, LEAF, 0, ip_traffic_generate_handler, 0, INT, "protocol", "Protocol");
                        libcli_register_param(&dst_addr, &protocol);
                        libcli_set_param_cmd_code(&protocol, CMDCODE_RUN_TRAFFIC);
                        {
                                /* run node <node-name> ip-traffic <src-addr> <dst-addr> <protocol> count <count>*/
                                static param_t count;
                                init_param(&count, CMD, "count", 0, 0, INVALID, 0, "Count");
                                libcli_register_param(&protocol, &count);
                                {
                                    static param_t count_value;
                                    init_param(&count_value, LEAF, 0, ip_traffic_generate_handler, 0, INT, "count", "No of packets to send");
                                    libcli_register_param(&count, &count_value);
                                    libcli_set_param_cmd_code(&count_value, CMDCODE_RUN_TRAFFIC);
                                }
                        }
                    }
                }
            }
        }

        {
            /* config node <node-name> mac-table install <vlan-id> <mac-addr> <OIF> [<remote-vtep>] */
            static param_t mac_table;
            init_param(&mac_table, CMD, "mac-table", 0, 0, INVALID, 0, "Mac Table Entry");
            libcli_register_param(&node_name, &mac_table);
            {
                static param_t install;
                init_param(&install, CMD, "install", 0, 0, INVALID, 0, "Install Mac Table Entry");
                libcli_register_param(&mac_table, &install);
                {
                    static param_t vlan_id;
                    init_param(&vlan_id, LEAF, 0, 0, validate_vlan_id, INT, "vlan-id", "VLAN ID (1-4096)");
                    libcli_register_param(&install, &vlan_id);
                    {
                        static param_t mac_addr;
                        init_param(&mac_addr, LEAF, 0, 0, 0, MAC, "mac-addr", "MAC Address");
                        libcli_register_param(&vlan_id, &mac_addr);
                        {
                            static param_t oif;
                            init_param(&oif, LEAF, 0, mac_table_config_handler, 0, STRING, "oif", "Out-going Interface Name");
                            libcli_register_param(&mac_addr, &oif);
                            libcli_set_param_cmd_code(&oif, CMDCODE_CONFIG_MAC_INSTALL);
                            {
                                static param_t remote_vtep;
                                init_param(&remote_vtep, LEAF, 0, mac_table_config_handler, 0, IPV4, "remote-vtep", "Remote VTEP IP Address");
                                libcli_register_param(&oif, &remote_vtep);
                                libcli_set_param_cmd_code(&remote_vtep, CMDCODE_CONFIG_MAC_INSTALL);
                            }
                        }
                    }
                }
            }
        }

        {
            /* conf node <node-name> rib <rib-name> import-policy <prefix-lst-name> */
            static param_t rib;
            init_param(&rib, CMD, "rib", 0, 0, INVALID, 0, "Routing Information Base rib");
            libcli_register_param(&node_name, &rib);
            {
                static param_t rib_name;
                init_param(&rib_name, LEAF, 0, 0, NULL, STRING, "rib-name", "Routing Table Name");
                libcli_register_param(&rib, &rib_name);
                {
                    static param_t import_pol;
                    init_param(&import_pol, CMD, "import-policy", 0, 0, INVALID, 0, "Import Policy Prefix Lst");
                    libcli_register_param(&rib_name, &import_pol);
                    {
                        static param_t prefix_lst_name;
                        init_param(&prefix_lst_name, LEAF, 0, l3_config_handler, NULL, STRING, "prefix-lst-name", "Prefix List Name");
                        libcli_register_param(&import_pol, &prefix_lst_name);
                        libcli_set_param_cmd_code(&prefix_lst_name, CMDCODE_CONF_RIB_IMPORT_POLICY);
                    }
                }                
            }
        }

        {
            {
                /*config node <node-name> [no] protocol*/
                static param_t protocol;
                init_param(&protocol, CMD, "protocol", 0, 0, INVALID, 0, "protocol");
                libcli_register_param(&node_name, &protocol);
				
				/* config node <node-name> protocol....*/
				cli_register_application_cli_trees(&protocol, 
						cli_register_cb_arr_config_node_node_name_protocol_level);
                libcli_support_cmd_negation(&protocol);
            }

            /*CLI for traceoptions at node level are hooked up here in tree */
            tcp_ip_traceoptions_cli(&node_name, 0);
        }
        
        {
            /*config node <node-name> route*/
            static param_t route;
            init_param(&route, CMD, "route", 0, 0, INVALID, 0, "L3 route");
            libcli_register_param(&node_name, &route);
            {
                /*config node <node-name> route <ip-address>*/    
                static param_t ip_addr;
                init_param(&ip_addr, LEAF, 0, 0, 0, IPV4, "ip-address", "IPv4 Address");
                libcli_register_param(&route, &ip_addr);
                {
                     /*config node <node-name> route <ip-address> <mask>*/
                    static param_t mask;
                    init_param(&mask, LEAF, 0, l3_config_handler, validate_mask_value, INT, "mask", "mask(0-32");
                    libcli_register_param(&ip_addr, &mask);
                    libcli_set_param_cmd_code(&mask, CMDCODE_CONF_NODE_L3ROUTE);
                    {
                        /*config node <node-name> route <ip-address> <mask> <gw-ip>*/
                        static param_t gwip;
                        init_param(&gwip, LEAF, 0, l3_config_handler, 0, IPV4, "gw-ip", "IPv4 Address");
                        libcli_register_param(&mask, &gwip);
                        libcli_set_param_cmd_code(&gwip, CMDCODE_CONF_NODE_L3ROUTE);
                        {
                            /*config node <node-name> route <ip-address> <mask> <gw-ip> <oif>*/
                            static param_t oif;
                            init_param(&oif, LEAF, 0, l3_config_handler, 0, STRING, "oif", "Out-going intf Name");
                            libcli_register_param(&gwip, &oif);
                            libcli_set_param_cmd_code(&oif, CMDCODE_CONF_NODE_L3ROUTE);
                        }
                    }
                }
            }    
        }


        libcli_support_cmd_negation(&node_name);
      }
    }
}
