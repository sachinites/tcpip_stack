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
#include "CommandParser/libcli.h"
#include "CommandParser/cmdtlv.h"
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

extern graph_t *topo;
class Interface;

extern int traceoptions_handler(param_t *param,
                                ser_buff_t *tlv_buf,
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

static int
display_mem_usage(param_t *param, ser_buff_t *tlv_buf,
                    op_mode enable_or_disable){

    tlv_struct_t *tlv = NULL;
    c_string struct_name = NULL;
    int cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "struct-name"))
            struct_name =  tlv->value;
    } TLV_LOOP_END;

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
		//ddcp_run_cli_tree,
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
display_graph_nodes(param_t *param, ser_buff_t *tlv_buf){

    node_t *node;
    glthread_t *curr;

    ITERATE_GLTHREAD_BEGIN(&topo->node_list, curr){

        node = graph_glue_to_node(curr);
        printf("%s\n", node->node_name);
    } ITERATE_GLTHREAD_END(&topo->node_list, curr);
}


static int
validate_node_extistence(c_string node_name){

    node_t *node = node_get_node_by_name(topo, node_name);
    if(node)
        return VALIDATION_SUCCESS;
    printf("Error : Node %s do not exist\n", node_name);
    return VALIDATION_FAILED;
}

int
validate_mask_value(c_string mask_str);

int
validate_mask_value(c_string mask_str){

    int mask = atoi((const char *)mask_str);
    if(mask >= 0 && mask <= 32)
        return VALIDATION_SUCCESS;
    printf("Error : Invalid Mask Value\n");
    return VALIDATION_FAILED;
}


/*Generic Topology Commands*/
static int
show_nw_topology_handler(param_t *param,
                         ser_buff_t *tlv_buf,
                         op_mode enable_or_disable){

    int CMDCODE = -1;
    node_t *node = NULL;
    c_string node_name = NULL;;
    tlv_struct_t *tlv = NULL;

    CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){
        
        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
    } TLV_LOOP_END;

    if(node_name)
        node = node_get_node_by_name(topo, node_name);

    switch(CMDCODE){

        case CMDCODE_SHOW_NW_TOPOLOGY:
            dump_nw_graph(topo, node);
            break;
        default:
            ;
    }
    return 0;
}

extern void
tcp_ip_refresh_tcp_log_file();

static int
clear_topology_handler(param_t *param,
                       ser_buff_t *tlv_buf,
                       op_mode enable_or_disable){

    int CMDCODE = -1;

    CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

    switch(CMDCODE) {
        case CMDCODE_CLEAR_LOG_FILE:
            tcp_ip_refresh_tcp_log_file();
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
show_arp_handler(param_t *param, ser_buff_t *tlv_buf, 
                    op_mode enable_or_disable){

    node_t *node;
    c_string node_name;
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_BEGIN(tlv_buf, tlv){

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
extern void
dump_mac_table(mac_table_t *mac_table);
static int
show_mac_handler(param_t *param, ser_buff_t *tlv_buf,
                    op_mode enable_or_disable){

    node_t *node;
    c_string node_name;
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    dump_mac_table(NODE_MAC_TABLE(node));
    return 0;
}



extern void
send_arp_broadcast_request(node_t *node,
                           Interface *oif,
                           c_string ip_addr);
static int
arp_handler(param_t *param, ser_buff_t *tlv_buf,
                op_mode enable_or_disable){

    node_t *node;
    c_string node_name;
    c_string ip_addr;
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_BEGIN(tlv_buf, tlv){

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
layer3_ping_fn(node_t *node, c_string dst_ip_addr);
extern void
layer3_ero_ping_fn(node_t *node, c_string dst_ip_addr,
                            c_string ero_ip_address);

static int
ping_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){

    int CMDCODE;
    node_t *node;
    c_string ip_addr = NULL;
    c_string ero_ip_addr = NULL;
    c_string node_name = NULL;

    CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

    tlv_struct_t *tlv = NULL;

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "ip-address"))
            ip_addr = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "ero-ip-address"))
            ero_ip_addr = tlv->value;
    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch(CMDCODE){

        case CMDCODE_PING:
            layer3_ping_fn(node, ip_addr);
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
show_rt_handler(param_t *param, ser_buff_t *tlv_buf,
                    op_mode enable_or_disable){

    node_t *node;
    c_string node_name;
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    dump_rt_table(NODE_RT_TABLE(node));
    return 0;
}

extern void
clear_rt_table(rt_table_t *rt_table, uint16_t proto_id);
static int
clear_rt_handler(param_t *param, ser_buff_t *tlv_buf,
                    op_mode enable_or_disable){

    node_t *node;
    c_string node_name;
    c_string rib_name;
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        if(parser_match_leaf_id(tlv->leaf_id, "rib-name"))
            rib_name = tlv->value;
    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    clear_rt_table(NODE_RT_TABLE(node), PROTO_ISIS);
    return 0;
}


extern void
rt_table_delete_route(rt_table_t *rt_table,
        c_string ip_addr, char mask, uint16_t proto);
extern void
rt_table_add_route(rt_table_t *rt_table,
        const char *dst, char mask,
        const char *gw, Interface *oif, uint32_t spf_metric,
        uint8_t proto);

static int
l3_config_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){

    node_t *node = NULL;
    c_string node_name = NULL;
    c_string intf_name = NULL;
    c_string gwip = NULL;
    c_string mask_str = NULL;
    c_string dest = NULL;
    c_string rib_name = NULL;
    c_string prefix_lst_name = NULL;

    int CMDCODE = -1;

    CMDCODE = EXTRACT_CMD_CODE(tlv_buf); 
    
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_BEGIN(tlv_buf, tlv){

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

    switch(CMDCODE){
        case CMDCODE_CONF_NODE_L3ROUTE:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                {
                    Interface *intf;
                    if(intf_name){
                        intf = node_get_intf_by_name(node, (const char *)intf_name);
                        if(!intf){
                            printf("Config Error : Non-Existing Interface : %s\n", intf_name);
                            return -1;
                        }
                        if (!intf->IsIpConfigured()) {
                            printf("Config Error : Not L3 Mode Interface : %s\n", intf_name);
                            return -1;
                        }
                    }
                    rt_table_add_route(NODE_RT_TABLE(node), (const char *)dest, mask, 
                        (const char *)gwip, intf, 0, PROTO_STATIC);
                }
                break;
                case CONFIG_DISABLE:
                    rt_table_delete_route(NODE_RT_TABLE(node), dest, mask, PROTO_STATIC);
                    break;
                default:
                    ;
            }
            break;
        case CMDCODE_CONF_RIB_IMPORT_POLICY:
        {
            if (string_compare(rib_name, "inet.0", 6) == 0) {
                rt_table_t *rt_table = NODE_RT_TABLE(node);
                prefix_list_t *prefix_lst = prefix_lst_lookup_by_name(&node->prefix_lst_db, prefix_lst_name);
                if (!prefix_lst) {
                    printf ("Error : Prefix List do not Exist\n");
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
                printf ("Error : Routing Table Support is inet.0\n");
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
debug_show_node_handler(param_t *param, ser_buff_t *tlv_buf,
                         op_mode enable_or_disable){

   node_t *node;
   c_string node_name;
   tlv_struct_t *tlv = NULL;
   c_string access_list_name = NULL;

   int CMDCODE;

   CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){
        
        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if   (parser_match_leaf_id(tlv->leaf_id, "access-list-name"))
            access_list_name = tlv->value;
    }TLV_LOOP_END;

   node = node_get_node_by_name(topo, node_name);

   switch(CMDCODE){
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
        case CMDCODE_DEBUG_SHOW_NODE_MTRIE_ACL:
             access_list_print_bitmap(node, access_list_name);
            break;
        default:
        break;
   }
   return 0;
}

static int 
show_interface_handler(param_t *param, ser_buff_t *tlv_buf, 
                       op_mode enable_or_disable){
    
    int CMDCODE;
    node_t *node;
    c_string node_name;
    c_string protocol_name = NULL;

    CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

    tlv_struct_t *tlv = NULL;

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "protocol-name"))
            protocol_name = tlv->value;        
    } TLV_LOOP_END;
   
    node = node_get_node_by_name(topo, node_name);

    switch(CMDCODE){

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

    init_libcli();

    cli_register_ctrlC_handler(tcp_ip_toggle_global_console_logging);

    param_t *show   = libcli_get_show_hook();
    param_t *debug  = libcli_get_debug_hook();
    param_t *config = libcli_get_config_hook();
    param_t *run    = libcli_get_run_hook();
    param_t *clear    = libcli_get_clear_hook();
    param_t *debug_show = libcli_get_debug_show_hook();
    param_t *root = libcli_get_root();

    {
        /*debug show node*/
        static param_t node;
        init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
        libcli_register_param(debug_show, &node);
        {
            /*debug show node <node-name>*/
            static param_t node_name;
            init_param(&node_name, LEAF, 0, 0, validate_node_extistence, STRING, "node-name", "Node Name");
            libcli_register_param(&node, &node_name);
            {
                    /*debug show node <node-name> access-list...*/
                    static param_t access_lst;
                    init_param(&access_lst, CMD, "access-list", 0, 0, INVALID, 0, "Access List");
                    libcli_register_param(&node_name, &access_lst);
                    {
                        /*debug show node <node-name> access-list <access-list-name> ...*/
                        static param_t access_list_name;
                        init_param(&access_list_name, LEAF, 0, 0, 0, STRING, "access-list-name", "Access List Name");
                        libcli_register_param(&access_lst, &access_list_name);
                        {
                            static param_t tcam;
                            init_param(&tcam, CMD, "tcam", debug_show_node_handler, 0, INVALID, 0, "Tcam format");
                            libcli_register_param(&access_list_name, &tcam);
                            set_param_cmd_code(&tcam, CMDCODE_DEBUG_SHOW_NODE_MTRIE_ACL);
                        }
                    }
                }
            {
                 /*debug show node <node-name> mtrie ...*/
                static param_t mtrie;
                init_param(&mtrie, CMD, "mtrie", 0, 0, INVALID, 0, "mtrie");
                libcli_register_param(&node_name, &mtrie);
                {
                    static param_t rt;
                    init_param(&rt, CMD, "rt", debug_show_node_handler, 0, INVALID, 0, "Routing Table");
                    libcli_register_param(&mtrie, &rt);
                    set_param_cmd_code(&rt, CMDCODE_DEBUG_SHOW_NODE_MTRIE_RT);
                }
            }
            {
                /*debug show node <node-name> timer*/
                static param_t timer;
                init_param(&timer, CMD, "timer", debug_show_node_handler, 0, INVALID, 0, "Timer State");
                libcli_register_param(&node_name, &timer);
                set_param_cmd_code(&timer, CMDCODE_DEBUG_SHOW_NODE_TIMER);
				{
					/*debug show node <node-name> timer logs*/
					static param_t logs;
					init_param(&logs, CMD, "logging", debug_show_node_handler, 0, INVALID, 0, "Timer Logging");
					libcli_register_param(&timer, &logs);
					set_param_cmd_code(&logs, CMDCODE_DEBUG_SHOW_NODE_TIMER_LOGGING);
				}
            }
        }
    }

    {
        /* debug show mem-usage*/
        static param_t mem_usage;
        init_param(&mem_usage, CMD, "mem-usage", display_mem_usage, 0, INVALID, 0, "Memory Usage");
        libcli_register_param(debug_show, &mem_usage);
        set_param_cmd_code(&mem_usage, CMDCODE_DEBUG_SHOW_MEMORY_USAGE);
        {
            /* debug show mem-usage detail*/
            static param_t detail;
            init_param(&detail, CMD, "detail", display_mem_usage, 0, INVALID, 0, "Memory Usage Detail");
            libcli_register_param(&mem_usage, &detail);
            set_param_cmd_code(&detail, CMDCODE_DEBUG_SHOW_MEMORY_USAGE_DETAIL);
            {
                /*  debug show mem-usage detail <struct-name> */
                static param_t struct_name;
                init_param(&struct_name, LEAF, 0, display_mem_usage, 0, STRING, "struct-name", "Structure Name Filter");
                libcli_register_param(&detail, &struct_name);
                set_param_cmd_code(&struct_name, CMDCODE_DEBUG_SHOW_MEMORY_USAGE_DETAIL);
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
            set_param_cmd_code(&log_file, CMDCODE_CLEAR_LOG_FILE);
        }
        /*clear node ...*/    
        static param_t node;
        init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
        libcli_register_param(clear, &node);
        libcli_register_display_callback(&node, display_graph_nodes);
        {
            /*clear node <node-name>*/ 
            static param_t node_name;
            init_param(&node_name, LEAF, 0, 0, validate_node_extistence, STRING, "node-name", "Node Name");
            libcli_register_param(&node, &node_name);	
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
                    set_param_cmd_code(&rib_name, CMDCODE_CLEAR_RT_TABLE);
                }
            }
        }
    }


    {
        /*show topology*/
         static param_t topology;
         init_param(&topology, CMD, "topology", show_nw_topology_handler, 0, INVALID, 0, "Dump Complete Network Topology");
         libcli_register_param(show, &topology);
         set_param_cmd_code(&topology, CMDCODE_SHOW_NW_TOPOLOGY);
         {
             /*show topology node*/ 
             static param_t node;
             init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
             libcli_register_param(&topology, &node);
             libcli_register_display_callback(&node, display_graph_nodes);
             {
                /*show topology node <node-name>*/ 
                 static param_t node_name;
                 init_param(&node_name, LEAF, 0, show_nw_topology_handler, validate_node_extistence, STRING, "node-name", "Node Name");
                 libcli_register_param(&node, &node_name);
                 set_param_cmd_code(&node_name, CMDCODE_SHOW_NW_TOPOLOGY);
             }
         }
         
         {
            /*show node*/    
             static param_t node;
             init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
             libcli_register_param(show, &node);
             libcli_register_display_callback(&node, display_graph_nodes);
             {
                /*show node <node-name>*/ 
                 static param_t node_name;
                 init_param(&node_name, LEAF, 0, 0, validate_node_extistence, STRING, "node-name", "Node Name");
                 libcli_register_param(&node, &node_name);
				
                 {
                     /* show CLIs for Access list mounted here */
                     acl_build_show_cli(&node_name);
                     /* show CLIs for Prefix List are mounted here */
                     prefix_list_cli_show_tree(&node_name);
                    /* Network Object Show CLIs */
                     network_object_build_show_cli (&node_name);
                     /* Object Group Show CLIs*/
                     object_group_build_show_cli (&node_name);
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
                     set_param_cmd_code(&log_status, CMDCODE_DEBUG_SHOW_LOG_STATUS);
                 }
                 {
                    /*show node <node-name> spf-result*/
                    static param_t spf_result;
                    init_param(&spf_result, CMD, "spf-result", spf_algo_handler, 0, INVALID, 0, "SPF Results");
                    libcli_register_param(&node_name, &spf_result);
                    set_param_cmd_code(&spf_result, CMDCODE_SHOW_SPF_RESULTS);
                 }
                 {
                    /*show node <node-name> arp*/
                    static param_t arp;
                    init_param(&arp, CMD, "arp", show_arp_handler, 0, INVALID, 0, "Dump Arp Table");
                    libcli_register_param(&node_name, &arp);
                    set_param_cmd_code(&arp, CMDCODE_SHOW_NODE_ARP_TABLE);
                 }
                 {
                    /*show node <node-name> mac*/
                    static param_t mac;
                    init_param(&mac, CMD, "mac", show_mac_handler, 0, INVALID, 0, "Dump Mac Table");
                    libcli_register_param(&node_name, &mac);
                    set_param_cmd_code(&mac, CMDCODE_SHOW_NODE_MAC_TABLE);
                 }
                 {
                    /*show node <node-name> rt*/
                    static param_t rt;
                    init_param(&rt, CMD, "rt", show_rt_handler, 0, INVALID, 0, "Dump L3 Routing table");
                    libcli_register_param(&node_name, &rt);
                    set_param_cmd_code(&rt, CMDCODE_SHOW_NODE_RT_TABLE);
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
                        set_param_cmd_code(&stats, CMDCODE_SHOW_INTF_STATS);
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
            /*run spf all*/
            static param_t all;
            init_param(&all, CMD, "all" , spf_algo_handler, 0, INVALID, 0, "All nodes");
            libcli_register_param(&spf, &all);
            set_param_cmd_code(&all, CMDCODE_RUN_SPF_ALL);
        }
    }

    {
        /*run node*/
        static param_t node;
        init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
        libcli_register_param(run, &node);
        libcli_register_display_callback(&node, display_graph_nodes);
        {
            /*run node <node-name>*/
            static param_t node_name;
            init_param(&node_name, LEAF, 0, 0, validate_node_extistence, STRING, "node-name", "Node Name");
            libcli_register_param(&node, &node_name);

			{
				/* run node <node-name> protocol */	
				static param_t protocol;
				init_param(&protocol, CMD, "protocol", 0, 0, INVALID, 0, "App Protocol");
				libcli_register_param(&node_name, &protocol);		

				/* run node <node-name> protocol ... */
				cli_register_application_cli_trees(&protocol, 
						cli_register_cb_arr_run_node_node_name_protocol_level);
			}

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
                    set_param_cmd_code(&ip_addr, CMDCODE_PING);
                    {
                        static param_t ero;
                        init_param(&ero, CMD, "ero", 0, 0, INVALID, 0, "ERO(Explicit Route Object)");
                        libcli_register_param(&ip_addr, &ero);
                        {
                            static param_t ero_ip_addr;
                            init_param(&ero_ip_addr, LEAF, 0, ping_handler, 0, IPV4, "ero-ip-address", "ERO Ipv4 Address");
                            libcli_register_param(&ero, &ero_ip_addr);
                            set_param_cmd_code(&ero_ip_addr, CMDCODE_ERO_PING);
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
                    set_param_cmd_code(&ip_addr, CMDCODE_RUN_ARP);
                }
            }
            {
                /*run node <node-name> spf*/
                static param_t spf;
                init_param(&spf, CMD, "spf", spf_algo_handler, 0, INVALID, 0, "Trigger SPF");
                libcli_register_param(&node_name, &spf);
                set_param_cmd_code(&spf, CMDCODE_RUN_SPF);
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
            set_param_cmd_code(&_stdout, CMDCODE_DEBUG_GLOBAL_STDOUT);
        }
        {
            /*config global no-stdout*/
            static param_t _no_stdout;
            init_param(&_no_stdout, CMD, "no-stdout", traceoptions_handler, 0, INVALID, 0, "Turn off stdio logging");
            libcli_register_param(&global, &_no_stdout);
            set_param_cmd_code(&_no_stdout, CMDCODE_DEBUG_GLOBAL_NO_STDOUT);
        }
    }
    {
      /*config node*/
      static param_t node;
      init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
      libcli_register_param(config, &node);  
      libcli_register_display_callback(&node, display_graph_nodes);
      {
        /*config node <node-name>*/
        static param_t node_name;
        init_param(&node_name, LEAF, 0, 0, validate_node_extistence, STRING, "node-name", "Node Name");
        libcli_register_param(&node, &node_name);

        {
            /* ACL CLIs are loaded */
            acl_build_config_cli(&node_name);

            /* Prefix List CLI loaded */
            prefix_list_cli_config_tree(&node_name);

            /* Object Network Config CLIs */
            network_object_build_config_cli (&node_name);

            /*Object Group Config CLIs */
            object_group_build_config_cli  (&node_name);

            /* Timer Range CLIs */
            time_range_config_cli_tree  (&node_name);

            /* Interface CLIs */
            Interface_config_cli_tree(&node_name);
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
                        set_param_cmd_code(&prefix_lst_name, CMDCODE_CONF_RIB_IMPORT_POLICY);
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
                support_cmd_negation(&protocol);
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
                    set_param_cmd_code(&mask, CMDCODE_CONF_NODE_L3ROUTE);
                    {
                        /*config node <node-name> route <ip-address> <mask> <gw-ip>*/
                        static param_t gwip;
                        init_param(&gwip, LEAF, 0, 0, 0, IPV4, "gw-ip", "IPv4 Address");
                        libcli_register_param(&mask, &gwip);
                        {
                            /*config node <node-name> route <ip-address> <mask> <gw-ip> <oif>*/
                            static param_t oif;
                            init_param(&oif, LEAF, 0, l3_config_handler, 0, STRING, "oif", "Out-going intf Name");
                            libcli_register_param(&gwip, &oif);
                            set_param_cmd_code(&oif, CMDCODE_CONF_NODE_L3ROUTE);
                        }
                    }
                }
            }    
        }    
        support_cmd_negation(&node_name);
      }
    }
    support_cmd_negation(config);
    /*Do not Add any param here*/
}
