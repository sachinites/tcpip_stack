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
#include "WheelTimer/WheelTimer.h"
#include "Layer5/app_handlers.h"
#include "BitOp/bitsop.h"
#include "tcpip_notif.h"

extern graph_t *topo;
extern void tcp_ip_traceoptions_cli(param_t *node_name_param, 
                                 param_t *intf_name_param);
extern int traceoptions_handler(param_t *param,
                                ser_buff_t *tlv_buf,
                                op_mode enable_or_disable);

/* Display functions when user presses ?*/
static void
display_graph_nodes(param_t *param, ser_buff_t *tlv_buf){

    node_t *node;
    glthread_t *curr;

    ITERATE_GLTHREAD_BEGIN(&topo->node_list, curr){

        node = graph_glue_to_node(curr);
        printf("%s\n", node->node_name);
    } ITERATE_GLTHREAD_END(&topo->node_list, curr);
}

/*Display Node Interfaces*/
static void
display_node_interfaces(param_t *param, ser_buff_t *tlv_buf){

    node_t *node;
    char *node_name;
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if(strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;

    }TLV_LOOP_END;

    if(!node_name)
        return;

    node = get_node_by_node_name(topo, node_name);
    
    int i = 0;
    interface_t *intf;

    for(; i < MAX_INTF_PER_NODE; i++){

        intf = node->intf[i];
        if(!intf) continue;

        printf(" %s\n", intf->if_name);
    }
}

/*General Validations*/

static int 
validate_if_up_down_status(char *value){

    if(strncmp(value, "up", strlen("up")) == 0 && 
        strlen("up") == strlen(value)){
        return VALIDATION_SUCCESS;
    }
    else if(strncmp(value, "down", strlen("down")) == 0 && 
            strlen("down") == strlen(value)){
        return VALIDATION_SUCCESS;
    }
    return VALIDATION_FAILED;
}

static int
validate_interface_metric_val(char *value){

    uint32_t metric_val = atoi(value);
    if(metric_val > 0 && metric_val <= INTF_MAX_METRIC)
        return VALIDATION_SUCCESS;
    return VALIDATION_FAILED;
}


static int
validate_node_extistence(char *node_name){

    node_t *node = get_node_by_node_name(topo, node_name);
    if(node)
        return VALIDATION_SUCCESS;
    printf("Error : Node %s do not exist\n", node_name);
    return VALIDATION_FAILED;
}

static int
validate_vlan_id(char *vlan_value){

    uint32_t vlan = atoi(vlan_value);
    if(!vlan){
        printf("Error : Invalid Vlan Value\n");
        return VALIDATION_FAILED;
    }
    if(vlan >= 1 && vlan <= 4095)
        return VALIDATION_SUCCESS;

    return VALIDATION_FAILED;
}

static int
validate_l2_mode_value(char *l2_mode_value){

    if((strncmp(l2_mode_value, "access", strlen("access")) == 0) || 
        (strncmp(l2_mode_value, "trunk", strlen("trunk")) == 0))
        return VALIDATION_SUCCESS;
    return VALIDATION_FAILED;
}

static int
validate_mask_value(char *mask_str){

    uint32_t mask = atoi(mask_str);
    if(!mask){
        printf("Error : Invalid Mask Value\n");
        return VALIDATION_FAILED;
    }
    if(mask >= 0 && mask <= 32)
        return VALIDATION_SUCCESS;
    return VALIDATION_FAILED;
}


/*Generic Topology Commands*/
static int
show_nw_topology_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){

    int CMDCODE = -1;
    node_t *node = NULL;
    char *node_name = NULL;;
    tlv_struct_t *tlv = NULL;

    CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){
        
        if(strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else
            assert(0);
    } TLV_LOOP_END;

    if(node_name)
        node = get_node_by_node_name(topo, node_name);

    switch(CMDCODE){

        case CMDCODE_SHOW_NW_TOPOLOGY:
            dump_nw_graph(topo, node);
            break;
        default:
            ;
    }
    return 0;
}


/*Layer 2 Commands*/

typedef struct arp_table_ arp_table_t;
extern void
dump_arp_table(arp_table_t *arp_table);

static int
show_arp_handler(param_t *param, ser_buff_t *tlv_buf, 
                    op_mode enable_or_disable){

    node_t *node;
    char *node_name;
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if(strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = get_node_by_node_name(topo, node_name);
    dump_arp_table(NODE_ARP_TABLE(node));
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
    char *node_name;
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if(strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = get_node_by_node_name(topo, node_name);
    dump_mac_table(NODE_MAC_TABLE(node));
    return 0;
}



extern void
send_arp_broadcast_request(node_t *node,
                           interface_t *oif,
                           char *ip_addr);
static int
arp_handler(param_t *param, ser_buff_t *tlv_buf,
                op_mode enable_or_disable){

    node_t *node;
    char *node_name;
    char *ip_addr;
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if(strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else if(strncmp(tlv->leaf_id, "ip-address", strlen("ip-address")) ==0)
            ip_addr = tlv->value;
    } TLV_LOOP_END;

    node = get_node_by_node_name(topo, node_name);
    send_arp_broadcast_request(node, NULL, ip_addr);
    return 0;
}


/*Layer 3 Commands*/
extern void
layer3_ping_fn(node_t *node, char *dst_ip_addr);
extern void
layer3_ero_ping_fn(node_t *node, char *dst_ip_addr,
                            char *ero_ip_address);

static int
ping_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){

    int CMDCODE;
    node_t *node;
    char *ip_addr = NULL, 
         *ero_ip_addr = NULL;
    char *node_name;

    CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

    tlv_struct_t *tlv = NULL;

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if     (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else if(strncmp(tlv->leaf_id, "ip-address", strlen("ip-address")) ==0)
            ip_addr = tlv->value;
        else if(strncmp(tlv->leaf_id, "ero-ip-address", strlen("ero-ip-address")) ==0)
            ero_ip_addr = tlv->value;
        else
            assert(0);
    }TLV_LOOP_END;

    node = get_node_by_node_name(topo, node_name);

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
    char *node_name;
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if(strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = get_node_by_node_name(topo, node_name);
    dump_rt_table(NODE_RT_TABLE(node));
    return 0;
}

extern void
delete_rt_table_entry(rt_table_t *rt_table,
        char *ip_addr, char mask);
extern void
rt_table_add_route(rt_table_t *rt_table,
        char *dst, char mask,
        char *gw, interface_t *oif, uint32_t spf_metric);

static int
l3_config_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){

    node_t *node = NULL;
    char *node_name = NULL;
    char *intf_name = NULL;
    char *gwip = NULL;
    char *mask_str = NULL;
    char *dest = NULL;
    int CMDCODE = -1;

    CMDCODE = EXTRACT_CMD_CODE(tlv_buf); 
    
    tlv_struct_t *tlv = NULL;
    
    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if     (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else if(strncmp(tlv->leaf_id, "ip-address", strlen("ip-address")) ==0)
            dest = tlv->value;
        else if(strncmp(tlv->leaf_id, "gw-ip", strlen("gw-ip")) ==0)
            gwip = tlv->value;
        else if(strncmp(tlv->leaf_id, "mask", strlen("mask")) ==0)
            mask_str = tlv->value;
        else if(strncmp(tlv->leaf_id, "oif", strlen("oif")) ==0)
            intf_name = tlv->value;
        else
            assert(0);

    }TLV_LOOP_END;

    node = get_node_by_node_name(topo, node_name);

    char mask;
    if(mask_str){
        mask = atoi(mask_str);
    }

    switch(CMDCODE){
        case CMDCODE_CONF_NODE_L3ROUTE:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                {
                    interface_t *intf;
                    if(intf_name){
                        intf = get_node_if_by_name(node, intf_name);
                        if(!intf){
                            printf("Config Error : Non-Existing Interface : %s\n", intf_name);
                            return -1;
                        }
                        if(!IS_INTF_L3_MODE(intf)){
                            printf("Config Error : Not L3 Mode Interface : %s\n", intf_name);
                            return -1;
                        }
                    }
                    rt_table_add_route(NODE_RT_TABLE(node), dest, mask, gwip, intf, 0);
                }
                break;
                case CONFIG_DISABLE:
                    delete_rt_table_entry(NODE_RT_TABLE(node), dest, mask);
                    break;
                default:
                    ;
            }
            break;
        default:
            break;
    }
    return 0;
}

/*Layer 4 Commands*/



/*Layer 5 Commands*/

extern void
ddcp_trigger_default_ddcp_query(node_t *node, int ddcp_q_interval);
extern void
ddcp_print_ddcp_reply_msgs_db(node_t *node);

static int
ddcp_validate_query_interval(char *ddcp_q_interval){

    int ddcp_q_intvl = atoi(ddcp_q_interval);
    if(ddcp_q_intvl < 1){
        printf("Error : Invalid Value, expected > 1\n");
        return VALIDATION_FAILED;
    }
    return VALIDATION_SUCCESS;
}

static int
ddcp_handler(param_t *param, ser_buff_t *tlv_buf, 
             op_mode enable_or_disable){

   node_t *node = NULL;
   char *node_name = NULL;
   int CMDCODE = -1;
   int ddcp_q_interval = 0 ;

   CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

   tlv_struct_t *tlv = NULL;

   TLV_LOOP_BEGIN(tlv_buf, tlv){
        
        if  (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else if(strncmp(tlv->leaf_id, "ddcp-q-interval", strlen("ddcp-q-interval")) == 0)
            ddcp_q_interval = atoi(tlv->value);
        else
            assert(0);
   } TLV_LOOP_END;

   node = get_node_by_node_name(topo, node_name);

    switch(CMDCODE){
        case CMDCODE_RUN_DDCP_QUERY:
        case CMDCODE_RUN_DDCP_QUERY_PERIODIC:
            ddcp_trigger_default_ddcp_query(node, ddcp_q_interval); 
            break;
        case CMDCODE_SHOW_DDCP_DB:
            ddcp_print_ddcp_reply_msgs_db(node); 
        default:
            ;
    }
}

/*Interface Config Handler*/
extern void
interface_set_l2_mode(node_t *node,
                       interface_t *interface,
                       char *l2_mode_option);

extern void
interface_unset_l2_mode(node_t *node,
                         interface_t *interface,
                         char *l2_mode_option);
extern void
interface_set_vlan(node_t *node,
                    interface_t *interface,
                    uint32_t vlan);
extern void
interface_unset_vlan(node_t *node,
                      interface_t *interface,
                      uint32_t vlan);
extern bool_t
schedule_hello_on_interface(interface_t *intf,
                            int interval_sec,
                            bool_t is_repeat);
extern void
stop_interface_hellos(interface_t *interface);

static int
intf_config_handler(param_t *param, ser_buff_t *tlv_buf, 
                    op_mode enable_or_disable){

   char *node_name;
   char *intf_name;
   uint32_t vlan_id;
   char *l2_mode_option;
   char *if_up_down;
   int CMDCODE;
   tlv_struct_t *tlv = NULL;
   node_t *node;
   interface_t *interface;
   uint32_t intf_new_matric_val;

   CMDCODE = EXTRACT_CMD_CODE(tlv_buf);
   
    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if     (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else if(strncmp(tlv->leaf_id, "if-name", strlen("if-name")) ==0)
            intf_name = tlv->value;
        else if(strncmp(tlv->leaf_id, "vlan-id", strlen("vlan-d")) ==0)
            vlan_id = atoi(tlv->value);
        else if(strncmp(tlv->leaf_id, "l2-mode-val", strlen("l2-mode-val")) == 0)
            l2_mode_option = tlv->value;
        else if(strncmp(tlv->leaf_id, "if-up-down", strlen("if-up-down")) == 0)
             if_up_down = tlv->value; 
        else if(strncmp(tlv->leaf_id, "metric-val", strlen("metric-val")) == 0)
             intf_new_matric_val = atoi(tlv->value);            
        else
            assert(0);
    } TLV_LOOP_END;

    node = get_node_by_node_name(topo, node_name);
    interface = get_node_if_by_name(node, intf_name);

    if(!interface){
        printf("Error : Interface %s do not exist\n", interface->if_name);
        return -1;
    }
    uint32_t if_change_flags = 0;
    switch(CMDCODE){
        case CMDCODE_INTF_CONFIG_METRIC:
        {
            uint32_t intf_existing_metric = get_link_cost(interface);

            if(intf_existing_metric != intf_new_matric_val){
                SET_BIT(if_change_flags, IF_METRIC_CHANGE_F); 
            }

            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    interface->link->cost = intf_new_matric_val;        
                break;
                case CONFIG_DISABLE:
                    interface->link->cost = INTF_METRIC_DEFAULT;
                break;
                default: ;
            }
            if(IS_BIT_SET(if_change_flags, IF_METRIC_CHANGE_F)){
				nfc_intf_invoke_notification_to_sbscribers(
					interface, 0, if_change_flags);
            }
        }    
        break;
        case CMDCODE_CONF_INTF_UP_DOWN:
            if(strncmp(if_up_down, "up", strlen("up")) == 0){
                if(interface->intf_nw_props.is_up == FALSE){
                    SET_BIT(if_change_flags, IF_UP_DOWN_CHANGE_F); 
                }
                interface->intf_nw_props.is_up = TRUE;
            }
            else{
                if(interface->intf_nw_props.is_up){
                    SET_BIT(if_change_flags, IF_UP_DOWN_CHANGE_F);
                }
                interface->intf_nw_props.is_up = FALSE;
            }
            if(IS_BIT_SET(if_change_flags, IF_UP_DOWN_CHANGE_F)){
				nfc_intf_invoke_notification_to_sbscribers(
					interface, 0, if_change_flags);
            }
            break;
        case CMDCODE_INTF_CONFIG_L2_MODE:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    interface_set_l2_mode(node, interface, l2_mode_option);
                    break;
                case CONFIG_DISABLE:
                    interface_unset_l2_mode(node, interface, l2_mode_option);
                    break;
                default:
                    ;
            }
            break;
        case CMDCODE_INTF_CONFIG_VLAN:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    interface_set_vlan(node, interface, vlan_id);
                    break;
                case CONFIG_DISABLE:
                    interface_unset_vlan(node, interface, vlan_id);
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

/*Miscellaneous Commands*/
static int
debug_show_node_handler(param_t *param, ser_buff_t *tlv_buf,
                         op_mode enable_or_disable){

   char *node_name;
   tlv_struct_t *tlv = NULL;
   node_t *node;
   int CMDCODE;

   CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){
        
        if     (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else
            assert(0);
    }TLV_LOOP_END;

   node = get_node_by_node_name(topo, node_name);

   switch(CMDCODE){
        case CMDCODE_DEBUG_SHOW_NODE_TIMER:
            print_wheel_timer(node->node_nw_prop.wt);         
        break;
        default:
        break;
   }
}

static int 
show_interface_handler(param_t *param, ser_buff_t *tlv_buf, 
                       op_mode enable_or_disable){
    
    int CMDCODE;
    node_t *node;
    char *node_name;
    char *protocol_name = NULL;

    CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

    tlv_struct_t *tlv = NULL;

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if     (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else if(strncmp(tlv->leaf_id, "protocol-name", strlen("protocol-name")) ==0)
            protocol_name = tlv->value;        
        else
            assert(0);
    } TLV_LOOP_END;
   
    node = get_node_by_node_name(topo, node_name);

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

    param_t *show   = libcli_get_show_hook();
    param_t *debug  = libcli_get_debug_hook();
    param_t *config = libcli_get_config_hook();
    param_t *run    = libcli_get_run_hook();
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
                /*debug show node <node-name> timer*/
                static param_t timer;
                init_param(&timer, CMD, "timer", debug_show_node_handler, 0, INVALID, 0, "Timer State");
                libcli_register_param(&node_name, &timer);
                set_param_cmd_code(&timer, CMDCODE_DEBUG_SHOW_NODE_TIMER);
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
                     static param_t log_status;
                     init_param(&log_status, CMD, "log-status", traceoptions_handler, 0, INVALID, 0, "log-status");
                     libcli_register_param(&node_name, &log_status);
                     set_param_cmd_code(&log_status, CMDCODE_DEBUG_SHOW_LOG_STATUS);
                 }
                 {
                    /*show node <node-name> nmp nbrships*/
                    static param_t nmp;
                    init_param(&nmp, CMD, "nmp", 0, 0, INVALID, 0, "nmp (Nbr Mgmt Protocol)"); 
                    libcli_register_param(&node_name,  &nmp);
                    {
                        static param_t nbrships;
                        init_param(&nbrships, CMD, "nbrships", nbrship_mgmt_handler, 0, INVALID, 0, "nbrships (Nbr Mgmt Protocol)");
                        libcli_register_param(&nmp, &nbrships);
                        set_param_cmd_code(&nbrships, CMDCODE_SHOW_NODE_NBRSHIP);
                    }
                    {
                        /*show node <node-name> nmp state*/
                        static param_t state;
                        init_param(&state, CMD, "state", nbrship_mgmt_handler, 0, INVALID, 0, "state (Nbr Mgmt Protocol)");
                        libcli_register_param(&nmp, &state);
                        set_param_cmd_code(&state, CMDCODE_SHOW_NODE_NMP_STATE);
                    }
                 }
                 {
                    /*show node <node-name> ddcp-db*/
                    static param_t ddcp_db;
                    init_param(&ddcp_db, CMD, "ddcp-db", ddcp_handler, 0, INVALID, 0, "Dump DDCP database");
                    libcli_register_param(&node_name, &ddcp_db);
                    set_param_cmd_code(&ddcp_db, CMDCODE_SHOW_DDCP_DB);
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
                        {
                            /*show node <node-name> interface statistics protocol*/
                            static param_t protocol;
                            init_param(&protocol, CMD, "protocol", 0, 0, INVALID, 0, "Protocol specific intf stats");
                            libcli_register_param(&stats, &protocol);
                            {
                                /*show node <node-name> interface statistics protocol <protocol-name>*/ 
                                static param_t nmp;
                                init_param(&nmp, CMD, "nmp", nbrship_mgmt_handler, 0, INVALID, 0, "nmp (Nbr Mgmt Protocol)"); 
                                libcli_register_param(&protocol, &nmp);
                                set_param_cmd_code(&nmp, CMDCODE_SHOW_NODE_NMP_PROTOCOL_ALL_INTF_STATS);
                            }
                        }
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
                /*run node <node-name> ddcp-query*/
                static param_t ddcp_query;
                init_param(&ddcp_query, CMD, "ddcp-query", ddcp_handler, 0, INVALID, 0, "Trigger DDCP Query Flood");
                libcli_register_param(&node_name, &ddcp_query);
                set_param_cmd_code(&ddcp_query, CMDCODE_RUN_DDCP_QUERY);
                {
                    static param_t periodic;
                    init_param(&periodic, CMD, "periodic", 0, 0, INVALID, 0, "Periodic ddcp Query");
                    libcli_register_param(&ddcp_query, &periodic);
                    {
                        static param_t ddcp_q_interval;
                        init_param(&ddcp_q_interval, LEAF, 0, ddcp_handler, ddcp_validate_query_interval, 
                            INT, "ddcp-q-interval", "ddcp query interval(min 1 sec)");
                        libcli_register_param(&periodic, &ddcp_q_interval);
                        set_param_cmd_code(&ddcp_q_interval, CMDCODE_RUN_DDCP_QUERY_PERIODIC);
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

            /*Nbrship Management CLIs will go here*/
            {
                /*config node <node-name> [no] protocol nmp*/
                static param_t protocol;
                init_param(&protocol, CMD, "protocol", 0, 0, INVALID, 0, "protocol");
                libcli_register_param(&node_name, &protocol);
                {
                    static param_t nmp;
                    init_param(&nmp, CMD, "nmp", nbrship_mgmt_handler, 0, INVALID, 0, "nmp (Nbr Mgmt Protocol)");
                    libcli_register_param(&protocol, &nmp);
                    set_param_cmd_code(&nmp, CMDCODE_CONF_NODE_NBRSHIP_ENABLE);
                }
            }
            {
                /*config node <node-name> [no] nbrship interface <intf-name>*/
                static param_t nbrship;
                init_param(&nbrship, CMD, "nmp", 0, 0, INVALID, 0, "nmp (Nbr Mgmt Protocol)");
                libcli_register_param(&node_name, &nbrship);
                {
                    static param_t interface;
                    init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "\"interface\" keyword");
                    libcli_register_display_callback(&interface, display_node_interfaces);
                    libcli_register_param(&nbrship, &interface);
                    {
                        static param_t if_name;
                        init_param(&if_name, LEAF, 0, nbrship_mgmt_handler, 0, STRING, "if-name", "Interface Name");
                        libcli_register_param(&interface, &if_name);
                        set_param_cmd_code(&if_name, CMDCODE_CONF_NODE_INTF_NBRSHIP_ENABLE);
                    }
                    {
                        static param_t all;
                        init_param(&all, CMD, "all", nbrship_mgmt_handler, 0, INVALID, 0, "All interfaces");
                        libcli_register_param(&interface, &all);
                        set_param_cmd_code(&all, CMDCODE_CONF_NODE_INTF_ALL_NBRSHIP_ENABLE);
                    }
                }
            }

            /*CLI for traceoptions at node level are hooked up here in tree */
            tcp_ip_traceoptions_cli(&node_name, 0);

            /*config node <node-name> interface*/
            static param_t interface;
            init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "\"interface\" keyword");
            libcli_register_display_callback(&interface, display_node_interfaces);
            libcli_register_param(&node_name, &interface);
            {
                /*config node <node-name> interface <if-name>*/
                static param_t if_name;
                init_param(&if_name, LEAF, 0, 0, 0, STRING, "if-name", "Interface Name");
                libcli_register_param(&interface, &if_name);
                {
                    /*CLI for traceoptions at interface level are hooked up here in tree */
                    tcp_ip_traceoptions_cli(0, &if_name);
                    {
                    #if 0
                        /*config node <node-name> interface <if-name> l2mode*/
                        static param_t l2_mode;
                        init_param(&l2_mode, CMD, "l2mode", 0, 0, INVALID, 0, "\"l2mode\" keyword");
                        libcli_register_param(&if_name, &l2_mode);
                        {
                            /*config node <node-name> interface <if-name> l2mode <access|trunk>*/
                            static param_t l2_mode_val;
                            init_param(&l2_mode_val, LEAF, 0, intf_config_handler, validate_l2_mode_value, STRING, "l2-mode-val", "access|trunk");
                            libcli_register_param(&l2_mode, &l2_mode_val);
                            set_param_cmd_code(&l2_mode_val, CMDCODE_INTF_CONFIG_L2_MODE);
                        }
                    #endif
                    }
                    {
                        /*config node <node-name> interface <if-name> <up|down>*/
                        static param_t if_up_down_status;
                        init_param(&if_up_down_status, LEAF, 0, intf_config_handler, validate_if_up_down_status, STRING, "if-up-down", "<up | down>");
                        libcli_register_param(&if_name, &if_up_down_status);
                        set_param_cmd_code(&if_up_down_status, CMDCODE_CONF_INTF_UP_DOWN);
                    }
                }
                {
                    static param_t metric;
                    init_param(&metric, CMD, "metric", 0, 0, INVALID, 0, "Interface Metric");
                    libcli_register_param(&if_name, &metric);
                    {
                        static param_t metric_val;
                        init_param(&metric_val, LEAF, 0, intf_config_handler, validate_interface_metric_val, INT, "metric-val", "Metric Value(1-16777215)");
                        libcli_register_param(&metric, &metric_val);
                        set_param_cmd_code(&metric_val, CMDCODE_INTF_CONFIG_METRIC);
                    }
                }
                {
                #if 0
                    /*config node <node-name> interface <if-name> vlan*/
                    static param_t vlan;
                    init_param(&vlan, CMD, "vlan", 0, 0, INVALID, 0, "\"vlan\" keyword");
                    libcli_register_param(&if_name, &vlan);
                    {
                        /*config node <node-name> interface <if-name> vlan <vlan-id>*/
                         static param_t vlan_id;
                         init_param(&vlan_id, LEAF, 0, intf_config_handler, validate_vlan_id, INT, "vlan-id", "vlan id(1-4096)");
                         libcli_register_param(&vlan, &vlan_id);
                         set_param_cmd_code(&vlan_id, CMDCODE_INTF_CONFIG_VLAN);
                    }
                #endif
                }    
            }
            support_cmd_negation(&interface); 
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
