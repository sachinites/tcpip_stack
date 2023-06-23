#include <stdio.h>
#include "../CommandParser/cmdtlv.h"
#include "../CommandParser/libcli.h"
#include "../cmdcodes.h"
#include "../utils.h"
#include "../tcpip_notif.h"
#include "../graph.h"
#include "InterfaceUApi.h"

extern graph_t *topo;
extern void gre_cli_config_tree (param_t *interface);
extern void tcp_ip_traceoptions_cli(
                                param_t *node_name_param, 
                                 param_t *intf_name_param);

extern int validate_mask_value(c_string mask_str);

static int
validate_vlan_id(c_string vlan_value){

    uint32_t vlan = atoi((const char *)vlan_value);
    if(!vlan){
        printf("Error : Invalid Vlan Value\n");
        return VALIDATION_FAILED;
    }
    if(vlan >= 1 && vlan <= 4095)
        return VALIDATION_SUCCESS;

    return VALIDATION_FAILED;
};

static int
validate_l2_mode_value(c_string l2_mode_value){

    if((string_compare(l2_mode_value, "access", strlen("access")) == 0) || 
        (string_compare(l2_mode_value, "trunk", strlen("trunk")) == 0))
        return VALIDATION_SUCCESS;
    return VALIDATION_FAILED;
}

static int
validate_interface_metric_val(c_string  value){

    uint32_t metric_val = atoi((const char *)value);
    if(metric_val > 0 && metric_val <= INTF_MAX_METRIC)
        return VALIDATION_SUCCESS;
    return VALIDATION_FAILED;
}

static int 
validate_if_up_down_status(c_string value){

    if(string_compare(value, "up", strlen("up")) == 0 ) {
        return VALIDATION_SUCCESS;
    }
    else if(string_compare(value, "down", strlen("down")) == 0) {
        return VALIDATION_SUCCESS;
    }
    return VALIDATION_FAILED;
}

/*Display Node Interfaces*/
void
display_node_interfaces(param_t *param, ser_buff_t *tlv_buf){

    node_t *node;
    c_string node_name = NULL;
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    
    int i = 0;
    Interface *intf;

    for(; i < MAX_INTF_PER_NODE; i++){

        intf = node->intf[i];
        if(!intf) continue;

        printf(" %s\n", intf->if_name.c_str());
    }
}


static int
intf_config_handler(param_t *param, ser_buff_t *tlv_buf, 
                    op_mode enable_or_disable){

   node_t *node;
   c_string intf_name = NULL;
   c_string node_name = NULL;
   uint32_t vlan_id;
   uint8_t mask;
   uint8_t lono;
   c_string l2_mode_option;
   c_string if_up_down;
   int CMDCODE;
   tlv_struct_t *tlv = NULL;
   c_string intf_ip_addr = NULL;
   Interface *interface = NULL;
   uint32_t intf_new_matric_val;
   intf_prop_changed_t intf_prop_changed;

   CMDCODE = EXTRACT_CMD_CODE(tlv_buf);
   
    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "if-name"))
            intf_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "vlan-id"))
            vlan_id = atoi((const char *)tlv->value);
        else if(parser_match_leaf_id(tlv->leaf_id, "l2-mode-val"))
            l2_mode_option = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "if-up-down"))
             if_up_down = tlv->value; 
        else if(parser_match_leaf_id(tlv->leaf_id, "metric-val"))
             intf_new_matric_val = atoi((const char *)tlv->value);      
        else if(parser_match_leaf_id(tlv->leaf_id, "intf-ip-address"))
             intf_ip_addr = tlv->value;     
        else if(parser_match_leaf_id(tlv->leaf_id, "mask"))
             mask = atoi((const char *)tlv->value);  
        else if(parser_match_leaf_id(tlv->leaf_id, "lono"))
             lono = atoi((const char *)tlv->value);  
        else if(parser_match_leaf_id(tlv->leaf_id, ""))
             lono = atoi((const char *)tlv->value);               
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    if (intf_name) {
        interface = node_get_intf_by_name(node, (const char *)intf_name);
    }

    switch (CMDCODE) {
        case CMDCODE_INTF_CONFIG_LOOPBACK:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    break;
                case CONFIG_DISABLE:
                    if (!interface) {
                        printf("Error : Interface do not exist\n");
                        return -1;
                    }
                    break;
                default:
                    break;
            }
        break;
        default:
            if (!interface) {
                printf("Error : Interface do not exist\n");
                return -1;
            }
            break;
    }

    uint32_t if_change_flags = 0;
    switch(CMDCODE){
        case CMDCODE_INTF_CONFIG_METRIC:
        {
            uint32_t intf_existing_metric = interface->GetIntfCost();

            if(intf_existing_metric != intf_new_matric_val){
                SET_BIT(if_change_flags, IF_METRIC_CHANGE_F); 
                intf_prop_changed.intf_metric = intf_existing_metric;
            }

            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    interface->cost = intf_new_matric_val;        
                break;
                case CONFIG_DISABLE:
                    interface->cost = INTF_METRIC_DEFAULT;
                break;
                default: ;
            }
            if(IS_BIT_SET(if_change_flags, IF_METRIC_CHANGE_F)){
				nfc_intf_invoke_notification_to_sbscribers(
					interface, &intf_prop_changed, if_change_flags);
            }
        }    
        break;
        case CMDCODE_CONF_INTF_UP_DOWN:
            if(string_compare(if_up_down, "up", strlen("up")) == 0){
                if(interface->is_up == false){
                    SET_BIT(if_change_flags, IF_UP_DOWN_CHANGE_F); 
                     intf_prop_changed.up_status = false;
                }
                interface->is_up = true;
            }
            else{
                if(interface->is_up){
                    SET_BIT(if_change_flags, IF_UP_DOWN_CHANGE_F);
                     intf_prop_changed.up_status = true;
                }
                interface->is_up = false;
            }
            if(IS_BIT_SET(if_change_flags, IF_UP_DOWN_CHANGE_F)){
				nfc_intf_invoke_notification_to_sbscribers(
					interface, &intf_prop_changed, if_change_flags);
            }
            break;
        case CMDCODE_INTF_CONFIG_L2_MODE:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    interface->SetSwitchport(true);
                    break;
                case CONFIG_DISABLE:
                    interface->SetSwitchport(false);
                    break;
                default:
                    ;
            }
            break;
        case CMDCODE_INTF_CONFIG_VLAN:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    interface->IntfConfigVlan(vlan_id, true);
                    break;
                case CONFIG_DISABLE:
                    interface->IntfConfigVlan(vlan_id, false);
                    break;
                default:
                    ;
            }
            break;
        case CMDCODE_INTF_CONFIG_IP_ADDR:
             switch(enable_or_disable){
                case CONFIG_ENABLE:
                    interface_set_ip_addr(node, interface, intf_ip_addr, mask);
                    break;
                case CONFIG_DISABLE:
                    interface_unset_ip_addr(node, interface);
                    break;
                default:
                    ;
            }
            break;
        case CMDCODE_INTF_CONFIG_LOOPBACK:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    break;
                case CONFIG_DISABLE:
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

void
Interface_config_cli_tree (param_t *root) {

            /*config node <node-name> interface*/
            static param_t interface;
            init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "\"interface\" keyword");
            libcli_register_display_callback(&interface, display_node_interfaces);
            libcli_register_param(root, &interface);
            {
                /* CLI for GRE Tunneling are mounted here*/
                gre_cli_config_tree(&interface);
            }

            {
                /*config node <node-name> interface <if-name>*/
                static param_t if_name;
                init_param(&if_name, LEAF, 0, 0, 0, STRING, "if-name", "Interface Name");
                libcli_register_param(&interface, &if_name);
	
                {
                    /*CLI for traceoptions at interface level are hooked up here in tree */
                    tcp_ip_traceoptions_cli (0, &if_name);
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
                            libcli_set_param_cmd_code(&l2_mode_val, CMDCODE_INTF_CONFIG_L2_MODE);
                        }
                    #endif
                    }
                    {
                        /*config node <node-name> interface <if-name> <up|down>*/
                        static param_t if_up_down_status;
                        init_param(&if_up_down_status, LEAF, 0, intf_config_handler, validate_if_up_down_status, STRING, "if-up-down", "<up | down>");
                        libcli_register_param(&if_name, &if_up_down_status);
                        libcli_set_param_cmd_code(&if_up_down_status, CMDCODE_CONF_INTF_UP_DOWN);
                    }
                }
                {
                    static param_t loopback;
                    init_param(&loopback, CMD, "loopback", 0, 0, INVALID, 0, "loopback");
                    libcli_register_param(&interface, &loopback);
                    {
                        static param_t lono;
                        init_param(&lono, LEAF, 0, intf_config_handler, NULL, INT, "lono", "Loopback ID");
                        libcli_register_param(&loopback, &lono);
                        libcli_set_param_cmd_code(&lono, CMDCODE_INTF_CONFIG_LOOPBACK);
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
                        libcli_set_param_cmd_code(&metric_val, CMDCODE_INTF_CONFIG_METRIC);
                    }
                }
                {
                    /* config node <node-name> ineterface <if-name> ip-address <ip-addr> <mask>*/
                    static param_t ip_addr;
                    init_param(&ip_addr, CMD, "ip-address", 0, 0, INVALID, 0, "Interface IP Address");
                    libcli_register_param(&if_name, &ip_addr);
                    {
                        static param_t ip_addr_val;
                        init_param(&ip_addr_val, LEAF, 0, 0, 0, IPV4, "intf-ip-address", "IPV4 address");
                        libcli_register_param(&ip_addr, &ip_addr_val);
                        {
                            static param_t mask;
                            init_param(&mask, LEAF, 0, intf_config_handler, validate_mask_value, INT, "mask", "mask [0-32]");
                            libcli_register_param(&ip_addr_val, &mask);
                            libcli_set_param_cmd_code(&mask, CMDCODE_INTF_CONFIG_IP_ADDR);
                        }
                    }
                }
                {
                    /*config node <node-name> interface <if-name> vlan*/
                    static param_t vlan;
                    init_param(&vlan, CMD, "vlan", 0, 0, INVALID, 0, "\"vlan\" keyword");
                    libcli_register_param(&if_name, &vlan);
                    {
                        /*config node <node-name> interface <if-name> vlan <vlan-id>*/
                         static param_t vlan_id;
                         init_param(&vlan_id, LEAF, 0, intf_config_handler, validate_vlan_id, INT, "vlan-id", "vlan id(1-4096)");
                         libcli_register_param(&vlan, &vlan_id);
                         libcli_set_param_cmd_code(&vlan_id, CMDCODE_INTF_CONFIG_VLAN);
                    }
                }    
            }
            libcli_support_cmd_negation(&interface); 
}

