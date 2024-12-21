#include <stdio.h>
#include "../CLIBuilder/cmdtlv.h"
#include "../CLIBuilder/libcli.h"
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
extern void 
config_interface_build_transport_svc_cli_tree (
    param_t *node_name_param,
    param_t *param);

extern int validate_mask_value(Stack_t *tlv_stack, c_string mask_str);

void
Interface_config_cli_common_subtree (param_t *if_name, uint64_t unsupported_configs);

static int
validate_vlan_id(Stack_t *tlv_stack, c_string vlan_value){

    uint32_t vlan = atoi((const char *)vlan_value);
    if(!vlan){
        cprintf("Error : Invalid Vlan Value\n");
        return LEAF_VALIDATION_FAILED;
    }
    if(vlan >= 1 && vlan <= 4095)
        return LEAF_VALIDATION_SUCCESS;

    return LEAF_VALIDATION_FAILED;
};

static int
validate_l2_mode_value(Stack_t *tlv_stack, c_string l2_mode_value){

    if((string_compare(l2_mode_value, "access", strlen("access")) == 0) || 
        (string_compare(l2_mode_value, "trunk", strlen("trunk")) == 0))
        return LEAF_VALIDATION_SUCCESS;
    return LEAF_VALIDATION_FAILED;
}

static int
validate_interface_metric_val(Stack_t *tlv_stack, c_string  value){

    uint32_t metric_val = atoi((const char *)value);
    if(metric_val > 0 && metric_val <= INTF_MAX_METRIC)
        return LEAF_VALIDATION_SUCCESS;
    return LEAF_VALIDATION_FAILED;
}

static int 
validate_if_up_down_status(Stack_t *tlv_stack, c_string value){

    if(string_compare(value, "up", strlen("up")) == 0 ) {
        return LEAF_VALIDATION_SUCCESS;
    }
    else if(string_compare(value, "down", strlen("down")) == 0) {
        return LEAF_VALIDATION_SUCCESS;
    }
    return LEAF_VALIDATION_FAILED;
}

/*Display Node Interfaces*/
void
display_node_interfaces (param_t *param, Stack_t *tlv_stack){

    node_t *node;
    c_string node_name = NULL;
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    }TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    
    Interface *intf;

     ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        printw (" %s\n", intf->if_name.c_str());

    }  ITERATE_NODE_INTERFACES_END(node, intf);
}

static Interface *
node_lookup_interface(node_t *node, c_string intf_name, vlan_id_t vlan_id){

    if (intf_name) {
        return node_get_intf_by_name (node, (const char *)intf_name);
    }

    if (vlan_id) {
        return (VlanInterface::VlanInterfaceLookUp(node, vlan_id));
    }

    return NULL;
}


static int
intf_config_handler(int cmdcode, Stack_t *tlv_stack,
                    op_mode enable_or_disable){

   node_t *node;
   vlan_id_t vlan_id;
   uint8_t mask;
   uint8_t lono;
   c_string l2_mode_option;
   c_string if_up_down;
   tlv_struct_t *tlv = NULL;
   c_string intf_name = NULL;
   c_string node_name = NULL;
   c_string intf_ip_addr = NULL;
   Interface *interface = NULL;
   uint32_t intf_new_matric_val;
   c_string overlay_tunnel_name = NULL;
   intf_prop_changed_t intf_prop_changed;
   
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

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
        else if(parser_match_leaf_id(tlv->leaf_id, "tunnel-name"))
             overlay_tunnel_name = tlv->value;     

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    uint32_t if_change_flags = 0;
    uint32_t minor_code = 0;
    ipc_interface_t *update_data;

    switch(cmdcode){

        case CMDCODE_INTF_CONFIG_METRIC:
        {
            interface = node_lookup_interface (node, intf_name, vlan_id ) ;

            if (!interface) {
                cprintf ("Error : Interface do not exist\n");
                return -1;
            }
            
            update_data = new ipc_interface_t;
            update_data->intf = interface->GetSharedPtr();

            uint32_t intf_existing_metric = interface->GetIntfCost();

            if(intf_existing_metric == intf_new_matric_val) break;

            SET_BIT(minor_code, IPC_INTERFACE_METRIC_UPDATE);
            update_data = new ipc_interface_t;
            update_data->intf = interface->GetSharedPtr();
            update_data->metric = intf_existing_metric;

            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    interface->cost = intf_new_matric_val;        
                break;
                case CONFIG_DISABLE:
                    interface->cost = INTF_METRIC_DEFAULT;
                break;
                default: ;
            }
            cp_ipc_send (node, IPC_INTERFACE, minor_code, 
                    update_data, sizeof (*update_data), true);
        }    
        break;

        case CMDCODE_CONF_INTF_UP_DOWN:
        {
            interface = node_lookup_interface (node, intf_name, vlan_id ) ;
            
            if (!interface) {
                cprintf ("Error : Interface do not exist\n");
                return -1;
            }

            if (string_compare(if_up_down, "up", strlen("up")) == 0){
                if(interface->is_up == false){
                    update_data = new ipc_interface_t;
                    update_data->intf = interface->GetSharedPtr();
                    SET_BIT(minor_code, IPC_INTERFACE_ADMIN_STATE_UP); 
                     update_data->up_status = false;
                }
                interface->is_up = true;
            }
            else{
                if (interface->is_up){
                    update_data = new ipc_interface_t;
                    SET_BIT(minor_code, IPC_INTERFACE_ADMIN_STATE_DOWN); 
                     update_data->up_status = true;
                     update_data->intf = interface->GetSharedPtr();
                }
                interface->is_up = false;
            }

            if (minor_code) {
                cp_ipc_send (node, IPC_INTERFACE, minor_code, 
                    update_data, sizeof (*update_data), true);
            }
        }
        break;

        case CMDCODE_INTF_CONFIG_SWITCHPORT:
        {
            interface = node_lookup_interface (node, intf_name, vlan_id ) ;
            
            if (!interface) {
                cprintf ("Error : Interface do not exist\n");
                return -1;
            }   

            bool old_switchport_status = interface->GetSwitchport();

            switch (enable_or_disable)
            {
                case CONFIG_ENABLE:
                    interface->SetSwitchport(true);
                    break;
                case CONFIG_DISABLE:
                    interface->SetSwitchport(false);
                    break;
                default:;
            }

            if (old_switchport_status != interface->GetSwitchport())
            {
                SET_BIT(minor_code, IPC_INTERFACE_SWITCHPORT_UPDATE);
                update_data = new ipc_interface_t;;
                update_data->intf = interface->GetSharedPtr();
                update_data->is_switchport = old_switchport_status;
                cp_ipc_send (node, IPC_INTERFACE, minor_code, 
                    update_data, sizeof (*update_data), true);
            }
        }
        break;


        case CMDCODE_INTF_CONFIG_VLAN:
        {
            interface = node_lookup_interface (node, intf_name, vlan_id ) ;
            
            if (!interface) {
                cprintf ("Error : Interface do not exist\n");
                return -1;
            }   

            vlan_id_t old_access_vlan = interface->GetVlanId();

            switch(enable_or_disable) {

                case CONFIG_ENABLE:
                    if (!interface->IntfConfigVlan(vlan_id, true) ) return -1;
                    break;
                case CONFIG_DISABLE:
                    if (!interface->IntfConfigVlan(vlan_id, false) ) return -1;
                    break;
                default:
                    ;
            }

            if (intf_prop_changed.access_vlan  !=
                     interface->GetVlanId()) {
                
                SET_BIT(minor_code, IPC_INTERFACE_ACCESS_VLAN_UPDATE);
                update_data = new ipc_interface_t;;
                update_data->intf = interface->GetSharedPtr();
                update_data->access_vlan = old_access_vlan;
                cp_ipc_send (node, IPC_INTERFACE, minor_code, 
                    update_data, sizeof (*update_data), true);
            }
        }
        break;


        case CMDCODE_INTF_CONFIG_IP_ADDR:
        {
            interface = node_lookup_interface (node, intf_name, vlan_id ) ;
            
            if (!interface) {
                cprintf ("Error : Interface do not exist\n");
                return -1;
            }       

            uint32_t old_ip_addr; 
            uint8_t old_mask;

            interface->InterfaceGetIpAddressMask (&old_ip_addr, &old_mask);

             switch(enable_or_disable){
                case CONFIG_ENABLE:
                    interface_set_ip_addr(node, interface, intf_ip_addr, mask);
                    break;
                case CONFIG_DISABLE:
                    interface_unset_ip_addr(node, interface, intf_ip_addr, mask);
                    break;
                default:
                    ;
            }

            uint32_t new_ip_addr;
            uint8_t new_mask;
            interface->InterfaceGetIpAddressMask (&new_ip_addr, &new_mask);

            if (old_ip_addr == 0 && old_mask == 0 && 
                    interface->IsIpConfigured()) {

                SET_BIT (minor_code, IPC_INTERFACE_IPV4_ADDR_ADD);
            }
            else if ((old_ip_addr || mask ) && !interface->IsIpConfigured()) {

                SET_BIT (minor_code, IPC_INTERFACE_IPV4_ADDR_DEL);
            }
            else {

                SET_BIT (minor_code, IPC_INTERFACE_IPV4_ADDR_UPDATE);
            }

            if (minor_code) {
                update_data = new ipc_interface_t;
                update_data->intf = interface->GetSharedPtr();
                update_data->ipv4_addr.ip_addr = old_ip_addr;
                update_data->ipv4_addr.mask = old_mask;
                cp_ipc_send (node, IPC_INTERFACE, minor_code, 
                        update_data, sizeof (*update_data), true);            
            }
        }
        break;


        case CMDCODE_INTF_CONFIG_LOOPBACK_CREATE:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    break;
                case CONFIG_DISABLE:
                    break;
                default:
                    ;
            }
        break;
     

        case CMDCODE_CONFIG_INTF_VLAN_CREATE:
            switch (enable_or_disable)
            {
            case CONFIG_ENABLE:
            {
                VlanInterface *vlan_intf =
                    static_cast<VlanInterface *>(VlanInterface::VlanInterfaceLookUp(node, vlan_id));
                if (vlan_intf)
                    return 0;
                VlanInterfaceP vlan_intfP = std::make_shared<VlanInterface>(vlan_id);
		vlan_intfP->SetSharedPtr(vlan_intfP);
                vlan_intfP->att_node = node;
                if (!node->vlan_intf_db) {
                    node->vlan_intf_db = new std::unordered_map<uint16_t, VlanInterfaceP>;
                }
                node->vlan_intf_db->insert(std::make_pair(vlan_id, vlan_intfP));
            }
            break;
            case CONFIG_DISABLE:
            {
                VlanInterface *vlan_intf =
                    static_cast<VlanInterface *>(VlanInterface::VlanInterfaceLookUp(node, vlan_id));
                if (!vlan_intf)
                    return 0;
                
                if (vlan_intf->IsCrossReferenced()) {
                    cprintf("Error : Vlan is in use\n");
                    return -1;
                }

                /* Interface us being dynamically used by some entities, send Delete notification */
                SET_BIT(if_change_flags, IF_DELETE_F);
                nfc_intf_invoke_notification_to_sbscribers(
					vlan_intf, &intf_prop_changed, if_change_flags);
                node->vlan_intf_db->erase(vlan_id);
            }
            break;
            default:;
            }
            break;


        case CMDCODE_CONFIG_INTF_VLAN_IP_ADDR:
            switch (enable_or_disable)
            {
            case CONFIG_ENABLE:
            {
                VlanInterface *vlan_intf =
                    static_cast<VlanInterface *>(node_lookup_interface (node, intf_name, vlan_id ));

                if (!vlan_intf)
                {
                    cprintf("Error : Vlan Interface not created\n");
                    return -1;
                }
                vlan_intf->InterfaceSetIpAddressMask(tcp_ip_convert_ip_p_to_n(intf_ip_addr), mask);
            }
            break;
            case CONFIG_DISABLE:
            {
                VlanInterface *vlan_intf =
                    static_cast<VlanInterface *>(node_lookup_interface (node, intf_name, vlan_id ));
                if (!vlan_intf)
                {
                    cprintf("Error : Vlan Interface not created\n");
                    return -1;
                }
                vlan_intf->InterfaceSetIpAddressMask(0, 0);
            }
            break;
            default:;
            }
            break;
        case CMDCODE_CONFIG_INTF_VLAN_UP_DOWN:
            switch (enable_or_disable)
            {
            case CONFIG_ENABLE:
            {
                VlanInterface *vlan_intf =
                    static_cast<VlanInterface *>(node_lookup_interface (node, intf_name, vlan_id ));
                if (!vlan_intf)
                {
                    cprintf("Error : Vlan Interface not created\n");
                    return -1;
                }
                vlan_intf->is_up = true;
            }
            break;
            case CONFIG_DISABLE:
            {
                VlanInterface *vlan_intf =
                    static_cast<VlanInterface *>(node_lookup_interface (node, intf_name, vlan_id ));
                if (!vlan_intf)
                {
                    cprintf("Error : Vlan Interface not created\n");
                    return -1;
                }
                vlan_intf->is_up = false;
            }
            break;
            default:;
            }
            break;

        case CMDCODE_INTF_CONFIG_BIND_OVERLAY_TUNNEL:
        {
            VirtualPort *vport_intf = reinterpret_cast<VirtualPort *>(
                node_get_intf_by_name(node, (const char *)intf_name));

            if (!vport_intf)
            {
                cprintf("Error : Virtual Port do not exist\n");
                return -1;
            }

            Interface *tunnel = node_get_intf_by_name(node, (const char *)overlay_tunnel_name);

            if (!tunnel)
            {
                cprintf("Error : Overlay Tunnel Interface do not exist\n");
                return -1;
            }

            if (enable_or_disable == CONFIG_ENABLE)
            {
                vport_intf->BindOverlayTunnel(tunnel);
            }
            else
            {
                vport_intf->UnBindOverlayTunnel(tunnel);
            }
        }
        break;
        default:;
        }
        return 0;
}


static int
intf_config_virtual_port_create_handler ( int cmdcode, 
                                                                    Stack_t *tlv_stack,
                                                                    op_mode enable_or_disable){

    node_t *node;
    tlv_struct_t *tlv = NULL;
    uint32_t if_change_flags = 0;
    c_string intf_name = NULL;
    c_string node_name = NULL;
    Interface *intf;
    intf_prop_changed_t intf_prop_changed;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "if-name"))
            intf_name = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (enable_or_disable) {

        case CONFIG_ENABLE:
        {
            intf = node_get_intf_by_name(node, (const char *)intf_name);
            
            if (intf) return 0;

            VirtualPortP vportP = std::make_shared<VirtualPort>(std::string((char *)intf_name));
            vportP->SetSharedPtr(vportP);
            intf = vportP.get();
            intf->att_node = node;

            int ifslot = node_get_intf_available_slot(node);
            if (ifslot < 0)
            {
                cprintf ("Error : Interface slot not available\n");
                intf->InterfaceReleaseAllResources();
                return -1;
            }

            node->intf[ifslot] = vportP;
            SET_BIT(if_change_flags, IF_CREATE_F);
            nfc_intf_invoke_notification_to_sbscribers(
                intf, &intf_prop_changed, if_change_flags);
        }
        break;
        case CONFIG_DISABLE:
        { 
            int i = 0;
            Interface *intf2;
            intf = node_get_intf_by_name(node, (const char *)intf_name);

            if (!intf)
            {
                cprintf("Error : Virtual Port do not exist\n");
                return -1;
            }

            if (intf->IsCrossReferenced())
            {
                cprintf("Error : Virtual Port is in use\n");
                return -1;
            }

             ITERATE_NODE_INTERFACES_BEGIN(node, intf2) 
            {
                i++;
                if (intf != intf2) continue;
                break;
            } ITERATE_NODE_INTERFACES_END(node, intf2);

            /* Interface us being dynamically used by some entities, send Delete notification */
            SET_BIT(if_change_flags, IF_DELETE_F);
            nfc_intf_invoke_notification_to_sbscribers(
                intf, &intf_prop_changed, if_change_flags);
            node->intf[i] = nullptr;
        }
        break;
    }

    return 0;
}

void
Interface_config_cli_common_subtree (param_t *if_name, uint64_t unsupported_configs)
{

    {
        /* config node <node-name> interface . . . <if-name> */
        if (!(unsupported_configs & INTF_CONFIG_NOT_SUPPORTED_TRACEOPTIONS))
        {
            tcp_ip_traceoptions_cli(0, if_name);
        }

        /* config node <node-name> interface . . . <if-name> */
        if (!(unsupported_configs & INTF_CONFIG_NOT_SUPPORTED_TSP))
        {
            config_interface_build_transport_svc_cli_tree(0, if_name);
        }

        /* config node <node-name> interface . . . <if-name> . . .*/
        if (!(unsupported_configs & INTF_CONFIG_NOT_SUPPORTED_SWITCHPORT))
        {
            /*config node <node-name> interface <if-name> switchport */
            static param_t switchport;
            init_param(&switchport, CMD, "switchport", intf_config_handler, 0, INVALID, 0, "\"switchport\" keyword");
            libcli_register_param(if_name, &switchport);
            libcli_set_param_cmd_code(&switchport, CMDCODE_INTF_CONFIG_SWITCHPORT);
            {
                /* config node <node-name> interface . . . <if-name> switchport access ...*/
                static param_t access;
                init_param(&access, CMD, "access", intf_config_handler, 0, INVALID, 0, "\"switchport\" keyword");
                libcli_register_param(&switchport, &access);
                {
                    /* config node <node-name> interface . . . <if-name> switchport access vlan <vlan-id>*/
                    static param_t vlan;
                    init_param(&vlan, CMD, "vlan", 0, 0, INVALID, 0, "vlan keyword");
                    libcli_register_param(&access, &vlan);
                    {
                        /*config node <node-name> interface . . . <if-name> switchport access vlan <vlan-id>*/
                        static param_t vlan_id;
                        init_param(&vlan_id, LEAF, 0, intf_config_handler, validate_vlan_id, INT, "vlan-id", "vlan id(1-4095)");
                        libcli_register_param(&vlan, &vlan_id);
                        libcli_set_param_cmd_code(&vlan_id, CMDCODE_INTF_CONFIG_VLAN);
                        libcli_set_tail_config_batch_processing(&vlan_id);
                    }
                }
            }
        }

         if (!(unsupported_configs & INTF_CONFIG_NOT_SUPPORTED_UP_DOWN))
        {
            /* config node <node-name> interface . . . <if-name>  <up|down>*/
            static param_t if_up_down_status;
            init_param(&if_up_down_status, LEAF, 0, intf_config_handler, validate_if_up_down_status, STRING, "if-up-down", "<up | down>");
            libcli_register_param(if_name, &if_up_down_status);
            libcli_set_param_cmd_code(&if_up_down_status, CMDCODE_CONF_INTF_UP_DOWN);
        }

        if (!(unsupported_configs & INTF_CONFIG_NOT_SUPPORTED_METRIC))
        {
            /*config node <node-name> interface . . . <if-name> metric <metric-val> */
            static param_t metric;
            init_param(&metric, CMD, "metric", 0, 0, INVALID, 0, "Interface Metric");
            libcli_register_param(if_name, &metric);
            {
                static param_t metric_val;
                init_param(&metric_val, LEAF, 0, intf_config_handler, validate_interface_metric_val, INT, "metric-val", "Metric Value(1-16777215)");
                libcli_register_param(&metric, &metric_val);
                libcli_set_param_cmd_code(&metric_val, CMDCODE_INTF_CONFIG_METRIC);
            }
        }

        if (!(unsupported_configs & INTF_CONFIG_NOT_SUPPORTED_IP_ADDRESS))
        {
            /* config node <node-name> interface . . . <if-name> ip-address <ip-addr> <mask>*/
            static param_t ip_addr;
            init_param(&ip_addr, CMD, "ip-address", 0, 0, INVALID, 0, "Interface IP Address");
            libcli_register_param(if_name, &ip_addr);
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

        if (!(unsupported_configs & INTF_CONFIG_NOT_SUPPORTED_VLAN))
        {
            /*config node <node-name> interface . . . <if-name> vlan . . .*/
            static param_t vlan;
            init_param(&vlan, CMD, "vlan", 0, 0, INVALID, 0, "\"vlan\" keyword");
            libcli_register_param(if_name, &vlan);
            {
                /*config node <node-name> interface . . . <if-name> vlan <vlan-id>*/
                static param_t vlan_id;
                init_param(&vlan_id, LEAF, 0, intf_config_handler, validate_vlan_id, INT, "vlan-id", "vlan id(1-4096)");
                libcli_register_param(&vlan, &vlan_id);
                libcli_set_param_cmd_code(&vlan_id, CMDCODE_INTF_CONFIG_VLAN);
            }
        }

        if (!(unsupported_configs & INTF_CONFIG_NOT_SUPPORTED_OVERLAY_TUNNEL))
        {
            /*config node <node-name> interface virtual-port <if-name> overlay-tunnel . . .*/
            static param_t overlay_tunnel;
            init_param(&overlay_tunnel, CMD, "overlay-tunnel", 0, 0, INVALID, 0, "overlay-tunnel keyword");
            libcli_register_param(if_name, &overlay_tunnel);
            {
                /*config node <node-name> interface virtual-port <if-name> overlay-tunnel <tunnel-name>*/
                static param_t tunnel_name;
                init_param(&tunnel_name, LEAF, 0, intf_config_handler, 0, STRING, "tunnel-name", "Tunnel Name");
                libcli_register_param(&overlay_tunnel, &tunnel_name);
                libcli_set_param_cmd_code(&tunnel_name, CMDCODE_INTF_CONFIG_BIND_OVERLAY_TUNNEL);
            }
        }


    }
}

static void
vlan_cli_config_tree(param_t *root)
{
        /*config node <node-name> interface vlan*/
        static param_t vlan;
        init_param(&vlan, CMD, "vlan", 0, 0, INVALID, 0, "\"vlan\" keyword");
        libcli_register_param(root, &vlan);
        {
            /*config node <node-name> interface <if-name> vlan <vlan-id>*/
            static param_t vlan_id;
            init_param(&vlan_id, LEAF, 0, intf_config_handler, validate_vlan_id, INT, "vlan-id", "vlan id(1-4096)");
            libcli_register_param(&vlan, &vlan_id);
            libcli_set_param_cmd_code(&vlan_id, CMDCODE_CONFIG_INTF_VLAN_CREATE);

             uint64_t unsupported_configs = ~0;
             unsupported_configs &= ~INTF_CONFIG_NOT_SUPPORTED_IP_ADDRESS;
             unsupported_configs &= ~INTF_CONFIG_NOT_SUPPORTED_UP_DOWN;
             unsupported_configs &= ~INTF_CONFIG_NOT_SUPPORTED_TRACEOPTIONS;
             Interface_config_cli_common_subtree(&vlan_id, unsupported_configs);
        }
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
                /* CLI for vlan Interfaces are mounted here*/
                vlan_cli_config_tree(&interface);
            }

            {
                static param_t loopback;
                init_param(&loopback, CMD, "loopback", 0, 0, INVALID, 0, "loopback");
                libcli_register_param(&interface, &loopback);
                {
                    static param_t lono;
                    init_param(&lono, LEAF, 0, intf_config_handler, NULL, INT, "lono", "Loopback ID");
                    libcli_register_param(&loopback, &lono);
                    libcli_set_param_cmd_code(&lono, CMDCODE_INTF_CONFIG_LOOPBACK_CREATE);
                }
            }

            {
                 /*config node <node-name> interface virtual-port <vp-name> */
                static param_t vp;
                init_param(&vp, CMD, "virtual-port", 0, 0, INVALID, 0, "virtual-port keyword");
                libcli_register_param(&interface, &vp);
                {
                    /*config node <node-name> interface virtual-port <vp-name> */
                    static param_t vp_name;
                    init_param(&vp_name, LEAF, 0, intf_config_virtual_port_create_handler, 0, STRING, "if-name", "Virtual Port Name");
                    libcli_register_param(&vp, &vp_name);
                    libcli_set_param_cmd_code(&vp_name, CMDCODE_INTF_CONFIG_VP_CREATE);
                    uint64_t unsupported_configs = 0;
                    unsupported_configs |= INTF_CONFIG_NOT_SUPPORTED_METRIC;
                    unsupported_configs |= INTF_CONFIG_NOT_SUPPORTED_IP_ADDRESS;
                    Interface_config_cli_common_subtree (&vp_name, unsupported_configs);
                }
            }

            {
                /*config node <node-name> interface ethernet ... */
                static param_t ethernet;
                init_param(&ethernet, CMD, "ethernet", 0, 0, INVALID, 0, "ethernet keyword");
                libcli_register_param(&interface, &ethernet);
                {
                    /*config node <node-name> interface ethernet <if-name>*/
                    static param_t if_name;
                    init_param(&if_name, LEAF, 0, 0, 0, STRING, "if-name", "Interface Name");
                    libcli_register_param(&ethernet, &if_name);
                    uint64_t unsupported_configs = 0;
                    unsupported_configs |= INTF_CONFIG_NOT_SUPPORTED_OVERLAY_TUNNEL;
                    Interface_config_cli_common_subtree (&if_name, unsupported_configs);
                }
            }
            libcli_support_cmd_negation(&interface); 
}

