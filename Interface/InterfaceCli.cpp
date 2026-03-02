#include <stdio.h>
#include "../CLIBuilder/cmdtlv.h"
#include "../CLIBuilder/libcli.h"
#include "../cmdcodes.h"
#include "../utils.h"
#include "../tcpip_notif.h"
#include "../router_init.h"
#include "InterfaceUApi.h"
#include "../dpal/cp2dp.h"
#include "../Layer2/vxlan/cp/vxlan.h"
#include "../datapath/Layer2/switching/mac_table.h"
#include "../RTM/rtm_nb_integ.h"
#include "../datapath/Interface/dp_intf.h"
#include "../datapath/dp-program/dp-prog-intf-struct.h"

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

static int
validate_vni_id(Stack_t *tlv_stack, c_string vni_value){

    uint32_t vni = atoi((const char *)vni_value);
    if(!vni){
        cprintf("Error : Invalid VNI Value\n");
        return LEAF_VALIDATION_FAILED;
    }
    if(vni >= 1 && vni <= 16777215)  /* VNI range: 1 to 2^24-1 */
        return LEAF_VALIDATION_SUCCESS;

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
        return node_interface_lookup_by_name (node, (const char *)intf_name);
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
   int gre_tunnel_id = 0;
   c_string l2_mode_option;
   c_string if_up_down;
   tlv_struct_t *tlv = NULL;
   c_string if_name = NULL;
   c_string node_name = NULL;
   c_string intf_ip_addr = NULL;
   Interface *interface = NULL;
   uint32_t intf_new_matric_val;
   c_string overlay_tunnel_name = NULL;
   c_string vni_value = NULL;
   c_string vrf_name = (c_string)DEF_VRF_NAME;
   intf_prop_changed_t intf_prop_changed;
   
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if     (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "if-name"))
            if_name = tlv->value;
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
        else if(parser_match_leaf_id(tlv->leaf_id, "intf-ipv6-address"))
             intf_ip_addr = tlv->value;     
        else if(parser_match_leaf_id(tlv->leaf_id, "tunnel-name"))
             overlay_tunnel_name = tlv->value;     
        else if(parser_match_leaf_id(tlv->leaf_id, "vni-id"))
             vni_value = tlv->value;     
        else if(parser_match_leaf_id(tlv->leaf_id, "vrf-name"))
             vrf_name = tlv->value;  
        else if(parser_match_leaf_id(tlv->leaf_id, "tunnel-id"))
             gre_tunnel_id = atoi((const char *)tlv->value);               
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    uint32_t if_change_flags = 0;
    uint32_t minor_code = 0;
    ipc_interface_t *update_data;

    vrf_t *vrf = vrf_get_by_name(node, (char *)vrf_name);
    vrf_t *def_vrf = NODE_DEF_VRF(node);
    char intf_name[IF_NAME_SIZE];

    if (!if_name && gre_tunnel_id) {
        snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", gre_tunnel_id);
        if_name = (c_string)intf_name;
    }

    switch(cmdcode){

        case CMDCODE_CONF_INTF_VRF:
        {
            switch(enable_or_disable) {

                case CONFIG_ENABLE:
                {
                    if (!vrf)
                    {
                        cprintf("%s : Error : VRF %s do not exist\nConfiguration Checkout failed\n",
                                node->node_name, vrf_name);
                        return -1;
                    }

                    interface = node_lookup_interface(node, if_name, 0);

                    if (!interface) {
                        cprintf ("Error : Interface do not exist\nConfiguration Checkout failed\n");
                        return -1;
                    }

                    /* Interface already in asked VRF, no op*/
                    if (interface->vrf == vrf) return 0;

                    if (interface->vrf) {
                         cprintf ("Error : Interface already configured in VRF %s\nConfiguration Checkout failed\n", 
                            interface->vrf->vrf_name); 
                        return -1;
                    }

                    /* Interface is in default vrf , check for L3 config now*/
                    if (interface->HasL3Config(true)) {
                         cprintf ("Error : Remove L3 config first from Interface\nConfiguration Checkout failed\n" );
                         return -1;
                    }
                    
                    if (!vrf_add_interface(vrf, interface)) {
                        cprintf ("Error : Failed to add interface in VRF %s\nConfiguration Checkout failed\n", vrf->vrf_name);
                        return -1;
                    }
                }
                break;
                case CONFIG_DISABLE:
                {
                    interface = node_lookup_interface(node, if_name, 0);

                    if (!interface) {
                        cprintf ("Error : Interface do not exist\nConfiguration Checkout failed\n");
                        return -1;
                    }
                    
                    if (!vrf)
                    {
                        cprintf("%s : Error : VRF %s do not exist\nConfiguration Checkout failed\n",
                                node->node_name, vrf_name);
                        return -1;
                    }

                    if (interface->vrf == NULL) {
                        return 0;
                    }

                    if (interface->vrf != vrf) {
                        cprintf ("Error : Interface is not operating in VRF %s\nConfiguration Checkout failed\n", vrf->vrf_name);
                        return -1;
                    }

                    if (!vrf_del_interface(vrf, interface)) {
                        cprintf ("Error : Configuration Checkout failed\n");
                        return -1;
                    }
                }
                break;
            }
        }
        break;
        case CMDCODE_INTF_CONFIG_METRIC:
        {
            interface = node_lookup_interface (node, if_name, vlan_id ) ;

            if (!interface) {
                cprintf ("Error : Interface do not exist\n");
                return -1;
            }

            uint32_t intf_existing_metric = interface->GetIntfCost();
            if (intf_existing_metric == intf_new_matric_val) break;
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
            cp_ips_send (node, IPC_INTERFACE, minor_code, 
                    update_data, sizeof (*update_data), true,  ips_free_ipc_interface_cbk);
        }    
        break;

        case CMDCODE_CONF_INTF_UP_DOWN:
        {
            interface = node_lookup_interface (node, if_name, vlan_id ) ;
            
            if (!interface) {
                cprintf ("Error : Interface do not exist\n");
                return -1;
            }

            if (string_compare(if_up_down, "up", strlen("up")) == 0){

                if (interface->is_up == true) return 0;

                if(interface->is_up == false){
                    update_data = new ipc_interface_t;
                    update_data->intf = interface->GetSharedPtr();
                    SET_BIT(minor_code, IPC_INTERFACE_ADMIN_STATE_UP); 
                     update_data->up_status = false;
                     cp2dp_send_intf_admin_status_update(node, interface->ifindex, false);
                }
                interface->is_up = true;
            }
            else{
                
                if (interface->is_up == false) return 0;

                if (interface->is_up){
                    update_data = new ipc_interface_t;
                    SET_BIT(minor_code, IPC_INTERFACE_ADMIN_STATE_DOWN); 
                     update_data->up_status = true;
                     update_data->intf = interface->GetSharedPtr();
                     cp2dp_send_intf_admin_status_update(node, interface->ifindex, true);
                }
                interface->is_up = false;
            }

            uint32_t intf_ip_addr = 0;
            uint8_t mask = 0;

            interface->InterfaceGetIpAddressMask(&intf_ip_addr, &mask);

            /* Install local routes in RIB if interface goes up */
            if (interface->is_up && interface->IsIpConfigured()) {
                interface_install_local_v4_routes  (node, interface);
                interface_install_local_v6_routes  (node, interface);
            }
            else if (!interface->is_up && interface->IsIpConfigured()) {
                interface_uninstall_local_v4_routes  (node, interface);
                interface_uninstall_local_v6_routes  (node, interface);
            }

            if (minor_code) {
                cp_ips_send (node, IPC_INTERFACE, minor_code, 
                    update_data, sizeof (*update_data), true, ips_free_ipc_interface_cbk);
            }
        }
        break;

        case CMDCODE_INTF_CONFIG_SWITCHPORT:
        {
            interface = node_lookup_interface (node, if_name, vlan_id ) ;
            
            if (!interface) {
                cprintf ("Error : Interface do not exist\n");
                return -1;
            }   

            rtm_t *rtm = rtm_get (node, DEFAULT_VRF, AF_IPV6, 0);
            bool old_switchport_status = interface->GetSwitchport();

            switch (enable_or_disable)
            {
                case CONFIG_ENABLE:
                    /* Remove link local address */
                    if (interface->rtm_link_local_rt6_idx)
                    {
                        cp_rtm_uninstall_route_by_idx(rtm, interface->rtm_link_local_rt6_idx);
                        interface->rtm_link_local_rt6_idx = 0;
                    }
                    interface->SetSwitchport(true);
                    break;
                case CONFIG_DISABLE:

                    interface->SetSwitchport(false);
                    
                    /* Add link local address*/
                    if (!interface->rtm_link_local_rt6_idx)
                    {
                        ipv6_addr_t ipv6_addr;
                        interface->InterfaceGetIpv6LinkLocalAddress(&ipv6_addr.addr);
                        interface->rtm_link_local_rt6_idx =
                            cp_rtm_install_local_or_connected_v6_routes(
                                rtm, &ipv6_addr, 128, interface->GetSharedPtr());
                    }
                    break;
                default:;
            }

            if (old_switchport_status != interface->GetSwitchport())
            {
                SET_BIT(minor_code, IPC_INTERFACE_SWITCHPORT_UPDATE);
                update_data = new ipc_interface_t;;
                update_data->intf = interface->GetSharedPtr();
                update_data->is_switchport = old_switchport_status;
                cp_ips_send (node, IPC_INTERFACE, minor_code, 
                    update_data, sizeof (*update_data), true, ips_free_ipc_interface_cbk);
                cp2dp_send_intf_switchport_update(node, interface->ifindex,
                    interface->GetSwitchport() ? 1 : 0);
            }
        }
        break;


        case CMDCODE_INTF_CONFIG_VLAN:
        {
            interface = node_lookup_interface (node, if_name, vlan_id ) ;
            
            if (!interface) {
                cprintf ("Error : Interface do not exist\n");
                return -1;
            }   

            vlan_id_t old_access_vlan = interface->GetVlanId();
            uint32_t vlan_intf_ifindex = 0;

            switch(enable_or_disable) {

                case CONFIG_ENABLE:
                    if (!interface->IntfConfigVlan(vlan_id, true) ) return -1;
                    cp2dp_send_intf_vlan_bind_update(node, interface->ifindex,
                        interface->GetAccessVlanIntf()->ifindex, LAN_ACCESS_MODE, true);
                    break;
                case CONFIG_DISABLE:
                    vlan_intf_ifindex = interface->GetAccessVlanIntf() ? \
                        interface->GetAccessVlanIntf()->ifindex : 0;
                    if (!interface->IntfConfigVlan(vlan_id, false) ) return -1;
                    cp2dp_send_intf_vlan_bind_update(node, interface->ifindex,
                        vlan_intf_ifindex, LAN_ACCESS_MODE, false);
                    break;
                default:
                    ;
            }

            if (intf_prop_changed.access_vlan  !=
                     interface->GetVlanId()) {
                
                SET_BIT(minor_code, IPC_INTERFACE_ACCESS_VLAN_UPDATE);
                update_data = new ipc_interface_t;
                update_data->intf = interface->GetSharedPtr();
                update_data->access_vlan = old_access_vlan;
                cp_ips_send (node, IPC_INTERFACE, minor_code, 
                    update_data, sizeof (*update_data), true, ips_free_ipc_interface_cbk);
            }
        }
        break;


        case CMDCODE_INTF_CONFIG_IP_ADDR:
        {
            interface = node_lookup_interface (node, if_name, vlan_id ) ;
            
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
                cp_ips_send (node, IPC_INTERFACE, minor_code, 
                        update_data, sizeof (*update_data), true, ips_free_ipc_interface_cbk);            
            }
        }
        break;


        case CMDCODE_INTF_CONFIG_IPV6_ADDR:
        {
            interface = node_lookup_interface (node, if_name, vlan_id ) ;
            
            if (!interface) {
                cprintf ("Error : Interface do not exist\n");
                return -1;
            }       

            uint8_t old_ipv6_addr[16]; 
            uint8_t old_prefix_len;

            interface->InterfaceGetIpv6AddressMask (&old_ipv6_addr, &old_prefix_len);

             switch(enable_or_disable){
                case CONFIG_ENABLE:
                    interface_set_ipv6_addr(node, interface, intf_ip_addr);
                    break;
                case CONFIG_DISABLE:
                    interface_unset_ipv6_addr(node, interface, intf_ip_addr);
                    break;
                default:
                    ;
            }

            uint8_t new_ipv6_addr[16];
            uint8_t new_prefix_len;
            interface->InterfaceGetIpv6AddressMask (&new_ipv6_addr, &new_prefix_len);

            if (old_prefix_len == 0 && new_prefix_len > 0) {
                SET_BIT (minor_code, IPC_INTERFACE_IPV6_ADDR_ADD);
            }
            else if (old_prefix_len > 0 && new_prefix_len == 0) {
                SET_BIT (minor_code, IPC_INTERFACE_IPV6_ADDR_DEL);
            }
            else if (old_prefix_len > 0 && new_prefix_len > 0) {
                SET_BIT (minor_code, IPC_INTERFACE_IPV6_ADDR_UPDATE);
            }

            if (minor_code) {
                update_data = new ipc_interface_t;
                update_data->intf = interface->GetSharedPtr();
                memcpy(update_data->ipv6_addr.ipv6_addr, old_ipv6_addr, 16);
                update_data->ipv6_addr.prefix_len = old_prefix_len;
                cp_ips_send (node, IPC_INTERFACE, minor_code, 
                        update_data, sizeof (*update_data), true, ips_free_ipc_interface_cbk);            
            }
        }
        break;


        case CMDCODE_INTF_CONFIG_LOOPBACK_CREATE:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    interface_loopback_create(node, (char *)intf_name);
                    break;
                case CONFIG_DISABLE:
                    interface_loopback_delete(node, (char *)intf_name);
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
                
                if (vlan_intf) return 0;

                VlanInterfaceP vlan_intfP = std::make_shared<VlanInterface>(vlan_id);
		        vlan_intfP->SetSharedPtr(vlan_intfP);
                vlan_intfP->att_node = node;
                vlan_intfP->ifindex = interface_get_new_ifindex(node);

                if (!node->vlan_intf_db) {
                    node->vlan_intf_db = new std::unordered_map<uint16_t, VlanInterfaceP>;
                }
                
                vlan_intfP->vrf = NODE_DEF_VRF(node);
                node->vlan_intf_db->insert(std::make_pair(vlan_id, vlan_intfP));
                
                cp2dp_interface_create(node, vlan_intfP.get());

                cp2dp_send_intf_vrf_bind_update(node, 
                    (vlan_intfP.get())->ifindex, vlan_intfP->vrf->vrf_id);
                
                cp2dp_send_intf_admin_status_update(node, vlan_intfP->ifindex, false);
                
                cp2dp_mac_table_entry_add (node, (uint8_t *)BROADCAST_MAC, 
                        vlan_id, 
                       NODE_VLAN_FLOOD_INTF(node)->ifindex, MAC_STATIC, true, 0);
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

                uint32_t if_index = vlan_intf->ifindex;

                /* Interface us being dynamically used by some entities, send Delete notification */
                SET_BIT(if_change_flags, IF_DELETE_F);

                nfc_intf_invoke_notification_to_sbscribers(
					vlan_intf, &intf_prop_changed, if_change_flags);

                cp2dp_mac_table_entry_del (node, (uint8_t *)BROADCAST_MAC, 
                    vlan_id, NODE_VLAN_FLOOD_INTF(node)->ifindex, true, 0);

                cp2dp_send_intf_vrf_bind_update(node, if_index, -1);

                cp2dp_interface_delete(node, (Interface *)vlan_intf);
                node->vlan_intf_db->erase(vlan_id);
            }
            break;
            default:;
            }
            break;

        case CMDCODE_CONFIG_INTF_VLAN_UP_DOWN:
        {
            VlanInterface *vlan_intf =
                static_cast<VlanInterface *>(node_lookup_interface (node, if_name, vlan_id ));

            if (!vlan_intf)
            {
                cprintf("Error : Vlan Interface not created\n");
                return -1;
            }

            switch (enable_or_disable)
            {
            case CONFIG_ENABLE:
            {
                if (vlan_intf->is_up)
                    return 0;
                vlan_intf->is_up = true;
                cp2dp_send_intf_admin_status_update(node, vlan_intf->ifindex, false);
                interface_install_local_v4_routes(node, vlan_intf);
                SET_BIT(minor_code, IPC_INTERFACE_ADMIN_STATE_UP);
            }
            break;
            case CONFIG_DISABLE:
            {
                if (vlan_intf->is_up == false)
                    return 0;
                vlan_intf->is_up = false;
                cp2dp_send_intf_admin_status_update(node, vlan_intf->ifindex, true);
                interface_uninstall_local_v4_routes(node, vlan_intf);
                SET_BIT(minor_code, IPC_INTERFACE_ADMIN_STATE_DOWN);
            }
            break;
            default:;
            }

            if (minor_code) {
                update_data = new ipc_interface_t;
                update_data->intf = interface->GetSharedPtr();
                update_data->up_status = !vlan_intf->IsInterfaceUp(0);
                cp_ips_send (node, IPC_INTERFACE, minor_code, 
                    update_data, sizeof (*update_data), true, ips_free_ipc_interface_cbk);
            }

        }
        break;

        case CMDCODE_INTF_CONFIG_BIND_OVERLAY_TUNNEL:
        {
            VirtualPort *vport_intf = reinterpret_cast<VirtualPort *>(
                node_interface_lookup_by_name(node, (const char *)intf_name));

            if (!vport_intf)
            {
                cprintf("Error : Virtual Port do not exist\n");
                return -1;
            }

            Interface *tunnel = node_interface_lookup_by_name(node, (const char *)overlay_tunnel_name);

            if (!tunnel)
            {
                cprintf("Error : Overlay Tunnel Interface do not exist\n");
                return -1;
            }

            if (enable_or_disable == CONFIG_ENABLE)
            {
                vport_intf->BindOverlayTunnel(dynamic_cast<VirtualInterface *>(tunnel));
            }
            else
            {
                vport_intf->UnBindOverlayTunnel(dynamic_cast<VirtualInterface *>(tunnel));
            }
        }
        break;

        case CMDCODE_CONFIG_INTF_VLAN_VNI:
        {
            VlanInterface *vlan_intf =
                static_cast<VlanInterface *>(node_lookup_interface (node, if_name, vlan_id ));

            if (!vlan_intf)
            {
                cprintf("Error : Vlan Interface not created\n");
                return -1;
            }

            switch (enable_or_disable)
            {
            case CONFIG_ENABLE:
            {
                /* Extract VNI value from TLV stack */
                uint32_t vni_id = atoi((const char *)vni_value);
                
                /* Add to VLAN-VNI database with 1:1 mapping check */
                if (!vlan_vni_add_mapping(node, vlan_id, vni_id)) {
                    cprintf("Error: Failed to configure VNI %u for VLAN %u\n", vni_id, vlan_id);
                    return -1;
                }
                
                vlan_intf->SetVniId(vni_id);
                cp2dp_send_intf_vlan_vni_update(node, vlan_intf->ifindex, vni_id, true);
            }
            break;
            case CONFIG_DISABLE:
            {
                uint32_t vni_id = atoi((const char *)vni_value);
                vlan_intf->SetVniId(0);  /* Clear VNI configuration */
                
                /* Remove from VLAN-VNI database */
                vlan_vni_remove_mapping(node, vlan_id);
                cp2dp_send_intf_vlan_vni_update(node, vlan_intf->ifindex, vni_id, false);
            }
            break;
            default:;
            }
        }
        break;

        case CMDCODE_INTF_CONFIG_NVE_CREATE:
        {
            switch (enable_or_disable)
            {
            case CONFIG_ENABLE:
            {
                // Check if NVE interface already exists
                NVEInterface *nve_intf = NVEInterface::NVEInterfaceLookUp(node, (const char *)intf_name);
                if (nve_intf) {
                    cprintf("Error : NVE interface %s already exists\n", intf_name);
                    return 0;
                }

                // Create new NVE interface
                NVEInterfaceP nve_intfP = std::make_shared<NVEInterface>(std::string((const char *)intf_name));
                nve_intfP->SetSharedPtr(nve_intfP);
                nve_intfP->att_node = node;
                nve_intfP->ifindex = interface_get_new_ifindex(node);
                nve_intfP->is_up = true;  // NVE interfaces are up by default
                node->node_nw_prop.nve = nve_intfP;
            }
            break;
            case CONFIG_DISABLE:
            {
                NVEInterface *nve_intf = NVEInterface::NVEInterfaceLookUp(node, (const char *)intf_name);
                if (!nve_intf) {
                    return 0;
                }

                // Check if interface is in use (has member VNIs)
                std::vector<uint32_t> vni_list;
                nve_intf->GetMemberVnis(vni_list);
                if (!vni_list.empty()) {
                    cprintf("Error: NVE interface %s has member VNIs, remove them first\n", intf_name);
                    return -1;
                }

                if (nve_intf->IsCrossReferenced()) {
                    cprintf("Error: NVE interface %s is in use\n", intf_name);
                    return -1;
                }
                // Release resources and delete interface
                nve_intf->InterfaceReleaseAllResources();

                if (node->node_nw_prop.nve) {
                    node->node_nw_prop.nve = nullptr;
                }
            }
            break;
            default:;
            }
        }
        break;

        case CMDCODE_INTF_CONFIG_NVE_MEMBER_VNI:
        {
            NVEInterface *nve_intf = NVEInterface::NVEInterfaceLookUp(node, (const char *)intf_name);
            if (!nve_intf) {
                cprintf("Error: NVE interface %s does not exist\n", intf_name);
                return -1;
            }

            uint32_t vni_id = atoi((const char *)vni_value);
            if (vni_id == 0) {
                cprintf("Error: Invalid VNI value %s\n", vni_value);
                return -1;
            }

            switch (enable_or_disable)
            {
            case CONFIG_ENABLE:
            {
                if (nve_intf->AddMemberVni(vni_id)) {
                } else {
                    cprintf("Failed to add VNI %u to NVE interface %s\n", vni_id, intf_name);
                    return -1;
                }
            }
            break;
            case CONFIG_DISABLE:
            {
                if (nve_intf->RemoveMemberVni(vni_id))
                {
                }
                else
                {
                    cprintf("Failed to remove VNI %u from NVE interface %s\n", vni_id, intf_name);
                    return -1;
                }
            }
            break;
            default:;
            }
        }
        break;

        default:;
        }
        return 0;
}

static int
intf_config_virtual_port_create_handler(int cmdcode,
                                        Stack_t *tlv_stack,
                                        op_mode enable_or_disable)
{

    node_t *node;
    Interface *intf;
    tlv_struct_t *tlv = NULL;
    c_string intf_name = NULL;
    c_string node_name = NULL;    
    uint32_t if_change_flags = 0;
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
            intf = node_interface_lookup_by_name(node, (const char *)intf_name);
            
            if (intf) return 0;

            VirtualPortP vportP = std::make_shared<VirtualPort>(std::string((char *)intf_name));
            vportP->SetSharedPtr(vportP);
            intf = vportP.get();
            intf->att_node = node;
            intf->ifindex =  interface_get_new_ifindex(node);
            
            if (!node_interface_insert(node, intf))
            {
                cprintf ("Error : Failed to insert interface\n");
                intf->InterfaceReleaseAllResources();
                return -1;
            }

            SET_BIT(if_change_flags, IF_CREATE_F);
            nfc_intf_invoke_notification_to_sbscribers(
                intf, &intf_prop_changed, if_change_flags);
        }
        break;
        case CONFIG_DISABLE:
        { 
            intf = node_interface_lookup_by_name(node, (const char *)intf_name);

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

            /* Interface us being dynamically used by some entities, send Delete notification */
            SET_BIT(if_change_flags, IF_DELETE_F);
            nfc_intf_invoke_notification_to_sbscribers(
                intf, &intf_prop_changed, if_change_flags);
            node_interface_delete_by_name(node, (const char *)intf_name);
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

            /* config node <node-name> interface . . . <if-name> ipv6-address <ipv6-addr/prefix-len>*/
            static param_t ipv6_addr;
            init_param(&ipv6_addr, CMD, "ipv6-address", 0, 0, INVALID, 0, "Interface IPv6 Address");
            libcli_register_param(if_name, &ipv6_addr);
            {
                static param_t ipv6_addr_val;
                init_param(&ipv6_addr_val, LEAF, 0, intf_config_handler, 0, STRING, "intf-ipv6-address", "IPv6 address with prefix (e.g., 2001:db8::1/64)");
                libcli_register_param(&ipv6_addr, &ipv6_addr_val);
                libcli_set_param_cmd_code(&ipv6_addr_val, CMDCODE_INTF_CONFIG_IPV6_ADDR);
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

         if (!(unsupported_configs & INTF_CONFIG_NOT_SUPPORTED_VRF))
        {
            /* config node <node-name> interface . . . <if-name> vrf*/
            static param_t vrf;
            init_param(&vrf, CMD, "vrf", NULL, NULL, INVALID, NULL, "Enable VRF on this interface");
            libcli_register_param(if_name, &vrf);
            {
                /* config node <node-name> interface . . . <if-name> vrf <vrf-name> */
                static param_t vrf_name;
                init_param(&vrf_name, LEAF, 0, intf_config_handler, 0, STRING, "vrf-name", "VRF Name");
                libcli_register_param(&vrf, &vrf_name);
                libcli_set_param_cmd_code(&vrf_name, CMDCODE_CONF_INTF_VRF);
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
            /*config node <node-name> interface vlan <vlan-id>*/
            static param_t vlan_id;
            init_param(&vlan_id, LEAF, 0, intf_config_handler, validate_vlan_id, INT, "vlan-id", "vlan id(1-4096)");
            libcli_register_param(&vlan, &vlan_id);
            libcli_set_param_cmd_code(&vlan_id, CMDCODE_CONFIG_INTF_VLAN_CREATE);

            /*config node <node-name> interface vlan <vlan-id> vni <vni-id>*/
            static param_t vni;
            init_param(&vni, CMD, "vni", 0, 0, INVALID, 0, "\"vni\" keyword");
            libcli_register_param(&vlan_id, &vni);
            {
                static param_t vni_id;
                init_param(&vni_id, LEAF, 0, intf_config_handler, validate_vni_id, INT, "vni-id", "vni id(1-16777215)");
                libcli_register_param(&vni, &vni_id);
                libcli_set_param_cmd_code(&vni_id, CMDCODE_CONFIG_INTF_VLAN_VNI);
            }

             uint64_t unsupported_configs = ~0;
             unsupported_configs &= ~INTF_CONFIG_NOT_SUPPORTED_IP_ADDRESS;
             unsupported_configs &= ~INTF_CONFIG_NOT_SUPPORTED_UP_DOWN;
             unsupported_configs &= ~INTF_CONFIG_NOT_SUPPORTED_TRACEOPTIONS;
             unsupported_configs &= ~INTF_CONFIG_NOT_SUPPORTED_VRF;
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
                    static param_t loname;
                    init_param(&loname, LEAF, 0, intf_config_handler, NULL, STRING, "if-name", "Loopback ifname");
                    libcli_register_param(&loopback, &loname);
                    libcli_set_param_cmd_code(&loname, CMDCODE_INTF_CONFIG_LOOPBACK_CREATE);
                    uint64_t unsupported_configs = 0;
                    unsupported_configs |= INTF_CONFIG_NOT_SUPPORTED_TSP;
                    unsupported_configs |= INTF_CONFIG_NOT_SUPPORTED_SWITCHPORT;
                    unsupported_configs |= INTF_CONFIG_NOT_SUPPORTED_VLAN;
                    unsupported_configs |= INTF_CONFIG_NOT_SUPPORTED_OVERLAY_TUNNEL;
                    Interface_config_cli_common_subtree (&loname, unsupported_configs);
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
                /*config node <node-name> interface nve <nve-name> */
                static param_t nve;
                init_param(&nve, CMD, "network-virtualization-edge", 0, 0, INVALID, 0, "nve keyword");
                libcli_register_param(&interface, &nve);
                {
                    /*config node <node-name> interface nve <nve-name> */
                    static param_t nve_name;
                    init_param(&nve_name, LEAF, 0, intf_config_handler, 0, STRING, "if-name", "NVE Interface Name");
                    libcli_register_param(&nve, &nve_name);
                    libcli_set_param_cmd_code(&nve_name, CMDCODE_INTF_CONFIG_NVE_CREATE);
                    
                    {
                        /*config node <node-name> interface nve <nve-name> member*/
                        static param_t member;
                        init_param(&member, CMD, "member", 0, 0, INVALID, 0, "member keyword");
                        libcli_register_param(&nve_name, &member);
                        {
                            /*config node <node-name> interface nve <nve-name> member l2vni*/
                            static param_t l2vni;
                            init_param(&l2vni, CMD, "l2vni", 0, 0, INVALID, 0, "l2vni keyword");
                            libcli_register_param(&member, &l2vni);
                            {
                                /*config node <node-name> interface nve <nve-name> member l2vni <vni-id>*/
                                static param_t vni_id;
                                init_param(&vni_id, LEAF, 0, intf_config_handler, 0, INT, "vni-id", "VNI ID");
                                libcli_register_param(&l2vni, &vni_id);
                                libcli_set_param_cmd_code(&vni_id, CMDCODE_INTF_CONFIG_NVE_MEMBER_VNI);
                            }
                        }
                    }
                    
                    libcli_support_cmd_negation(&nve_name);
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
		            libcli_support_cmd_negation(&if_name);                               
                }
            }
            libcli_support_cmd_negation(&interface); 
}

