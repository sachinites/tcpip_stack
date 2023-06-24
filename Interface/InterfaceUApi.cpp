#include "InterfaceUApi.h"
#include "../graph.h"
#include "../Layer3/layer3.h"
#include "../tcpip_notif.h"

void
interface_set_ip_addr(node_t *node, Interface *intf, 
                                    c_string intf_ip_addr, uint8_t mask) {

    byte ip_addr_str[16];
    uint32_t ip_addr_int;
    uint32_t if_change_flags = 0;
    intf_prop_changed_t intf_prop_changed;

    if (intf->GetSwitchport ()) {
        cprintf("Error : Remove L2 config from interface first\n");
        return;
    }

    ip_addr_int = tcp_ip_covert_ip_p_to_n(intf_ip_addr);
    
    /* new config */
    if (!intf->IsIpConfigured()) {

        intf->InterfaceSetIpAddressMask(ip_addr_int, mask);
        SET_BIT(if_change_flags, IF_IP_ADDR_CHANGE_F);
        intf_prop_changed.ip_addr.ip_addr = 0;
        intf_prop_changed.ip_addr.mask = 0;
        rt_table_add_direct_route(NODE_RT_TABLE(node), intf_ip_addr, mask);
        nfc_intf_invoke_notification_to_sbscribers(intf,  
                &intf_prop_changed, if_change_flags);
        return;
    }

    /* Existing config changed */
    uint32_t existing_ip_addr;
    uint8_t existing_mask;

    intf->InterfaceGetIpAddressMask(&existing_ip_addr, &existing_mask);

    if ((existing_ip_addr != ip_addr_int) || (existing_mask != mask)) {

        intf_prop_changed.ip_addr.ip_addr = existing_ip_addr;
        intf_prop_changed.ip_addr.mask = existing_mask;
        SET_BIT(if_change_flags, IF_IP_ADDR_CHANGE_F);

        rt_table_delete_route(NODE_RT_TABLE(node),  
                                            tcp_ip_covert_ip_n_to_p(existing_ip_addr, ip_addr_str),
                                            existing_mask,
                                            PROTO_STATIC);

        intf->InterfaceSetIpAddressMask(ip_addr_int, mask);

        rt_table_add_direct_route(NODE_RT_TABLE(node),
                                                  tcp_ip_covert_ip_n_to_p(ip_addr_int, ip_addr_str),
                                                  mask);

         nfc_intf_invoke_notification_to_sbscribers(intf,  
                &intf_prop_changed, if_change_flags);
    }
}

void
interface_unset_ip_addr(node_t *node, Interface *intf) {

    uint8_t mask;
    byte ip_addr_str[16];
    uint32_t ip_addr_int;
    uint8_t existing_mask;
    uint32_t existing_ip_addr;
    uint32_t if_change_flags = 0;
    intf_prop_changed_t intf_prop_changed;

    if ( !intf->IsIpConfigured()) {
        return;
    }

    intf->InterfaceGetIpAddressMask(&existing_ip_addr, &existing_mask);
    intf_prop_changed.ip_addr.ip_addr = existing_ip_addr;
    intf_prop_changed.ip_addr.mask = existing_mask;
    SET_BIT(if_change_flags, IF_IP_ADDR_CHANGE_F);

    rt_table_delete_route(NODE_RT_TABLE(node),  
                                            tcp_ip_covert_ip_n_to_p(existing_ip_addr, ip_addr_str),
                                            existing_mask,
                                            PROTO_STATIC);
    
    intf->InterfaceSetIpAddressMask(0, 0);
    
    nfc_intf_invoke_notification_to_sbscribers(intf,  
                &intf_prop_changed, if_change_flags);
}

void
interface_loopback_create (node_t *node, uint8_t lono) {

    (unused) node;
    (unused) lono;
}

void
interface_loopback_delete (node_t *node, uint8_t lono) {

    (unused) node;
    (unused) lono;
}

void
interface_set_lan_mode(node_t *node, 
                      Interface *interface, 
                      IntfL2Mode l2_mode) {

}

void
interface_unset_lan_mode(node_t *node, 
                      Interface *interface, 
                      IntfL2Mode l2_mode) {

}
