#include "InterfaceUApi.h"
#include "../graph.h"
#include "../Layer3/layer3.h"
#include "../tcpip_notif.h"

void
interface_set_ip_addr(node_t *node, Interface *intf, 
                                    c_string intf_ip_addr, uint8_t mask) {

    uint32_t ip_addr_int;

    if (intf->GetSwitchport ()) {
        cprintf("Error : Remove L2 config from interface first\n");
        return;
    }

    ip_addr_int = tcp_ip_convert_ip_p_to_n(intf_ip_addr);
    
    /* new config */
    if (!intf->IsIpConfigured()) {

        intf->InterfaceSetIpAddressMask(ip_addr_int, mask);
        interface_install_local_v4_routes  (node, intf);
        return;
    }

    /* Existing config changed */
    uint32_t existing_ip_addr;
    uint8_t existing_mask;

    intf->InterfaceGetIpAddressMask(&existing_ip_addr, &existing_mask);

    if ((existing_ip_addr != ip_addr_int) || (existing_mask != mask)) {

        interface_uninstall_local_v4_routes  (node, intf);
        intf->InterfaceSetIpAddressMask(0, 0);
        intf->InterfaceSetIpAddressMask(ip_addr_int, mask);
        interface_install_local_v4_routes  (node, intf);
    }
}

void
interface_unset_ip_addr(node_t *node, Interface *intf, 
                                        c_string intf_ip_addr, uint8_t mask) {

    byte ip_addr_str[IPV4_ADDR_LEN_STR];
    uint32_t ip_addr_int;
    uint8_t existing_mask;
    uint32_t existing_ip_addr;
    byte ip_addr_str_applied_mask[IPV4_ADDR_LEN_STR];
    uint32_t if_change_flags = 0;
    intf_prop_changed_t intf_prop_changed;

    if ( !intf->IsIpConfigured()) {
        return;
    }

    intf->InterfaceGetIpAddressMask(&existing_ip_addr, &existing_mask);

    ip_addr_int = tcp_ip_convert_ip_p_to_n(intf_ip_addr);

    if (ip_addr_int != existing_ip_addr || mask != existing_mask) {
        cprintf ("Error : IP address and mask do not match\n");
        return;
    }

    interface_uninstall_local_v4_routes  (node, intf);
    intf->InterfaceSetIpAddressMask(0, 0);
}

void
interface_loopback_create (node_t *node, uint8_t lono) {

    int empty_intf_slot;

    /*Plugin interface ends into Node*/
    empty_intf_slot = node_get_intf_available_slot (node);

    if (empty_intf_slot == -1) {
        cprintf("Error : No empty slot available for loopback interface %d\n", lono);
        return;
    }

    /* Create loopback interface */
    char loopback_name[IF_NAME_SIZE];
    snprintf(loopback_name, sizeof(loopback_name), "lo.%d", lono);
    InterfaceP intfP = std::make_shared<LoopbackInterface>(std::string(loopback_name));
    intfP->SetSharedPtr(intfP);
    intfP->att_node = node;
    node->intf[empty_intf_slot] = intfP;
    intfP->ifindex = empty_intf_slot;
}

void
interface_loopback_delete (node_t *node, uint8_t lono) {

    int i = 0;
    Interface *intf;
    uint32_t if_change_flags = 0;
    char loopback_name[IF_NAME_SIZE];
    intf_prop_changed_t intf_prop_changed;
    
    snprintf(loopback_name, sizeof(loopback_name), "lo.%d", lono);
    memset (&intf_prop_changed, 0, sizeof (intf_prop_changed_t));

    intf = node_get_intf_by_name_with_idx_pos (node, (const char *)loopback_name, &i);

    if (!intf) {
        cprintf ("Error : Loopback %s Do Not  Exist\n", loopback_name);
        return;
    }

    if (intf->IsCrossReferenced () ) {
        cprintf("Error : Loopback interface %s is in use, cannot delete \n", loopback_name);
        return;
    }

    /* Send Delete notification to all Subscribers */
    SET_BIT(if_change_flags, IF_DELETE_F);
        nfc_intf_invoke_notification_to_sbscribers(
       intf, &intf_prop_changed, if_change_flags);    

    node->intf[i] = nullptr;
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

void 
interface_install_local_v4_routes (node_t *node, Interface  *intf) {

    uint8_t mask;
    uint32_t ip_addr;

    if (!intf) return;
    if (!intf->IsInterfaceUp(0)) return;
    if (!intf->IsIpConfigured()) return;

    if (intf->iftype == INTF_TYPE_GRE_TUNNEL) {

        GRETunnelInterface *gre_intf = dynamic_cast <GRETunnelInterface *> (intf);
        if (!gre_intf->IsGRETunnelActive()) return;
    }

    intf->InterfaceGetIpAddressMask(&ip_addr, &mask);
    rt_ipv4_route_add (node, ip_addr, 32, 0, intf, 0, PROTO_STATIC, true);
    rt_ipv4_route_add (node, apply_mask2 (ip_addr, mask), mask, 0, intf, 0, PROTO_STATIC, true);
}

void 
interface_uninstall_local_v4_routes (node_t *node, Interface  *intf) {

    uint8_t mask;
    uint32_t ip_addr;
    
    if (!intf) return;
    intf->InterfaceGetIpAddressMask(&ip_addr, &mask);
    rt_ipv4_route_del (node, ip_addr, 32, PROTO_STATIC, true);
    rt_ipv4_route_del (node, apply_mask2 (ip_addr, mask), mask, PROTO_STATIC, true);
}
