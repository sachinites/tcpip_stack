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

        /* Add eg : 1.1.1.1/32 */
        rt_ipv4_route_add (node, 
                                    tcp_ip_convert_ip_p_to_n(intf_ip_addr), 32, 
                                    0, intf, 0, PROTO_STATIC, true);    

        /* Add eg : 1.1.1.0/24 */
        rt_ipv4_route_add (node, 
                                    apply_mask2 (ip_addr_int, mask),
                                     mask,
                                     0, intf, 0, PROTO_STATIC, true);

        return;
    }

    /* Existing config changed */
    uint32_t existing_ip_addr;
    uint8_t existing_mask;

    intf->InterfaceGetIpAddressMask(&existing_ip_addr, &existing_mask);

    if ((existing_ip_addr != ip_addr_int) || (existing_mask != mask)) {

        rt_ipv4_route_add (node,
                                        existing_ip_addr,
                                        existing_mask,
                                        0, 0, 0, PROTO_STATIC, true);

        intf->InterfaceSetIpAddressMask(ip_addr_int, mask);
        interface_install_local_v4_routes  (node, intf);
    }
}

void
interface_unset_ip_addr(node_t *node, Interface *intf, 
                                        c_string intf_ip_addr, uint8_t mask) {

    byte ip_addr_str[16];
    uint32_t ip_addr_int;
    uint8_t existing_mask;
    uint32_t existing_ip_addr;
    byte ip_addr_str_applied_mask[16];
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

void 
interface_install_local_v4_routes (node_t *node, Interface  *intf) {

    uint32_t ip_addr;
    uint8_t mask;

    intf->InterfaceGetIpAddressMask(&ip_addr, &mask);

    rt_ipv4_route_add (node, ip_addr, 32, 0, intf, 0, PROTO_STATIC, true);
    rt_ipv4_route_add (node, apply_mask2 (ip_addr, mask), mask, 0, intf, 0, PROTO_STATIC, true);
}

void 
interface_uninstall_local_v4_routes (node_t *node, Interface  *intf) {

    uint32_t ip_addr;
    uint8_t mask;

    intf->InterfaceGetIpAddressMask(&ip_addr, &mask);

    rt_ipv4_route_del (node, ip_addr, 32, PROTO_STATIC, true);
    rt_ipv4_route_del (node, apply_mask2 (ip_addr, mask), mask, PROTO_STATIC, true);
}