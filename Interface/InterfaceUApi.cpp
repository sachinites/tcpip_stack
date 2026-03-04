#include <string.h>
#include <arpa/inet.h>

#include "InterfaceUApi.h"
#include "../router_init.h"
#include "../Layer3/layer3.h"
#include "../tcpip_notif.h"
#include "../RTM/rtm_nb_integ.h"
#include "../vrf/vrf.h"
#include "../Layer3/ipv6/ipv6_utils.h"
#include "../dpal/cp2dp.h"
#include "../datapath/enums/l2_enums.h"
#include "../datapath/dp-program/dp-prog-intf-struct.h"

void
interface_set_ip_addr(node_t *node, 
                    Interface *intf, 
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
        cp2dp_send_intf_ipv4_addr_update(node, intf->ifindex,ip_addr_int, mask);
        interface_install_local_v4_routes  (node, intf);
        
        /* Add MAC table entry for VLAN interface */
        if (intf->iftype == INTF_TYPE_VLAN) {
            VlanInterface *vlan_intf = dynamic_cast<VlanInterface *>(intf);
            cp2dp_mac_table_entry_add (node, (uint8_t *)BROADCAST_MAC, vlan_intf->GetVlanId(), 
                       NODE_RMAC_INTF(node)->ifindex, MAC_STATIC, true, 0);
        }
        return;
    }

    /* Existing config changed */
    uint32_t existing_ip_addr;
    uint8_t existing_mask;

    intf->InterfaceGetIpAddressMask(&existing_ip_addr, &existing_mask);

    if ((existing_ip_addr != ip_addr_int) || (existing_mask != mask)) {

        interface_uninstall_local_v4_routes  (node, intf);
        intf->InterfaceSetIpAddressMask(0, 0);
        cp2dp_send_intf_ipv4_addr_update(node, intf->ifindex, existing_ip_addr, existing_mask);
        intf->InterfaceSetIpAddressMask(ip_addr_int, mask);
        cp2dp_send_intf_ipv4_addr_update(node, intf->ifindex, ip_addr_int, mask);
        interface_install_local_v4_routes  (node, intf);
    }
}

void
interface_unset_ip_addr(node_t *node, Interface *intf, 
                        c_string intf_ip_addr, uint8_t mask) {

    uint32_t ip_addr_int;
    uint8_t existing_mask;
    uint32_t existing_ip_addr;
    uint32_t if_change_flags = 0;
    intf_prop_changed_t intf_prop_changed;
    byte ip_addr_str[IPV4_ADDR_LEN_STR];
    byte ip_addr_str_applied_mask[IPV4_ADDR_LEN_STR];

    if ( !intf->IsIpConfigured()) {
        return;
    }

    intf->InterfaceGetIpAddressMask(&existing_ip_addr, &existing_mask);

    ip_addr_int = tcp_ip_convert_ip_p_to_n(intf_ip_addr);

    if ((ip_addr_int != existing_ip_addr) || mask != existing_mask) {
        cprintf ("Error : IP address and mask do not match\n");
        return;
    }

    interface_uninstall_local_v4_routes  (node, intf);
    
    /* Remove MAC table entry for VLAN interface before clearing IP */
    if (intf->iftype == INTF_TYPE_VLAN) {
        VlanInterface *vlan_intf = dynamic_cast<VlanInterface *>(intf);
         cp2dp_mac_table_entry_del (node, (uint8_t *)BROADCAST_MAC, vlan_intf->GetVlanId(), 
                        NODE_RMAC_INTF(node)->ifindex, true, 0);
    }
    
    intf->InterfaceSetIpAddressMask(0, 0);
    cp2dp_send_intf_ipv4_addr_update(node, intf->ifindex, 0, 0);
}

void
interface_set_ipv6_addr(node_t *node, 
                    Interface *intf, 
                    c_string intf_ipv6_addr_with_mask) {

    ipv6_addr_t ipv6_addr;
    uint8_t prefix_len;
    char ipv6_addr_str[48];
    char *slash_pos;

    if (intf->GetSwitchport ()) {
        cprintf("Error : Remove L2 config from interface first\n");
        return;
    }

    /* Parse IPv6 address and prefix length from format: "2001:db8::1/64" */
    strncpy(ipv6_addr_str, (const char *)intf_ipv6_addr_with_mask, sizeof(ipv6_addr_str) - 1);
    ipv6_addr_str[sizeof(ipv6_addr_str) - 1] = '\0';
    
    slash_pos = strchr(ipv6_addr_str, '/');
    if (!slash_pos) {
        cprintf("Error : IPv6 address must be in format <address>/<prefix-length>\n");
        return;
    }
    
    *slash_pos = '\0';
    prefix_len = atoi(slash_pos + 1);
    
    if (prefix_len > 128) {
        cprintf("Error : Invalid IPv6 prefix length (must be 0-128)\n");
        return;
    }

    /* Convert IPv6 address string to binary */
    if (inet_pton(AF_INET6, ipv6_addr_str, &ipv6_addr.addr) != 1) {
        cprintf("Error : Invalid IPv6 address format\n");
        return;
    }

    /* Check if IPv6 is already configured */
    uint8_t existing_addr[16];
    uint8_t existing_prefix_len;
    intf->InterfaceGetIpv6AddressMask(&existing_addr, &existing_prefix_len);
    
    /* new config */
    if (existing_prefix_len == 0) {
        intf->InterfaceSetIpv6AddressMask(&ipv6_addr.addr, prefix_len);
        cp2dp_send_intf_ipv6_addr_update(node, intf->ifindex, ipv6_addr.addr, prefix_len);
        interface_install_local_v6_routes(node, intf);
        return;
    }

    /* Existing config changed */
    if (memcmp(existing_addr, ipv6_addr.addr, 16) != 0 || existing_prefix_len != prefix_len) {
        interface_uninstall_local_v6_routes(node, intf);
        intf->InterfaceSetIpv6AddressMask((uint8_t (*)[16])"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 0);
        intf->InterfaceSetIpv6AddressMask(&ipv6_addr.addr, prefix_len);
        cp2dp_send_intf_ipv6_addr_update(node, intf->ifindex, 0,0);
        cp2dp_send_intf_ipv6_addr_update(node, intf->ifindex, ipv6_addr.addr, prefix_len);
        interface_install_local_v6_routes(node, intf);
    }
}

void
interface_unset_ipv6_addr(node_t *node, Interface *intf, 
                        c_string intf_ipv6_addr_with_mask) {

    ipv6_addr_t ipv6_addr;
    uint8_t prefix_len;
    char ipv6_addr_str[48];
    char *slash_pos;
    uint8_t existing_addr[16];
    uint8_t existing_prefix_len;

    /* Check if IPv6 is configured */
    intf->InterfaceGetIpv6AddressMask(&existing_addr, &existing_prefix_len);
    
    if (existing_prefix_len == 0) {
        cprintf("Error : No IPv6 address configured on interface\n");
        return;
    }

    /* Parse IPv6 address and prefix length from format: "2001:db8::1/64" */
    strncpy(ipv6_addr_str, (const char *)intf_ipv6_addr_with_mask, sizeof(ipv6_addr_str) - 1);
    ipv6_addr_str[sizeof(ipv6_addr_str) - 1] = '\0';
    
    slash_pos = strchr(ipv6_addr_str, '/');
    if (!slash_pos) {
        cprintf("Error : IPv6 address must be in format <address>/<prefix-length>\n");
        return;
    }
    
    *slash_pos = '\0';
    prefix_len = atoi(slash_pos + 1);

    /* Convert IPv6 address string to binary */
    if (inet_pton(AF_INET6, ipv6_addr_str, &ipv6_addr.addr) != 1) {
        cprintf("Error : Invalid IPv6 address format\n");
        return;
    }

    /* Verify address and prefix match */
    if (memcmp(existing_addr, ipv6_addr.addr, 16) != 0 || existing_prefix_len != prefix_len) {
        cprintf("Error : IPv6 address and prefix do not match configured address\n");
        return;
    }

    /* Uninstall all IPv6 routes (including link-local) */
    interface_uninstall_local_v6_routes(node, intf);
    
    /* Clear the configured IPv6 address */
    intf->InterfaceSetIpv6AddressMask((uint8_t (*)[16])"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 0);
    cp2dp_send_intf_ipv6_addr_update(node, intf->ifindex, 0,0);

    /* Re-install the link-local route (it should persist independently) */
    if (intf->IsInterfaceUp(0) && !intf->GetSwitchport()) {
        rtm_t *rtm = rtm_get(node, DEFAULT_VRF, AF_IPV6, 0);
        ipv6_addr_t link_local_addr;
        intf->InterfaceGetIpv6LinkLocalAddress(&link_local_addr.addr);
        
        intf->rtm_link_local_rt6_idx = 
            cp_rtm_install_local_or_connected_v6_routes(
                rtm, &link_local_addr, 128, intf->GetSharedPtr());
    }
}

Interface *
interface_loopback_create (node_t *node, char *ifname) {

    if (node_interface_lookup_by_name(node, ifname)) {
        return;
    }
    
    InterfaceP intfP = std::make_shared<LoopbackInterface>(std::string(ifname));
    intfP->SetSharedPtr(intfP);
    intfP->att_node = node;
    intfP->ifindex = interface_get_new_ifindex(node);
    
    if (!node_global_intf_map_insert(node, intfP.get())) {
        cprintf("Error : Failed to insert loopback interface %s\n", ifname);
        return;
    }
    cp2dp_interface_create(node, intfP.get());
    vrf_add_interface(NODE_DEF_VRF(node), intfP.get());
    return intfP.get();
}

void
interface_loopback_delete (node_t *node, char *ifname) {

    Interface *intf;
    uint32_t if_change_flags = 0;
    char loopback_name[IF_NAME_SIZE];
    intf_prop_changed_t intf_prop_changed;
    
    memset (&intf_prop_changed, 0, sizeof (intf_prop_changed_t));

    intf = node_interface_lookup_by_name(node, (const char *)ifname);

    if (!intf) {
        cprintf ("Error : Loopback %s Do Not  Exist\n", ifname);
        return;
    }

    if (intf->IsCrossReferenced () ) {
        cprintf("Error : Loopback interface %s is in use, cannot delete \n", ifname);
        return;
    }

    /* Send Delete notification to all Subscribers */
    SET_BIT(if_change_flags, IF_DELETE_F);
    nfc_intf_invoke_notification_to_sbscribers(
       intf, &intf_prop_changed, if_change_flags);    

    node_global_intf_map_delete_by_ifindex(node, intf->ifindex);
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
    uint32_t nh_idx = 0;

    if (!intf) return;
    if (!intf->IsInterfaceUp(0)) return;
    if (!intf->IsIpConfigured()) return;

    if (intf->iftype == INTF_TYPE_GRE_TUNNEL) {

        GRETunnelInterface *gre_intf = dynamic_cast <GRETunnelInterface *> (intf);
        if (!gre_intf->IsGRETunnelActive()) return;
    }

    intf->InterfaceGetIpAddressMask(&ip_addr, &mask);

    /* New RTM Route Installation */
    rtm_t *rtm = rtm_get (node, intf->vrf->vrf_id, AF_IPV4, 0);
    if ((nh_idx = cp_rtm_install_local_or_connected_v4_routes (rtm, ip_addr, 32, intf->GetSharedPtr()))) {
        intf->rtm_local_rt_idx = nh_idx;
    }

    if ((nh_idx = 
        cp_rtm_install_local_or_connected_v4_routes (rtm, apply_mask2 (ip_addr, mask), mask, intf->GetSharedPtr()))) {
        intf->rtm_connected_rt_idx = nh_idx;
    }
}

void 
interface_uninstall_local_v4_routes (node_t *node, Interface  *intf) {

    uint8_t mask;
    uint32_t ip_addr;
    
    if (!intf) return;
    
    intf->InterfaceGetIpAddressMask(&ip_addr, &mask);
    rtm_t *rtm = rtm_get (node, intf->vrf->vrf_id, AF_IPV4, 0);
    cp_rtm_uninstall_route_by_idx(rtm, intf->rtm_local_rt_idx);
    cp_rtm_uninstall_route_by_idx(rtm, intf->rtm_connected_rt_idx);
}

/* Install ipv6 address with actual mask as Connected Route
   Install ipv6 address with mask = 128 as local route
   Install Link local address 
*/
void 
interface_install_local_v6_routes (node_t *node, Interface  *intf) {

    uint8_t mask;
    uint32_t nh_idx = 0;
    ipv6_addr_t ipv6_addr;

    rtm_t *rtm = rtm_get (node, intf->vrf->vrf_id, AF_IPV6, 0);

    if (!intf) return;
    if (!intf->IsInterfaceUp(0)) return;

    if (intf->iftype == INTF_TYPE_GRE_TUNNEL) {

        GRETunnelInterface *gre_intf = dynamic_cast <GRETunnelInterface *> (intf);
        if (!gre_intf->IsGRETunnelActive()) return;
    }

    intf->InterfaceGetIpv6AddressMask(&ipv6_addr.addr, &mask);

    if (!is_ipv6_addr_unspecified (&ipv6_addr.addr) && 
            !intf->rtm_local_rt6_idx) {

        /* Local Route*/
        intf->rtm_local_rt6_idx = 
            cp_rtm_install_local_or_connected_v6_routes(
                rtm, &ipv6_addr, 128, intf->GetSharedPtr());

        /* Connected Route*/
        if (mask != 128) {
            intf->rtm_connected_rt6_idx = 
                cp_rtm_install_local_or_connected_v6_routes(
                    rtm, &ipv6_addr, mask, intf->GetSharedPtr());
        }
        
    }

    /* Link local Address */
    if (!intf->rtm_link_local_rt6_idx) {

        intf->InterfaceGetIpv6LinkLocalAddress(&ipv6_addr.addr);

        intf->rtm_link_local_rt6_idx = 
            cp_rtm_install_local_or_connected_v6_routes(
                rtm, &ipv6_addr, 128, intf->GetSharedPtr()); 
    }
}

void 
interface_uninstall_local_v6_routes (node_t *node, Interface  *intf) {

    rtm_t *rtm = rtm_get (node, intf->vrf->vrf_id, AF_IPV6, 0);

    if (intf->rtm_local_rt6_idx) {
        cp_rtm_uninstall_route_by_idx (rtm, intf->rtm_local_rt6_idx);
        intf->rtm_local_rt6_idx = 0;
    }

    if (intf->rtm_connected_rt6_idx) {
        cp_rtm_uninstall_route_by_idx (rtm, intf->rtm_connected_rt6_idx);
        intf->rtm_connected_rt6_idx = 0;
    }

    if (intf->rtm_link_local_rt6_idx) {
        cp_rtm_uninstall_route_by_idx (rtm, intf->rtm_link_local_rt6_idx);
        intf->rtm_link_local_rt6_idx = 0;        
    }
}

static Interface* 
node_interface_lookup_by_name_internal(node_t *node, const char *ifname) {
    
    vrf_t *def_vrf = NODE_DEF_VRF(node);
    return vrf_interface_lookup_by_name(def_vrf, ifname);
}


static Interface* 
node_global_intf_map_lookup_by_name(node_t *node, const char *ifname) {
    
    if (!node || !ifname) return nullptr;
    if (!node->intf_by_name) return nullptr;
    
    auto it = node->intf_by_name->find(ifname);
    if (it == node->intf_by_name->end()) {
        return nullptr;
    }
    
    return it->second.get();
}

Interface *
node_interface_lookup_by_name(node_t *node, const char *if_name){

    Interface *intf;

    if (string_compare(if_name, NODE_RMAC_INTF(node)->if_name.c_str(), IF_NAME_SIZE) == 0) {
        return NODE_RMAC_INTF(node).get();
    }

    else if (string_compare(if_name, NODE_VLAN_FLOOD_INTF(node)->if_name.c_str(), IF_NAME_SIZE) == 0) {
        return NODE_VLAN_FLOOD_INTF(node).get();
    }

    else if (NODE_NVE_INTF(node) && 
             string_compare(if_name, NODE_NVE_INTF(node)->if_name.c_str(), IF_NAME_SIZE) == 0) {
        return NODE_NVE_INTF(node).get();
    }

    // Look up in physical/loopback interface hashmap
    intf = node_global_intf_map_lookup_by_name(node, if_name);
    if (intf) return intf;

    /* Get vlan interface by name */
    if (node->vlan_intf_db) {

        for (auto it = node->vlan_intf_db->begin(); it != node->vlan_intf_db->end(); it++) {
            if (string_compare(it->second->if_name.c_str(), if_name, IF_NAME_SIZE) == 0) {
                return it->second.get();
            }
        }
    }

    return NULL;
}

Interface* 
node_interface_lookup_by_ifindex_internal(node_t *node, uint32_t ifindex) {
    
    vrf_t *def_vrf = NODE_DEF_VRF(node);
    return vrf_interface_lookup_by_ifindex(def_vrf, ifindex);
}

static Interface* 
node_global_intf_map_lookup_by_ifindex(node_t *node, uint32_t ifindex) ;

Interface *
node_get_intf_by_ifindex(node_t *node, uint32_t ifindex) {

    Interface *intf;

    if (ifindex == NODE_RMAC_INTF(node)->ifindex) {
        return NODE_RMAC_INTF(node).get();
    }
    else if (ifindex == NODE_VLAN_FLOOD_INTF(node)->ifindex) {
        return NODE_VLAN_FLOOD_INTF(node).get();
    }

    else if (NODE_NVE_INTF(node) && 
             ifindex == NODE_NVE_INTF(node)->ifindex) {
        return NODE_NVE_INTF(node).get();
    }
    
    // Look up in physical/loopback interface hashmap
    intf = node_global_intf_map_lookup_by_ifindex(node, ifindex);
    if (intf) return intf;

    /* Check for vlan interface */

    if (node->vlan_intf_db) {

        for (auto it = node->vlan_intf_db->begin(); it != node->vlan_intf_db->end(); it++) {
            if (it->second->ifindex == ifindex) return it->second.get();
        }
    }

    return NULL;
}


/* VRF Interface Management Implementation */
bool 
vrf_interface_insert(vrf_t *vrf, Interface *intf) {
    
    if (!vrf || !intf) return false;
    
    const char *ifname = intf->if_name.c_str();
    uint32_t ifindex = intf->ifindex;
    
    // Check if interface with same name or ifindex already exists
    if (vrf->intf_by_name && vrf->intf_by_name->find(ifname) != vrf->intf_by_name->end()) {
        return false; // Interface name already exists
    }
    
    if (vrf->intf_by_ifindex && vrf->intf_by_ifindex->find(ifindex) != vrf->intf_by_ifindex->end()) {
        return false; // Interface index already exists
    }
    
    // Initialize hashmaps if not already done
    if (!vrf->intf_by_name) {
        vrf->intf_by_name = new std::unordered_map<std::string, InterfaceP>();
    }
    
    if (!vrf->intf_by_ifindex) {
        vrf->intf_by_ifindex = new std::unordered_map<uint32_t, InterfaceP>();
    }
    
    // Insert into both VRF hashmaps
    (*vrf->intf_by_name)[ifname] = intf->GetSharedPtr();
    (*vrf->intf_by_ifindex)[ifindex] = intf->GetSharedPtr();
    
    return true;
}

bool 
vrf_interface_delete_by_name(vrf_t *vrf, const char *ifname) {
    
    if (!vrf || !ifname) return false;
    if (!vrf->intf_by_name) return false;
    
    auto it = vrf->intf_by_name->find(ifname);
    if (it == vrf->intf_by_name->end()) {
        return false; // Interface not found
    }
    
    InterfaceP intf = it->second;
    uint32_t ifindex = intf->ifindex;
    
    // Remove from both VRF hashmaps
    vrf->intf_by_name->erase(it);
    
    if (vrf->intf_by_ifindex) {
        vrf->intf_by_ifindex->erase(ifindex);
    }
    
    return true;
}

bool 
vrf_interface_delete_by_ifindex(vrf_t *vrf, uint32_t ifindex) {
    
    if (!vrf) return false;
    if (!vrf->intf_by_ifindex) return false;
    
    auto it = vrf->intf_by_ifindex->find(ifindex);
    if (it == vrf->intf_by_ifindex->end()) {
        return false;
    }
    
    InterfaceP intf = it->second;
    const char *ifname = intf->if_name.c_str();
    
    // Remove from both VRF hashmaps
    vrf->intf_by_ifindex->erase(it);
    
    if (vrf->intf_by_name) {
        vrf->intf_by_name->erase(ifname);
    }

    return true;
}

Interface* 
vrf_interface_lookup_by_name(vrf_t *vrf, const char *ifname) {
    
    if (!vrf || !ifname) return nullptr;
    if (!vrf->intf_by_name) return nullptr;
    
    auto it = vrf->intf_by_name->find(ifname);
    if (it == vrf->intf_by_name->end()) {
        return nullptr;
    }
    
    return it->second.get();
}

Interface* 
vrf_interface_lookup_by_ifindex(vrf_t *vrf, uint32_t ifindex) {
    
    if (!vrf) return nullptr;
    if (!vrf->intf_by_ifindex) return nullptr;
    
    auto it = vrf->intf_by_ifindex->find(ifindex);
    if (it == vrf->intf_by_ifindex->end()) {
        return nullptr;
    }
    
    return it->second.get();
}

uint32_t 
vrf_interface_count(vrf_t *vrf) {
    
    if (!vrf || !vrf->intf_by_name) return 0;
    return vrf->intf_by_name->size();
}

/* Global Node Interface Map Management Implementation */
bool 
node_global_intf_map_insert(node_t *node, Interface *intf) {
    
    if (!node || !intf) return false;
    
    const char *ifname = intf->if_name.c_str();
    uint32_t ifindex = intf->ifindex;
    
    // Check if interface with same name or ifindex already exists
    if (node->intf_by_name && node->intf_by_name->find(ifname) != node->intf_by_name->end()) {
        return false; // Interface name already exists
    }
    
    if (node->intf_by_ifindex && node->intf_by_ifindex->find(ifindex) != node->intf_by_ifindex->end()) {
        return false; // Interface index already exists
    }
    
    // Initialize hashmaps if not already done
    if (!node->intf_by_name) {
        node->intf_by_name = new std::unordered_map<std::string, InterfaceP>();
    }
    
    if (!node->intf_by_ifindex) {
        node->intf_by_ifindex = new std::unordered_map<uint32_t, InterfaceP>();
    }
    
    // Insert into both hashmaps
    (*node->intf_by_name)[ifname] = intf->GetSharedPtr();
    (*node->intf_by_ifindex)[ifindex] = intf->GetSharedPtr();
    
    return true;
}

bool
node_global_intf_map_delete_by_name(node_t *node, const char *ifname) {
    
    if (!node || !ifname) return false;
    if (!node->intf_by_name) return false;
    
    auto it = node->intf_by_name->find(ifname);

    if (it == node->intf_by_name->end()) {
        return false; // Interface not found
    }
    
    InterfaceP intf = it->second;

    /* Dont delete physical interfaces */
    if (intf->iftype == INTF_TYPE_PHY) return true;

    uint32_t ifindex = intf->ifindex;
    
    // Remove from both hashmaps
    node->intf_by_name->erase(it);
    node->intf_by_ifindex->erase(ifindex);

    return true;
}

bool 
node_global_intf_map_delete_by_ifindex(node_t *node, uint32_t ifindex) {
    
    if (!node) return false;
    if (!node->intf_by_ifindex) return false;
    
    auto it = node->intf_by_ifindex->find(ifindex);
    if (it == node->intf_by_ifindex->end()) {
        return false; // Interface not found
    }
    
    InterfaceP intf = it->second;

    /* Dont delete physical interfaces */
    if (intf->iftype == INTF_TYPE_PHY) return true;     

    const char *ifname = intf->if_name.c_str();
    
    // Remove from both hashmaps
    node->intf_by_ifindex->erase(it);
    node->intf_by_name->erase(ifname);

    return true;
}

Interface* 
node_global_intf_map_lookup_by_ifindex(node_t *node, uint32_t ifindex) {
    
    if (!node) return nullptr;
    if (!node->intf_by_ifindex) return nullptr;
    
    auto it = node->intf_by_ifindex->find(ifindex);
    if (it == node->intf_by_ifindex->end()) {
        return nullptr;
    }
    
    return it->second.get();
}
