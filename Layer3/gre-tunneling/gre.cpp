#include <assert.h>
#include "gre.h"
#include "greuapi.h"
#include "../layer3.h"
#include "../../Interface/InterfaceUApi.h"
#include "../../tcpip_notif.h"
#include "../../pkt_block.h"
#include "../../tcpconst.h"
#include "../../Tracer/tracer.h"
#include "../../vrf/vrf.h"
#include "../../dpal/cp2dp.h"

bool
gre_tunnel_create (node_t *node, uint32_t tunnel_id) {

    Interface *intf;
    byte intf_name[IF_NAME_SIZE];
    GRETunnelInterfaceP gre_shared_ptr ;

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", tunnel_id);
    intf = node_interface_lookup_by_name(node, (const char *)intf_name);

    if (intf) {
        return false;
    }

    /* Creating a new interface is a 2 step process as below.*/
    gre_shared_ptr = std::make_shared<GRETunnelInterface>(tunnel_id);
    gre_shared_ptr->SetSharedPtr(gre_shared_ptr);
    gre_shared_ptr->att_node = node;
    gre_shared_ptr->ifindex = interface_get_new_ifindex (node);
    intf = gre_shared_ptr.get();
    
    cp2dp_interface_create (node, intf);

    /* Add to VRF and global maps */
    if (!vrf_add_interface(NODE_DEF_VRF(node), intf)) {
        cprintf("Error : Failed to add GRE tunnel to VRF\n");
        return false;
    }
    
    if (!node_global_intf_map_insert(node, intf)) {
        cprintf("Error : Failed to add GRE tunnel to global map\n");
        vrf_del_interface(NODE_DEF_VRF(node), intf);
        return false;
    }
    
    return true;
}

bool
gre_tunnel_destroy (node_t *node, uint32_t tunnel_id) {
    
    Interface *tunnel;
    uint32_t if_change_flags = 0;
    byte intf_name[IF_NAME_SIZE];
    intf_prop_changed_t intf_prop_changed;

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", tunnel_id);
    memset (&intf_prop_changed, 0, sizeof (intf_prop_changed_t));

    tunnel = node_interface_lookup_by_name(node, (const char *)intf_name);

    if (!tunnel) {
        cprintf ("Error : Tunnel %s Do Not  Exist\n", intf_name);
        return false;
    }

    if (tunnel->IsCrossReferenced()) {
        cprintf ("Error : Tunnel is in use, can not be deleted\n");
        return false;
    }

    /* Send Delete notification to all Subscribers */
     SET_BIT(if_change_flags, IF_DELETE_F);
     nfc_intf_invoke_notification_to_sbscribers(
	   tunnel, &intf_prop_changed, if_change_flags);        

    /* User has to remove GRE tunnel inetrface from VRF first. We are here
        because interface has been already removed from vrf 
        config node <node-name> no interface tunnel 2 vrf <vrf-name>    
    */
    assert(node_global_intf_map_delete_by_name(node, (const char *)intf_name));
    return true;
}

void
gre_tunnel_set_src_addr (node_t *node, uint32_t tunnel_id, c_string src_addr) {

    Interface *tunnel;
    byte intf_name[IF_NAME_SIZE];

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", tunnel_id);

    tunnel = node_interface_lookup_by_name(node, (const char *)intf_name);

    if (!tunnel) {
        cprintf ("Error : Tunnel Do Not  Exist\n");
        return;
    }

    GRETunnelInterface *gre_tunnel = dynamic_cast <GRETunnelInterface *> (tunnel);

    if (src_addr) {
        gre_tunnel->SetTunnelSrcIp(tcp_ip_convert_ip_p_to_n(src_addr));
    }
    else {
        gre_tunnel->UnSetTunnelSrcIp();
    }
}

void
gre_tunnel_set_dst_addr (node_t *node, uint32_t tunnel_id, c_string dst_addr) {

    Interface *tunnel;
    byte intf_name[IF_NAME_SIZE];

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", tunnel_id);

    tunnel = node_interface_lookup_by_name(node, (const char *)intf_name);

    if (!tunnel) {
        cprintf ("Error : Tunnel Do Not  Exist\n");
        return;
    }

    GRETunnelInterface *gre_tunnel = dynamic_cast <GRETunnelInterface *> (tunnel);

    if (dst_addr) {
        gre_tunnel->SetTunnelDestination(tcp_ip_convert_ip_p_to_n(dst_addr));
    }
    else {
        gre_tunnel->SetTunnelDestination(0);
    }
}

bool
 gre_tunnel_set_src_interface (node_t *node, uint32_t tunnel_id, c_string if_name) {

    Interface *tunnel;
    Interface *phyIntf;

    byte intf_name[IF_NAME_SIZE];

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", tunnel_id);

    tunnel = node_interface_lookup_by_name(node, (const char *)intf_name);

    if (!tunnel) {
        cprintf ("Error : Tunnel Do Not  Exist\n");
        return false;
    }

    if (tunnel->iftype != INTF_TYPE_GRE_TUNNEL) {
        cprintf ("Error : Specified tunnel is not GRE tunnel\n");
        return false;
    }

    phyIntf = node_interface_lookup_by_name(node, (const char *)if_name);

    if (!phyIntf) {
        cprintf ("Error : Source Interface do not exist\n");
        return false;
    }

    if (phyIntf->GetL2Mode() != LAN_MODE_NONE) {
        cprintf ("Error : Source Interface must be P2P interface\n");
        return false;
    }

    GRETunnelInterface *gre_tunnel = dynamic_cast <GRETunnelInterface *> (tunnel);
    if (phyIntf) {
        return gre_tunnel->SetTunnelSource(dynamic_cast <PhysicalInterface *>(phyIntf));
    }
    else {
        return gre_tunnel->SetTunnelSource(NULL);
    }
 }

void 
gre_tunnel_set_lcl_ip_addr(node_t *node, 
                                             uint32_t gre_tun_id,
                                             c_string intf_ip_addr,
                                             uint8_t mask) {

    Interface *tunnel;
    byte intf_name[IF_NAME_SIZE];

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", gre_tun_id);

    tunnel = node_interface_lookup_by_name(node, (const char *)intf_name);

    if (!tunnel) {
        cprintf ("Error : Tunnel Do Not  Exist\n");
        return;
    }

    if (tunnel->iftype != INTF_TYPE_GRE_TUNNEL) {
        cprintf ("Error : Specified tunnel is not GRE tunnel\n");
        return;
    }

    if (intf_ip_addr && mask) {
        interface_set_ip_addr(node, tunnel, intf_ip_addr, mask);
    }
    else {
         interface_unset_ip_addr(node, tunnel, intf_ip_addr, mask);
    }
}

void
gre_interface_updates (event_dispatcher_t *ev_dis, void *arg, unsigned int arg_size) {

	intf_notif_data_t *intf_notif_data = 
		(intf_notif_data_t *)arg;

	uint32_t flags = intf_notif_data->change_flags;
	Interface *intf = intf_notif_data->interface.get();
	intf_prop_changed_t *old_intf_prop_changed =
            intf_notif_data->old_intf_prop_changed;
    
    /* GRE tunnel module dont need these events */
    if (intf->iftype == INTF_TYPE_GRE_TUNNEL ||
         intf->iftype ==  INTF_TYPE_VLAN) {
        return;
     }

    switch(flags) {
        case IF_UP_DOWN_CHANGE_F:
            //isis_handle_interface_up_down (intf, old_intf_prop_changed->up_status);
            break;
        case IF_IP_ADDR_CHANGE_F:
            /*isis_handle_interface_ip_addr_changed (intf, 
                    old_intf_prop_changed->ip_addr.ip_addr,
                    old_intf_prop_changed->ip_addr.mask);*/
         break;
        case IF_OPER_MODE_CHANGE_F:
        case IF_VLAN_MEMBERSHIP_CHANGE_F:
        case IF_METRIC_CHANGE_F :
        break;
        default: ;
    }
}

void 
gre_one_time_registration() {

    nfc_intf_register_for_events(gre_interface_updates);
}

