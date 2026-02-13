#include <assert.h>
#include "gre.h"
#include "greuapi.h"
#include "../layer3.h"
#include "../../Interface/InterfaceUApi.h"
#include "../../tcpip_notif.h"
#include "../../pkt_block.h"
#include "../../tcpconst.h"
#include "../../Tracer/tracer.h"

extern void
promote_pkt_to_layer3(node_t *node,           
                      Interface *interface, 
                      pkt_block_t *pkt_block, 
                      int L3_protocol_number) ;

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
    gre_shared_ptr->ifindex = node_get_sequence_no(node);

    if (!node_interface_insert(node, gre_shared_ptr.get())) {
        cprintf ("Error : Failed to insert GRE tunnel interface\n");
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

    interface_uninstall_local_v4_routes  (node, tunnel);

    /* Send Delete notification to all Subscribers */
     SET_BIT(if_change_flags, IF_DELETE_F);
     nfc_intf_invoke_notification_to_sbscribers(
	    tunnel, &intf_prop_changed, if_change_flags);        

    node_interface_delete_by_name(node, (const char *)intf_name);
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

void 
gre_encasulate (node_t *node, pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    hdr_type_t hdr_type = pkt_block_get_starting_hdr(pkt_block);
    uint16_t gre_inner_hdr_type = tcp_ip_convert_internal_proto_to_std_proto (hdr_type);
    
    /* Expland the size of the pkt by GRE HDR size */
    pkt_block_expand_buffer_left (pkt_block, sizeof (gre_hdr_t) ); 
    gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    /* Fill GRE packet Hdr contents*/
    memset (gre_hdr, 0, sizeof (gre_hdr_t));
    gre_hdr->protocol_type = htons(gre_inner_hdr_type);
    pkt_block_set_starting_hdr_type (pkt_block, GRE_HDR);        
    tracer (node->dptr, DTUNNEL | DFLOW, 
        "GRE Encapsulation %s\n", pkt_block_str (pkt_block));    
}

void 
gre_decapsulate (node_t *node, pkt_block_t *pkt_block, Interface *gre_interface) {

    uint8_t *pkt;
    pkt_size_t pkt_size;

    assert (pkt_block_get_starting_hdr(pkt_block) == GRE_HDR);

    if (!gre_interface) {
         tracer (node->dptr, DTUNNEL | DFLOW | DERR, 
            "Error : Pkt %s : Arrived on non-existant GRE Tunnel Interface\n", 
                pkt_block_str (pkt_block));
        return;
    }
    
    gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt_block_get_pkt(pkt_block, NULL);
    GRETunnelInterface *gre_intf = 
        dynamic_cast <GRETunnelInterface *> (gre_interface);

    gre_intf->pkt_recv++;

    if (!gre_intf->IsGRETunnelActive() || !gre_intf->is_up) {
        tracer (node->dptr, DTUNNEL | DFLOW | DERR, 
            "Error : Pkt : %s : Dropped, GRE Tunnel %s is not Active/Up\n", 
                pkt_block_str (pkt_block), gre_intf->if_name.c_str());
        return;
    }

    pkt = pkt_block_get_pkt (pkt_block, &pkt_size);
    pkt_block_set_new_pkt (pkt_block, 
        (uint8_t *)(gre_hdr + 1), pkt_size - sizeof (gre_hdr_t));

    switch (htons(gre_hdr->protocol_type)) {

        case ETH_IP:
        {
            pkt_block_set_starting_hdr_type (pkt_block, IP_HDR);
            tracer (node->dptr, DTUNNEL | DFLOW, 
                "GRE Decapsulation %s\n", pkt_block_str (pkt_block));    
            layer3_ip_route_pkt (node, gre_interface, pkt_block);
        }
        break;

        case PROTO_GRE_ENCAP_ETHERNET:
        {
             pkt_block_set_starting_hdr_type (pkt_block, ETH_HDR);
            tracer (node->dptr, DTUNNEL | DFLOW, 
                "GRE Decapsulation %s\n", pkt_block_str (pkt_block));                    
             dp_pkt_receive(node, gre_interface, pkt_block);
        }
        break;
    }
}

Interface *
gre_lookup_tunnel_intf (node_t *node, uint32_t src_ip, uint32_t dst_ip) {

    Interface *intf;
    GRETunnelInterface *gre_intf ;

    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

        if (intf->iftype != INTF_TYPE_GRE_TUNNEL)  continue;
        gre_intf = dynamic_cast <GRETunnelInterface *> (intf);
        if (gre_intf->tunnel_src_ip != src_ip) continue;
        if (gre_intf->tunnel_dst_ip != dst_ip)  continue;
        return intf;
    }
    ITERATE_NODE_INTERFACES_END(node, intf);

    return NULL;
}
