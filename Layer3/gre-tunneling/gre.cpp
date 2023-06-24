#include "gre.h"
#include "greuapi.h"
#include "../../Interface/InterfaceUApi.h"

bool
gre_tunnel_create (node_t *node, uint16_t tunnel_id) {

    Interface *tunnel;
    byte intf_name[IF_NAME_SIZE];

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", tunnel_id);

    tunnel = node_get_intf_by_name(node, (const char *)intf_name);

    if (tunnel) {
        cprintf ("Error : %s already exist\n", intf_name);
        return false;
    }

    int empty_intf_slot = node_get_intf_available_slot(node);

    if (empty_intf_slot < 0) {

        cprintf ("Error : No NIC slot available in a device\n");
        return false;
    }

    tunnel = new GRETunnelInterface(tunnel_id);

    if (!tunnel ) {
        cprintf ("Error : GRE Tunnel creation failed\n");
        return false;
    }

#if 0
    linkage_t *link = (linkage_t *)calloc(1, sizeof(linkage_t));
    link->Intf1 = tunnel;
    link->Intf1->link = link;
    link->cost = 1;
#endif

    node->intf[empty_intf_slot] = tunnel;

    tunnel->att_node = node;

    tcp_ip_init_intf_log_info(tunnel);

    return true;
}

bool
gre_tunnel_destroy (node_t *node, uint16_t tunnel_id) {

    return true;
}

void
gre_tunnel_set_src_addr (node_t *node, uint16_t tunnel_id, c_string src_addr) {

    Interface *tunnel;
    byte intf_name[IF_NAME_SIZE];

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", tunnel_id);

    tunnel = node_get_intf_by_name(node, (const char *)intf_name);

    if (!tunnel) {
        cprintf ("Error : Tunnel Do Not  Exist\n");
        return;
    }

    GRETunnelInterface *gre_tunnel = dynamic_cast <GRETunnelInterface *> (tunnel);

    if (src_addr) {
        gre_tunnel->SetTunnelSrcIp(tcp_ip_covert_ip_p_to_n(src_addr));
    }
    else {
        gre_tunnel->UnSetTunnelSrcIp();
    }
}

void
gre_tunnel_set_dst_addr (node_t *node, uint16_t tunnel_id, c_string dst_addr) {

    Interface *tunnel;
    byte intf_name[IF_NAME_SIZE];

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", tunnel_id);

    tunnel = node_get_intf_by_name(node, (const char *)intf_name);

    if (!tunnel) {
        cprintf ("Error : Tunnel Do Not  Exist\n");
        return;
    }

    GRETunnelInterface *gre_tunnel = dynamic_cast <GRETunnelInterface *> (tunnel);

    if (dst_addr) {
        gre_tunnel->SetTunnelDestination(tcp_ip_covert_ip_p_to_n(dst_addr));
    }
    else {
        gre_tunnel->SetTunnelDestination(0);
    }
}


void
 gre_tunnel_set_src_interface (node_t *node, uint16_t tunnel_id, c_string if_name) {

    Interface *tunnel;
    Interface *phyIntf;

    byte intf_name[IF_NAME_SIZE];

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", tunnel_id);

    tunnel = node_get_intf_by_name(node, (const char *)intf_name);

    if (!tunnel) {
        cprintf ("Error : Tunnel Do Not  Exist\n");
        return;
    }

    if (tunnel->iftype != INTF_TYPE_GRE_TUNNEL) {
        cprintf ("Error : Specified tunnel is not GRE tunnel\n");
        return;
    }

    phyIntf = node_get_intf_by_name(node, (const char *)if_name);

    if (!phyIntf) {
        cprintf ("Error : Source Interface do not exist\n");
        return;
    }

    if (phyIntf->GetL2Mode() != LAN_MODE_NONE) {
        cprintf ("Error : Source Interface must be P2P interface\n");
        return;
    }

    GRETunnelInterface *gre_tunnel = dynamic_cast <GRETunnelInterface *> (tunnel);
    if (phyIntf) {
        gre_tunnel->SetTunnelSource(dynamic_cast <PhysicalInterface *>(phyIntf));
    }
    else {
        gre_tunnel->SetTunnelSource(NULL);
    }
 }

void 
gre_tunnel_set_lcl_ip_addr(node_t *node, 
                                             uint16_t gre_tun_id,
                                             c_string intf_ip_addr,
                                             uint8_t mask) {

    Interface *tunnel;
    byte intf_name[IF_NAME_SIZE];

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", gre_tun_id);

    tunnel = node_get_intf_by_name(node, (const char *)intf_name);

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
         interface_unset_ip_addr(node, tunnel);
    }
}
