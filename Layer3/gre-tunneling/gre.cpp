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
        printf ("Error : %s already exist\n", intf_name);
        return false;
    }

    int empty_intf_slot = node_get_intf_available_slot(node);

    if (empty_intf_slot < 0) {

        printf ("Error : No NIC slot available in a device\n");
        return false;
    }

    tunnel = new GRETunnelInterface(tunnel_id);

    if (!tunnel ) {
        printf ("Error : GRE Tunnel creation failed\n");
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
        printf ("Error : Tunnel Do Not  Exist\n");
        return;
    }

    GRETunnelInterface *gre_tunnel = dynamic_cast <GRETunnelInterface *> (tunnel);
    gre_tunnel->SetTunnelSrcIp(tcp_ip_covert_ip_p_to_n(src_addr));
}

void
gre_tunnel_unset_src_addr (node_t *node, uint16_t tunnel_id) {

    Interface *tunnel;
    byte intf_name[IF_NAME_SIZE];

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", tunnel_id);

    tunnel = node_get_intf_by_name(node, (const char *)intf_name);

    if (!tunnel) {
        printf ("Error : Tunnel Do Not  Exist\n");
        return;
    }

    GRETunnelInterface *gre_tunnel = dynamic_cast <GRETunnelInterface *> (tunnel);
    gre_tunnel->UnSetTunnelSrcIp();
}

void
 gre_tunnel_set_src_interface (node_t *node, uint16_t tunnel_id, c_string if_name) {

    Interface *tunnel;
    Interface *phyIntf;

    byte intf_name[IF_NAME_SIZE];

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", tunnel_id);

    tunnel = node_get_intf_by_name(node, (const char *)intf_name);

    if (!tunnel) {
        printf ("Error : Tunnel Do Not  Exist\n");
        return;
    }

    if (tunnel->iftype != INTF_TYPE_GRE_TUNNEL) {
        printf ("Error : Specified tunnel is not GRE tunnel\n");
        return;
    }

    phyIntf = node_get_intf_by_name(node, (const char *)if_name);

    if (!phyIntf) {
        printf ("Error : Source Interface do not exist\n");
        return;
    }

    if (phyIntf->GetL2Mode() != LAN_MODE_NONE) {
        printf ("Error : Source Interface must be P2P interface\n");
        return;
    }

    GRETunnelInterface *gre_tunnel = dynamic_cast <GRETunnelInterface *> (tunnel);
    gre_tunnel->SetTunnelSource(dynamic_cast <PhysicalInterface *>(phyIntf));
 }

 void
 gre_tunnel_unset_src_interface (node_t *node, uint16_t tunnel_id) {

    Interface *tunnel;
    PhysicalInterface *phyIntf;

    byte intf_name[IF_NAME_SIZE];

    snprintf ((char *)intf_name, IF_NAME_SIZE, "tunnel%d", tunnel_id);

    tunnel = node_get_intf_by_name(node, (const char *)intf_name);

    if (!tunnel) {
        printf ("Error : Tunnel Do Not  Exist\n");
        return;
    }

    if (tunnel->iftype != INTF_TYPE_GRE_TUNNEL) {
        printf ("Error : Specified tunnel is not GRE tunnel\n");
        return;
    }

    GRETunnelInterface *gre_tunnel = dynamic_cast <GRETunnelInterface *> (tunnel);

    if (!(gre_tunnel->config_flags & GRETunnelInterface::GRE_TUNNEL_SRC_INTF_SET)) {
        return;
    }

    assert(gre_tunnel->tunnel_src_intf);
    phyIntf =  dynamic_cast <PhysicalInterface *> (gre_tunnel->tunnel_src_intf);
    assert(phyIntf->used_as_underlying_tunnel_intf);
    phyIntf->used_as_underlying_tunnel_intf--;
    gre_tunnel->tunnel_src_intf = NULL;
    gre_tunnel->config_flags &= ~ GRETunnelInterface::GRE_TUNNEL_SRC_INTF_SET;
 }