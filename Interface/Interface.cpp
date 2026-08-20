/*
 * =====================================================================================
 *
 *       Filename:  InterfaceBase.cpp
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/06/2022 11:39:18 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#include <assert.h>
#include <memory.h>
#include <pthread.h>
#include <stdio.h>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>
#include "../libs/common/l3_hdrs.h"
#include "../tcpconst.h"
#include "../utils.h"
#include "../libs/BitOp/bitsop.h"
#include "../FireWall/acl/acldb.h"
#include "../router_init.h"
#include "../libs/EventDispatcher/event_dispatcher.h"
#include "../Layer2/layer2.h"
#include "../Layer3/layer3.h"
#include "../Layer3/gre-tunneling/gre.h"
#include "../CLIBuilder/libcli.h"
#include "Interface.h"
#include "InterfaceUApi.h"
#include "../Layer2/transport_svc.h"
#include "../libs/Tracer/tracer.h"
#include "../libs/common/ipv6_utils.h"
#include "../RTM/rtm_nb_integ.h"
#include "../dpal/cp2dp.h"

extern void
snp_flow_init_flow_tree_root(avltree_t *avl_root);
extern int 
access_group_unconfig (node_t *node, 
                       Interface *intf, 
                       char *dirn, 
                       access_list_t *acc_lst) ;

extern void 
l2_switch_forward_frame(
                        node_t *node,
                        mac_table_t *mac_table,
                        dp_intf_t *vlan_bd_intf,
                        Interface *recv_intf, 
                        pkt_block_t *pkt_block);

extern void
dp_promote_pkt_to_layer3(dp_ctx_t *dp_ctx,
                         dp_vrf_t *vrf, 
                         dp_intf_t *interface, 
                         pkt_block_t *pkt_block);

extern bool LinuxRtr;

Interface::Interface(std::string if_name, InterfaceType_t iftype)
{
    this->if_name = std::move(if_name);
    this->iftype = iftype;
    this->att_node = NULL;
    this->link = NULL;
    this->is_up = true;
    this->ifindex = 0;
    this->cost = INTF_METRIC_DEFAULT;
    
    memset(this->padding3, 0, sizeof(padding3));

    this->rtm_local_rt_idx = 0;
    this->rtm_connected_rt_idx = 0;
    this->rtm_local_rt6_idx = 0;
    this->rtm_connected_rt6_idx = 0;
    this->rtm_link_local_rt6_idx = 0;

    this->vrf =  NULL;
    this->pkt_recv = 0;
    this->pkt_sent = 0;
    this->xmit_pkt_dropped = 0;
    this->recvd_pkt_dropped = 0;

    this->l2_egress_acc_lst = NULL;
    this->l2_ingress_acc_lst = NULL;

    this->l3_ingress_acc_lst = NULL;
    this->l3_egress_acc_lst = NULL;

    this->isis_intf_info = NULL;
    this->intfP.reset(); 
}

Interface::~Interface()
{
    uint32_t if_index = this->ifindex;
    
    InterfaceReleaseAllResources();

    assert (!rtm_local_rt_idx);
    assert (!rtm_connected_rt_idx);
    assert (!rtm_local_rt6_idx);
    assert (!rtm_connected_rt6_idx);
    assert (!rtm_link_local_rt6_idx);
    
    assert (!l2_ingress_acc_lst);
    assert (!l2_egress_acc_lst);
    assert (!l3_ingress_acc_lst);
    assert (!l3_egress_acc_lst);
    assert (!isis_intf_info);
    assert (!vrf);
    assert (!ifindex);

    cprintf ("CP : Intf %s deleted\n", this->if_name.c_str());

    
    if (iftype != INTF_TYPE_AC && /* AC are deleted in DP when they are dettached from BD */
        iftype != INTF_TYPE_NVE) {  /* NVE is persistent interface in DP */
        
        cp2dp_interface_delete (this->att_node, if_index);
    }
}

InterfaceP 
Interface::GetSharedPtr () {
    return this->intfP.lock();
}

void
Interface::SetSharedPtr (InterfaceP intfP) {
    this->intfP = intfP;
}


uint32_t
Interface::GetIntfCost()
{
    return this->cost;
}

vrf_t *
Interface::GetVRF() {
    return this->vrf;
}

void Interface::PrintInterfaceDetails()
{

    cprintf("%s   index = %u   Owning-Dev %s\n",
           this->if_name.c_str(), this->ifindex, this->att_node->node_name);

    cprintf("State : Administratively %s\n", this->is_up ? "Up" : "Down");

    cprintf("L2 access Lists : Ingress - %s, Egress - %s\n",
           this->l2_ingress_acc_lst ? (const char *)this->l2_ingress_acc_lst->name : "None",
           this->l2_egress_acc_lst ? (const char *)this->l2_egress_acc_lst->name : "None");

#if 0
    cprintf("L3 access Lists : Ingress - %s, Egress - %s\n",
           this->l3_ingress_acc_lst2 ? (const char *)this->l3_ingress_acc_lst2->name : "None",
           this->l3_egress_acc_lst2 ? (const char *)this->l3_egress_acc_lst2->name : "None");
#endif

    if (this->isis_intf_info)
    {
        cprintf("ISIS Running\n");
    }

    cprintf("Metric = %u\n", this->GetIntfCost());
    cprintf ("vrf = %s\n", this->vrf ? this->vrf->vrf_name : DEF_VRF_NAME);
    cprintf ("shared_ptr count = %u\n", this->GetSharedPtr().use_count());
}

node_t *
Interface::GetNbrNode()
{
    Interface *interface = this;
    assert(this->att_node);
    assert(this->link);

    linkage_t *link = interface->link;
    if (link->Intf1.get() == interface)
        return link->Intf2->att_node;
    else
        return link->Intf1->att_node;
}

Interface *
Interface::GetOtherInterface()
{
    return this->link->Intf1.get() == this ? this->link->Intf2.get() : this->link->Intf1.get();
}


void Interface::SetMacAddr(mac_addr_t *mac_add)
{

}

mac_addr_t *
Interface::GetMacAddr()
{
    return NULL;
}

bool Interface::IsIpConfigured()
{
    return false;
}

bool Interface::IsIpv6Configured()
{
    return false;
}

void Interface::InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask)
{
    
}

void Interface::InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask)
{
    
}

void 
Interface::InterfaceSetIpv6LinkLocalAddress(unsigned char (*mac)[6]) {
    
}

void 
Interface::InterfaceGetIpv6LinkLocalAddress(uint8_t (*addr)[16]) {
        
}

vlan_id_t
Interface::GetVlanId()
{
    return 0;
}

bool Interface::IsVlanTrunked(vlan_id_t vlan_id)
{
    return false;
}

void Interface::SetSwitchport(bool enable)
{

}

bool Interface::IntfConfigTransportSvc(std::string& trans_svc) 
{
   return false;
}

bool Interface::IntfUnConfigTransportSvc(std::string& trans_svc) 
{
    return false;
}

bool Interface::GetSwitchport()
{
    return false;
}

IntfL2Mode
Interface::GetL2Mode()
{

    return LAN_MODE_NONE;
}

void Interface::SetL2Mode(IntfL2Mode l2_mode)
{

}

bool Interface::IntfConfigVlan(vlan_id_t vlan_id, bool add)
{
    
    return false;
}

bool Interface::IsSameSubnet(uint32_t ip_addr)
{

    if (!this->IsIpConfigured()) return false;
     return false;
}

bool 
Interface:: IsInterfaceUp(vlan_id_t vlan_id) {

    return this->is_up;
}

void 
Interface::InterfaceReleaseAllResources() {

    if (this->link) {
        /* Nothing to do, we dont break topology !*/
    }

    if (this->l2_ingress_acc_lst) {
        assert(0); /* Not Supported Yet*/
    }

    if (this->l2_egress_acc_lst) {
        assert(0); /* Not Supported Yet*/
    }

    if (this->l3_ingress_acc_lst) {
        access_group_unconfig (this->att_node, this, "in", this->l3_ingress_acc_lst);
    }

    if (this->l3_egress_acc_lst) {
        access_group_unconfig (this->att_node, this, "out", this->l3_egress_acc_lst);
    }

    /* This is configuration, this fn call must not see it set*/
    assert (!this->isis_intf_info);

    /* AC interfaces borrow the physical ifindex and zero it before
       destruction so the bitmap bit is not released twice. */
    if (this->ifindex) {
        interface_release_index(this->att_node, this->ifindex);
        this->ifindex = 0;
    }
}

bool 
Interface::IsSVI () {

    return false;
}

void 
Interface::InterfaceSetIpv6AddressMask(uint8_t (*addr)[16], uint8_t prefix_len) {

}

void 
Interface::InterfaceGetIpv6AddressMask(uint8_t (*addr)[16], uint8_t *prefix_len) {

}

VlanInterfaceP 
Interface::GetAccessVlanIntf() {

    return nullptr;
}

uint32_t 
Interface::GetSockfd() {

    return sock_fd;
}

void 
Interface::SetSockfd(uint32_t sock_fd) {

    this->sock_fd = sock_fd;
}

bool Interface::HasL3Config(bool matchvrf) {return false;}

/* ************ PhysicalInterface ************ */
PhysicalInterface::PhysicalInterface(std::string ifname, InterfaceType_t iftype, mac_addr_t *mac_add)
    : Interface(ifname, iftype)
{
    this->switchport = false;
    
    if (mac_add)
        memcpy(this->mac_add.mac, mac_add->mac, sizeof(this->mac_add.mac));
    else
        memset (this->mac_add.mac, 0, sizeof(this->mac_add.mac));

    this->l2_mode = LAN_MODE_NONE;
    memset (this->v6addr_link_local, 0, sizeof(this->v6addr_link_local));
    memset (this->v6addr, 0, sizeof(this->v6addr));
    this->v6mask = 0;

    this->ip_addr = 0;
    this->mask = 0;
    this->used_as_underlying_tunnel_intf = 0;
    this->trans_svc = NULL;
    this->access_vlan_intf = nullptr;
    this->bd_ac = nullptr;
}

PhysicalInterface::~PhysicalInterface()
{
    InterfaceReleaseAllResources();
}

void PhysicalInterface::SetMacAddr(mac_addr_t *mac_add)
{

    if (mac_add)
    {
        memcpy(this->mac_add.mac, mac_add->mac, sizeof(this->mac_add.mac));
    }
}

mac_addr_t *
PhysicalInterface::GetMacAddr()
{

    return &this->mac_add;
}

void PhysicalInterface::PrintInterfaceDetails()
{

    byte ip_addr[IPV4_ADDR_LEN_STR];
    char v6_addr_str[48];

    cprintf("MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           this->mac_add.mac[0],
           this->mac_add.mac[1],
           this->mac_add.mac[2],
           this->mac_add.mac[3],
           this->mac_add.mac[4],
           this->mac_add.mac[5]);

    if (this->IsIpConfigured())
    {
        cprintf("IP Addr : %s/%d\n", 
            tcp_ip_covert_ip_n_to_p(this->ip_addr, ip_addr), this->mask);
    }
    else
    {
        cprintf("IP Addr : Not Configured\n");
    }

    /* print ipv6 link local addresses */
    inet_ntop(AF_INET6, this->v6addr_link_local, v6_addr_str, INET6_ADDRSTRLEN);
    cprintf ("link-local : %s\n", v6_addr_str);

    cprintf("Vlan L2 Mode : %s\n",
        PhysicalInterface::L2ModeToString(this->l2_mode).c_str());

    this->Interface::PrintInterfaceDetails();
}

void PhysicalInterface::InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask)
{

    if (this->switchport && ip_addr)
    {
        cprintf("Error : Remove L2 Config first\n");
        return;
    }

    this->ip_addr = ip_addr;
    this->mask = mask;
}

void PhysicalInterface::InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask)
{

    *ip_addr = this->ip_addr;
    *mask = this->mask;
}

void 
PhysicalInterface::InterfaceSetIpv6LinkLocalAddress(unsigned char (*mac)[6]) {
        
        ipv6_auto_generate_link_local_address(mac, &this->v6addr_link_local);
}

void 
PhysicalInterface::InterfaceGetIpv6LinkLocalAddress(uint8_t (*addr)[16]) {
        
        memcpy (addr, this->v6addr_link_local, sizeof(this->v6addr_link_local));
}


bool PhysicalInterface::IsIpConfigured()
{

    if (this->ip_addr && this->mask)
        return true;
    return false;
}

bool PhysicalInterface::IsIpv6Configured()
{
    /* Check if IPv6 address is configured (non-zero) and mask is set */
    if (this->v6mask == 0)
        return false;
    
    /* Check if v6addr is not all zeros */
    for (int i = 0; i < 16; i++) {
        if (this->v6addr[i] != 0)
            return true;
    }
    
    return false;
}

std::string
PhysicalInterface::L2ModeToString(IntfL2Mode l2_mode)
{

    switch (l2_mode)
    {

    case LAN_MODE_NONE:
        return std::string("None");
    case LAN_ACCESS_MODE:
        return std::string("Access");
    case LAN_TRUNK_MODE:
        return std::string("Trunk");
    default:;
    }
    return "Unknown";
}

bool PhysicalInterface::IsVlanTrunked(vlan_id_t vlan_id)
{
    TransportService *tsp = this->trans_svc;
    if (!tsp) return false;
    for (auto it = tsp->vlanSet.begin(); it != tsp->vlanSet.end(); ++it) {
        if (*it == vlan_id) return true;
    }
    return false;
}


vlan_id_t
PhysicalInterface::GetVlanId()
{
    if (this->l2_mode == LAN_MODE_NONE)
        return 0;

     if (this->l2_mode == LAN_ACCESS_MODE) {
        return this->access_vlan_intf->GetVlanId();
     }

     return 0;
}

void PhysicalInterface::SetSwitchport(bool enable)
{

    if (this->switchport == enable)
        return;

    if (!enable) {
        if (this->access_vlan_intf || this->trans_svc || this->bd_ac) {
            cprintf("Error : Remove L2 Config first (VLAN or bridge-domain membership)\n");
            return;
        }
    }

    if (this->used_as_underlying_tunnel_intf > 0)
    {
        cprintf("Error : Intf being used as underlying tunnel interface\n");
        return;
    }

    if (enable && this->IsIpConfigured()) {
        cprintf("Error : Remove L3 config first\n");
        return;
    }

    if (enable)
    {
        this->InterfaceSetIpAddressMask(0, 0);
        this->l2_mode = LAN_MODE_NONE;
    }
    else
    {
        this->l2_mode = LAN_MODE_NONE;
    }
    this->switchport = enable;
    cp2dp_send_intf_switchport_update(this->att_node, this->ifindex,enable ? 1 : 0);    
}

bool PhysicalInterface::GetSwitchport()
{

    return this->switchport;
}


IntfL2Mode
PhysicalInterface::GetL2Mode()
{

    return this->l2_mode;
}

void PhysicalInterface::SetL2Mode(IntfL2Mode l2_mode)
{

    if (this->IsIpConfigured())
    {
        cprintf("Error : Remove L3 config first\n");
        return;
    }

    if (this->used_as_underlying_tunnel_intf > 0)
    {
        cprintf("Error : Intf being used as underlying tunnel interface\n");
        return;
    }
    
    if (this->trans_svc) {

        cprintf("Error : Intf being used in Transport Service\n");
        return;
    }

    if (this->l2_mode == l2_mode)
        return;

    if (l2_mode != LAN_MODE_NONE &&
             this->l2_mode != LAN_MODE_NONE)
    {
        cprintf("Error : Remove configured L2 Mode first\n");
        return;
    }

    this->l2_mode = l2_mode;
}

bool
PhysicalInterface::IntfConfigTransportSvc(std::string& trans_svc_name) {

    if (!this->switchport) {
        printf ("Error : Interface %s is not L2 interface\n", this->if_name.c_str());
        return false;
    }

    if (interface_is_bd_member(this)) {
        cprintf("Error : Interface %s is a bridge-domain member, cannot attach transport service\n",
                this->if_name.c_str());
        return false;
    }

    TransportService *trans_svc_obj = TransportServiceLookUp (this->att_node->TransPortSvcDB, trans_svc_name);
    
    if (!trans_svc_obj) {
        printf ("Error : Transport Svc do not exist\n");
        return false;
    }

    if (this->trans_svc == trans_svc_obj) return true;

    /* Remove old Transport svc if any*/
    if (this->trans_svc) {
        this->trans_svc->DeAttachInterface(this);
    }

    trans_svc_obj->AttachInterface(this);
    return true;
}

bool 
PhysicalInterface::IntfUnConfigTransportSvc(std::string& trans_svc_name) {

    if (!this->trans_svc) return true;
    TransportService *trans_svc_obj = TransportServiceLookUp (this->att_node->TransPortSvcDB, trans_svc_name);
    if (!trans_svc_obj) return true;
    if (this->trans_svc != trans_svc_obj) return true;
    this->trans_svc->DeAttachInterface (this);
    this->trans_svc = NULL;
    return true;
}

bool 
PhysicalInterface::IntfConfigVlan(vlan_id_t vlan_id, bool add)
{

    int i;
    if (!this->switchport)
        return false;
    if (interface_is_bd_member(this))
    {
        cprintf("Error : Interface %s is a bridge-domain member, cannot configure VLAN\n",
                this->if_name.c_str());
        return false;
    }
    if (this->used_as_underlying_tunnel_intf > 0)
    {
        cprintf("Error : Intf being used as underlying tunnel interface");
        return false;
    }

    if (this->GetL2Mode() == LAN_TRUNK_MODE) {
        cprintf ("Error : Cannot (Un)configure Access Vlan to Interface in Trunk Mode");
        return false;
    }

    if (add)
    {
        if (this->access_vlan_intf && 
                this->access_vlan_intf->GetVlanId() == vlan_id) return true;

        if (this->access_vlan_intf)
        {
            cprintf("Error : Access Mode Interface already in vlan %u", this->access_vlan_intf->GetVlanId());
            return false;
        }

        VlanInterface *vlan_intf = VlanInterface::VlanInterfaceLookUp(this->att_node, vlan_id);

        if (!vlan_intf)
        {
            cprintf("Error : Node %s : Vlan Interface not found", this->att_node->node_name);
            return false;
        }        

        this->access_vlan_intf = std::dynamic_pointer_cast<VlanInterface>
                (VlanInterface::VlanInterfaceLookUp(this->att_node, vlan_id)->GetSharedPtr());

        this->access_vlan_intf->access_member_intf_lst.push_back(this->GetSharedPtr());
        this->l2_mode = LAN_ACCESS_MODE;

        cp2dp_send_switchport_intf_access(this->att_node, this, true);
        cp2dp_send_vlan_add_access_port (this->att_node, vlan_id, this->ifindex, true);
        return true;
    }
    else
    {
        if (this->access_vlan_intf->GetVlanId() == vlan_id)
            {
                this->access_vlan_intf->access_member_intf_lst.erase(
                    std::remove (this->access_vlan_intf->access_member_intf_lst.begin(), this->access_vlan_intf->access_member_intf_lst.end(),
                    this->GetSharedPtr()),
                    this->access_vlan_intf->access_member_intf_lst.end());
                this->access_vlan_intf = NULL;
                this->l2_mode = LAN_MODE_NONE;
                
                cp2dp_send_vlan_add_access_port (this->att_node, vlan_id, this->ifindex, false);
                cp2dp_send_switchport_intf_access(this->att_node, this, false);
                return true;
            }

            {
                cprintf("Error : Node %s : Interface not in vlan %u", this->att_node->node_name, vlan_id);
                return false;
            }
    }
    return true;
}

bool PhysicalInterface::IsSameSubnet(uint32_t ip_addr)
{

    uint8_t mask;
    uint32_t intf_ip_addr;
    uint32_t subnet_mask = ~0;

    if (!this->IsIpConfigured())
        return false;

    this->InterfaceGetIpAddressMask(&intf_ip_addr, &mask);

    if (mask != 32)
    {
        subnet_mask = subnet_mask << (32 - mask);
    }

    return ((intf_ip_addr & subnet_mask) == (ip_addr & subnet_mask));
}

bool 
PhysicalInterface:: IsInterfaceUp(vlan_id_t vlan_id) {

    if (!this->is_up) return false;

    if (this->IsIpConfigured()) return this->is_up;
    
    if (this->switchport && vlan_id) {

        if (this->access_vlan_intf) {
            return this->access_vlan_intf->IsInterfaceUp(vlan_id);
        }
        else {
            VlanInterface *vlan_intf = VlanInterface::VlanInterfaceLookUp(this->att_node, vlan_id);
            if (vlan_intf) {
                return vlan_intf->IsInterfaceUp(vlan_id);
            }
        }
    }
    return true;
}

void 
PhysicalInterface::InterfaceReleaseAllResources() {

    assert (this->used_as_underlying_tunnel_intf == 0);

    /* Handling attached TSP*/
    if (this->trans_svc) {
        this->IntfUnConfigTransportSvc (this->trans_svc->trans_svc);
    }
    
    /* Handling access Vlan Interface*/
    if (this->access_vlan_intf) {
        this->IntfConfigVlan (this->access_vlan_intf->GetVlanId(), false);
    }

    this->SetSwitchport (false);
}


bool
PhysicalInterface::IsCrossReferenced() {

    if (LinuxRtr) {
        /* We are also listening on this interface */
        return (this->GetSharedPtr().use_count() > (PHY_ETH_IF_DEF_REFCOUNT + 1 + 1)) ;
    }

    return this->GetSharedPtr().use_count() > (PHY_ETH_IF_DEF_REFCOUNT + 1);
}

void 
PhysicalInterface::InterfaceSetIpv6AddressMask(uint8_t (*addr)[16], uint8_t prefix_len) {

    memcpy(this->v6addr, addr, 16);
    this->v6mask = prefix_len;
}

void 
PhysicalInterface::InterfaceGetIpv6AddressMask(uint8_t (*addr)[16], uint8_t *prefix_len) {

    memcpy(addr, this->v6addr, 16);
    *prefix_len = this->v6mask;
}

VlanInterfaceP 
PhysicalInterface::GetAccessVlanIntf() {

    return this->access_vlan_intf;
}

bool PhysicalInterface::HasL3Config(bool matchvrf) {

    /* VRF itself is an L3 config */
    if (matchvrf && this->vrf) return true;

    /* IF IP address is already configured, not eligible */
    if (this->IsIpConfigured()) return true;

    /* If any Routing protocol configured , not eligible */
    if (this->isis_intf_info) return true;

    /* If ACLs configured, not eligible */
    if (this->l3_egress_acc_lst ||
        this->l3_ingress_acc_lst) return true;
    
    /* If used by any other config , not eligible */
    //if (this->IsCrossReferenced()) return true;

    return false;
}

/* ************ Virtual Interface ************ */
VirtualInterface::VirtualInterface(std::string ifname, InterfaceType_t iftype)
    : Interface(ifname, iftype)
{
}

VirtualInterface::~VirtualInterface()
{
}

void VirtualInterface::PrintInterfaceDetails()
{

    cprintf("pkt recvd : %u   pkt sent : %u   xmit pkt dropped : %u    recvd pkt dropped : %u\n",
           this->pkt_recv, this->pkt_sent, 
           this->xmit_pkt_dropped,
           this->recvd_pkt_dropped);

    this->Interface::PrintInterfaceDetails();
}


/* ************ GRETunnelInterface ************ */
GRETunnelInterface::GRETunnelInterface(uint32_t tunnel_id)

    : VirtualInterface(std::string("tunnel") + std::to_string(tunnel_id), INTF_TYPE_GRE_TUNNEL)
{
    this->tunnel_id = tunnel_id;
    this->config_flags = (uint16_t)0;
    this->config_flags |= GRE_TUNNEL_TUNNEL_ID_SET;
    this->tunnel_src_ip = 0;
    this->tunnel_dst_ip = 0;
    this->lcl_ip = 0;
    this->mask = 0;
    this->is_active = false;
    this->virtual_port_intf = nullptr;
    this->tunnel_src_intf = nullptr;
    memset(this->padding, 0, sizeof(padding));
}

GRETunnelInterface::~GRETunnelInterface() {

    InterfaceReleaseAllResources();
    assert (!this->tunnel_src_intf);
}

uint32_t
GRETunnelInterface::GetTunnelId()
{
    return this->tunnel_id;
}

bool GRETunnelInterface::IsGRETunnelActive()
{
    bool rc = false;

    if ((this->config_flags & GRE_TUNNEL_TUNNEL_ID_SET) &&
         (this->config_flags & GRE_TUNNEL_SRC_ADDR_SET || 
                this->config_flags & GRE_TUNNEL_SRC_INTF_SET) &&
        (this->config_flags & GRE_TUNNEL_DST_ADDR_SET) &&
            (this->config_flags & GRE_TUNNEL_OVLAY_IP_SET) &&
            this->is_up &&
            this->vrf)
    {
        rc = true;
    }

    if ( this->tunnel_src_intf) {

        if ( !this->tunnel_src_intf->IsInterfaceUp(0)  || 
                !this->tunnel_src_intf->IsIpConfigured()) {
            rc = false;
        }
    }

    return rc;
}

static void
gre_tunnel_update_local_v4_routes(GRETunnelInterface *gre_intf) {

    if (gre_intf->IsGRETunnelActive() && gre_intf->IsIpConfigured()) {
        if (!gre_intf->rtm_local_rt_idx || !gre_intf->rtm_connected_rt_idx) {
            interface_install_local_v4_routes(gre_intf->att_node, gre_intf);
        }
    } else if (gre_intf->rtm_local_rt_idx || gre_intf->rtm_connected_rt_idx) {
        interface_uninstall_local_v4_routes(gre_intf->att_node, gre_intf);
    }
}

static uint32_t
gre_tunnel_effective_src_ip(GRETunnelInterface *gre_intf) {

    if (gre_intf->config_flags & GRE_TUNNEL_SRC_ADDR_SET) {
        return gre_intf->tunnel_src_ip;
    }

    if ((gre_intf->config_flags & GRE_TUNNEL_SRC_INTF_SET) &&
            gre_intf->tunnel_src_intf) {
        uint32_t ip = 0;
        uint8_t mask = 0;
        gre_intf->tunnel_src_intf->InterfaceGetIpAddressMask(&ip, &mask);
        return ip;
    }

    return 0;
}

static void
gre_tunnel_cp2dp_sync_attrs(GRETunnelInterface *gre_intf) {

    bool tunnel_up = gre_intf->IsGRETunnelActive();

    cp2dp_send_intf_gre_tunnel_update(
        gre_intf->att_node,
        gre_intf->ifindex,
        tunnel_up ? gre_intf->lcl_ip : 0,
        tunnel_up ? gre_intf->mask : 0,
        gre_tunnel_effective_src_ip(gre_intf),
        gre_intf->tunnel_dst_ip,
        tunnel_up);
}

bool GRETunnelInterface::SetTunnelSource(PhysicalInterface *interface)
{

    uint32_t ip_addr;
    uint8_t mask;

    if (interface)
    {
        if (this->tunnel_src_intf == interface->GetSharedPtr())
        {
            return true;
        }
        if (this->tunnel_src_intf &&
            this->tunnel_src_intf != interface->GetSharedPtr())
        {
            cprintf("Error : Tunnel Src Interface %s already set\n",
                    this->tunnel_src_intf->if_name.c_str());
            return false;
        }
        this->tunnel_src_intf = std::dynamic_pointer_cast<PhysicalInterface>(interface->GetSharedPtr());
        interface->used_as_underlying_tunnel_intf++;
        this->config_flags |= GRE_TUNNEL_SRC_INTF_SET;
        gre_tunnel_check_and_activate_tunnel();
    }
    else
    {
        if (this->tunnel_src_intf == NULL)
            return true;
        PhysicalInterface *tunnel_src_intf = std::dynamic_pointer_cast<PhysicalInterface>(this->tunnel_src_intf).get();
        tunnel_src_intf->used_as_underlying_tunnel_intf--;
        this->tunnel_src_intf = nullptr;
        this->config_flags &= ~GRE_TUNNEL_SRC_INTF_SET;
        gre_deactivate_tunnel();
    }
    return true;
}

void 
GRETunnelInterface::SetTunnelDestination(uint32_t ip_addr)
{

    this->tunnel_dst_ip = ip_addr;
    if (ip_addr) {
        this->config_flags |= GRE_TUNNEL_DST_ADDR_SET;
        gre_tunnel_check_and_activate_tunnel ();
    }
    else {
        this->config_flags &= ~GRE_TUNNEL_DST_ADDR_SET;
        gre_deactivate_tunnel ();
    }
}

void 
GRETunnelInterface::SetTunnelLclIpMask(uint32_t ip_addr, uint8_t mask)
{
    this->InterfaceSetIpAddressMask(ip_addr, mask);
    gre_tunnel_check_and_activate_tunnel ();
}

 bool 
 GRETunnelInterface::IsIpConfigured() {

    return (this->config_flags & GRE_TUNNEL_OVLAY_IP_SET);
 }

void 
GRETunnelInterface::SetTunnelSrcIp(uint32_t src_addr)
{

    if (this->config_flags & GRE_TUNNEL_SRC_ADDR_SET)
    {
        cprintf("Error : Src Address Already Set\n");
        return;
    }

    this->tunnel_src_ip = src_addr;
    this->config_flags |= GRE_TUNNEL_SRC_ADDR_SET;
    gre_tunnel_check_and_activate_tunnel ();
}

void
GRETunnelInterface::UnSetTunnelSrcIp()
{
    if (this->config_flags & GRE_TUNNEL_SRC_ADDR_SET)
    {
        this->tunnel_src_ip = 0;
        this->config_flags &= ~GRE_TUNNEL_SRC_ADDR_SET;
        gre_deactivate_tunnel ();
    }
}

void 
GRETunnelInterface::InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) {

        this->lcl_ip = ip_addr;
        this->mask = mask;
        if (ip_addr == 0 ) {
            this->config_flags &= ~GRE_TUNNEL_OVLAY_IP_SET;
            gre_deactivate_tunnel ();
            return;
        }
        this->config_flags |= GRE_TUNNEL_OVLAY_IP_SET;
        gre_tunnel_check_and_activate_tunnel ();
    }
    
void 
GRETunnelInterface::InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask) {

    if (this->config_flags & GRE_TUNNEL_OVLAY_IP_SET) {

        *ip_addr = this->lcl_ip;
        *mask = this->mask;
        return;
    }
    *ip_addr = 0;
    *mask = 0;
}

bool 
GRETunnelInterface::IsSameSubnet(uint32_t ip_addr)
{

    uint8_t mask;
    uint32_t intf_ip_addr;
    uint32_t subnet_mask = ~0;

    if (!this->IsIpConfigured())
        return false;

    this->InterfaceGetIpAddressMask(&intf_ip_addr, &mask);

    if (mask != 32)
    {
        subnet_mask = subnet_mask << (32 - mask);
    }

    return ((intf_ip_addr & subnet_mask) == (ip_addr & subnet_mask));
}

mac_addr_t *
GRETunnelInterface::GetMacAddr() {

    return &this->att_node->node_nw_prop.rmac;
}

void GRETunnelInterface::PrintInterfaceDetails()
{

    byte ip_str[IPV4_ADDR_LEN_STR];

    cprintf("Tunnel Id : %u\n", this->tunnel_id);
    cprintf("Tunnel Src Intf  : %s\n",
           this->tunnel_src_intf ? this->tunnel_src_intf->if_name.c_str() : "Not Set");
    if (this->config_flags & GRE_TUNNEL_SRC_ADDR_SET) {
        cprintf("Tunnel Src Ip : %s\n", tcp_ip_covert_ip_n_to_p(this->tunnel_src_ip, ip_str));
    }
    else if (this->config_flags & GRE_TUNNEL_SRC_INTF_SET ){
        uint32_t ip_addr;
        uint8_t mask;
        this->tunnel_src_intf->InterfaceGetIpAddressMask(&ip_addr, &mask);
        cprintf("Tunnel Src Ip : %s\n", tcp_ip_covert_ip_n_to_p(ip_addr, ip_str));
    }
    else {
        cprintf("Tunnel Src Ip : Nil\n"); 
    }
    cprintf("Tunnel Dst Ip : %s\n", tcp_ip_covert_ip_n_to_p(this->tunnel_dst_ip, ip_str));
    cprintf("Tunnel Lcl Ip/Mask : %s/%d\n", tcp_ip_covert_ip_n_to_p(this->lcl_ip, ip_str), this->mask);
    cprintf("Is Tunnel Active : %s\n", this->IsGRETunnelActive() ? "Y" : "N");

    this->VirtualInterface::PrintInterfaceDetails();
}

void 
GRETunnelInterface::InterfaceReleaseAllResources() {

    if (this->tunnel_src_intf) {
        this->SetTunnelSource(NULL);
    }
    gre_deactivate_tunnel ();
}

/* Stored in default way*/
bool 
GRETunnelInterface::IsCrossReferenced()
{
    return this->GetSharedPtr().use_count() > (GRE_IF_REFCOUNT + 1);
}

void 
GRETunnelInterface::gre_tunnel_check_and_activate_tunnel () {

    if (this->is_active && !this->IsGRETunnelActive()) {
        this->is_active = false;
    } else if (!this->is_active && this->IsGRETunnelActive()) {
        this->is_active = true;
    }

    gre_tunnel_update_local_v4_routes(this);
    gre_tunnel_cp2dp_sync_attrs(this);
}

void 
GRETunnelInterface::gre_deactivate_tunnel () {

    this->is_active = false;
    gre_tunnel_update_local_v4_routes(this);
    gre_tunnel_cp2dp_sync_attrs(this);
}

void
GRETunnelInterface::gre_tunnel_sync_dp_attrs() {

    gre_tunnel_cp2dp_sync_attrs(this);
}





/* ******** VirtualPort **************** */

VirtualPort::VirtualPort(std::string ifname) 
    : VirtualInterface(ifname, INTF_TYPE_VIRTUAL_PORT)
{
    this->olay_tunnel_intf = NULL;
    this->trans_svc = NULL;
}

VirtualPort::~VirtualPort()
{
    InterfaceReleaseAllResources();
    assert (!this->olay_tunnel_intf);
    assert (!this->trans_svc);
}

void
VirtualPort::PrintInterfaceDetails()
{
    cprintf("Overlay Tunnel : %s\n",
           this->olay_tunnel_intf ? this->olay_tunnel_intf->if_name.c_str() : "Not Set");

    if (this->trans_svc) {
        cprintf("Transport Service Profile : %s\n", this->trans_svc->trans_svc.c_str());
    }

    this->VirtualInterface::PrintInterfaceDetails();
}

bool 
VirtualPort::IsInterfaceUp(vlan_id_t vlan_id) 
{
    if (!this->is_up) return false;
   
    if (vlan_id) {

        VlanInterface *vlan_intf = VlanInterface::VlanInterfaceLookUp(this->att_node, vlan_id);
        if (vlan_intf)
        {
            return vlan_intf->IsInterfaceUp(vlan_id);
        }
    }
    return true;
}

void 
VirtualPort::InterfaceReleaseAllResources()
{
    /* Handling attached TSP*/
    if (this->trans_svc) {
        this->IntfUnConfigTransportSvc (this->trans_svc->trans_svc);
    }
}

bool 
VirtualPort::IsVlanTrunked (vlan_id_t vlan_id) {

    TransportService *tsp = this->trans_svc;
    if (!tsp) return false;
    for (auto it = tsp->vlanSet.begin(); it != tsp->vlanSet.end(); ++it) {
        if (*it == vlan_id) return true;
    }
    return false;
}

bool 
VirtualPort::GetSwitchport( ) {

    return true;
}

IntfL2Mode 
VirtualPort::GetL2Mode ( ) {

        return LAN_TRUNK_MODE;
}

bool 
VirtualPort::IntfConfigTransportSvc(std::string& trans_svc_name) 
{
    TransportService *trans_svc_obj = TransportServiceLookUp (this->att_node->TransPortSvcDB, trans_svc_name);
    
    if (!trans_svc_obj) {
        printf ("Error : Transport Svc do not exist\n");
        return false;
    }

    if (this->trans_svc == trans_svc_obj) return true;

    /* Remove old Transport svc if any*/
    if (this->trans_svc) {
        this->trans_svc->DeAttachInterface(this);
    }

    trans_svc_obj->AttachInterface(this);
    return true;
}

bool 
VirtualPort::IntfUnConfigTransportSvc(std::string& trans_svc_name) 
{
    if (!this->trans_svc) return true;
    TransportService *trans_svc_obj = TransportServiceLookUp (this->att_node->TransPortSvcDB, trans_svc_name);
    if (!trans_svc_obj) return true;
    if (this->trans_svc != trans_svc_obj) return true;
    this->trans_svc->DeAttachInterface (this);
    this->trans_svc = NULL;
    return true;
}

bool 
VirtualPort::BindOverlayTunnel(VirtualInterface *tunnel) {

    if (this->olay_tunnel_intf == tunnel->GetSharedPtr()) return true;

    if (this->olay_tunnel_intf) {
        cprintf ("Error : Overlay Tunnel already set\n");
        return false;
    }

    this->olay_tunnel_intf = std::dynamic_pointer_cast<VirtualInterface> (tunnel->GetSharedPtr());

    /* If tunnel is GRE Interface*/
    switch (tunnel->iftype) {
        case INTF_TYPE_GRE_TUNNEL:
            {
                GRETunnelInterface *gre_tunnel_intf = dynamic_cast<GRETunnelInterface *>(tunnel);
                gre_tunnel_intf->virtual_port_intf =
                    std::dynamic_pointer_cast<VirtualPort>( this->GetSharedPtr());
            }
            break;
    }
    return true;
}


bool 
VirtualPort::UnBindOverlayTunnel(VirtualInterface *tunnel) {

    Interface *overlay_tunnel;
    
    if (!this->olay_tunnel_intf) return true;

    if (this->olay_tunnel_intf != tunnel->GetSharedPtr()) {
        cprintf ("Error : Could not unbind Tunnel\n");
        return false;
    }

    overlay_tunnel = this->olay_tunnel_intf.get();
    switch (overlay_tunnel->iftype) {
        case INTF_TYPE_GRE_TUNNEL:
            {
                GRETunnelInterface *gre_tunnel_intf = dynamic_cast<GRETunnelInterface *>(overlay_tunnel);
                assert (gre_tunnel_intf->virtual_port_intf ==
                    std::dynamic_pointer_cast<VirtualPort>( this->GetSharedPtr()));
                gre_tunnel_intf->virtual_port_intf = nullptr;
            }
            break;
    }
    this->olay_tunnel_intf = nullptr;
    return true;
}

bool 
VirtualPort::IsCrossReferenced() {

    return this->GetSharedPtr().use_count() > (VPORT_IF_REFCOUNT + 1);
}



/* ************ VlanInterface ************ */

VlanInterface::VlanInterface(vlan_id_t vlan_id)
    : VirtualInterface("null", INTF_TYPE_VLAN)
{

    this->vlan_id = vlan_id;
    this->ip_addr = 0;
    this->mask = 0;
    this->vni_id = 0;  /* Initialize VNI to 0 (not configured) */
    
    std::string if_name = "vlan" + std::to_string(vlan_id);
    this->if_name = if_name;
}

VlanInterface::~VlanInterface() {

    InterfaceReleaseAllResources();
    assert (this->access_member_intf_lst.empty());
}

/* Vlan interfaces when are queued up in vlanDB, therefore taking refcount
    of 1. Anything more than that, vlaninterface is suppose to be in use.
    Can use default Implementation of Base Class
    */
bool
VlanInterface::IsCrossReferenced() {

    return this->GetSharedPtr().use_count() > (VLAN_IF_DEF_REFCOUNT + 1);
}

bool 
VlanInterface::HasL3Config(bool matchvrf) {

    if (matchvrf && this->vrf) return true;
    if (this->IsIpConfigured()) return true;
    return false;
}

void 
VlanInterface::PrintInterfaceDetails() {

    byte ip_str[IPV4_ADDR_LEN_STR];
    TransportService *tsp;
    Interface *member_ports;

    cprintf("Vlan Id : %u\n", this->vlan_id);

    if (this->IsIpConfigured()) {
        cprintf("  IP Addr : %s/%d\n", tcp_ip_covert_ip_n_to_p(this->ip_addr, ip_str), this->mask);
    }

    if (this->IsVniConfigured()) {
        cprintf("  VNI : %u\n", this->vni_id);
    }

    cprintf ("Trunk Member Ports: \n");

    ITERATE_VLAN_MEMBER_PORTS_TRUNK_BEGIN(this, member_ports) {

        cprintf ("  %s\n", member_ports->if_name.c_str());

    } ITERATE_VLAN_MEMBER_PORTS_TRUNK_END;

    cprintf("  Access Member Ports: \n");

    ITERATE_VLAN_MEMBER_PORTS_ACCESS_BEGIN(this, member_ports) {

        cprintf ("  %s\n", member_ports->if_name.c_str());

    } ITERATE_VLAN_MEMBER_PORTS_ACCESS_END;

    this->VirtualInterface::PrintInterfaceDetails();
}


void 
VlanInterface::InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) {

    this->ip_addr = ip_addr;
    this->mask = mask;
}

void 
VlanInterface::InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask) {

    *ip_addr = this->ip_addr;
    *mask = this->mask;
}

bool
VlanInterface::IsIpConfigured() {

    return (this->ip_addr && this->mask);
}

mac_addr_t *
VlanInterface::GetMacAddr( ) {

    return &this->att_node->node_nw_prop.rmac;
}

bool
VlanInterface::IsSameSubnet(uint32_t ip_addr) {

    if (!this->IsIpConfigured()) return false;
    uint32_t subnet_mask = ~0;
    if (this->mask != 32) {
        subnet_mask = subnet_mask << (32 - this->mask);
    }
    return ((this->ip_addr & subnet_mask) == (ip_addr & subnet_mask));
}

vlan_id_t
VlanInterface::GetVlanId() {

    return (vlan_id_t)this->vlan_id;
}

VlanInterface *
VlanInterface::VlanInterfaceLookUp(node_t *node, vlan_id_t vlan_id) {

    if (!node->vlan_intf_db) return NULL;
    auto it = node->vlan_intf_db->find(vlan_id);
    if (it != node->vlan_intf_db->end()) {
        return it->second.get();
    }
    return NULL;
}


bool 
VlanInterface::IsInterfaceUp(vlan_id_t vlan_id) {

    return this->is_up;
}

void 
VlanInterface::InterfaceReleaseAllResources() {

    assert (this->access_member_intf_lst.empty());
}

bool 
VlanInterface::IsSVI () {

    return ( this->ip_addr && this->mask ) ;
}

/* VNI Management Methods */
void
VlanInterface::SetVniId(uint32_t vni_id) {
    this->vni_id = vni_id;
}

uint32_t
VlanInterface::GetVniId() const {
    return this->vni_id;
}

bool
VlanInterface::IsVniConfigured() const {
    return (this->vni_id != 0);
}

/* Implement Loopback Interface Methods*/

LoopbackInterface::LoopbackInterface(std::string ifname)
    : VirtualInterface(ifname, INTF_TYPE_LOOPBACK)
{
    this->ip_addr = 0;
    this->mask = 0;
    memset(this->v6addr, 0, sizeof(this->v6addr));
    this->v6mask = 0;
}

LoopbackInterface::~LoopbackInterface()
{
    InterfaceReleaseAllResources();
}

void LoopbackInterface::PrintInterfaceDetails()
{

    unsigned char ip_addr[IPV4_ADDR_LEN_STR];
    unsigned char v6_addr_str[INET6_ADDRSTRLEN];

    cprintf("IP Addr : %s/%d\n", tcp_ip_covert_ip_n_to_p(this->ip_addr, ip_addr), this->mask);
    inet_ntop(AF_INET6, this->v6addr, (char *)v6_addr_str, INET6_ADDRSTRLEN);
    cprintf ("IPv6 Addr : %s/%d\n", v6_addr_str, this->v6mask);
    this->VirtualInterface::PrintInterfaceDetails();
}

void LoopbackInterface::InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask)
{
    this->ip_addr = ip_addr;
    this->mask = mask;
}

void LoopbackInterface::InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask)
{
    *ip_addr = this->ip_addr;
    *mask = this->mask;
}

void LoopbackInterface::InterfaceSetIpv6AddressMask(uint8_t (*addr)[16], uint8_t prefix_len)
{
    if (addr && prefix_len) {
        memcpy (this->v6addr, addr, sizeof(this->v6addr));
        this->v6mask = prefix_len;
    }
    else {
        memset (this->v6addr, 0, sizeof(this->v6addr));
        this->v6mask = 0;
    }
}

void LoopbackInterface::InterfaceGetIpv6AddressMask(uint8_t (*addr)[16], uint8_t *prefix_len)
{
    memcpy (addr, this->v6addr, sizeof(this->v6addr));
    *prefix_len = this->v6mask;
}

bool LoopbackInterface::IsIpConfigured()
{
    if (this->ip_addr && this->mask)
        return true;
    return false;
}

bool LoopbackInterface::IsSameSubnet(uint32_t ip_addr)
{

    uint32_t subnet_mask = ~0;

    if (!this->IsIpConfigured())
        return false;

    if (this->mask != 32)
    {
        subnet_mask = subnet_mask << (32 - this->mask);
    }

    return ((this->ip_addr & subnet_mask) == (ip_addr & subnet_mask));
}

void 
LoopbackInterface::InterfaceReleaseAllResources() {

    /* Nothing to release */
}

bool 
LoopbackInterface::IsCrossReferenced() {

    return this->GetSharedPtr().use_count() > (LOOPBACK_IF_REFCOUNT + 1);
}

/* ------------------------------------------------------------------- */

void 
dump_intf_props_header() {

    cprintf("%-12s %-12s %-18s %-39s %-17s %-12s %-6s %s\n", 
            "ifname", "vrf", "ip-address/mask", "ipv6-address/prefix", "MAC", "Oper-Status", "Mode", "Vlan-memberships");
    cprintf("%-12s %-12s %-18s %-39s %-17s %-12s %-6s %s\n", 
            "------", "--------", "---------------", "------------------", "---", "-----------", "----", "----------------");
}

void
dump_intf_props (Interface *interface){

    uint32_t intf_ip_addr = 0;
    uint8_t ipv6_addr[16] = {0};
    mac_addr_t *mac_addr = NULL;
    PhysicalInterface *phyIntf = NULL;
    uint8_t intf_mask, ipv6_prefix_len;
    byte intf_ip_addr_str[IPV4_ADDR_LEN_STR];
    char ipv6_addr_str[INET6_ADDRSTRLEN];

    cprintf("%-12s(%u) %-14s", interface->if_name.c_str(), 
        interface->ifindex,
        interface->vrf ? interface->vrf->vrf_name : "None");

    interface->InterfaceGetIpAddressMask(&intf_ip_addr, &intf_mask);

    if (intf_ip_addr) {
        tcp_ip_covert_ip_n_to_p(intf_ip_addr, intf_ip_addr_str);
        char ip_with_mask[24];
        snprintf(ip_with_mask, sizeof(ip_with_mask), "%s/%u", (char*)intf_ip_addr_str, intf_mask);
        cprintf("%-18s ", ip_with_mask);
    } else {
        cprintf("%-18s ", "Not configured");
    }

    // IPv6 address/prefix
    if (interface->IsIpv6Configured()) {
        interface->InterfaceGetIpv6AddressMask(&ipv6_addr, &ipv6_prefix_len);
        if (inet_ntop(AF_INET6, ipv6_addr, ipv6_addr_str, INET6_ADDRSTRLEN)) {
            char ipv6_with_prefix[48];
            snprintf(ipv6_with_prefix, sizeof(ipv6_with_prefix), "%s/%u", ipv6_addr_str, ipv6_prefix_len);
            cprintf("%-39s ", ipv6_with_prefix);
        } else {
            cprintf("%-39s ", "Invalid IPv6");
        }
    } else {
        cprintf("%-39s ", "Not configured");
    }

    mac_addr = interface->GetMacAddr();
    if (mac_addr) {
        cprintf("%02x:%02x:%02x:%02x:%02x:%02x ", 
                mac_addr->mac[0], mac_addr->mac[1], mac_addr->mac[2], 
                mac_addr->mac[3], mac_addr->mac[4], mac_addr->mac[5]);
    } else {
        cprintf("%-17s ", "Not available");
    }

    cprintf("%-12s ", interface->is_up ? "UP" : "DOWN");

    phyIntf = dynamic_cast<PhysicalInterface *>(interface);
    if (phyIntf && phyIntf->GetSwitchport()) {
        cprintf("%-6s ", "L2");
    } else {
        cprintf("%-6s ", "L3");
    }

    // VLAN memberships
    if (phyIntf && phyIntf->GetSwitchport()) {
        IntfL2Mode l2_mode = phyIntf->GetL2Mode();
        
        if (l2_mode == LAN_ACCESS_MODE && phyIntf->access_vlan_intf) {
            cprintf("Access(%u)", phyIntf->access_vlan_intf->GetVlanId());
        }
        else if (l2_mode == LAN_TRUNK_MODE && phyIntf->trans_svc) {
            cprintf("Trunk(");
            bool first = true;
            for (auto vlan : phyIntf->trans_svc->vlanSet) {
                if (!first) cprintf(",");
                cprintf("%d", vlan);
                first = false;
            }
            cprintf(")");
        }
        else {
            cprintf("None");
        }
    } else {
        cprintf("N/A");
    }

    cprintf("\n");
}

/* ************ NVEInterface ************ */

NVEInterface::NVEInterface(std::string if_name)
    : VirtualInterface(if_name, INTF_TYPE_NVE)
{
    // Initialize all member VNIs to 0 (not configured)
    memset(member_vnis, 0, sizeof(member_vnis));
}

NVEInterface::~NVEInterface() {
    // No special cleanup needed for member_vnis array
    InterfaceReleaseAllResources();
}

void 
NVEInterface::PrintInterfaceDetails() {
    
    cprintf("NVE Interface : %s\n", this->if_name.c_str());
    cprintf("  Interface Type : NVE (Network Virtualization Edge)\n");
    cprintf("  Status : %s\n", this->is_up ? "UP" : "DOWN");
    
    cprintf("  Member VNIs : ");
    bool first = true;
    for (int i = 0; i < 16; i++) {
        if (member_vnis[i] != 0) {
            if (!first) cprintf(", ");
            cprintf("%u", member_vnis[i]);
            first = false;
        }
    }
    if (first) {
        cprintf("None");
    }
    cprintf("\n");
    
    this->VirtualInterface::PrintInterfaceDetails();
}

void 
NVEInterface::InterfaceReleaseAllResources() {
    
    // Clear all member VNIs
    memset(member_vnis, 0, sizeof(member_vnis));
}

bool 
NVEInterface::AddMemberVni(uint32_t vni) {
    
    if (vni == 0) {
        cprintf("Error: Invalid VNI 0\n");
        return false;
    }
    
    // Check if VNI already exists
    if (CheckMemberVniMembership(vni)) {
        return false;
    }
    
    // Find empty slot
    for (int i = 0; i < 16; i++) {
        if (member_vnis[i] == 0) {
            member_vnis[i] = vni;
            return true;
        }
    }
    
    cprintf("Error: NVE interface %s is full (max 16 VNIs)\n", this->if_name.c_str());
    return false;
}

bool 
NVEInterface::RemoveMemberVni(uint32_t vni) {
    
    if (vni == 0) {
        cprintf("Error: Invalid VNI 0\n");
        return false;
    }
    
    // Find and remove VNI
    for (int i = 0; i < 16; i++) {
        if (member_vnis[i] == vni) {
            member_vnis[i] = 0;
            return true;
        }
    }
    
    return false;
}

bool 
NVEInterface::CheckMemberVniMembership(uint32_t vni) {
    
    if (vni == 0) return false;
    
    for (int i = 0; i < 16; i++) {
        if (member_vnis[i] == vni) {
            return true;
        }
    }
    return false;
}

void 
NVEInterface::GetMemberVnis(std::vector<uint32_t>& vni_list) {
    
    vni_list.clear();
    for (int i = 0; i < 16; i++) {
        if (member_vnis[i] != 0) {
            vni_list.push_back(member_vnis[i]);
        }
    }
}

NVEInterface *
NVEInterface::NVEInterfaceLookUp(node_t *node, std::string if_name) {
    
    if (!node || !node->node_nw_prop.nve) {
        return nullptr;
    }
    
    return node->node_nw_prop.nve.get();
}

bool
NVEInterface::IsCrossReferenced() {

    return this->GetSharedPtr().use_count() > (NVE_IF_DEF_REFCOUNT + 1);
}


HostPathInterface::HostPathInterface() : 
    VirtualInterface (std::string("hostpIntf"), INTF_TYPE_HOST_PATH)
{

}

HostPathInterface::~HostPathInterface() {

}

bool
HostPathInterface::IsCrossReferenced() {

    return 0;
}


/* AC Interface */
ACInterface::ACInterface(std::string ifname, InterfaceType_t iftype) 
    : Interface (ifname, iftype),
    encap_tag_8021q(0),
    forwarding_intf(nullptr),
    bd_intf(nullptr)
{
    SetSwitchport(true);
}

ACInterface::~ACInterface() {

    assert (IsCrossReferenced() == false );
    InterfaceReleaseAllResources();
    assert(forwarding_intf == nullptr);
    assert(bd_intf == nullptr);
    /* ifindex was borrowed from the physical port. */
    this->ifindex = 0;
}

void 
ACInterface::InterfaceReleaseAllResources() {

    UnSetUnderlyingInterface();
    UnSetBdInterface();
}

void 
ACInterface::SetEncap_tag_8021q(uint16_t vlan_id) {

    if (encap_tag_8021q == vlan_id)
        return;

    encap_tag_8021q = vlan_id;
    if (att_node && ifindex)
        cp2dp_bd_ac_set_encap_8021q(att_node, ifindex, vlan_id);
}

void 
ACInterface::UnSetEncap_tag_8021q(uint16_t vlan_id) {

    if (!encap_tag_8021q) return;
    encap_tag_8021q = 0;
    if (att_node && ifindex)
        cp2dp_bd_ac_set_encap_8021q(att_node, ifindex, 0);
}

uint16_t
ACInterface::GetEncap_tag_8021q() const {

    return encap_tag_8021q;
}

bool
ACInterface::SetUnderlyingInterface(InterfaceP intf) {

    if (!intf) return false;

    if (forwarding_intf) {
        return forwarding_intf == intf;
    }

    switch (intf->iftype) {

        case INTF_TYPE_PHY:
        case INTF_TYPE_GRE_TUNNEL:
            break;

        default:
            return false;
    }

    forwarding_intf = intf;

    if (intf->iftype == INTF_TYPE_PHY) {
        PhysicalInterface *phy = dynamic_cast<PhysicalInterface *>(intf.get());
        if (phy) {
            phy->used_as_underlying_tunnel_intf++;
            phy->bd_ac = std::dynamic_pointer_cast<ACInterface>(this->GetSharedPtr());
        }
    }

    return true;
}

void 
ACInterface::UnSetUnderlyingInterface() {

    if (!forwarding_intf) return;

    if (forwarding_intf->iftype == INTF_TYPE_PHY) {
        PhysicalInterface *phy =
            dynamic_cast<PhysicalInterface *>(forwarding_intf.get());
        if (phy) {
            if (phy->used_as_underlying_tunnel_intf)
                phy->used_as_underlying_tunnel_intf--;
            if (phy->bd_ac.get() == this)
                phy->bd_ac.reset();
        }
    }

    forwarding_intf.reset();
}

InterfaceP
ACInterface::GetUnderlyingInterface() {

    return forwarding_intf;
}

bool
ACInterface::SetBdInterface(BDInterfaceP bd) {

    if (!bd) return false;
    if (bd_intf) return bd_intf == bd;
    bd_intf = bd;
    return true;
}

void
ACInterface::UnSetBdInterface() {

    bd_intf.reset();
}

BDInterfaceP
ACInterface::GetBdInterface() {

    return bd_intf;
}

bool 
ACInterface::IsCrossReferenced() {

    return this->GetSharedPtr().use_count() > (BD_AC_IF_REFCOUNT + 1);
}

/* BD Interface */
BDInterface::BDInterface(std::string ifname, InterfaceType_t iftype)
    : VirtualInterface(ifname, iftype),
      bd_id(0),
      ip_addr(0),
      mask(0)
{
}

BDInterface::~BDInterface() {

    assert(IsCrossReferenced() == false);
    InterfaceReleaseAllResources();
}

void
BDInterface::InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) {

    this->ip_addr = ip_addr;
    this->mask = mask;
}

void
BDInterface::InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask) {

    *ip_addr = this->ip_addr;
    *mask = this->mask;
}

bool
BDInterface::IsIpConfigured() {

    return (this->ip_addr && this->mask);
}

mac_addr_t *
BDInterface::GetMacAddr() {

    return &this->att_node->node_nw_prop.rmac;
}

bool
BDInterface::IsSameSubnet(uint32_t ip_addr) {

    if (!this->IsIpConfigured()) return false;
    uint32_t subnet_mask = ~0;
    if (this->mask != 32) {
        subnet_mask = subnet_mask << (32 - this->mask);
    }
    return ((this->ip_addr & subnet_mask) == (ip_addr & subnet_mask));
}

bool
BDInterface::IsSVI() {

    return (this->ip_addr && this->mask);
}

bool
BDInterface::HasL3Config(bool matchvrf) {

    if (matchvrf && this->vrf) return true;
    if (this->IsIpConfigured()) return true;
    if (this->IsIpv6Configured()) return true;
    if (this->isis_intf_info) return true;
    if (this->l3_egress_acc_lst || this->l3_ingress_acc_lst) return true;
    return false;
}

void
BDInterface::InterfaceReleaseAllResources() {
    assert(member_ac.empty());
}

bool
BDInterface::IsCrossReferenced() {

    return this->GetSharedPtr().use_count() > (BD_IF_REFCOUNT + 1);
}

bool
BDInterface::AddMemberAC(ACInterfaceP ac) {

    if (!ac) return false;
    if (FindMemberAC(ac->GetUnderlyingInterface().get()))
        return false;
    member_ac.push_back(ac);
    return true;
}

bool
BDInterface::DelMemberAC(ACInterfaceP ac) {

    if (!ac) return false;
    for (auto it = member_ac.begin(); it != member_ac.end(); ++it) {
        if (*it == ac) {
            ac->UnSetBdInterface();
            member_ac.erase(it);
            ac->UnSetUnderlyingInterface();
            return true;
        }
    }
    return false;
}

ACInterfaceP
BDInterface::FindMemberAC(Interface *phy) {

    if (!phy) return nullptr;
    for (auto &ac : member_ac) {
        if (ac && ac->GetUnderlyingInterface().get() == phy)
            return ac;
    }
    return nullptr;
}
