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
#include "../common/l3_hdrs.h"
#include "../tcpconst.h"
#include "../utils.h"
#include "../BitOp/bitsop.h"
#include "Interface.h"
#include "../FireWall/acl/acldb.h"
#include "../graph.h"
#include "../pkt_block.h"
#include "../EventDispatcher/event_dispatcher.h"
#include "../Layer2/layer2.h"
#include "../Layer3/layer3.h"
#include "../Layer2/vxlan/dp/vxlan_dp.h"
#include "../Layer3/gre-tunneling/gre.h"
#include "../CLIBuilder/libcli.h"
#include "../Layer2/transport_svc.h"
#include "../Tracer/tracer.h"
#include "../Layer3/ipv6/ipv6_utils.h"

extern void
snp_flow_init_flow_tree_root(avltree_t *avl_root);
extern void 
tcp_ip_de_init_intf_log_info(Interface *intf);
extern int 
access_group_unconfig (node_t *node, 
                       Interface *intf, 
                       char *dirn, 
                       access_list_t *acc_lst) ;

extern void l2_switch_forward_frame(
                        node_t *node,
                        Interface *recv_intf, 
                        pkt_block_t *pkt_block);
extern void
promote_pkt_to_layer3(node_t *node,         
                      Interface *interface, 
                      pkt_block_t *pkt_block, 
                      int L3_protocol_number) ;

/* A fn to send the pkt as it is (unchanged) out on the interface */
static int
send_xmit_out (Interface *interface, pkt_block_t *pkt_block)
{

    pkt_size_t pkt_size;
    ev_dis_pkt_data_t *ev_dis_pkt_data;
    node_t *sending_node = interface->att_node;
    node_t *nbr_node = interface->GetNbrNode();

    uint8_t *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    if (!(interface->is_up))
    {
        interface->xmit_pkt_dropped++;
        return 0;
    }

    if (!nbr_node)
        return -1;

    if (pkt_size > MAX_PACKET_BUFFER_SIZE)
    {
        cprintf("Error : Node :%s, Pkt Size exceeded\n", sending_node->node_name);
        return -1;
    }

    /* Access List Evaluation at Layer 2 Exit point*/
    if (access_list_evaluate_ethernet_packet(
            interface->att_node, interface,
            pkt_block, false) == ACL_DENY)
    {
        return -1;
    }

    tracer (sending_node->dptr, DFLOW_DET, "Pkt : %s Wired out of interface %s\n", 
        pkt_block_str (pkt_block), interface->if_name.c_str());

    Interface *other_interface = interface->GetOtherInterface();

    ev_dis_pkt_data = new ev_dis_pkt_data_t;

    ev_dis_pkt_data->recv_node = nbr_node;
    ev_dis_pkt_data->recv_intf = other_interface->GetSharedPtr();
    ev_dis_pkt_data->pkt = tcp_ip_get_new_pkt_buffer(pkt_size);
    memcpy(ev_dis_pkt_data->pkt, pkt, pkt_size);
    ev_dis_pkt_data->pkt_size = pkt_size;

    tcp_dump_send_logger(sending_node, interface,
                         pkt_block, pkt_block_get_starting_hdr(pkt_block));

    if (!pkt_q_enqueue(EV_DP(nbr_node), DP_PKT_Q(nbr_node),
                       (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t)))
    {
        cprintf("%s : Fatal : Ingress Pkt QueueExhausted\n", nbr_node->node_name);

        tcp_ip_free_pkt_buffer(ev_dis_pkt_data->pkt, ev_dis_pkt_data->pkt_size);
        delete (ev_dis_pkt_data);
    }

    interface->pkt_sent++;
    return pkt_size;
}

static int
SendPacketOutRaw(PhysicalInterface *Intf, pkt_block_t *pkt_block)
{

    return send_xmit_out(Intf, pkt_block);
}

static int
SendPacketOutLAN(PhysicalInterface *Intf, pkt_block_t *pkt_block)
{

    pkt_size_t pkt_size;

    IntfL2Mode intf_l2_mode = Intf->GetL2Mode();

    if (intf_l2_mode == LAN_MODE_NONE)
    {
        return 0;
    }

    ethernet_hdr_t *ethernet_hdr =
        (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr = is_pkt_vlan_tagged(ethernet_hdr);

    switch (intf_l2_mode)
    {

    case LAN_ACCESS_MODE:
    {
        vlan_id_t intf_vlan_id = Intf->GetVlanId();

        /*Case 1 : If interface is operating in ACCESS mode, but
         not in any vlan, and pkt is also untagged, then simply
         forward it. This is default Vlan unaware case*/
        if (!intf_vlan_id && !vlan_8021q_hdr)
        {
            return send_xmit_out(Intf, pkt_block);
        }

        /*Case 2 : if oif is VLAN aware, but pkt is untagged, simply
         drop the packet. This is not an error, it is a L2 switching
         behavior*/
        if (intf_vlan_id && !vlan_8021q_hdr)
        {
            return 0;
        }

        /*Case 3 : If oif is VLAN AWARE, and pkt is also tagged,
          forward the frame only if vlan IDs matches after untagging
          the frame*/
        if (vlan_8021q_hdr &&
            (intf_vlan_id == GET_802_1Q_VLAN_ID(vlan_8021q_hdr)))
        {

            untag_pkt_with_vlan_id(pkt_block);
            return send_xmit_out(Intf, pkt_block);
        }

        /* case 4 : if vlan id in pkt do not matches with the vlan id of
            the interface*/
        if (vlan_8021q_hdr &&
            (intf_vlan_id != GET_802_1Q_VLAN_ID(vlan_8021q_hdr)))
        {
            return 0;
        }

        /*case 5 : if oif is vlan unaware but pkt is vlan tagged,
         simply drop the packet.*/
        if (!intf_vlan_id && vlan_8021q_hdr)
        {
            return 0;
        }
    }
    break;
    case LAN_TRUNK_MODE:
    {
        vlan_id_t pkt_vlan_id = 0;

        if (vlan_8021q_hdr)
        {
            pkt_vlan_id = GET_802_1Q_VLAN_ID(vlan_8021q_hdr);
        }

        if (pkt_vlan_id &&
            Intf->IsVlanTrunked(pkt_vlan_id))
        {
            return send_xmit_out(Intf, pkt_block);
        }

        /*Do not send the pkt in any other case*/
        return 0;
    }
    break;
    case LAN_MODE_NONE:
        break;
    default:;
    }
    return 0;
}

Interface::Interface(std::string if_name, InterfaceType_t iftype)
{
    this->if_name = std::move(if_name);
    this->iftype = iftype;
    this->att_node = NULL;
    memset(&this->log_info, 0, sizeof(this->log_info));
    this->link = NULL;
    this->is_up = true;
    this->ifindex = get_new_ifindex();
    this->cost = INTF_METRIC_DEFAULT;
    
    this->pkt_recv = 0;
    this->pkt_sent = 0;
    this->xmit_pkt_dropped = 0;
    this->recvd_pkt_dropped = 0;

    this->l2_egress_acc_lst = NULL;
    this->l2_ingress_acc_lst = NULL;

    this->l3_ingress_acc_lst2 = NULL;
    this->l3_egress_acc_lst2 = NULL;

    this->isis_intf_info = NULL;
    this->intfP.reset(); 
}

Interface::~Interface()
{
    InterfaceReleaseAllResources();
    ConsOut ("%s : Interface %s deleted\n", this->att_node->node_name, this->if_name.c_str());
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

void Interface::PrintInterfaceDetails()
{

    cprintf("%s   index = %u   Owning-Dev %s\n",
           this->if_name.c_str(), this->ifindex, this->att_node->node_name);

    cprintf("State : Administratively %s\n", this->is_up ? "Up" : "Down");

#if 0
    cprintf("L2 access Lists : Ingress - %s, Egress - %s\n",
           this->l2_ingress_acc_lst ? (const char *)this->l2_ingress_acc_lst->name : "None",
           this->l2_egress_acc_lst ? (const char *)this->l2_egress_acc_lst->name : "None");

    cprintf("L3 access Lists : Ingress - %s, Egress - %s\n",
           this->l3_ingress_acc_lst2 ? (const char *)this->l3_ingress_acc_lst2->name : "None",
           this->l3_egress_acc_lst2 ? (const char *)this->l3_egress_acc_lst2->name : "None");
#endif 

    if (this->isis_intf_info)
    {
        cprintf("ISIS Running\n");
    }

    cprintf("Metric = %u\n", this->GetIntfCost());
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

int Interface::SendPacketOut(pkt_block_t *pkt_block)
{
    return -1;
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

/* Default fn : In Most cases, we store the interface in node->intf[] array. Hence,
    anything more than 1 (+1) ref count means interface is in use */
bool 
Interface::IsCrossReferenced() {

    if (this->GetSharedPtr().use_count() > 2) return true;
    return false;
}

void 
Interface::InterfaceReleaseAllResources() {

    tcp_ip_de_init_intf_log_info (this);

    if (this->link) {
        /* Nothing to do, we dont break topology !*/
    }

    if (this->l2_ingress_acc_lst) {
        assert(0); /* Not Supported Yet*/
    }

    if (this->l2_egress_acc_lst) {
        assert(0); /* Not Supported Yet*/
    }

    if (this->l3_ingress_acc_lst2) {
        access_group_unconfig (this->att_node, this, "in", this->l3_ingress_acc_lst2);
    }

    if (this->l3_egress_acc_lst2) {
        access_group_unconfig (this->att_node, this, "out", this->l3_egress_acc_lst2);
    }

    /* This is configuration, this fn call must not see it set*/
    assert (!this->isis_intf_info);
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


/* ************ PhysicalInterface ************ */
PhysicalInterface::PhysicalInterface(std::string ifname, InterfaceType_t iftype, mac_addr_t *mac_add)
    : Interface(ifname, iftype)
{

    this->switchport = false;
    
    memset (this->mac_add.mac, 0, sizeof(this->mac_add.mac));

    if (mac_add)
    {
        memcpy(this->mac_add.mac, mac_add->mac, sizeof(this->mac_add.mac));
    }
    this->l2_mode = LAN_MODE_NONE;
    this->ip_addr = 0;
    this->mask = 0;
    this->used_as_underlying_tunnel_intf = 0;
    this->trans_svc = NULL;
    this->access_vlan_intf = nullptr;
}

PhysicalInterface::~PhysicalInterface()
{
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
    return NULL;
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
        if (this->access_vlan_intf || this->trans_svc) {
            cprintf("Error : Remove L2 Config first\n");
            this->switchport = true;
            return;
        }
        this->l2_mode = LAN_MODE_NONE;
    }
    this->switchport = enable;
}

bool PhysicalInterface::GetSwitchport()
{

    return this->switchport;
}

int PhysicalInterface::SendPacketOut(pkt_block_t *pkt_block)
{

    if (this->switchport)
    {
        return SendPacketOutLAN(this, pkt_block);
    }
    else
    {
        return SendPacketOutRaw(this, pkt_block);
    }
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

        this->access_vlan_intf = std::dynamic_pointer_cast<VlanInterface>
                (VlanInterface::VlanInterfaceLookUp(this->att_node, vlan_id)->GetSharedPtr());
        
        if (!this->access_vlan_intf)
        {
            cprintf("Error : Vlan Interface not found");
            return false;
        }
        this->access_vlan_intf->access_member_intf_lst.push_back(this->GetSharedPtr());
        this->l2_mode = LAN_ACCESS_MODE;
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

                return true;
            }
            {
                cprintf("Error : Interface not in vlan %u", vlan_id);
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

    this->Interface::InterfaceReleaseAllResources();
}

/* Physical interface, by defauls are qued into nodes and linkage_t
    which take away '2' ref count. Anything more than that, interface is suppose to be
    in use*/
bool
PhysicalInterface::IsCrossReferenced() {

    if (this->GetSharedPtr().use_count() > 3) return true;
    return false;
}

void 
PhysicalInterface::InterfaceSetIpv6AddressMask(uint8_t (*addr)[16], uint8_t prefix_len) {


}

void 
PhysicalInterface::InterfaceGetIpv6AddressMask(uint8_t (*addr)[16], uint8_t *prefix_len) {

}

VlanInterfaceP 
PhysicalInterface::GetAccessVlanIntf() {

    return this->access_vlan_intf;
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

void 
VirtualInterface::InterfaceReleaseAllResources() {

    /* Nothing to release */

    /* Release Base class Resources */
    this->Interface::InterfaceReleaseAllResources();
}

/**      Rmac Interface  */

RmacInterface::RmacInterface() 
    :VirtualInterface(std::string(RMAC_INTF_NAME), INTF_TYPE_RMAC) {}

RmacInterface::~RmacInterface() {}
void RmacInterface::PrintInterfaceDetails () {}
void RmacInterface::InterfaceReleaseAllResources() {}

/* For Rmac Interface, pks send out means, handover the pkt to
    Layer 3 for routing */
int RmacInterface::SendPacketOut(pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;

    assert(pkt_block_verify_pkt(pkt_block, ETH_HDR));

    ethernet_hdr_t *eth_hdr = 
        ( ethernet_hdr_t  *)pkt_block_get_pkt(pkt_block, &pkt_size);

    /* Rmac interface never recvs untagged pkt */
    assert (is_pkt_vlan_tagged (eth_hdr));

    /* Case 1 : If this is ARP Broadcast pkt requesting IP for Rmac interface*/
    /* Case 2 : If this is ARP reply packet recvd by Rmac Interface */
    
    if ( is_arp_pkt_for_svi_interface (this->att_node, pkt_block) ) {
            svi_interface_intercept_arp_pkt (this->att_node, pkt_block);
            return 0;
    }

    /* Case 3 : if this is any other ethernet pkt with dst mac = RMAC address */

    if (!mac_address_compare ((char *)NODE_RMAC(this->att_node)->mac, 
          (char *)eth_hdr->dst_mac.mac) != 0) {

        this->recvd_pkt_dropped++;
        return 0;
    }

    untag_pkt_with_vlan_id(pkt_block);
    eth_hdr = ( ethernet_hdr_t  *)pkt_block_get_pkt(pkt_block, &pkt_size);

    promote_pkt_to_layer3 (this->att_node, 
            dynamic_cast<Interface*>(this),  pkt_block, eth_hdr->type);
    
    return 0;
}



/* VlanFloodInterface */
VlanFloodInterface::VlanFloodInterface()
    : VirtualInterface(std::string(VLAN_FLOOD_INTF_NAME) , INTF_TYPE_VLAN_FLOOD) { }

VlanFloodInterface::~VlanFloodInterface() {}

/* Any packet sent out of this interface should be flooded in the vlan.
    Extract vlan id from the pkt */
int 
VlanFloodInterface::SendPacketOut(pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    ethernet_hdr_t *ethernet_hdr = 
        ( ethernet_hdr_t  *)pkt_block_get_pkt(pkt_block, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr = is_pkt_vlan_tagged(ethernet_hdr);

    if (!vlan_8021q_hdr) {
        this->recvd_pkt_dropped++;
        return 0;
    }

    vlan_id_t vlan_id = GET_802_1Q_VLAN_ID(vlan_8021q_hdr);

    VlanInterface *vlan_intf = VlanInterface::VlanInterfaceLookUp (this->att_node, vlan_id);

    vlan_intf->VlanPacketFlood (pkt_block, 
            dynamic_cast<Interface *>(pkt_block->switchport_ingress_intf.get()));

    return 0;
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
    this->virtual_port_intf = nullptr;
     this->tunnel_src_intf = nullptr;
}

GRETunnelInterface::~GRETunnelInterface() {

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
            (this->config_flags & GRE_TUNNEL_OVLAY_IP_SET))
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

bool 
GRETunnelInterface::SetTunnelSource(PhysicalInterface *interface)
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
		this->tunnel_src_intf != interface->GetSharedPtr()) {
		    cprintf ("Error : Tunnel Src Interface %s already set\n",
            this->tunnel_src_intf->if_name.c_str());
		return false;
	}
        this->tunnel_src_intf = std::dynamic_pointer_cast
            <PhysicalInterface>( interface->GetSharedPtr());
        interface->used_as_underlying_tunnel_intf++;
        this->config_flags |= GRE_TUNNEL_SRC_INTF_SET;
    }
    else {

	if (this->tunnel_src_intf == NULL) return true;
        PhysicalInterface *tunnel_src_intf = std::dynamic_pointer_cast<PhysicalInterface>(this->tunnel_src_intf ).get();
        tunnel_src_intf->used_as_underlying_tunnel_intf--;
        this->tunnel_src_intf = nullptr;
        this->config_flags &= ~GRE_TUNNEL_SRC_INTF_SET;
    }
    return true;
}

void 
GRETunnelInterface::SetTunnelDestination(uint32_t ip_addr)
{

    this->tunnel_dst_ip = ip_addr;
    if (ip_addr) {
        this->config_flags |= GRE_TUNNEL_DST_ADDR_SET;
    }
    else {
        this->config_flags &= ~GRE_TUNNEL_DST_ADDR_SET;
    }
}

void 
GRETunnelInterface::SetTunnelLclIpMask(uint32_t ip_addr, uint8_t mask)
{
    this->InterfaceSetIpAddressMask(ip_addr, mask);
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
}

void
GRETunnelInterface::UnSetTunnelSrcIp()
{
    if (this->config_flags & GRE_TUNNEL_SRC_ADDR_SET)
    {
        this->tunnel_src_ip = 0;
        this->config_flags &= ~GRE_TUNNEL_SRC_ADDR_SET;
    }
}

void 
GRETunnelInterface::InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) {

        this->lcl_ip = ip_addr;
        this->mask = mask;
        if (ip_addr == 0 ) {
            this->config_flags &= ~GRE_TUNNEL_OVLAY_IP_SET;
            return;
        }
        this->config_flags |= GRE_TUNNEL_OVLAY_IP_SET;
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

int 
GRETunnelInterface::SendPacketOut(pkt_block_t *pkt_block)
{
    pkt_size_t pkt_size;
    bool no_modify = false;
    node_t *node = this->att_node;
    pkt_block_t *pkt_block_copy;

    if (!this->IsGRETunnelActive()) {
        return 0;
    }
    
    if (pkt_block->no_modify) {
        no_modify = pkt_block->no_modify;
        pkt_block_copy = pkt_block_dup (pkt_block);
        pkt_block = pkt_block_copy;
    }

    gre_encasulate (this->att_node, pkt_block);
    pkt_block_set_exclude_oif (pkt_block, this);
    pkt_block_get_pkt (pkt_block, &pkt_size);

    /* Now attach outer IP Hdr and send the pkt*/
    assert (pkt_block_expand_buffer_left (pkt_block, sizeof (ip_hdr_t)));
    pkt_block_set_starting_hdr_type (pkt_block, IP_HDR);
    ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr (pkt_block);
    initialize_ip_hdr (ip_hdr);
    ip_hdr->src_ip = tcp_ip_convert_ip_p_to_n (NODE_LO_ADDR(node));
    ip_hdr->dst_ip = this->tunnel_dst_ip;
    ip_hdr->protocol = GRE_PROTO;
    ip_hdr->total_length = IP_HDR_COMPUTE_DEFAULT_TOTAL_LEN(pkt_size);
    np_tcp_ip_send_ip_data (node, pkt_block);
    this->pkt_sent++;
    pkt_block_get_pkt (pkt_block, &pkt_size);

    if (no_modify) {
        pkt_block_dereference(pkt_block);
    }

    return pkt_size;
}

void 
GRETunnelInterface::InterfaceReleaseAllResources() {

    if (this->tunnel_src_intf) {
        this->SetTunnelSource(NULL);
    }

    this->VirtualInterface::InterfaceReleaseAllResources();
}

/* Stored in default way*/
bool 
GRETunnelInterface::IsCrossReferenced()
{
   /* Tunnels install local route with /mask and /32 in RT. They are
   referenced by those routes*/
   if (this->lcl_ip && this->is_up) {
         if (this->GetSharedPtr().use_count() > 4) return true;
         return false;
   }
    
   /* Default */
   return this->Interface::IsCrossReferenced();
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

int
VirtualPort::SendPacketOut(pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;

    if (!this->olay_tunnel_intf) {
        this->xmit_pkt_dropped++;
        return 0;
    }

    if (this->IsInterfaceUp(0) == false) {
        this->xmit_pkt_dropped++;
        return 0;
    }
    
    assert (pkt_block_get_starting_hdr(pkt_block) == ETH_HDR);

    ethernet_hdr_t *ethernet_hdr = 
        ( ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr = 
        is_pkt_vlan_tagged(ethernet_hdr);
    
    assert (vlan_8021q_hdr );

    /* If vport is in trunk mode, then check if vlan id is part of trunk*/
    if (!this->IsVlanTrunked (GET_802_1Q_VLAN_ID(vlan_8021q_hdr))) return 0;

    this->pkt_sent++;
    
    return this->olay_tunnel_intf->SendPacketOut(pkt_block);
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
    
    /* Handling access Vlan Interface*/
    this->VirtualInterface::InterfaceReleaseAllResources();
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

    return this->Interface::IsCrossReferenced();
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

    assert (this->access_member_intf_lst.empty());
}

/* Vlan interfaces when are queued up in vlanDB, therefore taking refcount
    of 1. Anything more than that, vlaninterface is suppose to be in use.
    Can use default Implementation of Base Class
    */
bool
VlanInterface::IsCrossReferenced() {

    if (this->GetSharedPtr().use_count() > 2) return true;
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


int 
VlanInterface::SendPacketOut(pkt_block_t *pkt_block) {

    tag_pkt_with_vlan_id(pkt_block, this->GetVlanId());
    VlanPacketFlood (pkt_block, NULL);
    return 0;
}

bool 
VlanInterface::IsInterfaceUp(vlan_id_t vlan_id) {

    return this->is_up;
}

void 
VlanInterface::InterfaceReleaseAllResources() {

    assert (this->access_member_intf_lst.empty());
    VirtualInterface::InterfaceReleaseAllResources();
}

bool 
VlanInterface::IsSVI () {

    return ( this->ip_addr && this->mask ) ;
}

void 
VlanInterface::VlanPacketFlood (pkt_block_t *pkt_block, Interface *exempt_intf) 
{
    Interface *member_intf;
    pkt_block_t *dup_pkt_block;

    dup_pkt_block = pkt_block_dup(pkt_block);

    untag_pkt_with_vlan_id(dup_pkt_block);

   ITERATE_VLAN_MEMBER_PORTS_ACCESS_BEGIN(this, member_intf)
   {
      if (member_intf == exempt_intf) continue;
       send_xmit_out(member_intf, dup_pkt_block);
   }
   ITERATE_VLAN_MEMBER_PORTS_ACCESS_END;

   pkt_block_free(dup_pkt_block);

   ITERATE_VLAN_MEMBER_PORTS_TRUNK_BEGIN(this, member_intf)
   {
        if (member_intf == exempt_intf) continue;
       send_xmit_out(member_intf, pkt_block);
    } 
    ITERATE_VLAN_MEMBER_PORTS_TRUNK_END;       
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

    /* Release Base class Resources */
    this->VirtualInterface::InterfaceReleaseAllResources();
}

bool 
LoopbackInterface::IsCrossReferenced() {

    return this->Interface::IsCrossReferenced();
}

/* ------------------------------------------------------------------- */

void 
dump_intf_props (Interface *interface){

    uint32_t intf_ip_addr = 0;
    uint8_t ipv6_addr[16] = {0};
    mac_addr_t *mac_addr = NULL;
    PhysicalInterface *phyIntf = NULL;
    uint8_t intf_mask, ipv6_prefix_len;
    byte intf_ip_addr_str[IPV4_ADDR_LEN_STR];
    char ipv6_addr_str[INET6_ADDRSTRLEN];
    static bool header_printed = false;

    // Print header only once
    if (!header_printed) {

        cprintf("%-12s %-18s %-39s %-17s %-12s %-6s %s\n", 
                "ifname", "ip-address/mask", "ipv6-address/prefix", "MAC", "Oper-Status", "Mode", "Vlan-memberships");
        cprintf("%-12s %-18s %-39s %-17s %-12s %-6s %s\n", 
                "------", "---------------", "------------------", "---", "-----------", "----", "----------------");
        header_printed = true;
    }

    cprintf("%-12s ", interface->if_name.c_str());

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
    interface->InterfaceGetIpv6AddressMask(&ipv6_addr, &ipv6_prefix_len);
    bool ipv6_configured = false;

    for (int i = 0; i < 16; i++) {
        if (ipv6_addr[i] != 0) {
            ipv6_configured = true;
            break;
        }
    }
    
    if (ipv6_configured) {
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
    this->VirtualInterface::InterfaceReleaseAllResources();
}

int 
NVEInterface::SendPacketOut(pkt_block_t *pkt_block) {
    
    pkt_size_t pkt_size;
    char ipv4_addr_str1[IPV4_ADDR_LEN_STR];
    char ipv4_addr_str2[IPV4_ADDR_LEN_STR];
    
    if (!this->is_up) {
        tracer (this->att_node->dptr, DTUNNEL | DFLOW | DERR, "VxLAN Encapsulation : Error : NVE Interface %s is down\n", this->if_name.c_str());
        this->xmit_pkt_dropped++;
        return -1;
    }

    if (!pkt_block->encap_data) {
        tracer (this->att_node->dptr, DTUNNEL | DFLOW | DERR, "VxLAN Encapsulation : Error : Pkt Block has no encap data\n");
        this->xmit_pkt_dropped++;
        return -1;
    }

    vxlan_encapsulate (this->att_node, pkt_block);

 /* Now attach outer IP Hdr and send the pkt*/
    assert (pkt_block_expand_buffer_left (pkt_block, sizeof (ip_hdr_t)));
    pkt_block_set_starting_hdr_type (pkt_block, IP_HDR);
    ip_hdr_t *ip_hdr = (ip_hdr_t *) pkt_block_get_pkt(pkt_block, &pkt_size);
    initialize_ip_hdr (ip_hdr);
    ip_hdr->src_ip = tcp_ip_convert_ip_p_to_n (NODE_LO_ADDR(this->att_node));
    ip_hdr->dst_ip = pkt_block->encap_data->u.vxlan.remote_vtep_ip;
    ip_hdr->protocol = UDP_PROTO;
    ip_hdr->total_length = IP_HDR_COMPUTE_DEFAULT_TOTAL_LEN(pkt_size);

    tracer (this->att_node->dptr, DTUNNEL | DFLOW, 
        "VxLAN Encapsulation : Outer IP Hdr Header Attached with Src : %s, Dst %s, Proto = %x\n",
        tcp_ip_covert_ip_n_to_p (ip_hdr->src_ip, ipv4_addr_str1),
        tcp_ip_covert_ip_n_to_p (ip_hdr->dst_ip, ipv4_addr_str2),
        ip_hdr->protocol );

    np_tcp_ip_send_ip_data (this->att_node, pkt_block);
    this->pkt_sent++;
    return 0;
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
