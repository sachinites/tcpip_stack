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
#include "../utils.h"
#include "../BitOp/bitsop.h"
#include "Interface.h"
#include "../FireWall/acl/acldb.h"
#include "../graph.h"
#include "../pkt_block.h"
#include "../EventDispatcher/event_dispatcher.h"
#include "../Layer2/layer2.h"

extern void
snp_flow_init_flow_tree_root(avltree_t *avl_root) ;

/* A fn to send the pkt as it is (unchanged) out on the interface */
static int 
send_xmit_out (Interface *interface, pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
	ev_dis_pkt_data_t *ev_dis_pkt_data;
    node_t *sending_node = interface->att_node;
    node_t *nbr_node = interface->GetNbrNode();
    
    uint8_t *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    if (!(interface->is_up)){
        interface->xmit_pkt_dropped++;
        return 0;
    }

    if (!nbr_node)
        return -1;

    if (pkt_size > MAX_PACKET_BUFFER_SIZE){
        printf("Error : Node :%s, Pkt Size exceeded\n", sending_node->node_name);
        return -1;
    }


    /* Access List Evaluation at Layer 2 Exit point*/
    if (access_list_evaluate_ethernet_packet(
            interface->att_node, interface, 
           pkt_block, false)  == ACL_DENY) {
        return -1;
    }

    Interface *other_interface = interface->GetOtherInterface();

	ev_dis_pkt_data = (ev_dis_pkt_data_t *)XCALLOC(0,1, ev_dis_pkt_data_t);

	ev_dis_pkt_data->recv_node = nbr_node;
	ev_dis_pkt_data->recv_Intf = other_interface;
    ev_dis_pkt_data->pkt = tcp_ip_get_new_pkt_buffer(pkt_size);
	memcpy(ev_dis_pkt_data->pkt, pkt, pkt_size);
	ev_dis_pkt_data->pkt_size = pkt_size;

#if 0
    tcp_dump_send_logger(sending_node, interface, 
			pkt_block, pkt_block_get_starting_hdr(pkt_block));
#endif 

	if (!pkt_q_enqueue(EV_DP(nbr_node), DP_PKT_Q(nbr_node),
                  (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t))) {

        printf ("%s : Fatal : Ingress Pkt QueueExhausted\n", nbr_node->node_name);

        tcp_ip_free_pkt_buffer(ev_dis_pkt_data->pkt, ev_dis_pkt_data->pkt_size);
        XFREE(ev_dis_pkt_data);
    }
	
    interface->pkt_sent++;
    return pkt_size;     
}

static int
SendPacketOutRaw (PhysicalInterface *Intf, pkt_block_t *pkt_block) {

   return send_xmit_out(Intf, pkt_block);
}

static int
SendPacketOutLAN(PhysicalInterface *Intf, pkt_block_t *pkt_block) {
    
    pkt_size_t pkt_size;
  
    PhysicalInterface::IntfL2Mode intf_l2_mode = Intf->l2_mode;
    
    if (intf_l2_mode == PhysicalInterface::IntfL2Mode::LAN_MODE_NONE){
        return false;
    }
    
    ethernet_hdr_t *ethernet_hdr =
        (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    vlan_8021q_hdr_t *vlan_8021q_hdr = is_pkt_vlan_tagged(ethernet_hdr);

    switch(intf_l2_mode){

        case PhysicalInterface::IntfL2Mode::LAN_ACCESS_MODE:
            {
                uint32_t intf_vlan_id = Intf->GetVlanId();

                /*Case 1 : If interface is operating in ACCESS mode, but
                 not in any vlan, and pkt is also untagged, then simply 
                 forward it. This is default Vlan unaware case*/
                if (!intf_vlan_id && !vlan_8021q_hdr){
                    return send_xmit_out(Intf, pkt_block);
                }

                /*Case 2 : if oif is VLAN aware, but pkt is untagged, simply
                 drop the packet. This is not an error, it is a L2 switching 
                 behavior*/
                if(intf_vlan_id && !vlan_8021q_hdr){
                    return 0;
                }

                /*Case 3 : If oif is VLAN AWARE, and pkt is also tagged, 
                  forward the frame only if vlan IDs matches after untagging
                  the frame*/
                if(vlan_8021q_hdr && 
                        (intf_vlan_id == GET_802_1Q_VLAN_ID(vlan_8021q_hdr))){

                    untag_pkt_with_vlan_id(pkt_block);
                    return send_xmit_out(Intf, pkt_block);
                }

                /*case 4 : if oif is vlan unaware but pkt is vlan tagged, 
                 simply drop the packet.*/
                if(!intf_vlan_id && vlan_8021q_hdr){
                    return 0;
                }
            }
            break;
        case PhysicalInterface::IntfL2Mode::LAN_TRUNK_MODE:
            {
                uint32_t pkt_vlan_id = 0;
                
                if(vlan_8021q_hdr){
                    pkt_vlan_id = GET_802_1Q_VLAN_ID(vlan_8021q_hdr);
                }

                if(pkt_vlan_id && 
                        Intf->IsVlanTrunked(pkt_vlan_id)) {
                    
                    return send_xmit_out(Intf, pkt_block);
                }

                /*Do not send the pkt in any other case*/
                return 0;
            }
            break;
        case PhysicalInterface::IntfL2Mode::LAN_MODE_NONE:
            break;
        default:
            ;
    }
    return 0;
}


Interface::Interface(std::string if_name, InterfaceType_t iftype) {

    this->if_name = if_name;
    this->iftype = iftype;
    this->ref_count = 0;
    this->att_node = NULL;
    memset (&this->log_info, 0, sizeof(this->log_info));
    this->link = NULL;
    this->is_up = true;
    this->ifindex = get_new_ifindex();

    this->l2_egress_acc_lst = NULL;
    this->l2_ingress_acc_lst = NULL;

    pthread_spin_init(&this->spin_lock_l3_ingress_acc_lst, PTHREAD_PROCESS_PRIVATE);
    this->l3_ingress_acc_lst = NULL;
    pthread_spin_init(&this->spin_lock_l3_egress_acc_lst, PTHREAD_PROCESS_PRIVATE);
    this->l3_egress_acc_lst = NULL;

    this->isis_intf_info = NULL;

    snp_flow_init_flow_tree_root(&this->flow_avl_root);
}

Interface::~Interface() {

    assert(this->ref_count == 0);
    pthread_spin_destroy(&this->spin_lock_l3_ingress_acc_lst);
    pthread_spin_destroy(&this->spin_lock_l3_egress_acc_lst);
}

uint32_t 
Interface::GetLinkCost() {

    return this->link->cost;
}



void 
Interface::PrintInterfaceDetails () {

    printf ("%s   index = %u   Owning-Dev %s\n", 
        this->if_name.c_str(), this->ifindex, this->att_node->node_name);

    printf ("State : Administratively %s\n", this->is_up ? "Up" : "Down");

    printf ("L2 access Lists : Ingress - %s, Egress - %s\n", 
        this->l2_ingress_acc_lst ? (const char *)this->l2_ingress_acc_lst->name : "None",
        this->l2_egress_acc_lst ? (const char *)this->l2_egress_acc_lst->name : "None");

    printf ("L3 access Lists : Ingress - %s, Egress - %s\n", 
        this->l3_ingress_acc_lst ?(const char *) this->l3_ingress_acc_lst->name : "None",
        this->l3_egress_acc_lst ? (const char *)this->l3_egress_acc_lst->name : "None");

    if (this->isis_intf_info) {
        printf ("ISIS Running\n");
    }

    printf ("Metric = %u\n", this->GetLinkCost());
}

node_t *
Interface::GetNbrNode () {

    Interface *interface = this;

    assert(this->att_node);
    assert(this->link);
    
    linkage_t *link = interface->link;
    if (link->Intf1 == interface)
        return link->Intf2->att_node;
    else
        return link->Intf1->att_node;
}

Interface *
Interface::GetOtherInterface() {

    return  this->link->Intf1 == this ? \
                this->link->Intf2 : this->link->Intf1;
}

int
Interface::SendPacketOut(pkt_block_t *pkt_block) {
   
    TO_BE_OVERRIDDEN_BY_DERIEVED_CLASS;
    return -1;
}




/* ************ PhysicalInterface ************ */
PhysicalInterface::PhysicalInterface ( std::string ifname, InterfaceType_t iftype, mac_addr_t *mac_add) 
    : Interface (ifname, iftype)
{

    this->switchport = false;
    if (mac_add) {
        memcpy (this->mac_add.mac, mac_add->mac, sizeof (*mac_add));
    }
    this->l2_mode = LAN_MODE_NONE;
    memset (vlans, 0, sizeof(vlans));
    this->ip_addr = 0;
    this->mask = 0;
}

PhysicalInterface::~PhysicalInterface () {

}

void
PhysicalInterface::SetMacAddr(mac_addr_t *mac_add ) {

    if (mac_add) {
        memcpy (this->mac_add.mac, mac_add->mac, sizeof (*mac_add));
    }
}

mac_addr_t *
PhysicalInterface::GetMacAddr( ) {

     return &this->mac_add;
}

void 
PhysicalInterface::PrintInterfaceDetails () {

    byte ip_addr[16];

    printf("\t MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", 
                this->mac_add.mac[0], 
                this->mac_add.mac[1], 
                this->mac_add.mac[2], 
                this->mac_add.mac[3], 
                this->mac_add.mac[4], 
                this->mac_add.mac[5] );
    
      if (this->IsIpConfigured ()) {
        printf ("IP Addr : %s/%d\n", tcp_ip_covert_ip_n_to_p (this->ip_addr, ip_addr), this->mask);
    }
    else {
        printf ("IP Addr : Not Configured\n");
    }

    printf("Vlan L2 Mode : %s\n", PhysicalInterface::L2ModeToString(this->l2_mode).c_str());

    this->Interface::PrintInterfaceDetails();
}

void 
PhysicalInterface::InterfaceSetIpAddressMask (uint32_t ip_addr, uint8_t mask) {

    this->ip_addr = ip_addr;
    this->mask = mask;
}

void
PhysicalInterface::InterfaceGetIpAddressMask (uint32_t *ip_addr, uint8_t *mask) {

    *ip_addr = this->ip_addr;
    *mask = this->mask;
}

bool 
PhysicalInterface::IsIpConfigured () {

     if (this->ip_addr && this->mask)
        return true;
    return false;
}

std::string
PhysicalInterface::L2ModeToString(IntfL2Mode l2_mode){

    switch (l2_mode) {
        
        case LAN_MODE_NONE:
            return std::string ("None");
        case LAN_ACCESS_MODE:
            return std::string ("Access");
        case LAN_TRUNK_MODE:
            return std::string ("Trunk");
        default : ;
    }
    return NULL;
}

bool 
PhysicalInterface::IsVlanTrunked (uint32_t vlan_id) {

    int i;

    if (!this->switchport) return false;

   for (i = 0; i < INTF_MAX_VLAN_MEMBERSHIP; i++) {
        if (this->vlans[i] == vlan_id) break;
   }
   
   if (i == INTF_MAX_VLAN_MEMBERSHIP) return false;

   return (this->l2_mode == LAN_TRUNK_MODE) ;
}

uint32_t 
PhysicalInterface::GetVlanId() {

    if (this->l2_mode == LAN_MODE_NONE) return 0;
    return this->vlans[0];
}

void 
PhysicalInterface::SetSwitchport(bool enable) {

    if (this->switchport == enable) return;
    this->switchport = enable;

    if (enable) {
        this->InterfaceSetIpAddressMask(0, 0);
        this->l2_mode = LAN_MODE_NONE;
        memset (vlans, 0, sizeof(vlans));
        this->iftype = INTF_TYPE_LAN;
    }
    else {
        this->l2_mode = LAN_MODE_NONE;
        memset (vlans, 0, sizeof(vlans));
        this->iftype = INTF_TYPE_P2P;
    }
}

int 
PhysicalInterface::SendPacketOut(pkt_block_t *pkt_block) {

    if (this->switchport) {
        return SendPacketOutLAN(this, pkt_block);
    }
    else {
        return SendPacketOutRaw(this, pkt_block);
    }
}



/* ************ Virtual Interface ************ */
VirtualInterface::VirtualInterface (std::string ifname, InterfaceType_t iftype) 
        : Interface (ifname, iftype)
{
    this->pkt_recv = 0;
    this->pkt_sent = 0;
    this->xmit_pkt_dropped = 0;
}

VirtualInterface::~VirtualInterface() {

}

void 
VirtualInterface::PrintInterfaceDetails () {

    printf ("pkt recvd : %u   pkt sent : %u   xmit pkt dropped : %u\n", 
        this->pkt_recv, this->pkt_sent, this->xmit_pkt_dropped);

    this->Interface::PrintInterfaceDetails();
}






















/* ************ GRETunnelInterface ************ */
GRETunnelInterface::GRETunnelInterface(uint32_t tunnel_id)

        : VirtualInterface ("tunnel" + tunnel_id, INTF_TYPE_GRE_TUNNEL) {

    this->tunnel_id = tunnel_id;
    this->config_flags = 0;
    this->config_flags |= GRE_TUNNEL_TUNNEL_ID_SET;
}

GRETunnelInterface::~GRETunnelInterface() {}

uint32_t
GRETunnelInterface::GetTunnelId () {

    return this->tunnel_id;
}

bool
GRETunnelInterface::IsGRETunnelActive () {

    if ((this->config_flags & GRE_TUNNEL_TUNNEL_ID_SET) &&
         ((this->config_flags & GRE_TUNNEL_SRC_INTF_SET) ||
            (this->config_flags &  GRE_TUNNEL_SRC_ADDR_SET)) ||
        (this->config_flags & GRE_TUNNEL_DST_ADDR_SET) &
        (this->config_flags & GRE_TUNNEL_LCL_IP_SET)) {

        return true;
    }
    return false;
}

void
GRETunnelInterface::SetTunnelSource (PhysicalInterface *interface) {

    uint32_t ip_addr;
    uint8_t mask;

    this->tunnel_src_intf = interface;
    interface->ref_count++;
    this->config_flags |= GRE_TUNNEL_SRC_INTF_SET;

   interface->InterfaceGetIpAddressMask(&ip_addr, &mask);
    if (ip_addr == 0) return;
    this->tunnel_src_ip = ip_addr;
    this->config_flags |= GRE_TUNNEL_SRC_ADDR_SET ;
}

void
GRETunnelInterface::SetTunnelDestination (uint32_t ip_addr) {

    this->tunnel_dst_ip = ip_addr;
    this->config_flags |= GRE_TUNNEL_DST_ADDR_SET;
}

void 
GRETunnelInterface::SetTunnelLclIpMask (uint32_t ip_addr, uint8_t mask) {

    this->lcl_ip = ip_addr;
    this->mask = mask;
    this->config_flags |= GRE_TUNNEL_LCL_IP_SET ;
}

void 
GRETunnelInterface::PrintInterfaceDetails () {

    byte ip_str[16];
    
    printf ("Tunnel Id : %u\n", this->tunnel_id);
    printf ("Tunnel Src Intf  : %s\n", this->tunnel_src_intf->if_name.c_str());
    printf ("Tunnel Src Ip : %s\n", tcp_ip_covert_ip_n_to_p(this->tunnel_src_ip, ip_str));
    printf ("Tunnel Dst Ip : %s\n", tcp_ip_covert_ip_n_to_p(this->tunnel_dst_ip, ip_str));
    printf ("Tunnel Lcl Ip/Mask : %s%d\n",  tcp_ip_covert_ip_n_to_p(this->lcl_ip, ip_str), this->mask);
    printf ("Is Tunnel Active : %s\n", this->IsGRETunnelActive() ? "Y" : "N");

    this->VirtualInterface::PrintInterfaceDetails();
}

int
GRETunnelInterface::SendPacketOut(pkt_block_t *pkt_block) {
    
    return -1;
}
