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

extern void
snp_flow_init_flow_tree_root(avltree_t *avl_root) ;

Interface::Interface(std::string if_name, InterfaceType_t iftype) {

    this->if_name = if_name;
    this->iftype = iftype;
    this->ref_count = 0;
    this->att_node = NULL;
    memset (&this->log_info, 0, sizeof(this->log_info));
    this->link = NULL;
    this->is_up = false;
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

void
Interface::InterfaceSetIpAddressMask (uint32_t ip_addr, uint8_t mask) { 
    
    TO_BE_OVERRIDDEN_BY_DERIEVED_CLASS;
}

void
Interface::InterfaceGetIpAddressMask (uint32_t *ip_addr, uint8_t *mask) {

    TO_BE_OVERRIDDEN_BY_DERIEVED_CLASS;
}

uint32_t 
Interface::GetLinkCost() {

    return this->link->cost;
}

void
Interface::SetMacAddr( mac_addr_t *mac_add) {

    TO_BE_OVERRIDDEN_BY_DERIEVED_CLASS;
}

mac_addr_t *
Interface::GetMacAddr( ) {

     TO_BE_OVERRIDDEN_BY_DERIEVED_CLASS;
}

bool 
Interface::IsIpConfigured () {

     TO_BE_OVERRIDDEN_BY_DERIEVED_CLASS;
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

void 
Interface::Xmit_pkt_dropped_inc() {

    TO_BE_OVERRIDDEN_BY_DERIEVED_CLASS;
}

void 
Interface::PktSentInc() {

    TO_BE_OVERRIDDEN_BY_DERIEVED_CLASS;
}

void 
Interface::BitRateNewBitStatsInc(uint64_t val) {

    TO_BE_OVERRIDDEN_BY_DERIEVED_CLASS;
}

node_t *
Interface::GetNbrNode () {

    Interface *interface = this;

    assert(this->att_node);
    assert(this->link);
    
    linkage_t *link = interface->link;
    if (link->intf1 == interface)
        return link->intf2->att_node;
    else
        return link->intf1->att_node;
}

Interface *
Interface::GetOtherInterface() {

    return  this->link->intf1 == this ? \
                this->link->intf2 : this->link->intf1;
}





/* ************ PhysicalInterface ************ */
PhysicalInterface::PhysicalInterface ( std::string ifname, InterfaceType_t iftype, mac_addr_t *mac_add) 
    : Interface (ifname, iftype)
{

    this->pkt_recv = 0;
    this->pkt_sent = 0;
    this->xmit_pkt_dropped = 0;

    this->bit_rate.old_bit_stats = 0;
    this->bit_rate.new_bit_stats = 0;
    this->bit_rate.bit_rate = 0;

    if (mac_add) {
        memcpy (this->mac_add.mac, mac_add->mac, sizeof (*mac_add));
    }
    this->ip_addr = 0;
    this->mask = 0;
}

PhysicalInterface::~PhysicalInterface () {

}

mac_addr_t *
PhysicalInterface::GetMacAddr( ) {

     return &this->mac_add;
}


bool 
PhysicalInterface::IsIpConfigured () {

     if (this->ip_addr && this->mask)
        return true;
    return false;
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

    this->Interface::PrintInterfaceDetails();
}

void 
PhysicalInterface::Xmit_pkt_dropped_inc() {

    this->xmit_pkt_dropped++;
}

void 
PhysicalInterface::PktSentInc() {

    this->pkt_sent++;
}


void 
PhysicalInterface::BitRateNewBitStatsInc(uint64_t val) {

    this->bit_rate.new_bit_stats += val;
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





/* ************ P2PInterface ************ */
P2PInterface::P2PInterface(std::string if_name, mac_addr_t *mac_addr)
        : PhysicalInterface(if_name, INTF_TYPE_P2P, mac_addr)

{

}

P2PInterface::~P2PInterface() { }

void
P2PInterface::InterfaceSetIpAddressMask (uint32_t ip_addr, uint8_t mask) {

    this->ip_addr = ip_addr;
    this->mask = mask;
}

void
P2PInterface::InterfaceGetIpAddressMask (uint32_t *ip_addr, uint8_t *mask) {

    *ip_addr = this->ip_addr;
    *mask = this->mask;
}

void 
P2PInterface::SetMacAddr( mac_addr_t *mac_add) {

    memcpy (&this->mac_add, mac_add, sizeof (*mac_add));
}

void 
P2PInterface::PrintInterfaceDetails () {

    this->PhysicalInterface::PrintInterfaceDetails ();
}





/* ************ LANInterface ************ */
LANInterface::LANInterface(std::string if_name, mac_addr_t *mac_addr) 
        : PhysicalInterface(if_name, INTF_TYPE_LAN, mac_addr)

{
    this->l2_mode = LAN_MODE_NONE;
}

LANInterface::~LANInterface() { }

void
LANInterface::InterfaceSetIpAddressMask (uint32_t ip_addr, uint8_t mask) {

    this->ip_addr = ip_addr;
    this->mask = mask;
}

void
LANInterface::InterfaceGetIpAddressMask (uint32_t *ip_addr, uint8_t *mask) {

    *ip_addr = this->ip_addr;
    *mask = this->mask;
}

void 
LANInterface::SetMacAddr( mac_addr_t *mac_add) {

    memcpy (&this->mac_add, mac_add, sizeof (*mac_add));
}

void
LANInterface::SetL2Mode ( IntfL2Mode l2_mode) {

    this->l2_mode = l2_mode;
}

std::string
LANInterface::L2ModeToString(LANInterface *interface){

    switch (interface->l2_mode) {
        
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

void 
LANInterface::PrintInterfaceDetails () {

    printf ("Vlan L2 Mode : %s\n", LANInterface::L2ModeToString(this).c_str());
    this->PhysicalInterface::PrintInterfaceDetails ();
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
GRETunnelInterface::SetTunnelSource (Interface *interface) {

    uint32_t ip_addr;
    uint8_t mask;

    assert(interface->iftype !=  INTF_TYPE_LAN);
    assert(interface->iftype !=  INTF_TYPE_GRE_TUNNEL);

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