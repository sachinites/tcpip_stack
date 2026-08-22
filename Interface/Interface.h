/*
 * =====================================================================================
 *
 *       Filename:  Interface.h
 *
 *    Description:  This file is a base class for various type of interfaces
 *
 *        Version:  1.0
 *        Created:  12/06/2022 11:28:41 AM
 *       Revision:  none
 *       Compiler:  g++
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Cisco Systems, Juniper Networks
 *
 * =====================================================================================
 */

#ifndef __INTERFACE__
#define __INTERFACE__

#include <string>
#include <stdint.h>
#include <atomic>
#include "../libs/Tree/libtree.h"
#include "InterfacEnums.h"
#include "../tcp_ip_trace.h"
#include "../net.h"
#include <vector>

#include "InterfaceFwd.h"

typedef struct node_ node_t;
typedef struct linkage_ linkage_t;
typedef struct access_list_ access_list_t;
typedef struct _wheel_timer_elem_t wheel_timer_elem_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct intf_info_  isis_intf_info_t;
typedef struct vrf_ vrf_t;

class TransportService;

/* Default Reference Count of the interfaces of various types*/

/* Physical Ethernet interface
  link->Intf1 
  node->intf_by_name
  node->intf_by_ifindex  
*/
#define PHY_ETH_IF_DEF_REFCOUNT   3

/* node->vlan_intf_db 
   node->intf_by_name
   node->intf_by_ifindex  
*/
#define VLAN_IF_DEF_REFCOUNT 3

/* node->node_nw_prop.nve */
#define NVE_IF_DEF_REFCOUNT 1


/*
  node->intf_by_name
  node->intf_by_ifindex  
  //default_vrf->intf_by_name
  //default_vrf->intf_by_ifindex  
*/
#define GRE_IF_REFCOUNT 2

/*
  node->intf_by_name
  node->intf_by_ifindex    
*/
#define VPORT_IF_REFCOUNT 2

/*
  node->intf_by_name
  node->intf_by_ifindex    
*/
#define LOOPBACK_IF_REFCOUNT  2

/*
  node->intf_by_name
  node->intf_by_ifindex    
*/
#define BD_AC_IF_REFCOUNT  2

/*
  node->intf_by_name
  node->intf_by_ifindex    
*/
#define BD_IF_REFCOUNT  2


class Interface {

    private:
        std::weak_ptr<Interface> intfP;
        uint32_t sock_fd;
        char padding1[4];
        void InterfaceReleaseAllResources();

    protected:
 
        Interface(std::string if_name, InterfaceType_t iftype);
    public:
        std::string if_name; // 24 B
        node_t *att_node;
        linkage_t *link;

        /* L1 Properties of Interface */
        uint32_t ifindex;
        uint32_t pkt_recv;
        uint32_t pkt_sent;
        uint32_t xmit_pkt_dropped;
        uint32_t recvd_pkt_dropped;
        uint32_t cost;
        uint32_t rtm_local_rt_idx;
        uint32_t rtm_connected_rt_idx;
        uint32_t rtm_local_rt6_idx;
        uint32_t rtm_connected_rt6_idx;
        uint32_t rtm_link_local_rt6_idx;
        char padding2[4];

        /* L2 Properties : Ingress & egress L2 Access_list */
        access_list_t *l2_ingress_acc_lst;
        access_list_t *l2_egress_acc_lst;

        /* L3 properties :  Ingress & egress L3 Access_list */
        access_list_t *l3_ingress_acc_lst;
        access_list_t *l3_egress_acc_lst;

        /* L3 protocols */
        isis_intf_info_t *isis_intf_info;
        vrf_t *vrf;
        
        bool is_up;
        InterfaceType_t iftype;
        char padding3[6];

        uint32_t GetIntfCost();
        uint32_t GetSockfd();
        vrf_t* GetVRF();
        void SetSockfd(uint32_t sockfd);
        node_t *GetNbrNode ();
        Interface *GetOtherInterface();

        /* APIs to work with Interfaces */
        virtual ~Interface();
        virtual InterfaceP GetSharedPtr () final;
        virtual void SetSharedPtr (InterfaceP intfP) final;

        virtual void PrintInterfaceDetails ();
        virtual void SetMacAddr( mac_addr_t *mac_add);
        virtual mac_addr_t *GetMacAddr( );
        virtual bool IsIpConfigured() ;
        virtual bool IsIpv6Configured() ;
        virtual void InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) ;
        virtual void InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask) ;
        virtual void InterfaceSetIpv6AddressMask(uint8_t (*addr)[16], uint8_t prefix_len) ;
        virtual void InterfaceGetIpv6AddressMask(uint8_t (*addr)[16], uint8_t *prefix_len) ;
        virtual void InterfaceSetIpv6LinkLocalAddress(unsigned char (*mac)[6]) ;
        virtual void InterfaceGetIpv6LinkLocalAddress(uint8_t (*addr)[16]) ;
        virtual vlan_id_t GetVlanId();
        virtual bool IsVlanTrunked (vlan_id_t vlan_id);
        virtual bool IntfConfigVlan(vlan_id_t vlan_id, bool add);
        virtual void SetSwitchport(bool enable);      
        virtual bool GetSwitchport(); 
        virtual bool HasL3Config(bool matchvrf); 
        virtual IntfL2Mode GetL2Mode ();
        virtual void SetL2Mode (IntfL2Mode l2_mode);
        virtual bool IsSameSubnet (uint32_t ip_addr);
        virtual bool IntfConfigTransportSvc(std::string& trans_svc);
        virtual bool IntfUnConfigTransportSvc(std::string& trans_svc);
        virtual bool IsInterfaceUp(vlan_id_t vlan_id);
        virtual bool IsCrossReferenced() = 0;
        virtual VlanInterfaceP GetAccessVlanIntf(); 
        /* Return TRUE if the interface is SVI*/
        virtual bool IsSVI ();
} __attribute__((aligned(8)));


/* ************ */
class PhysicalInterface : public Interface {

    private:
        /* L2 Properties */
        bool switchport;
        char pad1[3];
        mac_addr_t mac_add;
        char pad2[2];
        IntfL2Mode l2_mode;
        /* L3 properties */
        uint8_t v6addr_link_local[16];
        uint8_t v6addr[16];
        uint8_t v6mask;
        uint32_t ip_addr;
        uint8_t mask;
        char pad3[1];
        void InterfaceReleaseAllResources() ;
    protected:
    public:
         uint16_t used_as_underlying_tunnel_intf;
         char pad4[2];

        /* Below two are mutually exclusive with bd_ac */
        TransportService *trans_svc;
        VlanInterfaceP access_vlan_intf;
        ACInterfaceP bd_ac;

        PhysicalInterface(std::string ifname, InterfaceType_t iftype, mac_addr_t *mac_add);
        virtual ~PhysicalInterface();

        static std::string L2ModeToString(IntfL2Mode l2_mode);
        virtual void SetMacAddr( mac_addr_t *mac_add) final;
        virtual mac_addr_t *GetMacAddr( ) final;
        virtual bool IsIpConfigured() final;
        virtual bool IsIpv6Configured() final;
        virtual void InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) final;
        virtual void InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask) final;
        virtual void InterfaceSetIpv6AddressMask(uint8_t (*addr)[16], uint8_t prefix_len) final;
        virtual void InterfaceGetIpv6AddressMask(uint8_t (*addr)[16], uint8_t *prefix_len) final;
        virtual void InterfaceSetIpv6LinkLocalAddress(unsigned char (*mac)[6]) final;
        virtual void InterfaceGetIpv6LinkLocalAddress(uint8_t (*addr)[16]) final;
        virtual vlan_id_t GetVlanId() final;
        virtual bool IsVlanTrunked (vlan_id_t vlan_id) final;
        virtual bool IntfConfigVlan(vlan_id_t vlan_id, bool add) final;
        virtual void SetSwitchport(bool enable) final;
        virtual bool IsCrossReferenced() final;
        virtual bool GetSwitchport() final;
        virtual bool HasL3Config(bool matchvrf) final; 
        virtual IntfL2Mode GetL2Mode () final;
        virtual void SetL2Mode (IntfL2Mode l2_mode) final;
        virtual void PrintInterfaceDetails ();
        virtual bool IsSameSubnet (uint32_t ip_addr) final;
        virtual bool IntfConfigTransportSvc(std::string& trans_svc) final;
        virtual bool IntfUnConfigTransportSvc(std::string& trans_svc) final;
        virtual bool IsInterfaceUp(vlan_id_t vlan_id) final;
        virtual VlanInterfaceP GetAccessVlanIntf() final;
        
} __attribute__((aligned(8)));

typedef struct linkage_ {

    PhysicalInterfaceP Intf1;
    PhysicalInterfaceP Intf2;
} linkage_t;



/* ************ */
class VirtualInterface : public Interface {

    private:
    protected:
         VirtualInterface(std::string ifname, InterfaceType_t iftype);
    public:
        virtual ~VirtualInterface();
        virtual void PrintInterfaceDetails ();
} __attribute__((aligned(8)));;



/* ************ */

class VlanInterface : public VirtualInterface {

    private:
        void InterfaceReleaseAllResources() ;
    protected:
    public:
        uint32_t ip_addr;
        vlan_id_t vlan_id;
        uint8_t mask;
        uint32_t vni_id;  /* Virtual Network Identifier */
        /* Number of access mode interfaces using this LAN*/
        std::vector<InterfaceP> access_member_intf_lst;
        VlanInterface(vlan_id_t vlan_id);
         virtual ~VlanInterface();
        virtual void PrintInterfaceDetails ();
        virtual void InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) final;
        virtual void InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask) final;
        virtual bool IsIpConfigured() final;
        virtual vlan_id_t GetVlanId() final;
        virtual bool IsSameSubnet(uint32_t ip_addr) final;
        static VlanInterface *VlanInterfaceLookUp(node_t *node, vlan_id_t vlan_id);
        virtual bool IsInterfaceUp(vlan_id_t vlan_id) final;
        virtual bool IsCrossReferenced() final;
        virtual bool IsSVI ();
        virtual mac_addr_t *GetMacAddr( );
        virtual bool HasL3Config(bool matchvrf) final;
        
        /* VNI Management Methods */
        void SetVniId(uint32_t vni_id);
        uint32_t GetVniId() const;
        bool IsVniConfigured() const;
} __attribute__((aligned(8)));;


/* VxLAN interface*/
class NVEInterface : public VirtualInterface {

    private:
        uint32_t member_vnis[16];
        void InterfaceReleaseAllResources() ;
    protected:
    public:

        NVEInterface(std::string if_name);
        virtual ~NVEInterface();
        bool AddMemberVni(uint32_t vni);
        bool RemoveMemberVni(uint32_t vni);
        bool CheckMemberVniMembership(uint32_t vni);
        virtual void PrintInterfaceDetails ();
        void GetMemberVnis(std::vector<uint32_t>& vni_list);
        static NVEInterface *NVEInterfaceLookUp(node_t *node, std::string if_name);
        virtual bool IsCrossReferenced() final;
        
} __attribute__((aligned(8)));


enum GreTunnelConfigEnum
{
    GRE_TUNNEL_TUNNEL_ID_SET = 1,
    GRE_TUNNEL_SRC_INTF_SET = 2,
    GRE_TUNNEL_SRC_ADDR_SET = 4,
    GRE_TUNNEL_DST_ADDR_SET = 8,
    GRE_TUNNEL_OVLAY_IP_SET = 16,
    GRE_TUNNEL_ADMIN_SHUT_SET = 32
};

class GRETunnelInterface : public VirtualInterface {

private:
    void InterfaceReleaseAllResources() ;
protected:
public:
    
    VirtualPortP virtual_port_intf;
    PhysicalInterfaceP tunnel_src_intf;
    uint32_t tunnel_id;
    uint32_t tunnel_src_ip;
    uint32_t tunnel_dst_ip;
    uint32_t lcl_ip;
    uint16_t config_flags;
    uint8_t mask;
    uint8_t is_active;
    char padding[4];

    GRETunnelInterface(uint32_t tunnel_id);
    virtual ~GRETunnelInterface();
    uint32_t GetTunnelId();
    bool IsGRETunnelActive();
    bool SetTunnelSource(PhysicalInterface *interface);
    void SetTunnelDestination(uint32_t ip_addr);
    void SetTunnelLclIpMask(uint32_t ip_addr, uint8_t mask);
    virtual void PrintInterfaceDetails ();
    void SetTunnelSrcIp(uint32_t src_addr);
    void UnSetTunnelSrcIp();
    virtual void InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) final;
    virtual void InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask) final;
    virtual bool IsIpConfigured() final;
    virtual bool IsSameSubnet(uint32_t ip_addr);
    virtual mac_addr_t * GetMacAddr() final;
    virtual bool IsCrossReferenced() final;
    void gre_tunnel_check_and_activate_tunnel ();
    void gre_deactivate_tunnel ();
    void gre_tunnel_sync_dp_attrs ();
} __attribute__((aligned(8)));


class VirtualPort : public VirtualInterface {

    private:
        void InterfaceReleaseAllResources() ;
    protected:
    public:

        VirtualInterfaceP olay_tunnel_intf;
        /* Below two are mutually exclusive */
        TransportService *trans_svc;

        VirtualPort(std::string ifname);
        virtual ~VirtualPort();
        bool BindOverlayTunnel(VirtualInterface *tunnel);
        bool UnBindOverlayTunnel(VirtualInterface *tunnel);
        virtual void PrintInterfaceDetails ();
        virtual bool IsInterfaceUp(vlan_id_t vlan_id) final;
        virtual bool IsVlanTrunked (vlan_id_t vlan_id) final;
        virtual bool IntfConfigTransportSvc(std::string& trans_svc) final;
        virtual bool IntfUnConfigTransportSvc(std::string& trans_svc) final;
        virtual bool GetSwitchport() final;
        virtual IntfL2Mode GetL2Mode () final;
        virtual bool IsCrossReferenced() final;
} __attribute__((aligned(8)));;

class LoopbackInterface : public VirtualInterface {

    private:
        void InterfaceReleaseAllResources();
    protected:
    public:
        uint8_t v6addr[16];
        uint32_t ip_addr;
        uint8_t mask;
        uint8_t v6mask;
        char padding[2];

        LoopbackInterface(std::string ifname);
        virtual ~LoopbackInterface();
        virtual void PrintInterfaceDetails ();
        virtual bool IsIpConfigured() final;
        virtual void InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) final;
        virtual void InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask) final;
        virtual void InterfaceSetIpv6AddressMask(uint8_t (*addr)[16], uint8_t prefix_len) final;
        virtual void InterfaceGetIpv6AddressMask(uint8_t (*addr)[16], uint8_t *prefix_len) final;
        virtual bool IsSameSubnet (uint32_t ip_addr) final;
        virtual bool IsCrossReferenced() final;

} __attribute__((aligned(8)));


class HostPathInterface : public VirtualInterface {

    private:
    protected:
    public:
        HostPathInterface();
        virtual ~HostPathInterface();;
        virtual bool IsCrossReferenced() final;      
};

class ACInterface : public Interface {

    private:
        uint16_t encap_tag_8021q;
        InterfaceP forwarding_intf;
        BDInterfaceP bd_intf;
        void InterfaceReleaseAllResources();

    public:
        ACInterface(std::string ifname, InterfaceType_t iftype);
        virtual ~ACInterface();
        void SetEncap_tag_8021q(uint16_t vlan_id);
        void UnSetEncap_tag_8021q(uint16_t vlan_id);
        uint16_t GetEncap_tag_8021q() const;
        bool SetUnderlyingInterface(InterfaceP intf);
        void UnSetUnderlyingInterface();
        InterfaceP GetUnderlyingInterface();
        bool SetBdInterface(BDInterfaceP bd);
        void UnSetBdInterface();
        BDInterfaceP GetBdInterface();
        bool IsCrossReferenced() final;
        
} __attribute__((aligned(8)));


class BDInterface : public VirtualInterface {

    private:
        void InterfaceReleaseAllResources() ;

    protected:

    public:
        uint32_t ip_addr;
        uint32_t vpn_svc_label;
        uint16_t bd_id;
        uint8_t mask;
        char _pad[5];
        BDInterface(std::string ifname, InterfaceType_t iftype);
        virtual ~BDInterface();
        bool IsCrossReferenced() final;
        virtual void InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) final;
        virtual void InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask) final;
        virtual bool IsIpConfigured() final;
        virtual bool IsSameSubnet(uint32_t ip_addr) final;
        virtual mac_addr_t *GetMacAddr() final;
        virtual bool IsSVI() final;
        virtual bool HasL3Config(bool matchvrf) final;
        /* Member Attachment circuits */
        std::vector<ACInterfaceP> member_ac;
        bool AddMemberAC(ACInterfaceP ac);
        bool DelMemberAC(ACInterfaceP ac);
        ACInterfaceP FindMemberAC(Interface *phy);

} __attribute__((aligned(8)));


typedef union intf_prop_changed_ {

        uint32_t intf_metric;

        struct {
            uint32_t ip_addr;
            uint8_t mask;
        } ip_addr;
        
        bool up_status;           /* True for up, false for down */
        bool is_switchport;     /* True for SW, false for no switchport*/
        IntfL2Mode intf_l2_mode;
        uint32_t access_vlan;
        TransportService *trans_svc;

} intf_prop_changed_t;


void 
dump_intf_props_header();

void 
dump_intf_props (Interface *interface);

#endif
