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
#include "../Tree/libtree.h"
#include "InterfacEnums.h"
#include "../tcp_ip_trace.h"
#include "../net.h"

typedef struct node_ node_t;
typedef struct linkage_ linkage_t;
typedef struct access_list_ access_list_t;
typedef struct _wheel_timer_elem_t wheel_timer_elem_t;
typedef struct pkt_block_ pkt_block_t;
class TransportService;

#define INTF_MAX_VLAN_MEMBERSHIP 10

/* Interface Change Flags, used for Notification to 
 * Applications*/
#define IF_UP_DOWN_CHANGE_F         (1 << 0)
#define IF_IP_ADDR_CHANGE_F           (1 << 1)
#define IF_OPER_MODE_CHANGE_F    (1 << 2)
#define IF_VLAN_MEMBERSHIP_CHANGE_F (1 << 3)
#define IF_METRIC_CHANGE_F          (1 << 4)

class Interface {

    private:
       
    protected:
        Interface(std::string if_name, InterfaceType_t iftype);
        ~Interface();
    public:
        InterfaceType_t iftype;
        uint16_t ref_count;
        std::string if_name;
        node_t *att_node;
        log_t log_info;
        linkage_t *link;

        /* L1 Properties of Interface */
        bool is_up;
        uint32_t ifindex;
        uint32_t pkt_recv;
        uint32_t pkt_sent;
        uint32_t xmit_pkt_dropped;
        uint32_t cost;

        /* L2 Properties : Ingress & egress L2 Access_list */
        access_list_t *l2_ingress_acc_lst;
        access_list_t *l2_egress_acc_lst;

        /* L3 properties :  Ingress & egress L3 Access_list */
        pthread_spinlock_t spin_lock_l3_ingress_acc_lst;
        access_list_t *l3_ingress_acc_lst;
        pthread_spinlock_t spin_lock_l3_egress_acc_lst;
        access_list_t *l3_egress_acc_lst;

        /* L5 protocols */
        void *isis_intf_info;

        avltree_t flow_avl_root;

        uint32_t GetIntfCost();
        node_t *GetNbrNode ();
        Interface *GetOtherInterface();

        /* APIs to work with Interfaces */
        virtual int SendPacketOut(pkt_block_t *pkt_block);
        virtual void PrintInterfaceDetails ();
        virtual void SetMacAddr( mac_addr_t *mac_add);
        virtual mac_addr_t *GetMacAddr( );
        virtual bool IsIpConfigured() ;
        virtual void InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) ;
        virtual void InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask) ;
        virtual uint32_t GetVlanId();
        virtual bool IsVlanTrunked (uint32_t vlan_id);
        virtual bool IntfConfigVlan(uint32_t vlan_id, bool add);
        virtual void SetSwitchport(bool enable);      
        virtual bool GetSwitchport(); 
        virtual IntfL2Mode GetL2Mode ();
        virtual void SetL2Mode (IntfL2Mode l2_mode);
        virtual bool IsSameSubnet (uint32_t ip_addr);
        virtual bool IntfConfigTransportSvc(std::string& trans_svc);
        virtual bool IntfUnConfigTransportSvc(std::string& trans_svc);
};




/* ************ */

class PhysicalInterface : public Interface {

    private:
        /* L2 Properties */
        bool switchport;
        mac_addr_t mac_add;
        IntfL2Mode l2_mode;
        
       
        /* L3 properties */
        uint32_t ip_addr;
        uint8_t mask;
        
    protected:
    public:
         uint16_t used_as_underlying_tunnel_intf;
         uint32_t vlans[INTF_MAX_VLAN_MEMBERSHIP];  
        TransportService *trans_svc;

        PhysicalInterface(std::string ifname, InterfaceType_t iftype, mac_addr_t *mac_add);
        ~PhysicalInterface();

        static std::string L2ModeToString(IntfL2Mode l2_mode);
        virtual void SetMacAddr( mac_addr_t *mac_add) final;
        virtual mac_addr_t *GetMacAddr( ) final;
        virtual bool IsIpConfigured() final;
        virtual void InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) final;
        virtual void InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask) final;
        virtual uint32_t GetVlanId() final;
        virtual bool IsVlanTrunked (uint32_t vlan_id) final;
        virtual bool IntfConfigVlan(uint32_t vlan_id, bool add) final;
        virtual void SetSwitchport(bool enable) final;
        virtual bool GetSwitchport() final;
        virtual IntfL2Mode GetL2Mode () final;
        virtual void SetL2Mode (IntfL2Mode l2_mode) final;
        virtual void PrintInterfaceDetails ();
        virtual int SendPacketOut(pkt_block_t *pkt_block) final;
        virtual bool IsSameSubnet (uint32_t ip_addr) final;
        virtual bool IntfConfigTransportSvc(std::string& trans_svc) final;
        virtual bool IntfUnConfigTransportSvc(std::string& trans_svc) final;
};

typedef struct linkage_ {

    PhysicalInterface *Intf1;
    PhysicalInterface *Intf2;
} linkage_t;



/* ************ */
class VirtualInterface : public Interface {

    private:
    protected:
         VirtualInterface(std::string ifname, InterfaceType_t iftype);
        ~VirtualInterface();
    public:
        virtual void PrintInterfaceDetails ();
};




/* ************ */
class GRETunnelInterface : public VirtualInterface {

private:
protected:
public:
    
    uint32_t tunnel_id;
    Interface *tunnel_src_intf;
    uint32_t tunnel_src_ip;
    uint32_t tunnel_dst_ip;
    uint32_t lcl_ip;
    uint8_t mask;

    enum GreTunnelConfigEnum
    {
        GRE_TUNNEL_TUNNEL_ID_SET = 1,
        GRE_TUNNEL_SRC_INTF_SET = 2,
        GRE_TUNNEL_SRC_ADDR_SET = 4,
        GRE_TUNNEL_DST_ADDR_SET = 8,
        GRE_TUNNEL_LCL_IP_SET = 16
    };

    uint16_t config_flags;
    GRETunnelInterface(uint32_t tunnel_id);
    ~GRETunnelInterface();
    uint32_t GetTunnelId();
    bool IsGRETunnelActive();
    void SetTunnelSource(PhysicalInterface *interface);
    void SetTunnelDestination(uint32_t ip_addr);
    void SetTunnelLclIpMask(uint32_t ip_addr, uint8_t mask);
    virtual void PrintInterfaceDetails ();
    virtual int SendPacketOut(pkt_block_t *pkt_block) final;
    void SetTunnelSrcIp(uint32_t src_addr);
    void UnSetTunnelSrcIp();
    virtual void InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) final;
    virtual void InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask) final;
    virtual bool IsIpConfigured() final;
    virtual bool IsSameSubnet(uint32_t ip_addr);
    virtual mac_addr_t * GetMacAddr() final;
};


typedef union intf_prop_changed_ {

        uint32_t intf_metric;

        struct {
            uint32_t ip_addr;
            uint8_t mask;
        } ip_addr;
        
        bool up_status; /* True for up, false for down */
        IntfL2Mode intf_l2_mode;
        uint32_t vlan;
        TransportService *trans_svc;

} intf_prop_changed_t;


#endif
