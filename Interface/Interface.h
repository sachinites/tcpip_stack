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

typedef struct node_ node_t;
typedef struct linkage_ linkage_t;
typedef struct access_list_ access_list_t;
typedef struct _wheel_timer_elem_t wheel_timer_elem_t;
typedef struct pkt_block_ pkt_block_t;

#define INTF_MAX_VLAN_MEMBERSHIP 10

#pragma pack (push,1)

typedef struct mac_addr_ {
    unsigned char mac[6];
} mac_addr_t;

#pragma pack(pop)


class Interface {

    private:
       
    protected:
        InterfaceType_t iftype;
        Interface(std::string if_name, InterfaceType_t iftype);
        ~Interface();
    public:
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

        uint32_t GetLinkCost();
        node_t *GetNbrNode ();
        Interface *GetOtherInterface();

        virtual int SendPacketOut(pkt_block_t *pkt_block);
        virtual void PrintInterfaceDetails ();
};




/* ************ */

class PhysicalInterface : public Interface {

    private:
    protected:
    public:
        PhysicalInterface(std::string ifname, InterfaceType_t iftype, mac_addr_t *mac_add);
        ~PhysicalInterface();

        enum IntfL2Mode
        {
            LAN_MODE_NONE,
            LAN_ACCESS_MODE,
            LAN_TRUNK_MODE
        };

        /* L2 Properties */
        bool switchport;
        mac_addr_t mac_add;
        IntfL2Mode l2_mode;
        uint32_t vlans[INTF_MAX_VLAN_MEMBERSHIP];  

        /* L3 properties */
        uint32_t ip_addr;
        uint8_t mask;

        static std::string L2ModeToString(IntfL2Mode l2_mode);
        void SetMacAddr( mac_addr_t *mac_add);
        mac_addr_t *GetMacAddr( );
        bool IsIpConfigured() ;
        void InterfaceSetIpAddressMask(uint32_t ip_addr, uint8_t mask) ;
        void InterfaceGetIpAddressMask(uint32_t *ip_addr, uint8_t *mask) ;
        uint32_t GetVlanId();
        bool IsVlanTrunked (uint32_t vlan_id);
        void SetSwitchport(bool enable);        
        
        virtual void PrintInterfaceDetails ();
        virtual int SendPacketOut(pkt_block_t *pkt_block) final;
};

typedef struct linkage_ {

    PhysicalInterface *Intf1;
    PhysicalInterface *Intf2;
    uint32_t cost;
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

    enum GreTunnelConfigEnum
    {
        GRE_TUNNEL_TUNNEL_ID_SET = 1,
        GRE_TUNNEL_SRC_INTF_SET = 2,
        GRE_TUNNEL_SRC_ADDR_SET = 4,
        GRE_TUNNEL_DST_ADDR_SET = 8,
        GRE_TUNNEL_LCL_IP_SET = 16
    };

private:

    uint8_t config_flags;

protected:
    uint32_t tunnel_id;
    Interface *tunnel_src_intf;
    uint32_t tunnel_src_ip;
    uint32_t tunnel_dst_ip;
    uint32_t lcl_ip;
    uint8_t mask;
public:   
    GRETunnelInterface(uint32_t tunnel_id);
    ~GRETunnelInterface();
    uint32_t GetTunnelId();
    bool IsGRETunnelActive();
    void SetTunnelSource(PhysicalInterface *interface);
    void SetTunnelDestination(uint32_t ip_addr);
    void SetTunnelLclIpMask(uint32_t ip_addr, uint8_t mask);
    virtual void PrintInterfaceDetails ();
    virtual int SendPacketOut(pkt_block_t *pkt_block) final;
};

#endif