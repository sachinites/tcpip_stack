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

#pragma pack (push,1)

typedef struct mac_addr_ {
    unsigned char mac[6];
} mac_addr_t;

#pragma pack(pop)

class Interface {

    private:
        
    protected:
        Interface(std::string if_name, InterfaceType_t iftype);
        ~Interface();
    public:
        uint16_t ref_count;
        std::string if_name;
        InterfaceType_t iftype;
        node_t *att_node;
        log_t log_info;
        linkage_t *link;

        /* L1 Properties of Interface */
        bool is_up;
        uint32_t ifindex;

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

        virtual void InterfaceSetIpAddressMask (uint32_t ip_addr, uint8_t mask);
        virtual void InterfaceGetIpAddressMask (uint32_t *ip_addr, uint8_t *mask);
        virtual void SetMacAddr( mac_addr_t *mac_add);
        virtual mac_addr_t *GetMacAddr( );
        virtual bool IsIpConfigured ();
        virtual void PrintInterfaceDetails ();
};




/* ************ */

class PhysicalInterface : public Interface {

    private:
    protected:
         PhysicalInterface(std::string ifname, InterfaceType_t iftype, mac_addr_t *mac_add);
        ~PhysicalInterface();
    public:

        /* L1 Properties */
        uint32_t pkt_recv;
        uint32_t pkt_sent;
        uint32_t xmit_pkt_dropped;

        struct
        {
            uint64_t old_bit_stats;
            uint64_t new_bit_stats;
            uint64_t bit_rate;
            wheel_timer_elem_t *bit_rate_sampling_timer;
        } bit_rate;

        /* L2 Properties */
        mac_addr_t mac_add;

        /* L3 properties */
        uint32_t ip_addr;
        uint8_t mask;
        virtual mac_addr_t *GetMacAddr();
        virtual bool IsIpConfigured();
        virtual void PrintInterfaceDetails ();
};



/* ************ */
class VirtualInterface : public Interface {

    private:
    protected:
         VirtualInterface(std::string ifname, InterfaceType_t iftype);
        ~VirtualInterface();
    public:
        /* L1 Properties */
        uint32_t pkt_recv;
        uint32_t pkt_sent;
        uint32_t xmit_pkt_dropped;
        virtual void PrintInterfaceDetails ();
};


/* ************ */
class P2PInterface : public PhysicalInterface {

    private:     
    protected:
    public:
        P2PInterface(std::string if_name, mac_addr_t *mac_addr);
        P2PInterface();
        ~P2PInterface();
        virtual void InterfaceSetIpAddressMask (uint32_t ip_addr, uint8_t mask);
        virtual void InterfaceGetIpAddressMask (uint32_t *ip_addr, uint8_t *mask);
        virtual void SetMacAddr( mac_addr_t *mac_add);
        virtual void PrintInterfaceDetails ();
};

struct linkage_ {

    PhysicalInterface *intf1;
    PhysicalInterface *intf2;
    uint32_t cost;
}; 




/* ************ */
class LANInterface : public PhysicalInterface {

    enum IntfL2Mode {

        LAN_MODE_NONE,
        LAN_ACCESS_MODE,
        LAN_TRUNK_MODE
    };

    private:
    protected:
    public:
        /* L2 Properties */
        IntfL2Mode l2_mode;

        static std::string L2ModeToString(LANInterface *interface);
        LANInterface(std::string if_name, mac_addr_t *mac_addr);
        LANInterface();
        ~LANInterface();
        virtual void InterfaceSetIpAddressMask (uint32_t ip_addr, uint8_t mask);
        virtual void InterfaceGetIpAddressMask (uint32_t *ip_addr, uint8_t *mask);
        virtual void SetMacAddr( mac_addr_t *mac_add);
        void SetL2Mode ( IntfL2Mode l2_mode);
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
    void SetTunnelSource(Interface *interface);
    void SetTunnelDestination(uint32_t ip_addr);
    void SetTunnelLclIpMask(uint32_t ip_addr, uint8_t mask);
    virtual void PrintInterfaceDetails ();
};

#endif