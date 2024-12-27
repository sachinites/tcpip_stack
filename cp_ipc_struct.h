#ifndef __CP_IPC_STRUCT__
#define __CP_IPC_STRUCT__

#include <stdint.h>
#include <stdbool.h>
#include "Interface/InterfacEnums.h"
#include "Interface/InterfaceFwd.h"
#include "Layer3/ipv6/ipv6_hdrs.h"
#include "Layer3/SegmentRouting/SRv6/common/srv6_const.h"

class TransportService;

typedef enum ips_msg_code_ {

    IPC_IPV4_ROUTE,
    #define IPC_IPV4_ROUTE_ADD 1
    #define IPC_IPV4_ROUTE_DEL 2
    #define IPC_IPV4_ROUTE_GW_UPDATE 4
    #define IPC_IPV4_ROUTE_METRIC_UPDATE 8
    #define IPC_IPV4_ROUTE_OIF_UPDATE 16

    IPC_INTERFACE,
    #define IPC_INTERFACE_ADD 1
    #define IPC_INTERFACE_DEL 2
    #define IPC_INTERFACE_METRIC_UPDATE 4
    #define IPC_INTERFACE_BW_UPDATE 8
    #define IPC_INTERFACE_MTU_UPDATE 16
    #define IPC_INTERFACE_IPV4_ADDR_ADD 32
    #define IPC_INTERFACE_IPV4_ADDR_DEL 64
    #define IPC_INTERFACE_IPV4_ADDR_UPDATE 128
    #define IPC_INTERFACE_IPV6_ADDR_ADD 256
    #define IPC_INTERFACE_IPV6_ADDR_DEL 512
    #define IPC_INTERFACE_IPV6_ADDR_UPDATE 1024
    #define IPC_INTERFACE_ADMIN_STATE_DOWN 2048
    #define IPC_INTERFACE_ADMIN_STATE_UP 4096
    #define IPC_INTERFACE_IPV6_LINK_LOCAL_ADDR_ADD 8192
    #define IPC_INTERFACE_IPV6_LINK_LOCAL_ADDR_DEL (1 << 14)
    #define IPC_INTERFACE_IPV6_LINK_LOCAL_ADDR_UPDATE (1 << 15)
    #define  IPC_INTERFACE_SWITCHPORT_UPDATE    (1 << 16)
    #define  IPC_INTERFACE_L2MODE_UPDATE   (1 << 17)
    #define IPC_INTERFACE_ACCESS_VLAN_UPDATE    (1 << 18)
    #define IPC_INTERFACE_TSP_UPDATE (1 << 19)

    IPC_GRE_TUNNEL,
    #define IPC_GRE_TUNNEL_ADD 1
    #define IPC_GRE_TUNNEL_DEL 2
    #define IPC_GRE_TUNNEL_METRIC_UPDATE 4
    #define IPC_GRE_TUNNEL_BW_UPDATE 8
    #define IPC_GRE_TUNNEL_MTU_UPDATE 16
    #define IPC_GRE_TUNNEL_ADMIN_STATE_DOWN 32
    #define IPC_GRE_TUNNEL_ADMIN_STATE_UP 64
    
    IPC_ACCESS_LIST,
    #define IPC_ACCESS_LIST_ADD 1
    #define IPC_ACCESS_LIST_DEL 2
    #define IPC_ACCESS_LIST_UPDATE 4

    /* Producer is SRV6 Module */
    IPC_SRV6_INFO,
    #define IPC_SRV6_LOCATOR_ADD (1 << 0)
    #define IPC_SRV6_LOCATOR_DEL (1 << 1)
    #define IPC_SRV6_PREFIX_SID_ADD (1 << 2)
    #define IPC_SRV6_PREFIX_SID_DEL (1 << 3)
    #define IPC_SRV6_ADJ_SID_ADD (1 << 4)
    #define IPC_SRV6_ADJ_SID_DEL (1 << 5)

    /* Producer is ISIS , SRV6 info which it has learnt from
        LSDB advertisement */
    IPC_ISIS_SRV6_LSDB_INFO,
    #define IPC_ISIS_SRV6_LOCATOR_ADD (1 << 0)
    #define IPC_ISIS_SRV6_LOCATOR_DEL (1 << 1)
    #define IPC_ISIS_SRV6_PREFIX_SID_ADD (1 << 2)
    #define IPC_ISIS_SRV6_PREFIX_SID_DEL (1 << 3)
    #define IPC_ISIS_SRV6_ADJ_SID_ADD (1 << 4)
    #define IPC_ISIS_SRV6_ADJ_SID_DEL (1 << 5)
    #define IPC_ISIS_SRV6_TLVs ((IPC_ISIS_SRV6_LOCATOR_ADD | IPC_ISIS_SRV6_LOCATOR_DEL | \
                                                         IPC_ISIS_SRV6_PREFIX_SID_ADD | IPC_ISIS_SRV6_PREFIX_SID_DEL | \
                                                         IPC_ISIS_SRV6_ADJ_SID_ADD | IPC_ISIS_SRV6_ADJ_SID_DEL))

    /* Used by any client ( ISIS/OSPF) to request SRV6 to publish its
        SIDs*/
    IPC_IGP_REQUEST_SRV6_PUBLISH_SIDs,
    #define IPC_REQ_SRV6_PUBLISH_PFX_SIDS   (1)
    #define IPC_REQ_SRV6_PUBLISH_ADJ_SIDS   (1 << 1)

    IPC_MSG_TYPE_MAX

} ips_major_code_t;

#define IPC_ALL_MINOR_UPDATES (0xFFFFFFFF)

// IPC_IPV4_ROUTE
typedef struct ipc_ipv4_route_ {


}  ipc_ipv4_route_t;

// IPC_INTERFACE,
typedef struct ipc_interface_ {

        InterfaceP intf;
        uint32_t metric;

        struct {

            uint32_t ip_addr;
            uint8_t mask;
        } ipv4_addr;
        
        struct {

            uint8_t ipv6_addr[16];
            uint8_t prefix_len;
        } ipv6_addr;

        bool up_status;           /* True for up, false for down */

        bool is_switchport;     /* True for SW, false for no switchport*/

        IntfL2Mode intf_l2_mode;

        uint32_t access_vlan;

        TransportService *trans_svc;

}  ipc_interface_t;

// IPC_GRE_TUNNEL,
typedef struct ipc_gre_ {


}  ipc_gre_t;

// IPC_ACCESS_LST,
typedef struct ipc_access_lst_ {


}  ipc_access_lst_t;


// IPC_SRV6_DATA
typedef struct ips_srv6_data_ {

    uint32_t rtr_id;

    union {

            struct  {

                ipv6_addr_t prefix;
                Srv6_endpcode_t endfn;
                uint32_t metric;
                uint8_t prefix_len;
                uint8_t flavor;

            } locator;

            struct {

                ipv6_addr_t prefix;
                Srv6_endpcode_t endfn;
                uint8_t prefix_len;
                uint8_t flavor;

            } prefix_sid;

            struct {
                
                ipv6_addr_t prefix;
                ipv6_addr_t gw;
                uint32_t oif;
                Srv6_endpcode_t endfn;
                uint8_t prefix_len;
                uint8_t flavor;

            } adj_sid;

    } u;

}  __attribute__((aligned(8)))  ips_srv6_data_t;

#endif 