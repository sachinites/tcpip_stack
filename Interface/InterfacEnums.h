#ifndef __INTERFACE_TYPES__
#define __INTERFACE_TYPES__

enum IntfL2Mode
{
    LAN_MODE_NONE,
    LAN_ACCESS_MODE,
    LAN_TRUNK_MODE
};

enum InterfaceType_t {

    INTF_TYPE_PHY,
    INTF_TYPE_VLAN,
    INTF_TYPE_GRE_TUNNEL,
    INTF_TYPE_LOOPBACK,
    INTF_TYPE_VIRTUAL_PORT,
    INTF_TYPE_RMAC,
    INTF_TYPE_VLAN_FLOOD,
    INTF_TYPE_NVE,
    INTF_TYPE_SRv6_DT4,
    INTF_TYPE_VPNV4_STEER,
    INTF_TYPE_HOST_PATH,
    INTF_TYPE_UNKNOWN
};


static inline const char *
intf_type_str (InterfaceType_t iftype) {
    
    switch (iftype) {
        case INTF_TYPE_PHY: return "Physical";
        case INTF_TYPE_VLAN: return "VLAN";
        case INTF_TYPE_GRE_TUNNEL: return "GRE";
        case INTF_TYPE_LOOPBACK: return "Loopback";
        case INTF_TYPE_VIRTUAL_PORT: return "Virtual";
        case INTF_TYPE_RMAC: return "RMAC";
        case INTF_TYPE_VLAN_FLOOD: return "VLAN-Flood";
        case INTF_TYPE_NVE: return "NVE";
        case INTF_TYPE_SRv6_DT4: return "SRv6-DT4";
        case INTF_TYPE_VPNV4_STEER: return "VPNv4-Steering-Intf";
        case INTF_TYPE_HOST_PATH: return "HostPath";
        case INTF_TYPE_UNKNOWN: return "Unknown";
        default: return "Invalid";
    }
}



#define INTF_MAX_VLAN_MEMBERSHIP 10

/* Interface Change Flags, used for Notification to 
 * Applications*/
#define IF_UP_DOWN_CHANGE_F (1 << 0)
#define IF_IP_ADDR_CHANGE_F (1 << 1)
#define IF_OPER_MODE_CHANGE_F (1 << 2)
#define IF_VLAN_MEMBERSHIP_CHANGE_F (1 << 3)
#define IF_TSP_CHANGE_F ( 1<<4 )
#define IF_METRIC_CHANGE_F (1 << 5)
#define IF_DELETE_F (1 << 6)
#define IF_CREATE_F (1 << 7)


/* Interface common Configuration Bits */
#define INTF_CONFIG_SUPPORT_ALL 0
#define INTF_CONFIG_NOT_SUPPORTED_IP_ADDRESS 1
#define INTF_CONFIG_NOT_SUPPORTED_METRIC 2
#define INTF_CONFIG_NOT_SUPPORTED_TSP 4
#define INTF_CONFIG_NOT_SUPPORTED_SWITCHPORT 8
#define INTF_CONFIG_NOT_SUPPORTED_VLAN 16
#define INTF_CONFIG_NOT_SUPPORTED_UP_DOWN   32
#define INTF_CONFIG_NOT_SUPPORTED_TRACEOPTIONS 64
#define INTF_CONFIG_NOT_SUPPORTED_OVERLAY_TUNNEL 128
#define INTF_CONFIG_NOT_SUPPORTED_VRF 256


#endif 