#ifndef __INTF_CONST__
#define __INTF_CONST__

#define DP_INTF_NAME    32
#define DP_INTF_UPDATE_MSG_LEN 256
#define MAX_VLAN_MEMBER_PORTS 16

enum DP_IntfL2Mode
{
    DP_LAN_MODE_NONE,
    DP_LAN_ACCESS_MODE,
    DP_LAN_TRUNK_MODE
};

enum DP_InterfaceType_t {

    DP_INTF_TYPE_PHY,
    DP_INTF_TYPE_VLAN,
    DP_INTF_TYPE_GRE_TUNNEL,
    DP_INTF_TYPE_LOOPBACK,
    DP_INTF_TYPE_VIRTUAL_PORT,
    DP_INTF_TYPE_RMAC,
    DP_INTF_TYPE_VLAN_FLOOD,
    DP_INTF_TYPE_NVE,
    DP_INTF_TYPE_SRv6,
    DP_INTF_TYPE_HOST_PATH,
    DP_INTF_TYPE_UNKNOWN
};

static inline const char *
dp_intf_type_str (uint32_t iftype) {
    
    switch (iftype) {
        case DP_INTF_TYPE_PHY: return "Physical";
        case DP_INTF_TYPE_VLAN: return "VLAN";
        case DP_INTF_TYPE_GRE_TUNNEL: return "GRE";
        case DP_INTF_TYPE_LOOPBACK: return "Loopback";
        case DP_INTF_TYPE_VIRTUAL_PORT: return "Virtual";
        case DP_INTF_TYPE_RMAC: return "RMAC";
        case DP_INTF_TYPE_VLAN_FLOOD: return "VLAN-Flood";
        case DP_INTF_TYPE_NVE: return "NVE";
        case DP_INTF_TYPE_SRv6: return "SRv6";
        case DP_INTF_TYPE_HOST_PATH: return "HostPath";
        case DP_INTF_TYPE_UNKNOWN: return "Unknown";
        default: return "Invalid";
    }
}

#endif 