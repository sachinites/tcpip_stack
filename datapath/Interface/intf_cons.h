/*
 * =============================================================================
 * File: intf_cons.h
 * Description: Datapath interface constants, enums, and type-to-string helpers.
 * =============================================================================
 *
 * Design:
 *   - DP_INTF_NAME, DP_MAX_VLAN_SUPORT, etc.: shared size limits.
 *   - DP_IntfL2Mode: L2 mode (none, access, trunk).
 *   - DP_InterfaceType_t: interface type (physical, VLAN, GRE, loopback, etc.).
 *   - dp_intf_type_str / dp_intf_mode_str: for CLI and logging.
 * =============================================================================
 */

#ifndef __INTF_CONST__
#define __INTF_CONST__

#define DP_INTF_NAME    32
#define DP_INTF_UPDATE_MSG_LEN 256
#define MAX_VLAN_MEMBER_PORTS 16
#define MAX_BD_MEMBER_PORTS 16
#define DP_MAX_VLAN_SUPORT 4096
#define DP_MAX_INTF 1024
#define DP_MAX_BD_SUPPORT 64

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
    DP_INTF_TYPE_SRv6_DT4,
    DP_INTF_TYPE_VPNV4_STEER,
    DP_INTF_TYPE_AC,
    DP_INTF_TYPE_BD,
    DP_INTF_TYPE_BD_FLOOD,
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
        case DP_INTF_TYPE_SRv6_DT4: return "SRv6-DT4";
        case DP_INTF_TYPE_HOST_PATH: return "HostPath";
        case DP_INTF_TYPE_AC: return "AC";
	    case DP_INTF_TYPE_BD: return "BD";
        case DP_INTF_TYPE_BD_FLOOD: return "bd-vfif";
        case DP_INTF_TYPE_UNKNOWN: return "Unknown";
        default: return "Invalid";
    }
}

static inline const char *
dp_intf_mode_str(DP_IntfL2Mode l2mode) {

    switch (l2mode) {
        case DP_LAN_MODE_NONE:
            return "None";
        case DP_LAN_ACCESS_MODE:
            return "Access-Mode";
        case DP_LAN_TRUNK_MODE:
            return "Trunk-Mode";
    }
    return NULL;
}


#endif /* __INTF_CONST__ */
