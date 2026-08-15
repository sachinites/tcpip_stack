/*
 * =============================================================================
 * File: dp_intf_update.h
 * Description: CP-to-DP interface update message formats and API declarations.
 * =============================================================================
 *
 * Design:
 *   - Defines message structures for interface create/delete/update (IPv4/IPv6
 *     addr, VLAN bind, admin down, VRF bind, switchport, VLAN-VNI, VLAN group
 *     bind, log update). Packed with #pragma pack(8) for wire/queue compatibility.
 *   - cp2dp_interface_create / cp2dp_interface_delete: send create/delete to DP.
 *   - cp2dp_send_intf_*: send specific updates (addr, vlan, vrf, etc.).
 *   - dp_intf_table_process_msg: DP-side handler for these messages.
 * =============================================================================
 */

#ifndef __DP_INTF_UPDATE__
#define __DP_INTF_UPDATE__

#include <stdint.h>
#include "../Interface/intf_cons.h"

#pragma pack (push,8)

#define CP2DP_CODE_INTF_PHYSICAL 0

/* IPv4 addr Update */
#define CP2DP_CODE_INTF_IPV4_ADDR 1
typedef struct dp_intf_ipv4_addr_update_ {

    uint32_t ipv4_addr;
    uint8_t mask;

} dp_intf_ipv4_addr_update_t;

#define CP2DP_CODE_INTF_IPV6_ADDR 2
typedef struct dp_intf_ipv6_addr_update_ {

    uint8_t ipv6_addr[16];
    uint8_t prefix_len;
    
} dp_intf_ipv6_addr_update_t;

#define CP2DP_CODE_INTF_VLAN_BIND 3
typedef struct dp_intf_vlan_bind_ {

    uint32_t vlan_port_id;  // port id of vlan to be applied
    uint32_t port_id;       // physical interface port id
    uint8_t l2_mode;  // 0 - None, 1 - access, 2 - trunk mode
    uint8_t add;            // 1 for add , 0 for remove
    
} dp_intf_vlan_bind_t;

#define CP2DP_CODE_INTF_ADMIN_DOWN 4
typedef struct dp_intf_admin_down_ {

    uint32_t port_id; 
    bool status;
    
} dp_intf_admin_down_t;

#define CP2DP_CODE_INTF_SW 6
typedef struct dp_intf_boolean_property_ {

    uint32_t port_id; 
    uint8_t enable;
    
} dp_intf_boolean_property_t;

#define CP2DP_CODE_INTF_VLAN_VNI    7
typedef struct dp_intf_vlan_vni_ {

    uint32_t vni_id;
    uint8_t add;
    
} dp_intf_vlan_vni_t;

#define CP2DP_CODE_INTF_VLAN_GRP_BIND 8
typedef struct dp_intf_vlan_grp_bind_ {

    uint8_t vlan_bitmapp[DP_MAX_VLAN_SUPORT/8];
    uint8_t add; // 1 for add 0 or for remove.

} dp_intf_vlan_grp_bind_t;

#define CP2DP_CODE_INTF_GRP_VLAN_BIND 9
typedef struct dp_intf_grp_bind_ {

    /* Caution : This forces all ifindex of interfaces 
        must range between [1 and MAX_INTF_IFINDEX] */
    uint8_t if_bitmapp[128];
    uint8_t add; 
    
} dp_intf_grp_bind_t;

#define CP2DP_CODE_INTF_RMAC 10
#define CP2DP_CODE_INTF_VLAN_FLOOD 11
#define CP2DP_CODE_INTF_HOST_PATH 12
#define CP2DP_CODE_INTF_NVE 14

#define CP2DP_CODE_INTF_LOG_UPDATE 15
typedef struct dp_intf_log_update_ {

    //log_t log;

} dp_intf_log_update_t;


// code to bind steering vrf with dt4 interfaces, it has no
//  structure, dp_intf_cp2dp_msg_hdr_t will contain all info required
#define CP2DP_CODE_DT4_INTF_STEER_VRF_BIND 16
#define CP2DP_CODE_VPNV4_INTF_STEER_VRF_BIND 17

// use dp_intf_boolean_property_t
#define CP2DP_CODE_INTF_ACCESS_MODE           18

// use dp_intf_cp2dp_msg_hdr_t
#define CP2DP_CODE_ACCESS_INTF_VLAN_ADD 19
#define CP2DP_CODE_ACCESS_INTF_VLAN_DEL  20

#define CP2DP_CODE_INTF_ADD_ACL 21
typedef struct dp_intf_acl_update_ {

    uintptr_t acl;
    uint8_t layer;
    uint8_t ingress;

} dp_intf_acl_update_t;

/* GRE tunnel overlay / encapsulation attributes */
#define CP2DP_CODE_INTF_GRE_TUNNEL 22
typedef struct dp_intf_gre_tunnel_update_ {

    uint32_t lcl_ip;
    uint32_t tunnel_src_ip;
    uint32_t tunnel_dst_ip;
    uint8_t  mask;
    uint8_t  tunnel_up;
    uint8_t  _pad[2];

} dp_intf_gre_tunnel_update_t;

#define CP2DP_CODE_BD_AC_BIND 23
#define CP2DP_CODE_BD_AC_UNBIND 24
typedef struct dp_intf_bd_ac_bind_ {

    uint32_t bd_port_id;
    uint32_t ac_port_id;

} dp_intf_bd_ac_bind_t;

/* Set/clear 802.1Q encap on an AC (ac_port_id == underlying phy ifindex).
 * tag == 0 clears the encap. */
#define CP2DP_CODE_BD_AC_ENCAP_8021Q 25
typedef struct dp_intf_bd_ac_encap_8021q_ {

    uint32_t ac_port_id;
    uint16_t encap_8021q_tag;
    uint8_t  _pad[2];

} dp_intf_bd_ac_encap_8021q_t;

typedef struct dp_intf_cp2dp_msg_ {

    uint32_t port_id;  // key
    uint32_t vlan_id;
    uint32_t iftype;
    uint8_t  mac_addr[6];
    char intf_name[DP_INTF_NAME];
    uint16_t update_code;

} dp_intf_cp2dp_msg_hdr_t;


#pragma pack(pop)

#endif 