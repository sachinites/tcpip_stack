#ifndef __DP_INTF_UPDATE__
#define __DP_INTF_UPDATE__

#include <stdint.h>
#include "intf_cons.h"

#pragma pack (push,8)

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

    uint32_t vlan_port_id;  // vlan id to be applied
    uint32_t port_id;       // physical interface
    DP_IntfL2Mode l2_mode;  // access or trunk mode
    
} dp_intf_vlan_bind_t;

#define CP2DP_CODE_INTF_ADMIN_DOWN 4
typedef struct dp_intf_admin_down_ {

    uint32_t port_id; 
    bool status;
    
} dp_intf_admin_down_t;

#define CP2DP_CODE_INTF_VRF_BIND 5
typedef struct dp_intf_vrf_bind_ {

    uint32_t port_id; 
    uint16_t vrf_id;
    
} dp_intf_vrf_bind_t;

typedef struct dp_intf_cp2dp_msg_ {

    uint32_t port_id;  // key
    uint32_t iftype;
    uint8_t  mac_addr[6];
    char intf_name[IF_NAME_SIZE];
    uint16_t update_code;

} dp_intf_cp2dp_msg_t;


#pragma pack(pop)

/* Forward declarations */
typedef struct node_ node_t;
typedef struct dp_msg_ dp_msg_t;

/* Interface update message processing */
void 
dp_intf_table_process_msg(node_t *node, dp_msg_t *dp_msg);

/* Interface update message sending functions */
void 
cp2dp_send_intf_ipv4_addr_update(node_t *node, uint32_t port_id, uint32_t ipv4_addr, uint8_t mask);

void 
cp2dp_send_intf_ipv6_addr_update(node_t *node, uint32_t port_id, uint8_t ipv6_addr[16], uint8_t prefix_len);

void 
cp2dp_send_intf_vlan_bind_update(node_t *node, uint32_t port_id, uint32_t vlan_port_id, DP_IntfL2Mode l2_mode);

void 
cp2dp_send_intf_admin_status_update(node_t *node, uint32_t port_id, bool is_down);

void 
cp2dp_send_intf_vrf_bind_update(node_t *node, uint32_t port_id, uint16_t vrf_id);

#endif 