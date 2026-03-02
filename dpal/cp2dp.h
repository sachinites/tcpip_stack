#ifndef __CP2DP__
#define __CP2DP__

#include <stdint.h>

typedef struct node_ node_t;
typedef struct pkt_block_ pkt_block_t; 
typedef struct mac_table_entry_ mac_table_entry_t; 
typedef struct rtm_nh_fwd_info_ rtm_nh_fwd_info_t;
typedef struct dp_msg_ dp_msg_t;

class TransportService;

#include "../common/cmn_prefix.h"
#include "../Interface/InterfaceFwd.h"
#include "../Layer3/ipv6/ipv6_hdrs.h"
#include "../Layer3/mpls_enums.h"
#include "../RTM/rtm_fib_common.h"
#include "../RTM/rtm_nh.h"
#include "../Interface/InterfacEnums.h"

void 
cp2dp_submit (node_t *node, dp_msg_t *dp_msg, bool async);

void
cp2dp_xmit_pkt (node_t *node, pkt_block_t *pkt_block, Interface *xmit_interface) ;

void cp2dp_send_ip_data(node_t *node,
                        pkt_block_t *pkt_block,
                        uint32_t dest_ip_addr,
                        uint16_t std_ip_protocol);

void cp2dp_send_ip6_data(node_t *node,
                         pkt_block_t *pkt_block,
                         ipv6_addr_t dest_ip_addr,
                         uint16_t std_ip_protocol);

/* Wrapper fn to add MAC entry to MAC table Asynchronously*/
void
cp2dp_mac_table_entry_add (node_t *node,
                      uint8_t *mac_addr,
                      uint16_t vlan_id,
                      uint32_t ifindex,
                      uint16_t flags,
                      bool async,
                      uint32_t remote_dst_ip = 0);

void
cp2dp_mac_table_entry_del (node_t *node,
                      uint8_t *mac_addr,
                      uint16_t vlan_id,
                      uint32_t ifindex,
                      bool async, uint32_t remote_dst_ip);

void
cp2dp_fib_update (
                node_t *node,
                uint8_t target_fib_vrf_id,
                AFI_T target_fib_afi,
                cmn_prefix_t *prefix,
                uint32_t nh_idx,
                uint32_t inh_idx,
                rtm_nh_fwd_info_t *fwd_info,
                FIB_OPN_T operation) ;

void 
cp2dp_vrf_create (node_t *node, char *vrf_name, uint8_t vrf_id);

void 
cp2dp_vrf_delete (node_t *node, uint8_t vrf_id);

void 
cp2dp_vrf_delete_interface (node_t *node, uint8_t vrf_id, uint32_t ifindex);

void 
cp2dp_vrf_add_interface (node_t *node, uint8_t vrf_id, uint32_t ifindex);

/* Interface update message sending functions */
void 
cp2dp_send_intf_ipv4_addr_update(node_t *node, uint32_t port_id, uint32_t ipv4_addr, uint8_t mask);

void 
cp2dp_send_intf_ipv6_addr_update(node_t *node, uint32_t port_id, uint8_t ipv6_addr[16], uint8_t prefix_len);

void 
cp2dp_send_intf_vlan_bind_update(node_t *node, uint32_t port_id, 
                                uint32_t vlan_port_id, 
                                IntfL2Mode l2_mode, 
                                bool add);

void 
cp2dp_send_intf_grp_bind_to_vlan_update(node_t *node, TransportService *tsp, uint16_t vlan_id, bool add);

void 
cp2dp_send_intf_admin_status_update(node_t *node, uint32_t port_id, bool is_down);

void 
cp2dp_send_intf_vlan_vni_update(node_t *node, uint16_t vlan_port_id, uint32_t vni_id, bool add);

void 
cp2dp_send_intf_switchport_update(node_t *node, uint32_t port_id, uint8_t switchport);

void 
cp2dp_send_intf_vrf_bind_update(node_t *node, uint32_t port_id, int32_t vrf_id);

void 
cp2dp_send_intf_vlan_grp_bind_update(node_t *node, uint32_t port_id, bitmap_t *vlan_bitmap, bool add);

void 
cp2dp_interface_create (node_t *node, Interface *intf);

void 
cp2dp_interface_delete (node_t *node, Interface *intf);

#endif 
