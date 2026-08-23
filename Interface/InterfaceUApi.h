#ifndef __INTERFACE_UAPI__
#define __INTERFACE_UAPI__

#include "InterfacEnums.h"
#include "Interface.h"
#include "../utils.h"
#include "../CLIBuilder/libcli.h"
#include "InterfaceFwd.h"

typedef struct node_ node_t;
typedef struct vrf_ vrf_t;

/* Node Interface Management APIs */

Interface *
node_interface_lookup_by_name(node_t *node, const char *if_name);

Interface *
node_get_intf_by_ifindex(node_t *node, uint32_t ifindex) ;

bool
interface_is_bd_member(Interface *intf);

/* Canonicalize loopback names: "1" → "lo1"; "lo1" unchanged.
 * out always receives a NUL-terminated copy. Returns true if rewritten. */
bool
interface_loopback_canonical_name(const char *ifname, char *out, size_t out_len);

/* Global Node Interface Map Management APIs */
bool node_global_intf_map_insert(node_t *node, Interface *intf);
bool node_global_intf_map_delete_by_name(node_t *node, const char *ifname);
bool node_global_intf_map_delete_by_ifindex(node_t *node, uint32_t ifindex);


/* VRF Interface Management APIs */
bool vrf_interface_insert(vrf_t *vrf, Interface* intf);
bool vrf_interface_delete_by_name(vrf_t *vrf, const char *ifname);
bool vrf_interface_delete_by_ifindex(vrf_t *vrf, uint32_t ifindex);
Interface* vrf_interface_lookup_by_name(vrf_t *vrf, const char *ifname);
Interface* vrf_interface_lookup_by_ifindex(vrf_t *vrf, uint32_t ifindex);

void
interface_set_ip_addr (node_t *node, Interface *intf, 
                                    c_string intf_ip_addr, uint8_t mask) ;

void
interface_unset_ip_addr (node_t *node, Interface *intf, 
                                        c_string intf_ip_addr, uint8_t mask);

void
interface_set_ipv6_addr (node_t *node, Interface *intf, 
                                    c_string intf_ipv6_addr_with_mask);

void
interface_unset_ipv6_addr (node_t *node, Interface *intf, 
                                        c_string intf_ipv6_addr_with_mask);

void
interface_bd_install_router_mac(node_t *node, Interface *bd);

void
interface_bd_uninstall_router_mac(node_t *node, Interface *bd);

Interface * 
interface_loopback_create (node_t *node, char *ifname);

void interface_loopback_delete (node_t *node, char *ifname) ;

#define IF_MAC(intf)    (intf->GetMacAddr()->mac)

static inline uint32_t 
IF_IP(Interface *intf) {

    uint32_t ip_addr;
    uint8_t mask;

    if (!intf->IsIpConfigured()) assert(0);
    intf->InterfaceGetIpAddressMask(&ip_addr, &mask);
    return ip_addr;
}

static inline uint32_t 
IF_MASK(Interface *intf) {

    uint32_t ip_addr;
    uint8_t mask;

    if (!intf->IsIpConfigured()) assert(0);
    intf->InterfaceGetIpAddressMask(&ip_addr, &mask);
    return mask;
}

void
display_node_interfaces(param_t *param, Stack_t *tlv_stack);

void 
interface_install_local_v4_routes (node_t *node, Interface  *intf);
void 
interface_uninstall_local_v4_routes (node_t *node, Interface  *intf);
void 
interface_install_local_v6_routes (node_t *node, Interface  *intf);
void 
interface_uninstall_local_v6_routes (node_t *node, Interface  *intf);
#endif 
