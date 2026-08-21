/*
 * Control-plane resource limits from tcpconst.h.
 */

#ifndef __CP_LIMITS__
#define __CP_LIMITS__

#include "tcpconst.h"

#define CP_VLAN_ID_VALID(vid) \
    ((vid) >= 1 && (vid) < MAX_VLAN_SUPPORTED)

#define CP_VRF_ID_VALID(id) \
    ((id) >= 0 && (id) < MAX_VRF_SUPPORTED)

#define CP_EVPN_ID_VALID(id) \
    ((id) >= 0 && (id) < MAX_EVPN_INDEX)

#ifdef __cplusplus

#include "Interface/InterfacEnums.h"
#include "router_init.h"

static inline uint32_t
cp_node_count_interfaces_by_type(node_t *node, InterfaceType_t type)
{
    uint32_t count = 0;

    if (!node || !node->intf_by_ifindex)
        return 0;

    for (const auto &kv : *node->intf_by_ifindex) {
        if (kv.second && kv.second->iftype == type)
            count++;
    }

    return count;
}

static inline uint32_t
cp_node_count_bridge_domains(node_t *node)
{
    return cp_node_count_interfaces_by_type(node, INTF_TYPE_BD);
}

static inline uint32_t
cp_node_count_vrf_instances(node_t *node)
{
    uint32_t count = 0;
    int i;

    if (!node)
        return 0;

    for (i = 0; i < MAX_VRF_SUPPORTED; i++) {
        if (node->vrf[i])
            count++;
    }

    return count;
}

#endif /* __cplusplus */

#endif /* __CP_LIMITS__ */
