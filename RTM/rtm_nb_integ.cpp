/*
 * =====================================================================================
 *
 *       Filename:  rtm_nb_integ.cpp
 *
 *    Description:  RTM (Routing Table Manager) Network-Boundary Integration Layer
 *
 *        This file provides the high-level API for route installation, uninstallation,
 *        and protocol management. It acts as a bridge between the control plane
 *        applications and the core RTM infrastructure.
 *
 *        Architecture Overview:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │                    Control Plane Applications                │
 *        │  (BGP, OSPF, ISIS, Static Routes, Interface Routes, etc.)   │
 *        └────────────────────────┬────────────────────────────────────┘
 *                                 │
 *                                 │ cp_rtm_* APIs
 *                                 ▼
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │              RTM Network-Boundary Integration Layer            │
 *        │  (This File: rtm_nb_integ.cpp)                               │
 *        │  - Route Installation/Uninstallation                         │
 *        │  - Protocol Registration/Subscription                       │
 *        │  - VRF-aware Route Management                                │
 *        └────────────────────────┬────────────────────────────────────┘
 *                                 │
 *                                 │ rtm_* APIs
 *                                 ▼
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │                    RTM Core Layer                            │
 *        │  - Route Storage (AVL Trees, MTrie)                          │
 *        │  - Nexthop Management                                        │
 *        │  - Route Resolution                                         │
 *        │  - Route Advertisement                                      │
 *        └────────────────────────┬────────────────────────────────────┘
 *                                 │
 *                                 │ FIB APIs
 *                                 ▼
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │                    Forwarding Information Base               │
 *        │  - FIB Installation                                          │
 *        │  - Data Plane Integration                                    │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        VRF and RTM Structure:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │                        Node                                  │
 *        │  ┌──────────────────────────────────────────────────────┐   │
 *        │  │              node_nw_prop_t                          │   │
 *        │  │  ┌──────────────────────────────────────────────┐   │   │
 *        │  │  │         def_vrf_t *def_vrf                    │   │   │
 *        │  │  │  ┌──────────────────────────────────────┐   │   │   │
 *        │  │  │  │         vrf_t vrf                      │   │   │   │
 *        │  │  │  │         - inet0 (IPv4 unicast)        │   │   │   │
 *        │  │  │  │         - inet6 (IPv6 unicast)         │   │   │   │
 *        │  │  │  │         - fib_inet0, fib_inet6         │   │   │   │
 *        │  │  │  └──────────────────────────────────────┘   │   │   │
 *        │  │  │  - inet3 (IPv4 LDP/SR)                      │   │   │
 *        │  │  │  - inet63 (IPv6 LDP/SR)                     │   │   │
 *        │  │  │  - mpls0 (MPLS forwarding)                  │   │   │
 *        │  │  │  - l3vpnv4 (BGP L3VPN IPv4)                │   │   │
 *        │  │  │  - l3vpnv6 (BGP L3VPN IPv6)                │   │   │
 *        │  │  │  - mpls_fib                                │   │   │
 *        │  │  └──────────────────────────────────────────────┘   │   │
 *        │  └──────────────────────────────────────────────────────┘   │
 *        │  ┌──────────────────────────────────────────────────────┐   │
 *        │  │         vrf_t *vrf[MAX_VRF_PER_NODE]                  │   │
 *        │  │         (Customer VRFs with RD/RT)                    │   │
 *        │  └──────────────────────────────────────────────────────┘   │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Route Installation Flow:
 *        1. Application calls cp_rtm_install_route()
 *        2. Create nexthop template with protocol info
 *        3. Call rtm_install_route() (core layer)
 *        4. If L3VPN route, propagate to all client VRFs
 *        5. Trigger route resolution if needed
 *        6. Schedule route advertisement
 *        7. Install in FIB
 *
 *        Version:  1.0
 *        Created:  [Original Date]
 *       Revision:  1.0
 *       Compiler:  gcc/g++
 *
 * =====================================================================================
 */

#include "../router_init.h"
#include "../net.h"
#include "../Interface/InterfaceUApi.h"
#include "../lmm_enums.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../Tracer/tracer.h"
#include "../prefix-list/prefixlst.h"
#include "../common/mpls_lstack.h"

#include "rtm_enums.h"
#include "rtm_error.h"
#include "rtm_route.h"
#include "rtm_nb_integ.h"
#include "rtm_priv_api.h"
#include "rtm_proto.h"
#include "rtm_nh.h"
#include "rtm_fib_interface.h"
#include "rtm_presentation.h"
#include "rtm_resolution.h"
#include "../vrf/vrf.h"
#include "../Layer3/ipv6/ipv6_hdrs.h"

/* ========================================================================
 * Static Helper Functions
 * ======================================================================== */

/**
 * @brief Comparison function for route subscription AVL tree
 * 
 * This function is used to maintain subscriptions in sorted order
 * for efficient lookup. The comparison order is:
 * 1. Target protocol (RTM_PROTO_T)
 * 2. Target sub-protocol (RTM_SUB_PROTO_T)
 * 3. Target instance number
 * 4. Callback pointer (for unique identification)
 * 
 * @param node1 First AVL tree node
 * @param node2 Second AVL tree node
 * @return -1 if node1 < node2, 0 if equal, 1 if node1 > node2
 */
static int
rtm_rt_subscription_compare(const avltree_node_t *node1, const avltree_node_t *node2) {
    
    rtm_rt_subscription_t *sub1 = avltree_container_of(node1, rtm_rt_subscription_t, avl_glue);
    rtm_rt_subscription_t *sub2 = avltree_container_of(node2, rtm_rt_subscription_t, avl_glue);
    
    /* Compare by target protocol first */
    if (sub1->target_proto < sub2->target_proto) return -1;
    if (sub1->target_proto > sub2->target_proto) return 1;
    
    /* Then by target sub-protocol */
    if (sub1->target_sub_proto < sub2->target_sub_proto) return -1;
    if (sub1->target_sub_proto > sub2->target_sub_proto) return 1;
    
    /* Then by target instance number */
    if (sub1->target_instance_no < sub2->target_instance_no) return -1;
    if (sub1->target_instance_no > sub2->target_instance_no) return 1;
    
    /* Finally by callback pointer for unique identification */
    if ((uintptr_t)sub1->cbk < (uintptr_t)sub2->cbk) return -1;
    if ((uintptr_t)sub1->cbk > (uintptr_t)sub2->cbk) return 1;
    
    return 0;
}

/**
 * @brief Free internal resources of nexthop template
 * 
 * This function cleans up dynamically allocated resources within
 * a nexthop template structure, including:
 * - Protocol information structure
 * - MPLS label stack
 * - SRv6 segment list
 * 
 * @param nh_template Pointer to nexthop template to clean up
 */
void 
rtm_nh_template_free_internals (cp_nexthop_template_t *nh_template) {

    if (nh_template->rtm_nh_proto) {
        XFREE (nh_template->rtm_nh_proto);
        nh_template->rtm_nh_proto = NULL;
    }
    
    if (IS_BIT_SET (nh_template->fwd_flags, FIB_NH_FWD_F_MPLS_LBL_STCK)) {
        XFREE (nh_template->u.l_stack.label_stack);
        nh_template->u.l_stack.label_stack = NULL;
    }

    if (IS_BIT_SET (nh_template->fwd_flags, FIB_NH_FWD_F_IPV6_STCK) &&
            nh_template->u.srv6_stack.v6segment_lst) {
        XFREE (nh_template->u.srv6_stack.v6segment_lst);
        nh_template->u.srv6_stack.v6segment_lst = NULL;
    }
}

/* ========================================================================
 * RTM Lookup and Access Functions
 * ======================================================================== */

/**
 * @brief Get RTM (Routing Table) by VRF ID, Address Family, and Table ID
 * 
 * This function provides a unified interface to access routing tables
 * across different VRFs. It handles both the default VRF and customer VRFs.
 * 
 * RTM Table ID Mapping:
 * ┌─────────┬──────────────┬─────────────────────────────────┐
 * │ Table   │ Description  │ Usage                          │
 * ├─────────┼──────────────┼─────────────────────────────────┤
 * │ 0       │ Unicast      │ Main routing table (inet.0)    │
 * │ 3       │ LDP/SR       │ Label distribution (inet.3)     │
 * │ 128     │ L3VPN        │ BGP VPN routes (bgp.l3vpn.0)   │
 * └─────────┴──────────────┴─────────────────────────────────┘
 * 
 * @param node Pointer to network node
 * @param vrf_id VRF identifier (0 for default VRF)
 * @param afi Address Family (AF_IPV4, AF_IPV6, AF_LABEL)
 * @param rtm_id Routing table identifier (0, 3, or 128)
 * 
 * @return Pointer to RTM structure, or NULL if not found
 */
rtm_t *
rtm_get(node_t *node, uint8_t vrf_id, AFI_T afi, uint8_t rtm_id) {

    def_vrf_t *def_vrf = node->node_nw_prop.def_vrf;

    /* Handle default VRF (VRF ID = 0) */
    if (vrf_id == RTM_DEFAULT_VRF) {

        if (!def_vrf) return NULL;

        /* IPv4 routing tables */
        if (afi == AF_IPV4) {
            if (rtm_id == 0) return def_vrf->vrf.inet0;      /* inet.0 - Unicast */
            if (rtm_id == 3) return def_vrf->vrf.inet3;         /* inet.3 - LDP/SR */
            if (rtm_id == 128) return def_vrf->l3vpnv4;     /* bgp.l3vpn.0 (IPv4) */
        }
        /* IPv6 routing tables */
        else if (afi == AF_IPV6) {
            if (rtm_id == 0) return def_vrf->vrf.inet6;     /* inet6.0 - Unicast */
            if (rtm_id == 3) return def_vrf->vrf.inet63;        /* inet6.3 - LDP/SR */
            if (rtm_id == 128) return def_vrf->l3vpnv6;     /* bgp.l3vpn.0 (IPv6) */
        }
        /* MPLS/Label routing tables */
        else if (afi == AF_LABEL) {
            if (rtm_id == 0) return def_vrf->mpls0;         /* mpls.0 - MPLS forwarding */
        }
    }

    /* Handle customer VRFs (VRF ID > 0) */
    vrf_t *vrf = vrf_get_by_id (node, vrf_id);
    if (!vrf) return NULL;

    /* Customer VRFs only support unicast tables (table ID 0) */
    switch (afi) {
        case AF_IPV4: return vrf->inet0;
        case AF_IPV6: return vrf->inet6;
        break;
    }
    
    return NULL;
}

/* ========================================================================
 * Route Installation APIs
 * ======================================================================== */

/**
 * @brief Install local or connected IPv4 route
 * 
 * This function is used to install routes that are directly connected
 * to interfaces or local to the router (loopback addresses).
 * 
 * Route Type Determination:
 * - Mask == 32: LOCAL route (host route, typically loopback)
 * - Mask < 32:  CONNECTED route (subnet route)
 * 
 * Flow:
 * ┌─────────────────────────────────────────────────────────┐
 * │ 1. Determine route type (LOCAL vs CONNECTED)           │
 * │ 2. Create nexthop template with interface info          │
 * │ 3. Set forwarding flags (IPv4)                          │
 * │ 4. Create protocol info (RTM_PROTO_LOCAL)              │
 * │ 5. Install route in RTM                                │
 * │ 6. Trigger FIB installation                            │
 * └─────────────────────────────────────────────────────────┘
 * 
 * @param rtm Pointer to routing table
 * @param prefix IPv4 address (network byte order)
 * @param mask Subnet mask length (0-32)
 * @param Oif Outgoing interface shared pointer
 * 
 * @return Nexthop index if successful, 0 on failure
 */
uint32_t
cp_rtm_install_local_or_connected_v4_routes ( 
            rtm_t *rtm, 
            uint32_t prefix, 
            uint8_t mask, 
            InterfaceP Oif) {

    char addr_str[32];
    cmn_prefix_t route;
    uint16_t fwd_flags = 0;
    
    /* Initialize route prefix structure */
    route.afi = AF_IPV4;
    route.prefix_len = mask;
    route.u.v4_addr = prefix;
    rtm_nh_proto_t *nh_proto = NULL;

    /* Initialize nexthop template */
    cp_nexthop_template_t nh_template;
    memset (&nh_template, 0, sizeof(nh_template));

    /* Determine route type based on mask length */
    /* /32 = host route (LOCAL), otherwise subnet route (CONNECTED) */
    nh_template.proto = (mask == 32) ? \
        RTM_PROTO_LOCAL : RTM_PROTO_CONNECTED;

    /* Set forwarding flags for IPv4 */
    fwd_flags |= FIB_NH_FWD_F_IPV4;
    
    nh_template.sub_proto = RTM_SUB_PROTO_NA;
    
    /* Set forwarding action based on route type */
    nh_template.action = (nh_template.proto == RTM_PROTO_LOCAL) ? \
                                        RTM_NH_ACTION_LOCAL : \
                                        RTM_NH_ACTION_CONNECTED;

    fwd_flags |= rtm_set_fib_forwarding_action_flag (nh_template.action);
    nh_template.oif = Oif->ifindex;
    nh_template.is_resolved = true;
    
    /* Local routes have metric 0, connected routes have metric 1 */
    nh_template.metric = (nh_template.proto == RTM_PROTO_LOCAL) ? 0 : 1;
    
    /* Create protocol information structure */
    rtm_error_t rc = rtm_nh_proto_info_create(
            RTM_PROTO_LOCAL, RTM_SUB_PROTO_NA, 0, rtm->vrf, &nh_proto);
    assert (rc == RTM_SUCCESS);

    nh_template.rtm_nh_proto = nh_proto;

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Route %s  Gw:null recvd route installation request\n",  
        rtm->name, 
        rtm_format_prefix(&route, addr_str, sizeof(addr_str)));

    nh_template.fwd_flags = fwd_flags;
    rc = cp_rtm_install_route(rtm, &route, &nh_template);
    rtm_nh_template_free_internals (&nh_template);

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Route %s/%d  Gw:null installation Result Code: %s\n",  
        rtm->name, addr_str, mask, rtm_error_to_string (rc));

    return nh_template.idx;
}

/**
 * @brief Install local or connected IPv6 route
 *
 * Installs an IPv6 route for an interface address. /128 is treated as LOCAL
 * (host route), any other prefix length as CONNECTED (subnet route).
 *
 * @param rtm Pointer to routing table (IPv6 RTM)
 * @param ipv6_addr IPv6 address (interface address)
 * @param prefix_len Prefix length (128 = LOCAL, else CONNECTED)
 * @param Oif Outgoing interface
 * @return Nexthop index if successful, 0 on failure
 */
uint32_t
cp_rtm_install_local_or_connected_v6_routes (
        rtm_t *rtm,
        ipv6_addr_t *ipv6_addr,
        uint8_t prefix_len,
        InterfaceP Oif) {

    char addr_str[48];
    cmn_prefix_t route;
    uint16_t fwd_flags = 0;

    /* Initialize route prefix structure for IPv6 */
    cmn_prefix_initialize_v6(&route, &ipv6_addr->addr, prefix_len);

    rtm_nh_proto_t *nh_proto = NULL;

    /* Initialize nexthop template */
    cp_nexthop_template_t nh_template;
    memset(&nh_template, 0, sizeof(nh_template));

    /* Determine route type: /128 = host route (LOCAL), otherwise subnet (CONNECTED) */
    nh_template.proto = (prefix_len == 128) ? \
        RTM_PROTO_LOCAL : RTM_PROTO_CONNECTED;

    /* Set forwarding flags for IPv6 */
    fwd_flags |= FIB_NH_FWD_F_IPV6;

    nh_template.sub_proto = RTM_SUB_PROTO_NA;

    /* Set forwarding action based on route type */
    nh_template.action = (nh_template.proto == RTM_PROTO_LOCAL) ? \
        RTM_NH_ACTION_LOCAL : RTM_NH_ACTION_CONNECTED;

    fwd_flags |= rtm_set_fib_forwarding_action_flag(nh_template.action);
    nh_template.oif = Oif->ifindex;
    nh_template.is_resolved = true;

    /* Local routes metric 0, connected routes metric 1 */
    nh_template.metric = (nh_template.proto == RTM_PROTO_LOCAL) ? 0 : 1;

    /* Create protocol information structure */
    rtm_error_t rc = rtm_nh_proto_info_create(
            RTM_PROTO_LOCAL, RTM_SUB_PROTO_NA, 0, rtm->vrf, &nh_proto);
    assert(rc == RTM_SUCCESS);

    nh_template.rtm_nh_proto = nh_proto;

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Route %s  Gw:null recvd IPv6 route installation request\n",
        rtm->name,
        rtm_format_prefix(&route, addr_str, sizeof(addr_str)));

    nh_template.fwd_flags = fwd_flags;
    rc = cp_rtm_install_route(rtm, &route, &nh_template);
    rtm_nh_template_free_internals(&nh_template);

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Route %s/%d  Gw:null IPv6 installation Result Code: %s\n",
        rtm->name, addr_str, prefix_len, rtm_error_to_string(rc));

    return nh_template.idx;
}

/* ========================================================================
 * Static Route APIs
 * ======================================================================== */

/**
 * @brief Install static route
 * 
 * Installs a static route with a gateway (next-hop) address.
 * Static routes are manually configured and have a configurable metric.
 * 
 * Route Structure:
 * ┌─────────────────────────────────────────────────────────┐
 * │ Route Prefix: 192.168.1.0/24                            │
 * │   └─> Nexthop: 10.1.1.1 (gateway)                       │
 * │       └─> Outgoing Interface: eth0                       │
 * │       └─> Metric: 10                                     │
 * │       └─> Protocol: STATIC                               │
 * └─────────────────────────────────────────────────────────┘
 * 
 * @param rtm Pointer to routing table
 * @param prefix Route prefix (destination network)
 * @param gateway Gateway/next-hop address
 * @param oif Outgoing interface
 * @param cost Route metric/cost
 * 
 * @return Nexthop index if successful, 0 on failure
 */
uint32_t
cp_rtm_install_static_route (
        rtm_t *rtm,
        cmn_prefix_t *prefix, 
        cmn_prefix_t *gateway,
        InterfaceP oif, 
        uint32_t cost) {

    char gw_str[32];
    char addr_str[32];
    uint16_t fwd_flags = 0;
    rtm_nh_proto_t *nh_proto = NULL;

    /* Validate inputs */
    if (!gateway || !oif) return 0;

    /* Initialize nexthop template */
    cp_nexthop_template_t nh_template;
    memset(&nh_template, 0, sizeof(nh_template));

    /* Configure static route parameters */
    nh_template.proto = RTM_PROTO_STATIC;
    nh_template.sub_proto = RTM_SUB_PROTO_NA;
    nh_template.action = RTM_NH_ACTION_FORWARD;
    nh_template.oif = oif->ifindex;
    nh_template.is_resolved = true;  /* Static routes are always resolved */
    nh_template.metric = cost;
    nh_template.gateway = *gateway;

    /* Set forwarding flags based on gateway address family */
    switch (gateway->afi) {
        case AF_IPV4:
            fwd_flags |= FIB_NH_FWD_F_IPV4;
            break;

        case AF_IPV6:
            fwd_flags |= FIB_NH_FWD_F_IPV6;
            break;
    }

    /* Create protocol information structure */
    rtm_error_t rc = rtm_nh_proto_info_create(
        RTM_PROTO_STATIC, RTM_SUB_PROTO_NA, 0, rtm->vrf, &nh_proto);
    assert (rc == RTM_SUCCESS);

    nh_template.rtm_nh_proto = nh_proto;

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Route %s  Gw:%s recvd route installation request\n",  
        rtm->name, 
        rtm_format_prefix(prefix, addr_str, sizeof(addr_str)),
        rtm_format_nexthop(gateway, gw_str, sizeof(gw_str)));

    fwd_flags |= rtm_set_fib_forwarding_action_flag (nh_template.action);
    nh_template.fwd_flags = fwd_flags;
    rc = cp_rtm_install_route(rtm, prefix, &nh_template);
    rtm_nh_template_free_internals (&nh_template);

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Route %s  Gw:%s installation Result Code: %s\n",  
        rtm->name, 
        rtm_format_prefix(prefix, addr_str, sizeof(addr_str)),
        rtm_format_nexthop(gateway, gw_str, sizeof(gw_str)),
        rtm_error_to_string (rc));

    return nh_template.idx;   
}

/**
 * @brief Uninstall static route
 * 
 * Removes a static route that matches the given prefix, gateway,
 * interface, and cost.
 * 
 * @param rtm Pointer to routing table
 * @param prefix Route prefix to remove
 * @param gateway Gateway address
 * @param oif Outgoing interface
 * @param cost Route metric (must match for removal)
 * 
 * @return RTM_SUCCESS on success, error code on failure
 */
rtm_error_t
cp_rtm_uninstall_static_route (
        rtm_t *rtm,
        cmn_prefix_t *prefix, 
        cmn_prefix_t *gateway,
        InterfaceP oif, 
        uint32_t cost) {

    uint16_t fwd_flags = 0;
    rtm_error_t rc = RTM_SUCCESS;
    cp_nexthop_template_t nh_template;
            
    memset(&nh_template, 0, sizeof(nh_template));

    /* Configure template to match the route to be removed */
    nh_template.proto = RTM_PROTO_STATIC;
    nh_template.sub_proto = RTM_SUB_PROTO_NA;

    /* Create protocol info to match the route */
    rc = rtm_nh_proto_info_create (
                    RTM_PROTO_STATIC, 
                    RTM_SUB_PROTO_NA, 
                    0, INTF_VRF_ID(oif.get()),
                    &nh_template.rtm_nh_proto);

    nh_template.metric = cost;
    nh_template.action = RTM_NH_ACTION_FORWARD;
    nh_template.gateway = *gateway;
    nh_template.oif = oif->ifindex;
    nh_template.is_indirect = false;
    nh_template.is_resolved = true;

    /* Set forwarding flags based on gateway address family */
    switch (gateway->afi) {
        case AF_IPV4:
            fwd_flags |= FIB_NH_FWD_F_IPV4;
            break;

        case AF_IPV6:
            fwd_flags |= FIB_NH_FWD_F_IPV6;
            break;
    }

    nh_template.fwd_flags = fwd_flags;
    fwd_flags |= rtm_set_fib_forwarding_action_flag (nh_template.action);
    rc = cp_rtm_uninstall_route(rtm, prefix, &nh_template);
    XFREE (nh_template.rtm_nh_proto);
    return rc;
}

/* ========================================================================
 * Core Route Installation/Uninstallation Functions
 * ======================================================================== */

/**
 * @brief Install route in RTM (with L3VPN propagation)
 * 
 * This is the main route installation function. It installs a route
 * in the specified RTM and handles L3VPN route propagation if needed.
 * 
 * L3VPN Route Propagation:
 * ┌─────────────────────────────────────────────────────────┐
 * │ When route is installed in bgp.l3vpn.0:                  │
 * │                                                          │
 * │  1. Install in default VRF's bgp.l3vpn.0                │
 * │  2. For each customer VRF with matching Import RT:      │
 * │     - Copy route to customer VRF's inet.0/inet6.0       │
 * │     - Apply VRF-specific label                           │
 * │     - Update nexthop information                         │
 * └─────────────────────────────────────────────────────────┘
 * 
 * @param rtm Pointer to routing table
 * @param prefix Route prefix
 * @param cp_nh_template Nexthop template with all route information
 * 
 * @return RTM_SUCCESS on success, error code on failure
 */
rtm_error_t 
cp_rtm_install_route ( 
        rtm_t *rtm, 
        cmn_prefix_t *prefix,
        cp_nexthop_template_t *cp_nh_template) {

    rtm_error_t rc;

    /* Install route in the target RTM */
    rc = rtm_install_route(rtm, prefix, cp_nh_template);

    if (rc != RTM_SUCCESS) return rc;

    /* Handle L3VPN route propagation to customer VRFs */
    /* If this route is being installed in bgp.l3vpn.0, we need to */
    /* propagate it to all customer VRFs that have matching Import RT */
    def_vrf_t *def_vrf = rtm->node->node_nw_prop.def_vrf;

    if ((rtm == def_vrf->l3vpnv4 || rtm == def_vrf->l3vpnv6)) {

        rtm_install_l3vpn_routes_to_all_client_ribs(
            rtm, 
            prefix, cp_nh_template, true);
    }

    return rc;
}

/**
 * @brief Uninstall route by nexthop index
 * 
 * This function removes a specific nexthop from a route by its index.
 * If this is the last nexthop, the route itself is also removed.
 * 
 * Uninstallation Flow:
 * ┌─────────────────────────────────────────────────────────┐
 * │ 1. Lookup nexthop by index                             │
 * │ 2. Get owning route                                    │
 * │ 3. Withdraw from resolution system                     │
 * │ 4. Delete nexthop from route                           │
 * │ 5. If route has active nexthops, refresh them          │
 * │ 6. Remove nexthop from index tree                      │
 * │ 7. If route has 0 nexthops, delete route               │
 * │ 8. If L3VPN route, uninstall from customer VRFs        │
 * └─────────────────────────────────────────────────────────┘
 * 
 * @param rtm Pointer to routing table
 * @param idx Nexthop index to remove
 * 
 * @return RTM_SUCCESS on success, error code on failure
 */
rtm_error_t 
cp_rtm_uninstall_route_by_idx ( 
                            rtm_t *rtm, 
                            uint32_t idx) {

    rtm_error_t rc = RTM_SUCCESS;
    char prefix_str[48];
    char gw_str[48];

    if (!rtm || !idx) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    /* Look up the nexthop by its unique index */
    rtm_nh *nh = rtm_nh_lookup_by_idx(rtm, idx);
    
    /* Get the route that owns this nexthop */
    rtm_route *route = nh->owner_route;
    assert (route);

    if (!nh) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : Route %s, Nexthop %s[%u] not found\n", rtm->name, 
            rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)), 
            rtm_format_nexthop(&nh->prefix, gw_str, sizeof (gw_str)), idx);
        return RTM_ERROR_CONTAINER_LOOKUP_FAILED;
    }

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Uninstalling route %s, Nexthop %s[%u]\n",
        rtm->name,
        rtm_format_prefix(&route->prefix, prefix_str, sizeof(prefix_str)),
        rtm_format_nexthop(&nh->prefix, gw_str, sizeof (gw_str)), idx);

    /* Withdraw nexthop from resolution system */
    /* This ensures any dependent routes are notified */
    rtm_resolution_nh_withdraw (rtm, nh);
    
    /* Delete the nexthop from the route */
    /* Note: Application must ensure no duplicate nexthops are installed */
    rc = rtm_route_delete_nh (rtm, route, nh);
    
    if (rc != RTM_SUCCESS) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Failed to delete NH %s[%u] from route %s - %s\n",
            rtm->name, gw_str, idx, prefix_str,
            rtm_error_to_string(rc));
        return rc;
    }

    /* If the deleted nexthop was active and route still has nexthops, */
    /* we need to refresh the route to select a new active nexthop */
    if (nh->is_active && route->nh_count) {
        rtm_route_refresh_nexthops (rtm, route);
    }

    /* Remove nexthop from index tree for O(1) lookup */
    rtm_nh_remove_from_idx_tree(rtm, nh);
    
    /* Remove nexthop from source protocol list */
    /* Note: rtm_nh_remove_glthread already calls rtm_nh_dereference */
    rtm_nh_remove_glthread(rtm, nh, &nh->src_glue);

    /* If route has no more nexthops, delete the route as well */
    if (route->nh_count == 0) {
        /* Schedule route deletion advertisement */
        rtm_schedule_route_advertisement (rtm, route);
        rtm_route_delete(rtm, route);

        /* Note: Route deletion cases are automatically handled */
        /* If route was resolved, dependent routes would be notified */
    }

    /* Handle L3VPN route uninstallation from customer VRFs */
    def_vrf_t *def_vrf = rtm->node->node_nw_prop.def_vrf;
    if (def_vrf && (rtm == def_vrf->l3vpnv4 || rtm == def_vrf->l3vpnv6)) {
        rtm_uninstall_l3vpn_routes_to_all_client_ribs(rtm, idx);
    }

    return RTM_SUCCESS;
}

/**
 * @brief Uninstall route by prefix and nexthop template
 * 
 * Removes a route that matches the given prefix and nexthop template.
 * This is used when the exact route characteristics are known.
 * 
 * @param rtm Pointer to routing table
 * @param prefix Route prefix to remove
 * @param cp_nh_template Nexthop template to match
 * 
 * @return RTM_SUCCESS on success, error code on failure
 */
rtm_error_t 
cp_rtm_uninstall_route ( 
        rtm_t *rtm, 
        cmn_prefix_t *prefix, 
        cp_nexthop_template_t *cp_nh_template) {

    rtm_error_t rc;

    /* Uninstall route from the target RTM */
    rc = rtm_uninstall_route(rtm, prefix, cp_nh_template);

    /* Handle L3VPN route uninstallation from customer VRFs */
    def_vrf_t *def_vrf = rtm->node->node_nw_prop.def_vrf;
    if (def_vrf && (rtm == def_vrf->l3vpnv4 || rtm == def_vrf->l3vpnv6)) {
        rtm_install_l3vpn_routes_to_all_client_ribs(rtm, prefix, cp_nh_template, false);
    }

    return rc;
}

/**
 * @brief Uninstall all nexthops for a route matching a specific protocol
 * 
 * This function removes all nexthops from a route that match the given
 * protocol and sub-protocol. Useful for protocol shutdown scenarios.
 * 
 * Example: Remove all OSPF nexthops from a route
 * 
 * @param rtm Pointer to routing table
 * @param route Route prefix
 * @param proto Protocol type
 * @param sub_proto Sub-protocol type
 * 
 * @return Number of nexthops deleted
 */
uint32_t
cp_rtm_uninstall_route_by_proto ( rtm_t *rtm, 
        cmn_prefix_t *route, 
        RTM_PROTO_T proto, 
        RTM_SUB_PROTO_T sub_proto) {

    uint32_t deleted_count = 0;
    glthread_t *curr;
    rtm_nh *nh;

    if (!rtm || !route) {
        return 0;
    }

    if (proto >= RTM_PROTO_MAX) {
        return 0;
    }

    /* Look up the route in the RTM */
    rtm_route *rt = rtm_route_lookup(rtm, route);
    if (!rt) {
        return 0;
    }

    /* Iterate through all nexthops of the route */
    ITERATE_GLTHREAD_BEGIN(&rt->path_list, curr) {

        nh = route_glue_to_rtm_nh(curr);

        /* Check if this nexthop belongs to the specified protocol */
        if (nh->proto == proto && nh->sub_proto == sub_proto) {
            
            /* Delete the nexthop */
            cp_rtm_uninstall_route_by_idx(rtm, nh->idx);
            deleted_count++;
        }

    } ITERATE_GLTHREAD_END(&rt->path_list, curr);

    /* If route has no more nexthops, delete the route as well */
    if (rt->nh_count == 0) {
        rtm_route_delete(rtm, rt);
    }

    return deleted_count;
}

/**
 * @brief Uninstall all routes for a specific protocol
 * 
 * Removes all routes (across all prefixes) that belong to a specific
 * protocol. This is typically used during protocol shutdown.
 * 
 * @param rtm Pointer to routing table
 * @param proto Protocol type
 * @param sub_proto Sub-protocol type
 * 
 * @return Number of routes/nexthops deleted
 */
uint32_t
cp_rtm_uninstall_routes_by_proto ( rtm_t *rtm, 
                RTM_PROTO_T proto, 
                RTM_SUB_PROTO_T sub_proto,
                bool (*qualifier)(rtm_nh *)) {

    rtm_nh *nh;
    glthread_t *curr;
    uint32_t deleted_count = 0;

    /* Iterate through all nexthops from this protocol */
    ITERATE_GLTHREAD_BEGIN(&rtm->nhs_by_src[proto], curr) {

        nh = src_glue_to_rtm_nh(curr);
        
        /* Filter by sub-protocol if specified */
        if (nh->sub_proto != sub_proto) continue;
        
        if (qualifier && qualifier(nh)) {
            cp_rtm_uninstall_route_by_idx(rtm, nh->idx);
            deleted_count++;
            continue;
        }

        cp_rtm_uninstall_route_by_idx(rtm, nh->idx);
        deleted_count++;

    } ITERATE_GLTHREAD_END(&rtm->nhs_by_src[proto], curr);

    return deleted_count;
}

/* ========================================================================
 * Advanced Route Installation APIs
 * ======================================================================== */

/**
 * @brief Advanced route installation API with full control
 * 
 * This function provides a comprehensive API for installing routes
 * with all possible options including:
 * - Protocol and sub-protocol specification
 * - MPLS label stacks
 * - L3VPN labels
 * - Custom metrics
 * - Gateway and interface specification
 * 
 * Route Template Structure:
 * ┌─────────────────────────────────────────────────────────┐
 * │ Prefix: 192.168.1.0/24                                   │
 * │ Protocol: BGP                                            │
 * │ Sub-Protocol: BGP_VPN                                    │
 * │ Instance: 1                                              │
 * │ Action: FORWARD                                           │
 * │ Metric: 100                                              │
 * │ Gateway: 10.1.1.1                                        │
 * │ Interface: eth0                                          │
 * │ Label Stack: [100, 200, 300]                            │
 * │ L3VPN Label: 5000                                        │
 * └─────────────────────────────────────────────────────────┘
 * 
 * @param rtm Pointer to routing table
 * @param prefix Route prefix
 * @param proto Protocol type
 * @param sub_proto Sub-protocol type
 * @param instance_no Protocol instance number
 * @param action Nexthop action (FORWARD, LOCAL, DROP, etc.)
 * @param metric Route metric
 * @param gateway Gateway address (optional)
 * @param oif Outgoing interface (optional)
 * @param label_stack MPLS label stack (optional)
 * @param label_stack_count Number of labels in stack
 * @param l3_vpn_label L3VPN service label
 * 
 * @return RTM_SUCCESS on success, error code on failure
 */
rtm_error_t
cp_rtm_install_route_advanced (
    rtm_t *rtm,
    cmn_prefix_t *prefix,
    RTM_PROTO_T proto,
    RTM_SUB_PROTO_T sub_proto,
    uint32_t instance_no,
    RTM_NH_ACTION_TYPE_T action,
    uint32_t metric,
    cmn_prefix_t *gateway,
    InterfaceP oif,
    uint32_t *label_stack,
    uint8_t label_stack_count,
    mpls_label_val_t l3_vpn_label) {

    uint16_t fwd_flags = 0;
    rtm_error_t rc = RTM_SUCCESS;
    cp_nexthop_template_t nh_template;
    rtm_nh_proto_t *nh_proto = NULL;

    /* Validate inputs */
    if (!rtm || !prefix) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    /* Validate protocol and sub-protocol */
    if (proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_PROTO;
    }

    if (sub_proto >= RTM_SUB_PROTO_MAX) {
        return RTM_ERROR_INVALID_SUB_PROTO;
    }

    /* Validate action */
    if (action >= RTM_NH_ACTION_MAX) {
        return RTM_ERROR_NEXTHOP_INVALID_ACTION;
    }

    /* Initialize nexthop template */
    memset(&nh_template, 0, sizeof(nh_template));

    nh_template.proto = proto;
    nh_template.sub_proto = sub_proto;
    nh_template.action = action;
    nh_template.metric = metric;
    nh_template.l3_vpn_label = l3_vpn_label;

    /* Set gateway if provided */
    if (gateway && !cmn_prefix_is_null(gateway)) {
        nh_template.gateway = *gateway;

        /* Set forwarding flags based on gateway address family */
        switch (gateway->afi) {
            case AF_IPV4:
                fwd_flags |= FIB_NH_FWD_F_IPV4;
                break;

            case AF_IPV6:
                fwd_flags |= FIB_NH_FWD_F_IPV6;
                break;
            
            case AF_LABEL:
                break;
        }
    }

    /* Set outgoing interface if provided */
    if (oif) {
        nh_template.oif = oif->ifindex;
        nh_template.is_indirect = false;
        nh_template.is_resolved = true;
    } else {
        /* No interface means indirect route (requires resolution) */
        nh_template.is_indirect = true;
        nh_template.is_resolved = false;
    }

    /* Create protocol information structure */
    rc = rtm_nh_proto_info_create(proto, sub_proto, instance_no, rtm->vrf, &nh_proto);
    if (rc != RTM_SUCCESS) return rc;
    
    nh_template.rtm_nh_proto = nh_proto;

    /* Handle MPLS label stack if provided */
    if (label_stack && label_stack_count > 0) {
        if (label_stack_count > MAX_LBL_DEPTH) {
            XFREE(nh_proto);
            return RTM_ERROR_INVALID_ARGUMENT;
        }

        /* Allocate and initialize label stack */
        mpls_lstack_t *lstack = (mpls_lstack_t *)XCALLOC2(0, 1, mpls_lstack_t);
        mpls_lstack_init (lstack);

        /* Populate label stack */
        for (uint8_t i = 0; i < label_stack_count; i++) {
            lstack->labels[i].label_val = label_stack[i];
            lstack->labels[i].op = MPLS_OP_PUSH;
            lstack->curr_index++;
        }

        nh_template.u.l_stack.label_stack = lstack;
        fwd_flags |= FIB_NH_FWD_F_MPLS_LBL_STCK;
    }

    fwd_flags |= rtm_set_fib_forwarding_action_flag (nh_template.action);
    nh_template.fwd_flags = fwd_flags;
    
    /* Install the route */
    rc = cp_rtm_install_route(rtm, prefix, &nh_template);
    rtm_nh_template_free_internals (&nh_template);
    return rc;
}

/**
 * @brief Advanced route uninstallation API
 * 
 * Removes a route matching all the specified parameters.
 * This is the counterpart to cp_rtm_install_route_advanced().
 * 
 * @param rtm Pointer to routing table
 * @param prefix Route prefix
 * @param proto Protocol type
 * @param sub_proto Sub-protocol type
 * @param instance_no Protocol instance number
 * @param action Nexthop action
 * @param metric Route metric
 * @param gateway Gateway address
 * @param oif Outgoing interface
 * @param label_stack MPLS label stack
 * @param label_stack_count Number of labels
 * @param l3_vpn_label L3VPN service label
 * 
 * @return RTM_SUCCESS on success, error code on failure
 */
rtm_error_t
cp_rtm_uninstall_route_advanced (
    rtm_t *rtm,
    cmn_prefix_t *prefix,
    RTM_PROTO_T proto,
    RTM_SUB_PROTO_T sub_proto,
    uint32_t instance_no,
    RTM_NH_ACTION_TYPE_T action,
    uint32_t metric,
    cmn_prefix_t *gateway,
    InterfaceP oif,
    uint32_t *label_stack,
    uint8_t label_stack_count,
    mpls_label_val_t l3_vpn_label) {

    uint16_t fwd_flags = 0;
    rtm_error_t rc = RTM_SUCCESS;
    cp_nexthop_template_t nh_template;
    rtm_nh_proto_t *nh_proto = NULL;

    /* Validate inputs */
    if (!rtm || !prefix) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    /* Validate protocol and sub-protocol */
    if (proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_PROTO;
    }

    if (sub_proto >= RTM_SUB_PROTO_MAX) {
        return RTM_ERROR_INVALID_SUB_PROTO;
    }

    /* Validate action */
    if (action >= RTM_NH_ACTION_MAX) {
        return RTM_ERROR_NEXTHOP_INVALID_ACTION;
    }

    /* Initialize nexthop template */
    memset(&nh_template, 0, sizeof(nh_template));

    nh_template.proto = proto;
    nh_template.sub_proto = sub_proto;
    nh_template.action = action;
    nh_template.metric = metric;
    nh_template.l3_vpn_label = l3_vpn_label;
    nh_template.is_resolved = true;

    /* Set gateway if provided */
    if (gateway && !cmn_prefix_is_null(gateway)) {
        nh_template.gateway = *gateway;

        switch (gateway->afi) {
            case AF_IPV4:
                fwd_flags |= FIB_NH_FWD_F_IPV4;
                break;

            case AF_IPV6:
                fwd_flags |= FIB_NH_FWD_F_IPV6;
                break;

            case AF_LABEL:
                break;
        }
    }

    /* Set outgoing interface if provided */
    if (oif) {
        nh_template.oif = oif->ifindex;
        nh_template.is_indirect = false;
    } else {
        nh_template.is_indirect = true;
    }

    /* Create protocol info */
    rc = rtm_nh_proto_info_create(proto, sub_proto, 
            instance_no, rtm->vrf, &nh_proto);

    if (rc != RTM_SUCCESS) {
        return rc;
    }

    nh_template.rtm_nh_proto = nh_proto;

    /* Handle label stack if provided */
    if (label_stack && label_stack_count > 0) {
        if (label_stack_count > MAX_LBL_DEPTH) {
            XFREE(nh_proto);
            return RTM_ERROR_INVALID_ARGUMENT;
        }

        /* Allocate label stack */
        mpls_lstack_t *lstack = (mpls_lstack_t *)XCALLOC2(0, 1, mpls_lstack_t);
        mpls_lstack_init(lstack);

        for (uint8_t i = 0; i < label_stack_count; i++) {
            lstack->labels[i].label_val = label_stack[i];
            lstack->labels[i].op = MPLS_OP_PUSH;
            lstack->curr_index++;
        }

        nh_template.u.l_stack.label_stack = lstack;
        fwd_flags |= FIB_NH_FWD_F_MPLS_LBL_STCK;
    }

    fwd_flags |= rtm_set_fib_forwarding_action_flag (nh_template.action);
    nh_template.fwd_flags = fwd_flags;
    
    /* Uninstall the route */
    rc = cp_rtm_uninstall_route(rtm, prefix, &nh_template);
    rtm_nh_template_free_internals (&nh_template);
    return rc;
}

/* ========================================================================
 * Protocol Registration and Subscription APIs
 * ======================================================================== */

/**
 * @brief Register a routing protocol with RTM
 * 
 * Protocols must be registered before they can install routes or
 * subscribe to route updates. Registration creates protocol-specific
 * data structures and subscription databases.
 * 
 * Protocol Registration Flow:
 * ┌─────────────────────────────────────────────────────────┐
 * │ 1. Validate protocol type                                │
 * │ 2. Check if already registered                          │
 * │ 3. Create protocol info structure                       │
 * │ 4. Initialize subscription database (AVL tree)          │
 * │ 5. Add protocol info to RTM's protocol tree             │
 * └─────────────────────────────────────────────────────────┘
 * 
 * @param rtm Pointer to routing table
 * @param proto Protocol type (BGP, OSPF, ISIS, etc.)
 * @param instance_no Protocol instance number
 * @param vrf_id VRF identifier
 * 
 * @return true on success, false on failure
 */
bool
cp_rtm_protocol_register(rtm_t *rtm, RTM_PROTO_T proto, uint32_t instance_no, uint8_t vrf_id) {
    
    /* Validate protocol type */
    if (proto >= RTM_PROTO_MAX) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Protocol registration failed - Invalid protocol %d\n",
            rtm->name, proto);
        return false;
    }

    /* Check if protocol is already registered */
    rtm_proto_info_t *existing = rtm_proto_lookup(rtm, proto, instance_no);
    if (existing) {
        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : WARNING: Protocol %s instance %u already registered\n",
            rtm->name, rtm_proto_to_string(proto), instance_no);
        return false;
    }

    /* Create new protocol info structure */
    rtm_proto_info_t *proto_info = rtm_proto_info_create(rtm, proto, instance_no);
    if (!proto_info) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Failed to create protocol info for %s instance %u\n",
            rtm->name, rtm_proto_to_string(proto), instance_no);
        return false;
    }

    /* Initialize subscription database (AVL tree for efficient lookup) */
    avltree_init(&proto_info->sub_db, rtm_rt_subscription_compare);

    /* Add protocol info to RTM's protocol tree */
    rtm_error_t rc = rtm_proto_info_add(rtm, proto_info);

    if (rc != RTM_SUCCESS) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Failed to add protocol info for %s instance %u - %s\n",
            rtm->name, rtm_proto_to_string(proto), instance_no, rtm_error_to_string(rc));
        XFREE(proto_info);
        return false;
    }

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Protocol %s instance %u registered successfully\n",
        rtm->name, rtm_proto_to_string(proto), instance_no);

    return true;
}

/**
 * @brief Unregister a routing protocol from RTM
 * 
 * Removes protocol registration and cleans up all associated
 * subscriptions. This is typically called during protocol shutdown.
 * 
 * @param rtm Pointer to routing table
 * @param proto Protocol type
 * @param instance_no Protocol instance number
 * @param vrf_id VRF identifier
 * 
 * @return true on success, false on failure
 */
bool
cp_rtm_protocol_unregister(rtm_t *rtm, RTM_PROTO_T proto, uint32_t instance_no, uint8_t vrf_id) {

    /* Validate protocol type */
    if (proto >= RTM_PROTO_MAX) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Protocol unregistration failed - Invalid protocol %d\n",
            rtm->name, proto);
        return false;
    }

    /* Validate VRF */
    if (vrf_id != rtm->vrf) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Protocol unregistration failed - VRF mismatch (expected %d, got %d)\n",
            rtm->name, rtm->vrf, vrf_id);
        return false;
    }

    /* Check if protocol is registered */
    rtm_proto_info_t *proto_info = rtm_proto_lookup(rtm, proto, instance_no);
    if (!proto_info) {
        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : WARNING: Protocol %s instance %u not registered\n",
            rtm->name, rtm_proto_to_string(proto), instance_no);
        return false;
    }

    /* Check if there are active subscriptions */
    if (!avltree_is_empty(&proto_info->sub_db)) {
        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : WARNING: Protocol %s instance %u has active subscriptions, clearing them\n",
            rtm->name, rtm_proto_to_string(proto), instance_no);
        
        /* Clear all subscriptions */
        while (!avltree_is_empty(&proto_info->sub_db)) {
            avltree_node_t *node = avltree_first(&proto_info->sub_db);
            rtm_rt_subscription_t *sub = avltree_container_of(node, rtm_rt_subscription_t, avl_glue);
            avltree_strict_remove(&sub->avl_glue, &proto_info->sub_db);
            XFREE(sub);
        }
    }

    /* Delete protocol info from RTM */
    rtm_error_t rc = rtm_proto_info_del(rtm, proto, instance_no);
    if (rc != RTM_SUCCESS) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Failed to delete protocol info for %s instance %u - %s\n",
            rtm->name, rtm_proto_to_string(proto), instance_no, rtm_error_to_string(rc));
        return false;
    }

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Protocol %s instance %u unregistered successfully\n",
        rtm->name, rtm_proto_to_string(proto), instance_no);

    return true;
}

/**
 * @brief Subscribe to route notifications
 * 
 * Allows a protocol to subscribe to route updates from another protocol.
 * This enables route redistribution and protocol interaction.
 * 
 * Subscription Model:
 * ┌─────────────────────────────────────────────────────────┐
 * │ Source Protocol (e.g., OSPF)                            │
 * │   └─> Installs route in RTM                             │
 * │       └─> RTM notifies all subscribers                  │
 * │           └─> Target Protocol (e.g., BGP)               │
 * │               └─> Receives route update via callback    │
 * └─────────────────────────────────────────────────────────┘
 * 
 * @param rtm Pointer to routing table
 * @param src_vrf Source VRF ID
 * @param src_instance_no Source protocol instance
 * @param src_proto Source protocol type
 * @param sub_template Subscription template with target protocol info
 * 
 * @return RTM_SUCCESS on success, error code on failure
 */
rtm_error_t
cp_rtm_subscribe(rtm_t *rtm, 
                            uint8_t src_vrf, uint8_t src_instance_no, RTM_PROTO_T src_proto, 
                            rtm_rt_subscription_t *sub_template) {

    /* Validate target protocol */
    if (sub_template->target_proto >= RTM_PROTO_MAX) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Subscription failed - Invalid target protocol %d\n",
            rtm->name, sub_template->target_proto);
        return RTM_ERROR_INVALID_PROTO;
    }

    /* Validate target sub-protocol */
    if (sub_template->target_sub_proto >= RTM_SUB_PROTO_MAX) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Subscription failed - Invalid target sub-protocol %d\n",
            rtm->name, sub_template->target_sub_proto);
        return RTM_ERROR_INVALID_SUB_PROTO;
    }

    /* Check if target protocol is registered */
    rtm_proto_info_t *proto_info = rtm_proto_lookup(rtm, 
                                                     src_proto, src_instance_no);

    if (!proto_info) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Subscription failed - Target protocol %s instance %u not registered\n",
            rtm->name, rtm_proto_to_string(sub_template->target_proto), 
            sub_template->target_instance_no);
        return RTM_ERROR_PROTO_NOT_REGISTERED;
    }

    /* Allocate new subscription structure */
    rtm_rt_subscription_t *sub = (rtm_rt_subscription_t *)XCALLOC2(0, 1, rtm_rt_subscription_t);
    if (!sub) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Subscription failed - Memory allocation error\n",
            rtm->name);
        return RTM_ERROR_MEMORY_ALLOC_FAILED;
    }

    /* Copy subscription template */
    sub->target_proto = sub_template->target_proto;
    sub->target_sub_proto = sub_template->target_sub_proto;
    sub->target_instance_no = sub_template->target_instance_no;
    sub->prefix_list = sub_template->prefix_list;
    sub->cbk = sub_template->cbk;

    /* Initialize AVL glue for tree insertion */
    avltree_node_init(&sub->avl_glue);

    /* Add subscription to protocol's subscription database */
    if (avltree_insert(&sub->avl_glue, &proto_info->sub_db)) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Subscription failed - Failed to insert into subscription database\n",
            rtm->name);
        XFREE(sub);
        return RTM_ERROR_CONTAINER_INSERTION_FAILED;
    }

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Subscription added for protocol %s instance %u\n",
        rtm->name, rtm_proto_to_string(sub_template->target_proto), 
        sub_template->target_instance_no);

    return RTM_SUCCESS;
}

/**
 * @brief Unsubscribe from route notifications
 * 
 * Removes a previously created subscription.
 * 
 * @param rtm Pointer to routing table
 * @param sub_template Subscription template to match for removal
 * 
 * @return RTM_SUCCESS on success, error code on failure
 */
rtm_error_t
cp_rtm_unsubscribe(rtm_t *rtm, rtm_rt_subscription_t *sub_template) {
    
    if (!rtm || !sub_template) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    /* Validate target protocol */
    if (sub_template->target_proto >= RTM_PROTO_MAX) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Unsubscription failed - Invalid target protocol %d\n",
            rtm->name, sub_template->target_proto);
        return RTM_ERROR_INVALID_PROTO;
    }

    /* Check if target protocol is registered */
    rtm_proto_info_t *proto_info = rtm_proto_lookup(rtm, 
                                                     sub_template->target_proto, 
                                                     sub_template->target_instance_no);
    if (!proto_info) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Unsubscription failed - Target protocol %s instance %u not registered\n",
            rtm->name, rtm_proto_to_string(sub_template->target_proto), 
            sub_template->target_instance_no);
        return RTM_ERROR_PROTO_NOT_REGISTERED;
    }

    /* Search for the subscription in the database */
    avltree_node_t *node = avltree_lookup(&sub_template->avl_glue, &proto_info->sub_db);
    
    if (!node) {
        tracer(rtm->node->cptr, DRTM | DERR,
            "RTM[%s] : ERROR: Unsubscription failed - Subscription not found for protocol %s instance %u\n",
            rtm->name, rtm_proto_to_string(sub_template->target_proto), 
            sub_template->target_instance_no);
        return RTM_ERROR_SUBSCRIPTION_NOT_FOUND;
    }
    
    rtm_rt_subscription_t *sub = avltree_container_of(node, rtm_rt_subscription_t, avl_glue);

    /* Remove subscription from database */
    avltree_strict_remove(&sub->avl_glue, &proto_info->sub_db);
    
    /* Free subscription resources */
    if (sub->prefix_list) prefix_list_dereference (sub->prefix_list);
    XFREE(sub);

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Subscription removed for protocol %s instance %u\n",
        rtm->name, rtm_proto_to_string(sub_template->target_proto), 
        sub_template->target_instance_no);

    return RTM_SUCCESS;
}

/**
 * @brief Get route target RTM (wrapper function)
 * 
 * This is a convenience wrapper that calls the core rtm_get_route_target_rtm()
 * function. It provides a consistent API for control plane applications.
 * 
 * @param node Pointer to network node
 * @param vrf VRF pointer (NULL for default VRF)
 * @param afi Address family
 * @param proto Protocol type
 * @param sub_proto Sub-protocol type
 * 
 * @return Pointer to target RTM, or NULL if not found
 */
rtm_t *
cp_rtm_get_route_target_rtm( node_t *node, 
                          vrf_t *vrf, AFI_T afi,
                          RTM_PROTO_T proto, 
                          RTM_SUB_PROTO_T sub_proto) {

    return rtm_get_route_target_rtm(node, vrf, afi, proto, sub_proto);
}
