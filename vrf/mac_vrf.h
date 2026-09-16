#ifndef __MACVRF__
#define __MACVRF__

#include "vrf.h"
#include "../tcpconst.h"

typedef  struct hashtable hashtable_t;

#pragma pack(push, 8)

typedef struct mac_vrf_ {

    uint16_t mac_vrf_id;

    /* This MAC VRF is housed under this L3 VRF*/
    vrf_t *vrf;

    /* Owning VPN instance*/
    evpn_inst_t *evpn_inst;

    // RIB for type 2 routes.
    hashtable_t *type2_rib;

    // RIB for type 3 (IMET) routes, keyed by originating router IP.
    hashtable_t *type3_rib;

    // RTM to install Type 2 routes. Though RTM is specially designed for
    // for IP routes, it can be used to install MAC routes as well. Doing
    // so will help us view MAC Type 2 EVPN routes using common RTM clis, 
    // and primary reason would be to resolve the indirect Nexthop in default VRF.
    rtm_t *mac_rtm;
    
} mac_vrf_t;

#pragma pack(pop)

typedef struct evpn_inst_ evpn_inst_t;

mac_vrf_t *
mac_vrf_create (vrf_t *vrf, uint16_t mac_vrf_id);

void
mac_vrf_destroy (mac_vrf_t *mac_vrf);


void 
mac_vrf_evpn_route_type2_local_import (
        node_t *node,
        mac_vrf_t *mac_vrf, 
        mac_addr_t *mac_addr);

void
mac_vrf_evpn_route_type2_delete (
        node_t *node,
        mac_vrf_t *mac_vrf,
        mac_addr_t *mac_addr);

void
mac_vrf_evpn_route_type2_remote_import(
        mac_vrf_t *mac_vrf,
        mac_addr_t *mac_addr,
        uint32_t vtep_ip,
        uint32_t label);

void
mac_vrf_evpn_route_type2_remote_delete(
        mac_vrf_t *mac_vrf,
        mac_addr_t *mac_addr);

void
mac_vrf_evpn_route_type3_local_import(
        node_t *node,
        mac_vrf_t *mac_vrf);

void
mac_vrf_evpn_route_type3_delete(
        node_t *node,
        mac_vrf_t *mac_vrf);

void
mac_vrf_evpn_route_type3_remote_import(
        mac_vrf_t *mac_vrf,
        uint32_t pe_addr,
        uint32_t vtep_ip,
        uint32_t label);

void
mac_vrf_evpn_route_type3_remote_delete(
        mac_vrf_t *mac_vrf,
        uint32_t pe_addr);

void
mac_vrf_flush_remote_bgp_routes(mac_vrf_t *mac_vrf);

void 
mac_vrf_export_evpn_local_evpn_routes_to_bgp(node_t *node, evpn_inst_t *evpn);

void 
mac_vrf_export_all_local_evpn_routes_to_bgp(node_t *node);

rtm_t *
mac_vrf_get_rtm (node_t *node, uint16_t mac_vrf_id);

#endif 
