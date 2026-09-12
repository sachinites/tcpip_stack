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

    // RTM to install Type 2 routes. Though RTM is specially designed for
    // for IP routes, it can be used to install MAC routes as well. Doing
    // so will help us view MAC Type 2 EVPN routes using common RTM clis, 
    // and primary reason would be to resolve the indirect Nexthop in default VRF.
    rtm_t *mac_rtm;
    
    // ToDo : Evpn Imet RIB

    // RIB of Type 5 EVPN Routes are not functionally distinguishable from
    // l3 vpn routes. So, they will go in def_vrf->l3evpnv4 rtm.

} mac_vrf_t;

#pragma pack(pop)

struct evpn_inst_;
typedef struct evpn_inst_ evpn_inst_t;

mac_vrf_t *
mac_vrf_create (vrf_t *vrf, uint16_t mac_vrf_id, evpn_inst_t *evpn_inst);

void
mac_vrf_destroy (vrf_t *vrf, uint16_t mac_vrf_id);


void 
mac_vrf_evpn_route_type2_local_import (
        mac_vrf_t *mac_vrf, 
        mac_addr_t *mac_addr);

void
mac_vrf_evpn_route_type2_delete (
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

#endif 