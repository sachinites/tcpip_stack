#ifndef __MACVRF__
#define __MACVRF__

#include "vrf.h"
#include "../tcpconst.h"


#pragma pack(push, 8)

typedef struct mac_vrf_ {

    vrf_t vrf;

    // rtm <evpn-instance-name>.mac.<bd-id>
    rtm_t *mac_rib;

    /* Service VPN label assignment per BD/MAC VRF 
    To steer incoming traffic from default VRF */
    uint32_t l2vpn_evpn_uc_lbl;
    uint32_t rtm_local_bd_uc_rt_mpls_idx ;

    uint32_t l2vpn_evpn_mc_lbl;
    uint32_t rtm_local_bd_mc_rt_mpls_idx ;

} mac_vrf_t;

#pragma pack(pop)


#endif 