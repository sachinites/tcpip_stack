#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../../tcpconst.h"

#include "bgp_rib.h"
#include "bgp_rib_evpn.h"
#include "bgp_rib_vpnv4.h"

static void
test_evpn_rib(void)
{
    bgp_rib_t *rib;
    bgp_evpn_nlri_t nlri;
    bgp_rib_attrs_t attrs;
    evpn_rt_t evpn_rt;
    const bgp_rib_attrs_t *found;

    rib = bgp_rib_create(AFI_L2VPN, SAFI_MPLS_EVPN);
    assert(rib);

    memset(&nlri, 0, sizeof(nlri));
    nlri.route_type = EVPN_RT_TYPE_MAC_ONLY;
    nlri.rd.type = 2;
    nlri.rd.rtr_id = 65000;
    nlri.rd.vrf_id = 100;
    memset(nlri.esi, 0, sizeof(nlri.esi));
    nlri.eth_tag_id = 100;
    nlri.mac_len = 48;
    nlri.mac.mac[0] = 0x00;
    nlri.mac.mac[1] = 0x11;
    nlri.mac.mac[2] = 0x22;
    nlri.mac.mac[3] = 0x33;
    nlri.mac.mac[4] = 0x44;
    nlri.mac.mac[5] = 0x55;
    nlri.ip_len = 32;
    nlri.ip_addr = 0xc0a8010a;
    nlri.label = 1000;
    nlri.label_present = true;

    memset(&attrs, 0, sizeof(attrs));
    strncpy(attrs.nexthop, "10.0.0.1", sizeof(attrs.nexthop) - 1);
    attrs.med = 100;
    attrs.med_present = true;
    attrs.best = true;

    assert(bgp_evpn_rib_route_add(rib, &nlri, &attrs) == BGP_RIB_OK);

    found = bgp_evpn_rib_route_lookup(rib, &nlri);
    assert(found);
    assert(found->med == 100);

    assert(bgp_evpn_nlri_to_evpn_rt(&nlri, 0x0a000001, &evpn_rt) == BGP_RIB_OK);
    assert(evpn_rt.type == EVPN_RT_TYPE_MAC_ONLY);
    assert(evpn_rt.u.mac_only.ip_addr == 0xc0a8010a);

    printf("EVPN RIB routes:\n");
    bgp_rib_print_routes(rib, stdout);

    assert(bgp_evpn_rib_route_delete(rib, &nlri) == BGP_RIB_OK);
    assert(bgp_rib_route_count(rib) == 0);

    bgp_rib_destroy(rib);
}

static void
test_vpnv4_rib(void)
{
    bgp_rib_t *rib;
    bgp_vpnv4_nlri_t nlri;
    bgp_rib_attrs_t attrs;

    rib = bgp_rib_create(AFI_IPV4, SAFI_MPLS_VPN);
    assert(rib);

    memset(&nlri, 0, sizeof(nlri));
    nlri.rd.type = 1;
    nlri.rd.rtr_id = 0x01010101;
    nlri.rd.vrf_id = 100;
    nlri.prefix_len = 24;
    nlri.prefix = 0x0a010100;
    nlri.label = 1000;
    nlri.label_present = true;

    memset(&attrs, 0, sizeof(attrs));
    strncpy(attrs.nexthop, "10.0.0.2", sizeof(attrs.nexthop) - 1);

    assert(bgp_vpnv4_rib_route_add(rib, &nlri, &attrs) == BGP_RIB_OK);
    assert(bgp_vpnv4_rib_route_lookup(rib, &nlri) != NULL);

    printf("VPNv4 RIB routes:\n");
    bgp_rib_print_routes(rib, stdout);

    assert(bgp_vpnv4_rib_route_delete(rib, &nlri) == BGP_RIB_OK);
    bgp_rib_destroy(rib);
}

int
main(void)
{
    test_evpn_rib();
    test_vpnv4_rib();
    printf("bgp_rib_test: OK\n");
    return 0;
}
