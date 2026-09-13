#ifndef BGP_RIB_VPNV4_H_
#define BGP_RIB_VPNV4_H_

#include "../../vrf/vrf.h"

#include "bgp_rib.h"
#include "bgp_rib_types.h"

typedef struct bgp_vpnv4_nlri_ {
    rd_t     rd;
    uint8_t  prefix_len;
    uint32_t prefix;
    uint32_t label;
    bool     label_present;
} bgp_vpnv4_nlri_t;

bgp_rib_err_t
bgp_vpnv4_nlri_encode(const bgp_vpnv4_nlri_t *nlri,
                      bgp_nlri_key_t *key_out);

bgp_rib_err_t
bgp_vpnv4_nlri_decode(const bgp_nlri_key_t *key,
                      bgp_vpnv4_nlri_t *nlri_out);

int
bgp_vpnv4_nlri_format_compact(const bgp_nlri_key_t *key,
                              const bgp_rib_attrs_t *attrs,
                              char *buf,
                              size_t buflen);

int
bgp_vpnv4_nlri_format_bracket(const bgp_nlri_key_t *key,
                              char *buf,
                              size_t buflen);

int
bgp_vpnv4_ipv4_unicast_format_compact(const bgp_nlri_key_t *key,
                                       const bgp_rib_attrs_t *attrs,
                                       char *buf,
                                       size_t buflen);

bgp_rib_err_t
bgp_vpnv4_rib_route_add(bgp_rib_t *rib,
                        const bgp_vpnv4_nlri_t *nlri,
                        const bgp_rib_attrs_t *attrs);

bgp_rib_err_t
bgp_vpnv4_rib_route_delete(bgp_rib_t *rib,
                           const bgp_vpnv4_nlri_t *nlri);

const bgp_rib_attrs_t *
bgp_vpnv4_rib_route_lookup(const bgp_rib_t *rib,
                           const bgp_vpnv4_nlri_t *nlri);

#endif /* BGP_RIB_VPNV4_H_ */
