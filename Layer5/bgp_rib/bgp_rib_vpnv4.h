#ifndef BGP_RIB_VPNV4_H_
#define BGP_RIB_VPNV4_H_

#include "../../vrf/vrf.h"

#include "bgp_rib.h"
#include "bgp_rib_types.h"

typedef struct cp_nexthop_template_ cp_nexthop_template_t;
typedef struct cmn_prefix_ cmn_prefix_t;

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


void 
bgp_vpnv4_nlri_key_to_cmn_prefix (bgp_nlri_key_t *key, 
                                  cmn_prefix_t *cmn_prefix);

bool
bgp_vpnv4_build_nh_template(bgp_nlri_key_t *key, 
                            bgp_rib_attrs_t *attrs, 
                            cp_nexthop_template_t *cp_nh_template);

void 
bgp_global_rib_export_vpnv4_route_cb(     
                                   void *ctx,
                                   uint8_t afi,
                                   uint8_t safi,
                                   bgp_nlri_key_t *key,
                                   bgp_rib_attrs_t *attrs,
                                   bool is_add,
                                   uint16_t target_vrf_id);

#endif /* BGP_RIB_VPNV4_H_ */
