#ifndef BGP_RIB_IPV4_H_
#define BGP_RIB_IPV4_H_

#include "bgp_rib.h"
#include "bgp_rib_types.h"

typedef struct cp_nexthop_template_ cp_nexthop_template_t;
typedef struct cmn_prefix_ cmn_prefix_t;

typedef struct bgp_ipv4_unicast_nlri_ {
    uint8_t  prefix_len;
    uint32_t prefix;
} bgp_ipv4_unicast_nlri_t;

bgp_rib_err_t
bgp_ipv4_unicast_nlri_decode(const bgp_nlri_key_t *key,
                             bgp_ipv4_unicast_nlri_t *nlri_out);

void
bgp_ipv4_unicast_nlri_key_to_cmn_prefix(bgp_nlri_key_t *key,
                                        cmn_prefix_t *cmn_prefix);

bool
bgp_ipv4_unicast_build_nh_template(bgp_rib_attrs_t *attrs,
                                   cp_nexthop_template_t *cp_nh_template);

void
bgp_global_rib_export_ipv4_unicast_route_cb(void *ctx,
                                            uint8_t afi,
                                            uint8_t safi,
                                            bgp_nlri_key_t *key,
                                            bgp_rib_attrs_t *attrs,
                                            bool is_add,
                                            uint16_t target_vrf_id);

#endif /* BGP_RIB_IPV4_H_ */
