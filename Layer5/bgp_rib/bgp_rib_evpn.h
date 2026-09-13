#ifndef BGP_RIB_EVPN_H_
#define BGP_RIB_EVPN_H_

#include "../../Layer2/Evpn/evpn_rt.h"
#include "../../libs/common/cmn_struct.h"
#include "../../vrf/vrf.h"

#include "bgp_rib.h"
#include "bgp_rib_types.h"

typedef struct bgp_evpn_nlri_ {
    uint8_t      route_type;
    rd_t         rd;
    uint8_t      esi[10];
    uint32_t     eth_tag_id;
    uint8_t      mac_len;
    mac_addr_t   mac;
    uint8_t      ip_len;
    uint32_t     ip_addr;
    uint32_t     label;
    bool         label_present;
} bgp_evpn_nlri_t;

bgp_rib_err_t
bgp_evpn_nlri_encode(const bgp_evpn_nlri_t *nlri,
                     bgp_nlri_key_t *key_out);

bgp_rib_err_t
bgp_evpn_nlri_decode(const bgp_nlri_key_t *key,
                     bgp_evpn_nlri_t *nlri_out);

int
bgp_evpn_nlri_format_compact(const bgp_nlri_key_t *key,
                             const bgp_rib_attrs_t *attrs,
                             char *buf,
                             size_t buflen);

bgp_rib_err_t
bgp_evpn_nlri_to_evpn_rt(const bgp_evpn_nlri_t *nlri,
                         uint32_t vtep_ip,
                         evpn_rt_t *evpn_rt_out);

bgp_rib_err_t
bgp_evpn_rib_route_add(bgp_rib_t *rib,
                       const bgp_evpn_nlri_t *nlri,
                       const bgp_rib_attrs_t *attrs);

bgp_rib_err_t
bgp_evpn_rib_route_delete(bgp_rib_t *rib,
                          const bgp_evpn_nlri_t *nlri);

const bgp_rib_attrs_t *
bgp_evpn_rib_route_lookup(const bgp_rib_t *rib,
                          const bgp_evpn_nlri_t *nlri);

#endif /* BGP_RIB_EVPN_H_ */
