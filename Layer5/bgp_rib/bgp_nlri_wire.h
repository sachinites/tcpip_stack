#ifndef BGP_NLRI_WIRE_H_
#define BGP_NLRI_WIRE_H_

#include <stdio.h>

#include "bgp_rib_types.h"

int
bgp_rd_wire_to_str(const uint8_t rd_wire[8],
                   char *buf,
                   size_t buflen);

int
bgp_nlri_wire_format_compact(uint8_t afi,
                             uint8_t safi,
                             const bgp_nlri_key_t *key,
                             const bgp_rib_attrs_t *attrs,
                             char *buf,
                             size_t buflen);

int
bgp_nlri_wire_format_network(uint8_t afi,
                             uint8_t safi,
                             const bgp_nlri_key_t *key,
                             char *buf,
                             size_t buflen);

void
bgp_nlri_wire_print_route(uint8_t afi,
                          uint8_t safi,
                          const bgp_nlri_key_t *key,
                          const bgp_rib_attrs_t *attrs,
                          FILE *fp);

#endif /* BGP_NLRI_WIRE_H_ */
