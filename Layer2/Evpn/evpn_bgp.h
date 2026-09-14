#ifndef __EVPN_BGP_H__
#define __EVPN_BGP_H__

#include <stdbool.h>

#include "../../Layer5/bgp_route.h"
#include "evpn_rt.h"

void
evpn_route_export_to_bgp(node_t *node,
                         rd_t *rd,
                         rt_t *export_rt,
                         evpn_exp_rt_t *evpn_rt,
                         bool is_delete);

#endif /* __EVPN_BGP_H__ */
