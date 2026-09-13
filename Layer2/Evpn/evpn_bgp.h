#ifndef __EVPN_BGP_H__
#define __EVPN_BGP_H__

#include <stdbool.h>

#include "../../Layer5/bgp_route.h"
#include "evpn_rt.h"

void
evpn_route_export_to_bgp(node_t *node,
                         rd_t *rd,
                         rt_t *export_rt,
                         evpn_rt_t *evpn_rt,
                         bool is_delete);

int
bgp_evpn_type2_route_update(node_t *node,
                            rd_t *rd,
                            rt_t *export_rt,
                            evpn_rt_t *evpn_rt,
                            bool is_delete);

void
bgp_rtm_evpn_route_install(node_t *node, const bgp_route_info_t *route);

void
bgp_rtm_evpn_route_uninstall(node_t *node, const bgp_route_info_t *route);

void
bgp_schedule_evpn_route_processing_job(node_t *node,
                                       const bgp_route_info_t *route,
                                       bool is_add);

#endif /* __EVPN_BGP_H__ */
