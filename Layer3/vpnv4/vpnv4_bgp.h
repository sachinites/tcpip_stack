#ifndef __VPNV4_BGP_H__
#define __VPNV4_BGP_H__

#include <stdbool.h>

#include "../../Layer5/bgp_route.h"

void
bgp_rtm_vpn_route_install(node_t *node, const bgp_route_info_t *route);

void
bgp_rtm_vpn_route_uninstall(node_t *node, const bgp_route_info_t *route);

void
bgp_schedule_vpn_route_processing_job(node_t *node,
                                      const bgp_route_info_t *route,
                                      bool is_add);

#endif /* __VPNV4_BGP_H__ */
