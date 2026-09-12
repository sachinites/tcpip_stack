#include "evpn_rt.h"
#include "../../Layer5/bgp_route.h"

void
evpn_route_export_to_bgp(node_t *node,
                         rd_t *rd,
                         rt_t *export_rt,
                         evpn_rt_t *evpn_rt,
                         bool is_delete)
{
    if (!node || !rd || !export_rt || !evpn_rt) {
        return;
    }

    bgp_evpn_type2_route_update(node, rd, export_rt, evpn_rt, is_delete);
}
