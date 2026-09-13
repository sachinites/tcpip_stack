#ifndef BGP_GLOBAL_RIB_H_
#define BGP_GLOBAL_RIB_H_

#include "bgp_route.h"

struct bgp_inst_;
typedef struct bgp_inst_ bgp_inst_t;

struct node_;
typedef struct node_ node_t;

int
bgp_global_rib_af_enable(node_t *node, int afi, int safi);

void
bgp_global_rib_af_disable(node_t *node, int afi, int safi);

void
bgp_global_rib_deinit(bgp_inst_t *bgp);

void
bgp_global_rib_route_update(node_t *node,
                            const bgp_route_info_t *route,
                            bool is_add);

struct bgp_rib_;
typedef struct bgp_rib_ bgp_rib_t;

bgp_rib_t *
bgp_global_rib_get(node_t *node, int afi, int safi);

#endif /* BGP_GLOBAL_RIB_H_ */
