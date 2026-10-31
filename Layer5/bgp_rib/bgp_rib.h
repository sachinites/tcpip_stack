#ifndef BGP_RIB_H_
#define BGP_RIB_H_

#include <stdio.h>

#include "bgp_rib_types.h"
#include "../../libs/common/cmn_prefix.h"
#include <stdint.h>

typedef struct rtm_ rtm_t;
typedef struct bgp_rib_ bgp_rib_t;

bgp_rib_t *
bgp_rib_create(uint8_t afi, uint8_t safi);

void
bgp_rib_destroy(bgp_rib_t *rib);

uint8_t
bgp_rib_get_afi(const bgp_rib_t *rib);

uint8_t
bgp_rib_get_safi(const bgp_rib_t *rib);

typedef void (*bgp_rib_export_route_cb)(void *bgp_inst,
                                        uint8_t afi,
                                        uint8_t safi,
                                        bgp_nlri_key_t *key,
                                        bgp_rib_attrs_t *attrs,
                                        bool is_add,
                                        uint16_t target_vrf_id);

void
bgp_rib_set_export_route(bgp_rib_t *rib,
                         void *bgp_instance,
                         bgp_rib_export_route_cb export_route);

void
bgp_rib_set_nh_tracker(bgp_rib_t *rib,
                       uintptr_t nh_tracker_reg_id);

uintptr_t
bgp_rib_nh_tracker_reg_id(const bgp_rib_t *rib);

void
bgp_rib_nh_tracker_unregister(bgp_rib_t *rib);

bgp_rib_err_t
bgp_rib_route_add(bgp_rib_t *rib,
                  const bgp_nlri_key_t *key,
                  const bgp_rib_attrs_t *attrs);

bgp_rib_err_t
bgp_rib_route_delete(bgp_rib_t *rib,
                     const bgp_nlri_key_t *key);

const bgp_rib_attrs_t *
bgp_rib_route_lookup(const bgp_rib_t *rib,
                     const bgp_nlri_key_t *key);

typedef int (*bgp_rib_walk_cb)(const bgp_nlri_key_t *key,
                               const bgp_rib_attrs_t *attrs,
                               void *userdata);

void
bgp_rib_route_walk(bgp_rib_t *rib,
                   bgp_rib_walk_cb cb,
                   void *userdata);

typedef int (*bgp_rib_nh_walk_cb)(const cmn_prefix_t *nexthop,
                                  unsigned int route_count,
                                  void *userdata);

void
bgp_rib_nh_walk(bgp_rib_t *rib,
                bgp_rib_nh_walk_cb cb,
                void *userdata);

void
bgp_rib_route_walk_by_nh(bgp_rib_t *rib,
                         const cmn_prefix_t *nh_prefix,
                         bgp_rib_walk_cb cb,
                         void *userdata);

unsigned int
bgp_rib_route_count_by_nh(const bgp_rib_t *rib,
                          const cmn_prefix_t *nh_prefix);

void
bgp_rib_export_all(bgp_rib_t *rib,
                   uint16_t target_vrf_id,
                   uint8_t export_route_type);

unsigned int
bgp_rib_route_count(const bgp_rib_t *rib);

void
bgp_rib_print_routes(bgp_rib_t *rib, FILE *fp);

#endif /* BGP_RIB_H_ */
