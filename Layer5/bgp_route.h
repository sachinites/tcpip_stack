#ifndef BGP_ROUTE_H_
#define BGP_ROUTE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_;
typedef struct node_ node_t;

struct bgp_inst_;
typedef struct bgp_inst_ bgp_inst_t;

typedef struct bgp_route_params_ {
    char prefix[64];
    char nexthop[64];
    char rd[32];
    char rt[32];
    uint32_t med;
    uint32_t local_pref;
    uint32_t l3_vpn_label;
    bool med_present;
    bool local_pref_present;
    bool l3_vpn_label_present;
    char mac_addr[32];
    uint32_t evpn_label;
    bool evpn_label_present;
} bgp_route_params_t;

typedef struct bgp_route_info_ {
    char prefix[64];
    char nexthop[64];
    char rd[32];
    char rt[32];
    uint32_t med;
    uint32_t local_pref;
    uint32_t l3_vpn_label;
    bool med_present;
    bool local_pref_present;
    bool l3_vpn_label_present;
    bool best;
    bool is_from_external;
} bgp_route_info_t;

typedef int (*bgp_route_walk_cb)(const bgp_route_info_t *route, void *userdata);

int bgp_node_add_route(node_t *node, const bgp_route_params_t *params);
int bgp_node_delete_route(node_t *node, const bgp_route_params_t *params);
int bgp_node_walk_routes(node_t *node,
                         const char *afi,
                         const char *safi,
                         bgp_route_walk_cb callback,
                         void *userdata);

typedef void (*bgp_route_update_notify_cb)(const bgp_route_info_t *route,
                                           bool is_withdraw,
                                           void *userdata);

int bgp_node_monitor_start(node_t *node);
int bgp_node_monitor_stop(node_t *node);
int bgp_node_monitor_subscribe(node_t *node,
                               const char *afi,
                               const char *safi,
                               bgp_route_update_notify_cb callback,
                               void *userdata);

int bgp_node_monitor_subscribe_af(node_t *node,
                                  int afi,
                                  int safi,
                                  bgp_route_update_notify_cb callback,
                                  void *userdata);

void 
bgp_rtm_route_install(node_t *node, const bgp_route_info_t *route);

void 
bgp_rtm_route_uninstall(node_t *node, const bgp_route_info_t *route);

void
bgp_rtm_vpn_route_install(node_t *node, const bgp_route_info_t *route);

void
bgp_rtm_vpn_route_uninstall(node_t *node, const bgp_route_info_t *route);

void 
bgp_schedule_route_processing_job (node_t *node, 
                                  const bgp_route_info_t *route, 
                                  bool is_add);

void
bgp_schedule_vpn_route_processing_job(node_t *node,
                                      const bgp_route_info_t *route,
                                      bool is_add);

void
bgp_schedule_evpn_route_processing_job(node_t *node,
                                       const bgp_route_info_t *route,
                                       bool is_add);

bool
bgp_route_is_af_enabled_on_any_neighbor(node_t *node, int afi, int safi);

void
bgp_route_withdraw_originated_routes(node_t *node, int afi, int safi);

void
bgp_rtm_evpn_route_install(node_t *node, const bgp_route_info_t *route);

void
bgp_rtm_evpn_route_uninstall(node_t *node, const bgp_route_info_t *route);

void
bgp_route_processing_pkt_q_init(node_t *node, bgp_inst_t *bgp);

struct evpn_rt_;
typedef struct evpn_rt_ evpn_rt_t;
struct rd_;
typedef struct rd_ rd_t;
struct rt_;
typedef struct rt_ rt_t;

int
bgp_evpn_type2_route_update(node_t *node,
                            rd_t *rd,
                            rt_t *export_rt,
                            evpn_rt_t *evpn_rt,
                            bool is_delete);

#endif  /* BGP_ROUTE_H_ */
