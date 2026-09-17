#ifndef BGP_ROUTE_H_
#define BGP_ROUTE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bgp_rib/bgp_rib_types.h"

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
    char pe_addr[16];
    uint32_t evpn_label;
    bool evpn_label_present;
    uint8_t evpn_route_type;
    uint32_t eth_tag_id;
    uint32_t pmsi_label;
    bool pmsi_label_present;
} bgp_route_params_t;

typedef struct bgp_unified_rt_ {
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
    int afi;
    int safi;
    uint16_t nlri_wire_len;
    uint8_t nlri_wire[BGP_NLRI_WIRE_MAX];
    uint8_t ext_comm_count;
    bgp_rib_ext_comm_t ext_comms[BGP_RIB_EXT_COMM_MAX];
    uint32_t evpn_label1;
    bool evpn_label1_present;
    bool evpn_label1_from_ext_comm;
    uint32_t mac_mobility_seq;
    bool mac_mobility_seq_present;
    uint32_t pmsi_label;
    bool pmsi_label_present;
    uint8_t pmsi_tunnel_type;
    uint16_t tunnel_encap_type;
    bool tunnel_encap_present;
} bgp_unified_rt_t;

typedef int (*bgp_route_walk_cb)(const bgp_unified_rt_t *route, void *userdata);

int bgp_node_add_route(node_t *node, const bgp_route_params_t *params);
int bgp_node_delete_route(node_t *node, const bgp_route_params_t *params);
int bgp_node_walk_routes(node_t *node,
                         const char *afi,
                         const char *safi,
                         bgp_route_walk_cb callback,
                         void *userdata);

typedef void (*bgp_route_update_notify_cb)(const bgp_unified_rt_t *route,
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
bgp_monitor_recv_global_rib_cbk(const bgp_unified_rt_t *route,
                                bool is_withdraw,
                                void *userdata);

void 
bgp_rtm_route_install(node_t *node, const bgp_unified_rt_t *route);

void 
bgp_rtm_route_uninstall(node_t *node, const bgp_unified_rt_t *route);

void 
bgp_schedule_route_processing_job (node_t *node, 
                                  const bgp_unified_rt_t *route, 
                                  bool is_add);

/* Shared helpers for AFI/SAFI-specific BGP modules (vpnv4_bgp, evpn_bgp). */
struct rt_;
typedef struct rt_ rt_t;

int
bgp_route_apply_to_gobgp(node_t *node,
                         const bgp_route_params_t *params,
                         int sf_afi,
                         int sf_safi,
                         bool is_delete);

bool
bgp_route_parse_rt_string(const char *rt_str, rt_t *out);

bool
bgp_route_is_af_enabled_on_any_neighbor(node_t *node, int afi, int safi);

void
bgp_route_withdraw_originated_routes(node_t *node, int afi, int safi);

void
bgp_route_processing_pkt_q_init(node_t *node, bgp_inst_t *bgp);

#endif  /* BGP_ROUTE_H_ */
