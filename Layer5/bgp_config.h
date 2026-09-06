#ifndef BGP_CONFIG_H_
#define BGP_CONFIG_H_

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include "gobgp/sf_gobgp_grpc_client.h"

#define BGP_ROUTER_ID_LEN 16
#define BGP_MONITOR_MAX_SUBS 16

#pragma pack(push, 8)

typedef struct bgp_neighbor_config_ {
    char neighbor_address[64];
    uint32_t peer_asn;
    bool configured;
    bool ipv4_unicast;
    bool ipv4_vpn;
} bgp_neighbor_config_t;

typedef void (*bgp_monitor_notify_cb)(const void *route_info,
                                      bool is_withdraw,
                                      void *userdata);

typedef struct bgp_monitor_sub_ {
    int afi;       /* wire AFI: 1=ipv4, 2=ipv6, -1=any */
    int safi;      /* wire SAFI: 1=unicast, 128=mpls-vpn, 70=evpn, -1=any */
    bgp_monitor_notify_cb callback;
    void *userdata;
} bgp_monitor_sub_t;

typedef struct bgp_monitor_ctx_ {
    pthread_t thread;
    bool running;
    sf_gobgp_watch_handle_t *watch_handle;
    bgp_monitor_sub_t subs[BGP_MONITOR_MAX_SUBS];
    int num_subs;
    pthread_mutex_t lock;
} bgp_monitor_ctx_t;

typedef struct bgp_node_config_ {
    bool started;
    uint32_t local_asn;
    char router_id[BGP_ROUTER_ID_LEN];
    bgp_neighbor_config_t neighbors[SF_GOBGP_MAX_PEERS];
    int num_neighbors;
    bgp_monitor_ctx_t monitor;
} bgp_node_config_t;

#pragma pack(pop)

#endif  /* BGP_CONFIG_H_ */
