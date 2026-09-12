#ifndef SF_GOBGP_GRPC_CLIENT_H_
#define SF_GOBGP_GRPC_CLIENT_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sf_gobgp_grpc_client sf_gobgp_grpc_client_t;

typedef struct sf_gobgp_rpc_result {
    bool ok;
    int code;
    char message[256];
} sf_gobgp_rpc_result_t;

#define SF_GOBGP_MAX_PEERS 64

typedef struct sf_gobgp_peer_info {
    char neighbor_address[64];
    uint32_t peer_asn;
    char router_id[64];
    int session_state;
    char description[128];
} sf_gobgp_peer_info_t;

typedef struct sf_gobgp_global_info {
    uint32_t asn;
    char router_id[64];
    int32_t listen_port;
} sf_gobgp_global_info_t;

sf_gobgp_grpc_client_t *sf_gobgp_grpc_client_create(const char *endpoint);
void sf_gobgp_grpc_client_destroy(sf_gobgp_grpc_client_t *client);

sf_gobgp_rpc_result_t sf_gobgp_start_bgp(sf_gobgp_grpc_client_t *client,
                                          uint32_t asn,
                                          const char *router_id,
                                          int32_t listen_port);

sf_gobgp_rpc_result_t sf_gobgp_stop_bgp(sf_gobgp_grpc_client_t *client);

sf_gobgp_rpc_result_t sf_gobgp_get_bgp(sf_gobgp_grpc_client_t *client,
                                        sf_gobgp_global_info_t *info);

sf_gobgp_rpc_result_t sf_gobgp_list_peers(sf_gobgp_grpc_client_t *client,
                                           sf_gobgp_peer_info_t *peers,
                                           int max_peers,
                                           int *num_peers);

sf_gobgp_rpc_result_t sf_gobgp_add_peer(sf_gobgp_grpc_client_t *client,
                                        const char *neighbor_address,
                                        uint32_t peer_asn,
                                        const char *local_address,
                                        bool enable_ipv4,
                                        bool enable_evpn);

sf_gobgp_rpc_result_t sf_gobgp_remove_peer(sf_gobgp_grpc_client_t *client,
                                           const char *neighbor_address);

sf_gobgp_rpc_result_t sf_gobgp_enable_ipv4(sf_gobgp_grpc_client_t *client,
                                            const char *neighbor_address,
                                            uint32_t peer_asn,
                                            const char *local_address);

sf_gobgp_rpc_result_t sf_gobgp_disable_ipv4(sf_gobgp_grpc_client_t *client,
                                            const char *neighbor_address,
                                            uint32_t peer_asn,
                                            const char *local_address);

sf_gobgp_rpc_result_t sf_gobgp_enable_ipv4_vpn(sf_gobgp_grpc_client_t *client,
                                               const char *neighbor_address,
                                               uint32_t peer_asn,
                                               const char *local_address);

sf_gobgp_rpc_result_t sf_gobgp_disable_ipv4_vpn(sf_gobgp_grpc_client_t *client,
                                                const char *neighbor_address,
                                                uint32_t peer_asn,
                                                const char *local_address);

sf_gobgp_rpc_result_t sf_gobgp_enable_evpn(sf_gobgp_grpc_client_t *client,
                                           const char *neighbor_address,
                                           uint32_t peer_asn,
                                           const char *local_address);

sf_gobgp_rpc_result_t sf_gobgp_disable_evpn(sf_gobgp_grpc_client_t *client,
                                            const char *neighbor_address,
                                            uint32_t peer_asn,
                                            const char *local_address);

sf_gobgp_rpc_result_t
sf_gobgp_apply_neighbor_address_families(
    sf_gobgp_grpc_client_t *client,
    const char *neighbor_address,
    uint32_t peer_asn,
    const char *local_address,
    bool ipv4_unicast,
    bool ipv4_vpn,
    bool evpn);

typedef struct sf_gobgp_route_params {
    char prefix[64];
    char nexthop[64];
    char rd[32];
    char rt[32];
    uint32_t med;
    uint32_t local_pref;
    bool med_present;
    bool local_pref_present;
    uint32_t l3_vpn_label;
    bool l3_vpn_label_present;
    char mac_addr[32];
    uint32_t evpn_label;
    bool evpn_label_present;
    int afi;
    int safi;
} sf_gobgp_route_params_t;

typedef struct sf_gobgp_route_info {
    char prefix[64];
    char nexthop[64];
    char rd[32];
    char rt[32];
    uint32_t med;
    uint32_t local_pref;
    bool med_present;
    bool local_pref_present;
    uint32_t l3_vpn_label;
    bool l3_vpn_label_present;
    bool best;
    int afi;
    int safi;
    bool is_from_external;
} sf_gobgp_route_info_t;

typedef int (*sf_gobgp_route_walk_cb)(const sf_gobgp_route_info_t *route,
                                      void *userdata);

sf_gobgp_rpc_result_t sf_gobgp_add_route(sf_gobgp_grpc_client_t *client,
                                         const sf_gobgp_route_params_t *params);

sf_gobgp_rpc_result_t sf_gobgp_delete_route(sf_gobgp_grpc_client_t *client,
                                            const sf_gobgp_route_params_t *params);

sf_gobgp_rpc_result_t
sf_gobgp_is_address_family_enabled(sf_gobgp_grpc_client_t *client,
                                   int afi,
                                   int safi,
                                   bool *enabled_out);

sf_gobgp_rpc_result_t sf_gobgp_walk_routes(sf_gobgp_grpc_client_t *client,
                                           int afi,
                                           int safi,
                                           sf_gobgp_route_walk_cb callback,
                                           void *userdata);

typedef struct sf_gobgp_route_update {
    sf_gobgp_route_info_t route;
    bool is_withdraw;
} sf_gobgp_route_update_t;

typedef void (*sf_gobgp_route_update_cb)(const sf_gobgp_route_update_t *update,
                                         void *userdata);

typedef struct sf_gobgp_watch_handle sf_gobgp_watch_handle_t;

sf_gobgp_watch_handle_t *sf_gobgp_watch_handle_create(void);
void sf_gobgp_watch_handle_destroy(sf_gobgp_watch_handle_t *handle);

sf_gobgp_rpc_result_t sf_gobgp_watch_routes(sf_gobgp_grpc_client_t *client,
                                            bool init_rib,
                                            sf_gobgp_route_update_cb callback,
                                            void *userdata,
                                            sf_gobgp_watch_handle_t *handle);

void sf_gobgp_watch_cancel(sf_gobgp_watch_handle_t *handle);

#ifdef __cplusplus
}
#endif

#endif  // SF_GOBGP_GRPC_CLIENT_H_
