#include "sf_gobgp_grpc_client.h"

#include <cstring>

/* Provide the real implementation in sf_gobgp_grpc_client.cpp */

static sf_gobgp_rpc_result_t
fake_result()
{
    sf_gobgp_rpc_result_t result = {};
    result.ok = false;
    result.code = -1;
    std::strncpy(result.message, "GoBGP gRPC support is not linked",
                 sizeof(result.message) - 1);
    return result;
}

__attribute__((weak))
sf_gobgp_grpc_client_t *
sf_gobgp_grpc_client_create(const char *endpoint __attribute__((unused)))
{
    return nullptr;
}

__attribute__((weak))
void
sf_gobgp_grpc_client_destroy(sf_gobgp_grpc_client_t *client
                             __attribute__((unused)))
{
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_start_bgp(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                    uint32_t asn __attribute__((unused)),
                    const char *router_id __attribute__((unused)),
                    int32_t listen_port __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_stop_bgp(sf_gobgp_grpc_client_t *client __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_get_bgp(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                  sf_gobgp_global_info_t *info __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_list_peers(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                    sf_gobgp_peer_info_t *peers __attribute__((unused)),
                    int max_peers __attribute__((unused)),
                    int *num_peers __attribute__((unused)))
{
    if (num_peers) *num_peers = 0;
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_add_peer(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                  const char *neighbor_address __attribute__((unused)),
                  uint32_t peer_asn __attribute__((unused)),
                  const char *local_address __attribute__((unused)),
                  bool enable_ipv4 __attribute__((unused)),
                  bool enable_evpn __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_remove_peer(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                     const char *neighbor_address __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_apply_neighbor_address_families(
    sf_gobgp_grpc_client_t *client __attribute__((unused)),
    const char *neighbor_address __attribute__((unused)),
    uint32_t peer_asn __attribute__((unused)),
    const char *local_address __attribute__((unused)),
    bool ipv4_unicast __attribute__((unused)),
    bool ipv4_vpn __attribute__((unused)),
    bool evpn __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_enable_ipv4(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                     const char *neighbor_address __attribute__((unused)),
                     uint32_t peer_asn __attribute__((unused)),
                     const char *local_address __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_disable_ipv4(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                      const char *neighbor_address __attribute__((unused)),
                      uint32_t peer_asn __attribute__((unused)),
                      const char *local_address __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_enable_ipv4_vpn(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                         const char *neighbor_address __attribute__((unused)),
                         uint32_t peer_asn __attribute__((unused)),
                         const char *local_address __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_disable_ipv4_vpn(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                          const char *neighbor_address __attribute__((unused)),
                          uint32_t peer_asn __attribute__((unused)),
                          const char *local_address __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_enable_evpn(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                     const char *neighbor_address __attribute__((unused)),
                     uint32_t peer_asn __attribute__((unused)),
                     const char *local_address __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_disable_evpn(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                      const char *neighbor_address __attribute__((unused)),
                      uint32_t peer_asn __attribute__((unused)),
                      const char *local_address __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_is_address_family_enabled(sf_gobgp_grpc_client_t *client
                                   __attribute__((unused)),
                                   int afi __attribute__((unused)),
                                   int safi __attribute__((unused)),
                                   bool *enabled_out)
{
    if (enabled_out) {
        *enabled_out = false;
    }
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_add_route(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                   const sf_gobgp_route_params_t *params __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_delete_route(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                      const sf_gobgp_route_params_t *params __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_walk_routes(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                     int afi __attribute__((unused)),
                     int safi __attribute__((unused)),
                     sf_gobgp_route_walk_cb callback __attribute__((unused)),
                     void *userdata __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
sf_gobgp_watch_handle_t *
sf_gobgp_watch_handle_create(void)
{
    return nullptr;
}

__attribute__((weak))
void
sf_gobgp_watch_handle_destroy(sf_gobgp_watch_handle_t *handle
                              __attribute__((unused)))
{
}

__attribute__((weak))
sf_gobgp_rpc_result_t
sf_gobgp_watch_routes(sf_gobgp_grpc_client_t *client __attribute__((unused)),
                      bool init_rib __attribute__((unused)),
                      sf_gobgp_route_update_cb callback __attribute__((unused)),
                      void *userdata __attribute__((unused)),
                      sf_gobgp_watch_handle_t *handle __attribute__((unused)))
{
    return fake_result();
}

__attribute__((weak))
void
sf_gobgp_watch_cancel(sf_gobgp_watch_handle_t *handle __attribute__((unused)))
{
}
