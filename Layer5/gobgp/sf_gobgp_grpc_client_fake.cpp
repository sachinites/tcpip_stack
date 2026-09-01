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
