#include "sf_gobgp_grpc_client.h"

#include <cstring>
#include <string>

#include "gobgp-grpc/gobgp_grpc.h"

struct sf_gobgp_grpc_client {
    gobgp_client::GoBgpGrpcClient client;
};

static sf_gobgp_rpc_result_t
to_c_result(const gobgp_client::RpcResult& result)
{
    sf_gobgp_rpc_result_t out = {};
    out.ok = result.ok;
    out.code = static_cast<int>(result.code);
    std::strncpy(out.message, result.message.c_str(), sizeof(out.message) - 1);
    return out;
}

extern "C" sf_gobgp_grpc_client_t *
sf_gobgp_grpc_client_create(const char *endpoint)
{
    const char *ep = (endpoint != nullptr) ? endpoint : "127.0.0.1:50051";
    return new sf_gobgp_grpc_client{gobgp_client::GoBgpGrpcClient(ep)};
}

extern "C" void
sf_gobgp_grpc_client_destroy(sf_gobgp_grpc_client_t *client)
{
    delete client;
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_add_peer(sf_gobgp_grpc_client_t *client,
                  const char *neighbor_address,
                  uint32_t peer_asn,
                  const char *local_address,
                  bool enable_ipv4,
                  bool enable_evpn)
{
    if (client == nullptr || neighbor_address == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    const std::string local = (local_address != nullptr) ? local_address : "";
    return to_c_result(client->client.AddPeer(neighbor_address, peer_asn, local,
                                               enable_ipv4, enable_evpn));
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_remove_peer(sf_gobgp_grpc_client_t *client,
                     const char *neighbor_address)
{
    if (client == nullptr || neighbor_address == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    return to_c_result(client->client.RemovePeer(neighbor_address));
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_enable_ipv4(sf_gobgp_grpc_client_t *client,
                     const char *neighbor_address,
                     uint32_t peer_asn,
                     const char *local_address)
{
    if (client == nullptr || neighbor_address == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    const std::string local = (local_address != nullptr) ? local_address : "";
    return to_c_result(
        client->client.EnableIpv4(neighbor_address, peer_asn, local));
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_disable_ipv4(sf_gobgp_grpc_client_t *client,
                      const char *neighbor_address,
                      uint32_t peer_asn,
                      const char *local_address)
{
    if (client == nullptr || neighbor_address == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    const std::string local = (local_address != nullptr) ? local_address : "";
    return to_c_result(
        client->client.DisableIpv4(neighbor_address, peer_asn, local));
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_enable_evpn(sf_gobgp_grpc_client_t *client,
                     const char *neighbor_address,
                     uint32_t peer_asn,
                     const char *local_address)
{
    if (client == nullptr || neighbor_address == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    const std::string local = (local_address != nullptr) ? local_address : "";
    return to_c_result(
        client->client.EnableEvpn(neighbor_address, peer_asn, local));
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_disable_evpn(sf_gobgp_grpc_client_t *client,
                      const char *neighbor_address,
                      uint32_t peer_asn,
                      const char *local_address)
{
    if (client == nullptr || neighbor_address == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    const std::string local = (local_address != nullptr) ? local_address : "";
    return to_c_result(
        client->client.DisableEvpn(neighbor_address, peer_asn, local));
}
