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

sf_gobgp_grpc_client_t *sf_gobgp_grpc_client_create(const char *endpoint);
void sf_gobgp_grpc_client_destroy(sf_gobgp_grpc_client_t *client);

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

sf_gobgp_rpc_result_t sf_gobgp_enable_evpn(sf_gobgp_grpc_client_t *client,
                                           const char *neighbor_address,
                                           uint32_t peer_asn,
                                           const char *local_address);

sf_gobgp_rpc_result_t sf_gobgp_disable_evpn(sf_gobgp_grpc_client_t *client,
                                            const char *neighbor_address,
                                            uint32_t peer_asn,
                                            const char *local_address);

#ifdef __cplusplus
}
#endif

#endif  // SF_GOBGP_GRPC_CLIENT_H_
