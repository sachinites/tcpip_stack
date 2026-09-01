#ifndef GOBGP_GRPC_H_
#define GOBGP_GRPC_H_

#include <cstdint>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include "api/gobgp.grpc.pb.h"

namespace gobgp_client {

enum class AddressFamily {
    kIpv4Unicast,
    kEvpn
};

struct RpcResult {
    bool ok;
    grpc::StatusCode code;
    std::string message;
};

class GoBgpGrpcClient {
public:
    explicit GoBgpGrpcClient(
        const std::string& endpoint = "127.0.0.1:50051");

    RpcResult AddPeer(const std::string& neighbor_address,
                      std::uint32_t peer_asn,
                      const std::string& local_address,
                      bool enable_ipv4,
                      bool enable_evpn);

    RpcResult RemovePeer(const std::string& neighbor_address);

    RpcResult EnableAddressFamily(const std::string& neighbor_address,
                                  std::uint32_t peer_asn,
                                  const std::string& local_address,
                                  AddressFamily family);

    RpcResult DisableAddressFamily(const std::string& neighbor_address,
                                   std::uint32_t peer_asn,
                                   const std::string& local_address,
                                   AddressFamily family);

    RpcResult EnableIpv4(const std::string& neighbor_address,
                         std::uint32_t peer_asn,
                         const std::string& local_address);

    RpcResult DisableIpv4(const std::string& neighbor_address,
                          std::uint32_t peer_asn,
                          const std::string& local_address);

    RpcResult EnableEvpn(const std::string& neighbor_address,
                         std::uint32_t peer_asn,
                         const std::string& local_address);

    RpcResult DisableEvpn(const std::string& neighbor_address,
                          std::uint32_t peer_asn,
                          const std::string& local_address);

private:
    static RpcResult FromStatus(const grpc::Status& status);
    static void SetDeadline(grpc::ClientContext* context);
    static void PopulateBasePeer(api::Peer* peer,
                                 const std::string& neighbor_address,
                                 std::uint32_t peer_asn,
                                 const std::string& local_address);
    static void AppendFamily(api::Peer* peer,
                             AddressFamily family,
                             bool enabled);

    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<api::GoBgpService::Stub> stub_;
};

}  // namespace gobgp_client

#endif  // GOBGP_GRPC_H_
