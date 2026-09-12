#ifndef GOBGP_GRPC_H_
#define GOBGP_GRPC_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <grpcpp/grpcpp.h>
#include "api/gobgp.grpc.pb.h"

namespace gobgp_client {

enum class AddressFamily {
    kIpv4Unicast,
    kIpv4Vpn,
    kEvpn
};

enum class BgpAfi {
    kIpv4,
    kIpv6
};

enum class BgpSafi {
    kUnicast,
    kMplsVpn,
    kEvpn
};

struct BgpRouteParams {
    std::string prefix;
    std::string nexthop;
    std::string rd;
    std::string rt;
    std::uint32_t med = 0;
    std::uint32_t local_pref = 0;
    bool med_present = false;
    bool local_pref_present = false;
    std::uint32_t l3_vpn_label = 0;
    bool l3_vpn_label_present = false;
    std::string mac_addr;
    std::uint32_t evpn_label = 0;
    bool evpn_label_present = false;
    BgpAfi afi = BgpAfi::kIpv4;
    BgpSafi safi = BgpSafi::kUnicast;
};

struct BgpRouteInfo {
    std::string prefix;
    std::string nexthop;
    std::string rd;
    std::string rt;
    std::uint32_t med = 0;
    std::uint32_t local_pref = 0;
    bool med_present = false;
    bool local_pref_present = false;
    std::uint32_t l3_vpn_label = 0;
    bool l3_vpn_label_present = false;
    bool best = false;
    bool is_from_external = false;
    BgpAfi afi = BgpAfi::kIpv4;
    BgpSafi safi = BgpSafi::kUnicast;
};

using BgpRouteWalkCallback =
    std::function<int(const BgpRouteInfo& route)>;

struct BgpRouteUpdate {
    BgpRouteInfo route;
    bool is_withdraw = false;
};

using BgpRouteUpdateCallback =
    std::function<void(const BgpRouteUpdate& update)>;

struct WatchHandle {
    grpc::ClientContext* context = nullptr;
};

struct RpcResult {
    bool ok;
    grpc::StatusCode code;
    std::string message;
};

struct PeerInfo {
    std::string neighbor_address;
    std::uint32_t peer_asn;
    std::string router_id;
    int session_state;
    std::string description;
};

struct BgpGlobalInfo {
    std::uint32_t asn;
    std::string router_id;
    std::int32_t listen_port;
};

class GoBgpGrpcClient {
public:
    explicit GoBgpGrpcClient(
        const std::string& endpoint = "127.0.0.1:50051");

    RpcResult StartBgp(std::uint32_t asn,
                       const std::string& router_id,
                       std::int32_t listen_port = -1);

    RpcResult StopBgp();

    RpcResult GetBgp(BgpGlobalInfo* info);

    RpcResult ListPeers(std::vector<PeerInfo>* peers);

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

    RpcResult EnableIpv4Vpn(const std::string& neighbor_address,
                            std::uint32_t peer_asn,
                            const std::string& local_address);

    RpcResult DisableIpv4Vpn(const std::string& neighbor_address,
                             std::uint32_t peer_asn,
                             const std::string& local_address);

    RpcResult EnableEvpn(const std::string& neighbor_address,
                         std::uint32_t peer_asn,
                         const std::string& local_address);

    RpcResult DisableEvpn(const std::string& neighbor_address,
                          std::uint32_t peer_asn,
                          const std::string& local_address);

    RpcResult ApplyNeighborAddressFamilies(
        const std::string& neighbor_address,
        std::uint32_t peer_asn,
        const std::string& local_address,
        bool ipv4_unicast,
        bool ipv4_vpn,
        bool evpn);

    RpcResult AddRoute(const BgpRouteParams& params);

    RpcResult DeleteRoute(const BgpRouteParams& params);

    RpcResult IsAddressFamilyEnabledOnAnyPeer(BgpAfi afi,
                                              BgpSafi safi,
                                              bool* enabled);

    RpcResult WalkRoutes(BgpAfi afi,
                         BgpSafi safi,
                         const BgpRouteWalkCallback& callback);

    RpcResult WatchRoutes(bool init_rib,
                          const BgpRouteUpdateCallback& callback,
                          WatchHandle* handle);

    static void CancelWatch(WatchHandle* handle);

private:
    static void ExtractAfiSafi(const api::Path& path, BgpAfi* afi, BgpSafi* safi);
    static RpcResult FromStatus(const grpc::Status& status);
    static void SetDeadline(grpc::ClientContext* context);
    static void PopulateBasePeer(api::Peer* peer,
                                 const std::string& neighbor_address,
                                 std::uint32_t peer_asn,
                                 const std::string& local_address);
    static void AppendFamily(api::Peer* peer,
                             AddressFamily family,
                             bool enabled);
    static void SetFamily(api::Family* family, BgpAfi afi, BgpSafi safi);
    static api::Path BuildPath(const BgpRouteParams& params, bool withdraw);
    static void FillRouteInfo(const api::Path& path,
                              const std::string& dest_prefix,
                              BgpAfi afi,
                              BgpSafi safi,
                              BgpRouteInfo* info);

    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<api::GoBgpService::Stub> stub_;
};

}  // namespace gobgp_client

#endif  // GOBGP_GRPC_H_
