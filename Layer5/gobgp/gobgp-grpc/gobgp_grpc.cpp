#include "gobgp_grpc.h"

#include <chrono>

namespace gobgp_client {
namespace {
constexpr int kRpcDeadlineSeconds = 5;
}

GoBgpGrpcClient::GoBgpGrpcClient(const std::string& endpoint)
    : channel_(grpc::CreateChannel(
          endpoint, grpc::InsecureChannelCredentials())),
      stub_(api::GoBgpService::NewStub(channel_))
{
}

RpcResult GoBgpGrpcClient::FromStatus(const grpc::Status& status)
{
    return {status.ok(), status.error_code(), status.error_message()};
}

void GoBgpGrpcClient::SetDeadline(grpc::ClientContext* context)
{
    context->set_deadline(
        std::chrono::system_clock::now() +
        std::chrono::seconds(kRpcDeadlineSeconds));
}

void GoBgpGrpcClient::PopulateBasePeer(
    api::Peer* peer,
    const std::string& neighbor_address,
    std::uint32_t peer_asn,
    const std::string& local_address)
{
    api::PeerConf* conf = peer->mutable_conf();
    conf->set_neighbor_address(neighbor_address);
    conf->set_peer_asn(peer_asn);

    if (!local_address.empty()) {
        peer->mutable_transport()->set_local_address(local_address);
    }
}

void GoBgpGrpcClient::AppendFamily(api::Peer* peer,
                                   AddressFamily family,
                                   bool enabled)
{
    api::AfiSafi* afi_safi = peer->add_afi_safis();
    api::AfiSafiConfig* config = afi_safi->mutable_config();
    api::Family* proto_family = config->mutable_family();

    if (family == AddressFamily::kIpv4Unicast) {
        proto_family->set_afi(api::Family::AFI_IP);
        proto_family->set_safi(api::Family::SAFI_UNICAST);
    } else {
        proto_family->set_afi(api::Family::AFI_L2VPN);
        proto_family->set_safi(api::Family::SAFI_EVPN);
    }

    config->set_enabled(enabled);
}

RpcResult GoBgpGrpcClient::AddPeer(
    const std::string& neighbor_address,
    std::uint32_t peer_asn,
    const std::string& local_address,
    bool enable_ipv4,
    bool enable_evpn)
{
    api::AddPeerRequest request;
    api::AddPeerResponse response;

    api::Peer* peer = request.mutable_peer();
    PopulateBasePeer(peer, neighbor_address, peer_asn, local_address);

    if (enable_ipv4) {
        AppendFamily(peer, AddressFamily::kIpv4Unicast, true);
    }
    if (enable_evpn) {
        AppendFamily(peer, AddressFamily::kEvpn, true);
    }

    grpc::ClientContext context;
    SetDeadline(&context);
    return FromStatus(stub_->AddPeer(&context, request, &response));
}

RpcResult GoBgpGrpcClient::RemovePeer(
    const std::string& neighbor_address)
{
    api::DeletePeerRequest request;
    api::DeletePeerResponse response;
    request.set_address(neighbor_address);

    grpc::ClientContext context;
    SetDeadline(&context);
    return FromStatus(stub_->DeletePeer(&context, request, &response));
}

RpcResult GoBgpGrpcClient::EnableAddressFamily(
    const std::string& neighbor_address,
    std::uint32_t peer_asn,
    const std::string& local_address,
    AddressFamily family)
{
    api::UpdatePeerRequest request;
    api::UpdatePeerResponse response;

    api::Peer* peer = request.mutable_peer();
    PopulateBasePeer(peer, neighbor_address, peer_asn, local_address);
    AppendFamily(peer, family, true);
    request.set_do_soft_reset_in(true);

    grpc::ClientContext context;
    SetDeadline(&context);
    return FromStatus(stub_->UpdatePeer(&context, request, &response));
}

RpcResult GoBgpGrpcClient::DisableAddressFamily(
    const std::string& neighbor_address,
    std::uint32_t peer_asn,
    const std::string& local_address,
    AddressFamily family)
{
    api::UpdatePeerRequest request;
    api::UpdatePeerResponse response;

    api::Peer* peer = request.mutable_peer();
    PopulateBasePeer(peer, neighbor_address, peer_asn, local_address);
    AppendFamily(peer, family, false);
    request.set_do_soft_reset_in(true);

    grpc::ClientContext context;
    SetDeadline(&context);
    return FromStatus(stub_->UpdatePeer(&context, request, &response));
}

RpcResult GoBgpGrpcClient::EnableIpv4(
    const std::string& neighbor_address,
    std::uint32_t peer_asn,
    const std::string& local_address)
{
    return EnableAddressFamily(neighbor_address, peer_asn, local_address,
                               AddressFamily::kIpv4Unicast);
}

RpcResult GoBgpGrpcClient::DisableIpv4(
    const std::string& neighbor_address,
    std::uint32_t peer_asn,
    const std::string& local_address)
{
    return DisableAddressFamily(neighbor_address, peer_asn, local_address,
                                AddressFamily::kIpv4Unicast);
}

RpcResult GoBgpGrpcClient::EnableEvpn(
    const std::string& neighbor_address,
    std::uint32_t peer_asn,
    const std::string& local_address)
{
    return EnableAddressFamily(neighbor_address, peer_asn, local_address,
                               AddressFamily::kEvpn);
}

RpcResult GoBgpGrpcClient::DisableEvpn(
    const std::string& neighbor_address,
    std::uint32_t peer_asn,
    const std::string& local_address)
{
    return DisableAddressFamily(neighbor_address, peer_asn, local_address,
                                AddressFamily::kEvpn);
}

}  // namespace gobgp_client
