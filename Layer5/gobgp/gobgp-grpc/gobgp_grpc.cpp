#include "gobgp_grpc.h"

#include <chrono>
#include <cstdlib>
#include <sstream>

#include "api/attribute.pb.h"
#include "api/common.pb.h"
#include "api/extcom.pb.h"
#include "api/nlri.pb.h"

namespace gobgp_client {
namespace {
constexpr int kRpcDeadlineSeconds = 5;
constexpr int kListPathDeadlineSeconds = 30;
constexpr std::uint32_t kEcSubtypeRouteTarget = 0x02;

bool ParsePrefixCidr(const std::string& cidr,
                     std::string* addr,
                     std::uint32_t* prefix_len)
{
    const std::size_t slash = cidr.find('/');
    if (slash == std::string::npos || slash == 0 || slash == cidr.size() - 1) {
        return false;
    }

    *addr = cidr.substr(0, slash);
    *prefix_len = static_cast<std::uint32_t>(std::strtoul(
        cidr.substr(slash + 1).c_str(), nullptr, 10));
    return true;
}

bool ParseColonSeparatedValue(const std::string& value,
                              std::string* left,
                              std::uint32_t* right)
{
    const std::size_t colon = value.find(':');
    if (colon == std::string::npos || colon == 0 ||
        colon == value.size() - 1) {
        return false;
    }

    *left = value.substr(0, colon);
    *right = static_cast<std::uint32_t>(std::strtoul(
        value.substr(colon + 1).c_str(), nullptr, 10));
    return true;
}

bool LooksLikeIpv4(const std::string& value)
{
    return value.find('.') != std::string::npos;
}

void SetRouteDistinguisher(const std::string& rd_str,
                           api::RouteDistinguisher* rd)
{
    std::string left;
    std::uint32_t right = 0;

    if (!ParseColonSeparatedValue(rd_str, &left, &right)) {
        return;
    }

    if (LooksLikeIpv4(left)) {
        api::RouteDistinguisherIPAddress* ip = rd->mutable_ip_address();
        ip->set_admin(left);
        ip->set_assigned(right);
        return;
    }

    const unsigned long admin = std::strtoul(left.c_str(), nullptr, 10);
    if (admin > 0xFFFFUL) {
        api::RouteDistinguisherFourOctetASN* asn = rd->mutable_four_octet_asn();
        asn->set_admin(static_cast<std::uint32_t>(admin));
        asn->set_assigned(right);
        return;
    }

    api::RouteDistinguisherTwoOctetASN* asn = rd->mutable_two_octet_asn();
    asn->set_admin(static_cast<std::uint32_t>(admin));
    asn->set_assigned(right);
}

void SetRouteTargetCommunity(const std::string& rt_str,
                             api::ExtendedCommunity* community)
{
    std::string left;
    std::uint32_t right = 0;

    if (!ParseColonSeparatedValue(rt_str, &left, &right)) {
        return;
    }

    if (LooksLikeIpv4(left)) {
        api::IPv4AddressSpecificExtended* rt =
            community->mutable_ipv4_address_specific();
        rt->set_is_transitive(true);
        rt->set_sub_type(kEcSubtypeRouteTarget);
        rt->set_address(left);
        rt->set_local_admin(right);
        return;
    }

    const unsigned long admin = std::strtoul(left.c_str(), nullptr, 10);
    if (admin > 0xFFFFUL) {
        api::FourOctetAsSpecificExtended* rt =
            community->mutable_four_octet_as_specific();
        rt->set_is_transitive(true);
        rt->set_sub_type(kEcSubtypeRouteTarget);
        rt->set_asn(static_cast<std::uint32_t>(admin));
        rt->set_local_admin(right);
        return;
    }

    api::TwoOctetAsSpecificExtended* rt =
        community->mutable_two_octet_as_specific();
    rt->set_is_transitive(true);
    rt->set_sub_type(kEcSubtypeRouteTarget);
    rt->set_asn(static_cast<std::uint32_t>(admin));
    rt->set_local_admin(right);
}

std::string FormatRouteDistinguisher(const api::RouteDistinguisher& rd)
{
    if (rd.has_two_octet_asn()) {
        return std::to_string(rd.two_octet_asn().admin()) + ":" +
               std::to_string(rd.two_octet_asn().assigned());
    }
    if (rd.has_ip_address()) {
        return rd.ip_address().admin() + ":" +
               std::to_string(rd.ip_address().assigned());
    }
    if (rd.has_four_octet_asn()) {
        return std::to_string(rd.four_octet_asn().admin()) + ":" +
               std::to_string(rd.four_octet_asn().assigned());
    }
    return "";
}

std::string FormatRouteTargetCommunity(
    const api::ExtendedCommunity& community)
{
    if (community.has_two_octet_as_specific()) {
        const api::TwoOctetAsSpecificExtended& rt =
            community.two_octet_as_specific();
        if (rt.sub_type() != kEcSubtypeRouteTarget) {
            return "";
        }
        return std::to_string(rt.asn()) + ":" +
               std::to_string(rt.local_admin());
    }
    if (community.has_ipv4_address_specific()) {
        const api::IPv4AddressSpecificExtended& rt =
            community.ipv4_address_specific();
        if (rt.sub_type() != kEcSubtypeRouteTarget) {
            return "";
        }
        return rt.address() + ":" + std::to_string(rt.local_admin());
    }
    if (community.has_four_octet_as_specific()) {
        const api::FourOctetAsSpecificExtended& rt =
            community.four_octet_as_specific();
        if (rt.sub_type() != kEcSubtypeRouteTarget) {
            return "";
        }
        return std::to_string(rt.asn()) + ":" +
               std::to_string(rt.local_admin());
    }
    return "";
}
}  // namespace

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
    } else if (family == AddressFamily::kIpv4Vpn) {
        proto_family->set_afi(api::Family::AFI_IP);
        proto_family->set_safi(api::Family::SAFI_MPLS_VPN);
    } else {
        proto_family->set_afi(api::Family::AFI_L2VPN);
        proto_family->set_safi(api::Family::SAFI_EVPN);
    }

    config->set_enabled(enabled);
}

RpcResult GoBgpGrpcClient::StartBgp(
    std::uint32_t asn,
    const std::string& router_id,
    std::int32_t listen_port)
{
    api::StartBgpRequest request;
    api::StartBgpResponse response;

    api::Global* global = request.mutable_global();
    global->set_asn(asn);
    global->set_router_id(router_id);
    if (!router_id.empty()) {
        global->add_listen_addresses(router_id);
    }
    if (listen_port >= 0) {
        global->set_listen_port(listen_port);
    }

    grpc::ClientContext context;
    SetDeadline(&context);
    return FromStatus(stub_->StartBgp(&context, request, &response));
}

RpcResult GoBgpGrpcClient::StopBgp()
{
    api::StopBgpRequest request;
    api::StopBgpResponse response;

    grpc::ClientContext context;
    SetDeadline(&context);
    return FromStatus(stub_->StopBgp(&context, request, &response));
}

RpcResult GoBgpGrpcClient::GetBgp(BgpGlobalInfo* info)
{
    api::GetBgpRequest request;
    api::GetBgpResponse response;

    grpc::ClientContext context;
    SetDeadline(&context);
    grpc::Status status = stub_->GetBgp(&context, request, &response);

    if (status.ok() && info && response.has_global()) {
        const api::Global& g = response.global();
        info->asn = g.asn();
        info->router_id = g.router_id();
        info->listen_port = g.listen_port();
    }

    return FromStatus(status);
}

RpcResult GoBgpGrpcClient::ListPeers(std::vector<PeerInfo>* peers)
{
    api::ListPeerRequest request;
    request.set_enable_advertised(false);

    grpc::ClientContext context;
    SetDeadline(&context);

    std::unique_ptr<grpc::ClientReader<api::ListPeerResponse>> reader(
        stub_->ListPeer(&context, request));

    api::ListPeerResponse response;
    while (reader->Read(&response)) {
        if (!response.has_peer())
            continue;

        const api::Peer& peer = response.peer();
        PeerInfo pi{};

        if (peer.has_state()) {
            const api::PeerState& st = peer.state();
            pi.neighbor_address = st.neighbor_address();
            pi.peer_asn = st.peer_asn();
            pi.router_id = st.router_id();
            pi.session_state = static_cast<int>(st.session_state());
            pi.description = st.description();
        } else if (peer.has_conf()) {
            const api::PeerConf& conf = peer.conf();
            pi.neighbor_address = conf.neighbor_address();
            pi.peer_asn = conf.peer_asn();
        }

        if (peers)
            peers->push_back(std::move(pi));
    }

    return FromStatus(reader->Finish());
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

RpcResult GoBgpGrpcClient::ApplyNeighborAddressFamilies(
    const std::string& neighbor_address,
    std::uint32_t peer_asn,
    const std::string& local_address,
    bool ipv4_unicast,
    bool ipv4_vpn,
    bool evpn)
{
    api::UpdatePeerRequest request;
    api::UpdatePeerResponse response;

    api::Peer* peer = request.mutable_peer();
    PopulateBasePeer(peer, neighbor_address, peer_asn, local_address);

    if (ipv4_unicast) {
        AppendFamily(peer, AddressFamily::kIpv4Unicast, true);
    }
    if (ipv4_vpn) {
        AppendFamily(peer, AddressFamily::kIpv4Vpn, true);
    }
    if (evpn) {
        AppendFamily(peer, AddressFamily::kEvpn, true);
    }

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

RpcResult GoBgpGrpcClient::EnableIpv4Vpn(
    const std::string& neighbor_address,
    std::uint32_t peer_asn,
    const std::string& local_address)
{
    return EnableAddressFamily(neighbor_address, peer_asn, local_address,
                               AddressFamily::kIpv4Vpn);
}

RpcResult GoBgpGrpcClient::DisableIpv4Vpn(
    const std::string& neighbor_address,
    std::uint32_t peer_asn,
    const std::string& local_address)
{
    return DisableAddressFamily(neighbor_address, peer_asn, local_address,
                                AddressFamily::kIpv4Vpn);
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

void GoBgpGrpcClient::SetFamily(api::Family* family,
                                BgpAfi afi,
                                BgpSafi safi)
{
    if (afi == BgpAfi::kIpv6) {
        family->set_afi(api::Family::AFI_IP6);
    } else {
        family->set_afi(api::Family::AFI_IP);
    }

    switch (safi) {
        case BgpSafi::kMplsVpn:
            family->set_safi(api::Family::SAFI_MPLS_VPN);
            break;
        case BgpSafi::kEvpn:
            family->set_safi(api::Family::SAFI_EVPN);
            break;
        default:
            family->set_safi(api::Family::SAFI_UNICAST);
            break;
    }
}

api::Path GoBgpGrpcClient::BuildPath(const BgpRouteParams& params,
                                     bool withdraw)
{
    api::Path path;
    std::string addr;
    std::uint32_t prefix_len = 0;

    if (!ParsePrefixCidr(params.prefix, &addr, &prefix_len)) {
        return path;
    }

    if (withdraw) {
        path.set_is_withdraw(true);
    }

    SetFamily(path.mutable_family(), params.afi, params.safi);

    api::NLRI* nlri = path.mutable_nlri();
    if (!params.rd.empty() || params.safi == BgpSafi::kMplsVpn) {
        api::LabeledVPNIPAddressPrefix* vpn =
            nlri->mutable_labeled_vpn_ip_prefix();
        if (!params.rd.empty()) {
            SetRouteDistinguisher(params.rd, vpn->mutable_rd());
        }
        vpn->set_prefix(addr);
        vpn->set_prefix_len(prefix_len);
        if (params.l3_vpn_label_present && params.l3_vpn_label != 0) {
            vpn->add_labels(params.l3_vpn_label);
        } else {
            vpn->add_labels(0);
        }
    } else {
        api::IPAddressPrefix* prefix = nlri->mutable_prefix();
        prefix->set_prefix(addr);
        prefix->set_prefix_len(prefix_len);
    }

    if (!withdraw) {
        api::Attribute* origin_attr = path.add_pattrs();
        origin_attr->mutable_origin()->set_origin(0);

        if (!params.nexthop.empty()) {
            if (params.safi == BgpSafi::kMplsVpn) {
                api::Attribute* mp_attr = path.add_pattrs();
                api::MpReachNLRIAttribute* mp =
                    mp_attr->mutable_mp_reach();
                SetFamily(mp->mutable_family(), params.afi, params.safi);
                mp->add_next_hops(params.nexthop);
                *mp->add_nlris() = path.nlri();
            } else {
                api::Attribute* nh_attr = path.add_pattrs();
                nh_attr->mutable_next_hop()->set_next_hop(params.nexthop);
            }
        }

        if (params.med_present) {
            api::Attribute* med_attr = path.add_pattrs();
            med_attr->mutable_multi_exit_disc()->set_med(params.med);
        }

        if (params.local_pref_present) {
            api::Attribute* lp_attr = path.add_pattrs();
            lp_attr->mutable_local_pref()->set_local_pref(params.local_pref);
        }

        if (!params.rt.empty()) {
            api::Attribute* rt_attr = path.add_pattrs();
            api::ExtendedCommunity* community =
                rt_attr->mutable_extended_communities()->add_communities();
            SetRouteTargetCommunity(params.rt, community);
        }
    }

    return path;
}

void GoBgpGrpcClient::FillRouteInfo(const api::Path& path,
                                    const std::string& dest_prefix,
                                    BgpAfi afi,
                                    BgpSafi safi,
                                    BgpRouteInfo* info)
{
    if (!info) {
        return;
    }

    info->afi = afi;
    info->safi = safi;
    info->best = path.best();
    info->is_from_external = path.is_from_external();

    if (path.has_nlri()) {
        const api::NLRI& nlri = path.nlri();
        if (nlri.has_prefix()) {
            const api::IPAddressPrefix& prefix = nlri.prefix();
            info->prefix = prefix.prefix() + "/" +
                           std::to_string(prefix.prefix_len());
        } else if (nlri.has_labeled_vpn_ip_prefix()) {
            const api::LabeledVPNIPAddressPrefix& vpn =
                nlri.labeled_vpn_ip_prefix();
            info->prefix = vpn.prefix() + "/" +
                           std::to_string(vpn.prefix_len());
            if (vpn.has_rd()) {
                info->rd = FormatRouteDistinguisher(vpn.rd());
            }
            if (vpn.labels_size() > 0) {
                info->l3_vpn_label = vpn.labels(0);
                info->l3_vpn_label_present = true;
            }
        }
    }

    if (info->prefix.empty() && !dest_prefix.empty()) {
        info->prefix = dest_prefix;
    }

    for (int i = 0; i < path.pattrs_size(); ++i) {
        const api::Attribute& attr = path.pattrs(i);
        switch (attr.attr_case()) {
            case api::Attribute::kNextHop:
                info->nexthop = attr.next_hop().next_hop();
                break;
            case api::Attribute::kMpReach:
                if (attr.mp_reach().next_hops_size() > 0) {
                    info->nexthop = attr.mp_reach().next_hops(0);
                }
                break;
            case api::Attribute::kMultiExitDisc:
                info->med = attr.multi_exit_disc().med();
                info->med_present = true;
                break;
            case api::Attribute::kLocalPref:
                info->local_pref = attr.local_pref().local_pref();
                info->local_pref_present = true;
                break;
            case api::Attribute::kExtendedCommunities:
                if (info->rt.empty()) {
                    const api::ExtendedCommunitiesAttribute& ecs =
                        attr.extended_communities();
                    for (int j = 0; j < ecs.communities_size(); ++j) {
                        info->rt =
                            FormatRouteTargetCommunity(ecs.communities(j));
                        if (!info->rt.empty()) {
                            break;
                        }
                    }
                }
                break;
            default:
                break;
        }
    }
}

RpcResult GoBgpGrpcClient::AddRoute(const BgpRouteParams& params)
{
    api::AddPathRequest request;
    api::AddPathResponse response;

    request.set_table_type(api::TABLE_TYPE_GLOBAL);
    *request.mutable_path() = BuildPath(params, false);

    grpc::ClientContext context;
    SetDeadline(&context);
    return FromStatus(stub_->AddPath(&context, request, &response));
}

RpcResult GoBgpGrpcClient::DeleteRoute(const BgpRouteParams& params)
{
    api::DeletePathRequest request;
    api::DeletePathResponse response;

    request.set_table_type(api::TABLE_TYPE_GLOBAL);
    SetFamily(request.mutable_family(), params.afi, params.safi);
    *request.mutable_path() = BuildPath(params, true);

    grpc::ClientContext context;
    SetDeadline(&context);
    return FromStatus(stub_->DeletePath(&context, request, &response));
}

RpcResult GoBgpGrpcClient::WalkRoutes(
    BgpAfi afi,
    BgpSafi safi,
    const BgpRouteWalkCallback& callback)
{
    api::ListPathRequest request;
    request.set_table_type(api::TABLE_TYPE_GLOBAL);
    SetFamily(request.mutable_family(), afi, safi);

    grpc::ClientContext context;
    context.set_deadline(
        std::chrono::system_clock::now() +
        std::chrono::seconds(kListPathDeadlineSeconds));

    std::unique_ptr<grpc::ClientReader<api::ListPathResponse>> reader(
        stub_->ListPath(&context, request));

    api::ListPathResponse response;
    while (reader->Read(&response)) {
        if (!response.has_destination()) {
            continue;
        }

        const api::Destination& dest = response.destination();
        const std::string dest_prefix = dest.prefix();

        for (int i = 0; i < dest.paths_size(); ++i) {
            BgpRouteInfo info;
            FillRouteInfo(dest.paths(i), dest_prefix, afi, safi, &info);
            if (callback && callback(info) != 0) {
                return {true, grpc::StatusCode::OK, ""};
            }
        }
    }

    return FromStatus(reader->Finish());
}

void GoBgpGrpcClient::ExtractAfiSafi(const api::Path& path,
                                     BgpAfi* afi,
                                     BgpSafi* safi)
{
    *afi = BgpAfi::kIpv4;
    *safi = BgpSafi::kUnicast;

    if (!path.has_family()) {
        return;
    }

    const api::Family& fam = path.family();
    if (fam.afi() == api::Family::AFI_IP6) {
        *afi = BgpAfi::kIpv6;
    }

    switch (fam.safi()) {
        case api::Family::SAFI_MPLS_VPN:
            *safi = BgpSafi::kMplsVpn;
            break;
        case api::Family::SAFI_EVPN:
            *safi = BgpSafi::kEvpn;
            break;
        default:
            *safi = BgpSafi::kUnicast;
            break;
    }
}

RpcResult GoBgpGrpcClient::WatchRoutes(
    bool init_rib,
    const BgpRouteUpdateCallback& callback,
    WatchHandle* handle)
{
    api::WatchEventRequest request;

    api::WatchEventRequest_Table* table = request.mutable_table();
    api::WatchEventRequest_Table_Filter* filter = table->add_filters();
    filter->set_type(
        api::WatchEventRequest_Table_Filter_Type_TYPE_BEST);
    filter->set_init(init_rib);

    auto* context = new grpc::ClientContext();
    if (handle) {
        handle->context = context;
    }

    std::unique_ptr<grpc::ClientReader<api::WatchEventResponse>> reader(
        stub_->WatchEvent(context, request));

    api::WatchEventResponse response;
    while (reader->Read(&response)) {
        if (!response.has_table()) {
            continue;
        }

        const api::WatchEventResponse_TableEvent& table_event =
            response.table();

        for (int i = 0; i < table_event.paths_size(); ++i) {
            const api::Path& path = table_event.paths(i);

            BgpAfi afi;
            BgpSafi safi;
            ExtractAfiSafi(path, &afi, &safi);

            BgpRouteUpdate update;
            FillRouteInfo(path, "", afi, safi, &update.route);
            /* WatchEvent TYPE_BEST filter delivers only best-path updates,
             * but GoBGP does not set Path.best on watch notifications. */
            update.route.best = true;
            update.is_withdraw = path.is_withdraw();
            update.route.is_from_external = path.is_from_external();

            if (callback) {
                callback(update);
            }
        }
    }

    grpc::Status status = reader->Finish();

    if (handle) {
        handle->context = nullptr;
    }
    delete context;

    return FromStatus(status);
}

void GoBgpGrpcClient::CancelWatch(WatchHandle* handle)
{
    if (handle && handle->context) {
        handle->context->TryCancel();
    }
}

}  // namespace gobgp_client
