#include "gobgp_grpc.h"

#include <arpa/inet.h>
#include <chrono>
#include <ctime>
#include <cstring>
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

bool ParseIpv4Address(const std::string& addr, std::uint8_t out[4])
{
    struct in_addr in {};

    if (addr.empty() || ::inet_pton(AF_INET, addr.c_str(), &in) != 1) {
        return false;
    }

    const char* bytes = reinterpret_cast<const char*>(&in.s_addr);
    out[0] = static_cast<std::uint8_t>(bytes[0]);
    out[1] = static_cast<std::uint8_t>(bytes[1]);
    out[2] = static_cast<std::uint8_t>(bytes[2]);
    out[3] = static_cast<std::uint8_t>(bytes[3]);
    return true;
}

bool ParseMacAddress(const std::string& mac, std::uint8_t out[6])
{
    unsigned int b[6];

    if (mac.empty()) {
        return false;
    }

    if (std::sscanf(mac.c_str(),
                    "%x:%x:%x:%x:%x:%x",
                    &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return false;
    }

    for (int i = 0; i < 6; ++i) {
        out[i] = static_cast<std::uint8_t>(b[i]);
    }
    return true;
}

std::uint8_t Ipv4PrefixByteCount(std::uint32_t prefix_len)
{
    return static_cast<std::uint8_t>((prefix_len + 7U) / 8U);
}

bool EncodeRouteDistinguisherWire(const api::RouteDistinguisher& rd,
                                  std::uint8_t out[8])
{
    if (rd.has_two_octet_asn()) {
        const api::RouteDistinguisherTwoOctetASN& asn = rd.two_octet_asn();
        out[0] = 0x00;
        out[1] = 0x00;
        out[2] = static_cast<std::uint8_t>((asn.admin() >> 8) & 0xff);
        out[3] = static_cast<std::uint8_t>(asn.admin() & 0xff);
        out[4] = static_cast<std::uint8_t>((asn.assigned() >> 24) & 0xff);
        out[5] = static_cast<std::uint8_t>((asn.assigned() >> 16) & 0xff);
        out[6] = static_cast<std::uint8_t>((asn.assigned() >> 8) & 0xff);
        out[7] = static_cast<std::uint8_t>(asn.assigned() & 0xff);
        return true;
    }

    if (rd.has_ip_address()) {
        const api::RouteDistinguisherIPAddress& ip = rd.ip_address();
        std::uint8_t addr[4] = {};

        if (!ParseIpv4Address(ip.admin(), addr)) {
            return false;
        }

        out[0] = 0x00;
        out[1] = 0x01;
        out[2] = addr[0];
        out[3] = addr[1];
        out[4] = addr[2];
        out[5] = addr[3];
        out[6] = static_cast<std::uint8_t>((ip.assigned() >> 8) & 0xff);
        out[7] = static_cast<std::uint8_t>(ip.assigned() & 0xff);
        return true;
    }

    if (rd.has_four_octet_asn()) {
        const api::RouteDistinguisherFourOctetASN& asn = rd.four_octet_asn();
        out[0] = 0x00;
        out[1] = 0x02;
        out[2] = static_cast<std::uint8_t>((asn.admin() >> 24) & 0xff);
        out[3] = static_cast<std::uint8_t>((asn.admin() >> 16) & 0xff);
        out[4] = static_cast<std::uint8_t>((asn.admin() >> 8) & 0xff);
        out[5] = static_cast<std::uint8_t>(asn.admin() & 0xff);
        out[6] = static_cast<std::uint8_t>((asn.assigned() >> 8) & 0xff);
        out[7] = static_cast<std::uint8_t>(asn.assigned() & 0xff);
        return true;
    }

    return false;
}

void AppendMplsLabel(std::uint32_t label,
                     std::uint8_t* wire,
                     std::uint16_t* offset)
{
    /* RFC 8277: 20-bit label in high-order bits of 3 octets; BoS in LSB. */
    const std::uint32_t entry = ((label & 0xfffffU) << 4) | 0x1U;

    wire[*offset] = static_cast<std::uint8_t>((entry >> 16) & 0xff);
    (*offset)++;
    wire[*offset] = static_cast<std::uint8_t>((entry >> 8) & 0xff);
    (*offset)++;
    wire[*offset] = static_cast<std::uint8_t>(entry & 0xff);
    (*offset)++;
}

bool ExtractNlriWire(const api::NLRI& nlri,
                     BgpSafi safi,
                     BgpRouteInfo* info)
{
    std::uint16_t offset = 0;

    if (!info) {
        return false;
    }

    info->nlri_wire_len = 0;

    if (nlri.has_prefix()) {
        const api::IPAddressPrefix& prefix = nlri.prefix();
        std::uint8_t addr[4] = {};
        const std::uint32_t prefix_len = prefix.prefix_len();
        const std::uint8_t prefix_bytes = Ipv4PrefixByteCount(prefix_len);

        if (!ParseIpv4Address(prefix.prefix(), addr)) {
            return false;
        }

        info->nlri_wire[offset++] = static_cast<std::uint8_t>(prefix_len);
        for (std::uint8_t i = 0; i < prefix_bytes; ++i) {
            info->nlri_wire[offset++] = addr[i];
        }
        info->nlri_wire_len = offset;
        return true;
    }

    if (nlri.has_labeled_vpn_ip_prefix()) {
        const api::LabeledVPNIPAddressPrefix& vpn =
            nlri.labeled_vpn_ip_prefix();
        std::uint8_t addr[4] = {};
        const std::uint32_t prefix_len = vpn.prefix_len();
        const std::uint8_t prefix_bytes = Ipv4PrefixByteCount(prefix_len);

        if (!vpn.has_rd() ||
            !EncodeRouteDistinguisherWire(vpn.rd(), &info->nlri_wire[offset])) {
            return false;
        }
        offset += 8;

        if (!ParseIpv4Address(vpn.prefix(), addr)) {
            return false;
        }

        info->nlri_wire[offset++] = static_cast<std::uint8_t>(prefix_len);
        for (std::uint8_t i = 0; i < prefix_bytes; ++i) {
            info->nlri_wire[offset++] = addr[i];
        }

        if (vpn.labels_size() > 0) {
            AppendMplsLabel(vpn.labels(0), info->nlri_wire, &offset);
        }

        info->nlri_wire_len = offset;
        return true;
    }

    if (nlri.has_evpn_macadv()) {
        const api::EVPNMACIPAdvertisementRoute& evpn = nlri.evpn_macadv();
        std::uint8_t mac[6] = {};

        info->nlri_wire[offset++] = 2;

        if (!evpn.has_rd() ||
            !EncodeRouteDistinguisherWire(evpn.rd(), &info->nlri_wire[offset])) {
            return false;
        }
        offset += 8;

        if (evpn.has_esi()) {
            const api::EthernetSegmentIdentifier& esi = evpn.esi();
            info->nlri_wire[offset++] = static_cast<std::uint8_t>(esi.type());
            const std::string& value = esi.value();
            const std::size_t copy_len = std::min<std::size_t>(value.size(), 9);
            if (copy_len > 0) {
                std::memcpy(&info->nlri_wire[offset], value.data(), copy_len);
            }
            offset += 9;
        } else {
            std::memset(&info->nlri_wire[offset], 0, 10);
            offset += 10;
        }

        const std::uint32_t eth_tag = evpn.ethernet_tag();
        info->nlri_wire[offset++] =
            static_cast<std::uint8_t>((eth_tag >> 24) & 0xff);
        info->nlri_wire[offset++] =
            static_cast<std::uint8_t>((eth_tag >> 16) & 0xff);
        info->nlri_wire[offset++] =
            static_cast<std::uint8_t>((eth_tag >> 8) & 0xff);
        info->nlri_wire[offset++] =
            static_cast<std::uint8_t>(eth_tag & 0xff);

        if (!ParseMacAddress(evpn.mac_address(), mac)) {
            return false;
        }

        info->nlri_wire[offset++] = 48;
        std::memcpy(&info->nlri_wire[offset], mac, 6);
        offset += 6;

        if (!evpn.ip_address().empty()) {
            std::uint8_t ip[4] = {};
            if (!ParseIpv4Address(evpn.ip_address(), ip)) {
                return false;
            }
            info->nlri_wire[offset++] = 32;
            std::memcpy(&info->nlri_wire[offset], ip, 4);
            offset += 4;
        } else {
            info->nlri_wire[offset++] = 0;
        }

        if (evpn.labels_size() > 0) {
            AppendMplsLabel(evpn.labels(0), info->nlri_wire, &offset);
        }

        info->nlri_wire_len = offset;
        return true;
    }

    if (nlri.has_evpn_multicast()) {
        const api::EVPNInclusiveMulticastEthernetTagRoute& imet =
            nlri.evpn_multicast();
        std::uint8_t ip[4] = {};

        info->nlri_wire[offset++] = 3;

        if (!imet.has_rd() ||
            !EncodeRouteDistinguisherWire(imet.rd(), &info->nlri_wire[offset])) {
            return false;
        }
        offset += 8;

        const std::uint32_t eth_tag = imet.ethernet_tag();
        info->nlri_wire[offset++] =
            static_cast<std::uint8_t>((eth_tag >> 24) & 0xff);
        info->nlri_wire[offset++] =
            static_cast<std::uint8_t>((eth_tag >> 16) & 0xff);
        info->nlri_wire[offset++] =
            static_cast<std::uint8_t>((eth_tag >> 8) & 0xff);
        info->nlri_wire[offset++] =
            static_cast<std::uint8_t>(eth_tag & 0xff);

        if (!imet.ip_address().empty() &&
            ParseIpv4Address(imet.ip_address(), ip)) {
            info->nlri_wire[offset++] = 32;
            std::memcpy(&info->nlri_wire[offset], ip, 4);
            offset += 4;
        } else {
            info->nlri_wire[offset++] = 0;
        }

        info->nlri_wire_len = offset;
        return true;
    }

    (void)safi;
    return false;
}

void SetDefaultEthernetSegmentIdentifier(
    api::EthernetSegmentIdentifier* esi)
{
    if (!esi) {
        return;
    }

    /* Single-homed / non-ES route: type-0 ESI with 9 zero bytes.
     * GoBGP AddPath dereferences esi unconditionally. */
    esi->set_type(0);
    esi->set_value(std::string(9, '\0'));
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

std::uint16_t
EcTypeField(bool transitive, std::uint32_t sub_type, std::uint8_t transitive_high)
{
    const std::uint8_t high =
        transitive ? transitive_high
                   : static_cast<std::uint8_t>(transitive_high | 0x40);
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(high) << 8) |
        static_cast<std::uint16_t>(sub_type & 0xff));
}

const char *
TunnelEncapTypeName(std::uint32_t tunnel_type)
{
    switch (tunnel_type) {
    case 2:
        return "GRE";
    case 8:
        return "VXLAN";
    case 10:
        return "MPLS";
    case 12:
        return "MPLS-in-GRE";
    default:
        return "Unknown";
    }
}

bool
AppendExtendedCommunity(const api::ExtendedCommunity& community,
                        BgpRouteInfo* info)
{
    BgpExtCommunityEntry entry{};

    if (!info || info->ext_comm_count >= 16) {
        return false;
    }

    if (community.has_two_octet_as_specific()) {
        const api::TwoOctetAsSpecificExtended& ec =
            community.two_octet_as_specific();
        entry.type = EcTypeField(ec.is_transitive(), ec.sub_type(), 0x00);
        entry.subtype = static_cast<std::uint16_t>(ec.sub_type());
        if (ec.sub_type() == kEcSubtypeRouteTarget) {
            snprintf(entry.text, sizeof(entry.text), "RT:%u:%u",
                     ec.asn(), ec.local_admin());
            if (info->rt.empty()) {
                info->rt = std::to_string(ec.asn()) + ":" +
                           std::to_string(ec.local_admin());
            }
        } else {
            snprintf(entry.text, sizeof(entry.text),
                     "2-octet-AS:%u:%u", ec.asn(), ec.local_admin());
        }
    } else if (community.has_ipv4_address_specific()) {
        const api::IPv4AddressSpecificExtended& ec =
            community.ipv4_address_specific();
        entry.type = EcTypeField(ec.is_transitive(), ec.sub_type(), 0x01);
        entry.subtype = static_cast<std::uint16_t>(ec.sub_type());
        if (ec.sub_type() == kEcSubtypeRouteTarget) {
            snprintf(entry.text, sizeof(entry.text), "RT:%s:%u",
                     ec.address().c_str(), ec.local_admin());
            if (info->rt.empty()) {
                info->rt = ec.address() + ":" +
                           std::to_string(ec.local_admin());
            }
        } else {
            snprintf(entry.text, sizeof(entry.text), "IPv4:%s:%u",
                     ec.address().c_str(), ec.local_admin());
        }
    } else if (community.has_four_octet_as_specific()) {
        const api::FourOctetAsSpecificExtended& ec =
            community.four_octet_as_specific();
        entry.type = EcTypeField(ec.is_transitive(), ec.sub_type(), 0x02);
        entry.subtype = static_cast<std::uint16_t>(ec.sub_type());
        if (ec.sub_type() == kEcSubtypeRouteTarget) {
            snprintf(entry.text, sizeof(entry.text), "RT:%u:%u",
                     ec.asn(), ec.local_admin());
            if (info->rt.empty()) {
                info->rt = std::to_string(ec.asn()) + ":" +
                           std::to_string(ec.local_admin());
            }
        } else {
            snprintf(entry.text, sizeof(entry.text), "4-octet-AS:%u:%u",
                     ec.asn(), ec.local_admin());
        }
    } else if (community.has_encap()) {
        const api::EncapExtended& ec = community.encap();
        entry.type = 0x030c;
        entry.subtype = 0x000c;
        snprintf(entry.text, sizeof(entry.text), "Tunnel-Encap:%s",
                 TunnelEncapTypeName(ec.tunnel_type()));
        info->tunnel_encap_type =
            static_cast<std::uint16_t>(ec.tunnel_type());
        info->tunnel_encap_present = true;
    } else if (community.has_esi_label()) {
        const api::ESILabelExtended& ec = community.esi_label();
        entry.type = 0x0601;
        entry.subtype = 0x0001;
        snprintf(entry.text, sizeof(entry.text), "ESI-Label:%u",
                 ec.label());
        info->evpn_label1 = ec.label();
        info->evpn_label1_present = true;
        info->evpn_label1_from_ext_comm = true;
    } else if (community.has_router_mac()) {
        const api::RouterMacExtended& ec = community.router_mac();
        entry.type = 0x0603;
        entry.subtype = 0x0003;
        snprintf(entry.text, sizeof(entry.text), "Router-MAC:%s",
                 ec.mac().c_str());
    } else if (community.has_es_import()) {
        const api::ESImportRouteTarget& ec = community.es_import();
        entry.type = 0x0602;
        entry.subtype = 0x0002;
        snprintf(entry.text, sizeof(entry.text), "ES-Import:%s",
                 ec.es_import().c_str());
    } else if (community.has_mac_mobility()) {
        const api::MacMobilityExtended& ec = community.mac_mobility();
        entry.type = 0x0600;
        entry.subtype = 0x0000;
        snprintf(entry.text, sizeof(entry.text), "MAC-Mobility:seq:%u",
                 ec.sequence_num());
    } else if (community.has_opaque()) {
        const api::OpaqueExtended& ec = community.opaque();
        entry.type = ec.is_transitive() ? 0x0303 : 0x4303;
        entry.subtype = 0x0003;
        snprintf(entry.text, sizeof(entry.text), "Opaque:%s",
                 ec.value().c_str());
    } else {
        snprintf(entry.text, sizeof(entry.text), "Unknown");
    }

    info->ext_comms[info->ext_comm_count++] = entry;
    return true;
}

void
FillExtendedCommunities(const api::Path& path, BgpRouteInfo* info)
{
    if (!info) {
        return;
    }

    info->ext_comm_count = 0;
    info->evpn_label1 = 0;
    info->evpn_label1_present = false;
    info->evpn_label1_from_ext_comm = false;
    info->tunnel_encap_type = 0;
    info->tunnel_encap_present = false;

    for (int i = 0; i < path.pattrs_size(); ++i) {
        const api::Attribute& attr = path.pattrs(i);
        if (attr.attr_case() != api::Attribute::kExtendedCommunities) {
            continue;
        }

        const api::ExtendedCommunitiesAttribute& ecs =
            attr.extended_communities();
        for (int j = 0; j < ecs.communities_size(); ++j) {
            AppendExtendedCommunity(ecs.communities(j), info);
        }
    }
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

        if (peer.has_timers() && peer.timers().has_state() &&
            peer.timers().state().has_uptime()) {
            const auto& uptime_ts = peer.timers().state().uptime();
            const time_t uptime_epoch =
                static_cast<time_t>(uptime_ts.seconds());
            if (uptime_epoch > 0) {
                pi.uptime_seconds = static_cast<std::uint64_t>(
                    std::difftime(std::time(nullptr), uptime_epoch));
                pi.uptime_valid = true;
            }
        }

        for (int i = 0; i < peer.afi_safis_size(); ++i) {
            const api::AfiSafi& afi_safi = peer.afi_safis(i);
            PeerAfiSafiInfo af_info{};

            if (afi_safi.has_config()) {
                const api::AfiSafiConfig& cfg = afi_safi.config();
                af_info.configured = cfg.enabled();
                if (cfg.has_family()) {
                    const api::Family& family = cfg.family();
                    if (family.afi() == api::Family::AFI_IP6) {
                        af_info.afi = 2;
                    } else if (family.afi() == api::Family::AFI_L2VPN) {
                        af_info.afi = 25;
                    } else {
                        af_info.afi = 1;
                    }

                    switch (family.safi()) {
                        case api::Family::SAFI_MPLS_VPN:
                            af_info.safi = 128;
                            break;
                        case api::Family::SAFI_EVPN:
                            af_info.safi = 70;
                            break;
                        default:
                            af_info.safi = 1;
                            break;
                    }
                }
            }

            if (afi_safi.has_state()) {
                const api::AfiSafiState& st = afi_safi.state();
                af_info.enabled = st.enabled();
                af_info.received = st.received();
                af_info.accepted = st.accepted();
                af_info.advertised = st.advertised();

                if (af_info.afi == 0 && st.has_family()) {
                    const api::Family& family = st.family();
                    if (family.afi() == api::Family::AFI_IP6) {
                        af_info.afi = 2;
                    } else if (family.afi() == api::Family::AFI_L2VPN) {
                        af_info.afi = 25;
                    } else {
                        af_info.afi = 1;
                    }

                    switch (family.safi()) {
                        case api::Family::SAFI_MPLS_VPN:
                            af_info.safi = 128;
                            break;
                        case api::Family::SAFI_EVPN:
                            af_info.safi = 70;
                            break;
                        default:
                            af_info.safi = 1;
                            break;
                    }
                }
            }

            if (!af_info.configured && !af_info.enabled) {
                continue;
            }

            pi.afi_safis.push_back(af_info);
        }

        if (peers)
            peers->push_back(std::move(pi));
    }

    return FromStatus(reader->Finish());
}

namespace {

bool
GrpcFamilyMatches(BgpAfi afi, BgpSafi safi, const api::Family& family)
{
    if (safi == BgpSafi::kEvpn) {
        return family.afi() == api::Family::AFI_L2VPN &&
               family.safi() == api::Family::SAFI_EVPN;
    }

    if (safi == BgpSafi::kMplsVpn) {
        return family.afi() == api::Family::AFI_IP &&
               family.safi() == api::Family::SAFI_MPLS_VPN;
    }

    if (afi == BgpAfi::kIpv6) {
        return family.afi() == api::Family::AFI_IP6 &&
               family.safi() == api::Family::SAFI_UNICAST;
    }

    return family.afi() == api::Family::AFI_IP &&
           family.safi() == api::Family::SAFI_UNICAST;
}

}  // namespace

RpcResult GoBgpGrpcClient::IsAddressFamilyEnabledOnAnyPeer(
    BgpAfi afi,
    BgpSafi safi,
    bool* enabled)
{
    api::ListPeerRequest request;
    request.set_enable_advertised(false);

    if (enabled) {
        *enabled = false;
    }

    grpc::ClientContext context;
    SetDeadline(&context);

    std::unique_ptr<grpc::ClientReader<api::ListPeerResponse>> reader(
        stub_->ListPeer(&context, request));

    api::ListPeerResponse response;
    while (reader->Read(&response)) {
        if (!response.has_peer()) {
            continue;
        }

        const api::Peer& peer = response.peer();
        for (int i = 0; i < peer.afi_safis_size(); ++i) {
            const api::AfiSafi& afi_safi = peer.afi_safis(i);
            if (!afi_safi.has_config() || !afi_safi.config().enabled()) {
                continue;
            }
            if (!afi_safi.config().has_family()) {
                continue;
            }
            if (GrpcFamilyMatches(afi, safi, afi_safi.config().family())) {
                if (enabled) {
                    *enabled = true;
                }
                return FromStatus(grpc::Status::OK);
            }
        }
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

    /* Always send explicit enable/disable for every AF so GoBGP withdraws
     * routes on disable (soft-reset-in) and emits WatchEvent withdrawals. */
    AppendFamily(peer, AddressFamily::kIpv4Unicast, ipv4_unicast);
    AppendFamily(peer, AddressFamily::kIpv4Vpn, ipv4_vpn);
    AppendFamily(peer, AddressFamily::kEvpn, evpn);

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
    if (safi == BgpSafi::kEvpn) {
        family->set_afi(api::Family::AFI_L2VPN);
    } else if (afi == BgpAfi::kIpv6) {
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
    bool has_prefix = ParsePrefixCidr(params.prefix, &addr, &prefix_len);

    if (params.safi == BgpSafi::kEvpn) {
        if (params.evpn_route_type == 3) {
            if (params.pe_addr.empty()) {
                return path;
            }
        } else if (params.mac_addr.empty()) {
            return path;
        }
    } else if (!has_prefix) {
        return path;
    }

    if (withdraw) {
        path.set_is_withdraw(true);
    }

    SetFamily(path.mutable_family(), params.afi, params.safi);

    api::NLRI* nlri = path.mutable_nlri();
    if (params.safi == BgpSafi::kEvpn) {
        if (params.evpn_route_type == 3) {
            api::EVPNInclusiveMulticastEthernetTagRoute* imet =
                nlri->mutable_evpn_multicast();
            if (!params.rd.empty()) {
                SetRouteDistinguisher(params.rd, imet->mutable_rd());
            }
            imet->set_ethernet_tag(params.eth_tag_id);
            imet->set_ip_address(params.pe_addr);
        } else {
            api::EVPNMACIPAdvertisementRoute* evpn =
                nlri->mutable_evpn_macadv();
            if (!params.rd.empty()) {
                SetRouteDistinguisher(params.rd, evpn->mutable_rd());
            }
            SetDefaultEthernetSegmentIdentifier(evpn->mutable_esi());
            evpn->set_ethernet_tag(0);
            evpn->set_mac_address(params.mac_addr);
            if (!params.pe_addr.empty())
                evpn->set_ip_address(params.pe_addr);
            else
                evpn->clear_ip_address();
            if (params.evpn_label_present) {
                evpn->add_labels(params.evpn_label);
            }
        }
    } else if (!params.rd.empty() || params.safi == BgpSafi::kMplsVpn) {
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
            if (params.safi == BgpSafi::kMplsVpn ||
                params.safi == BgpSafi::kEvpn) {
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

        if (params.safi == BgpSafi::kEvpn &&
            params.evpn_route_type == 3 &&
            params.pmsi_label_present) {
            api::Attribute* pmsi_attr = path.add_pattrs();
            api::PmsiTunnelAttribute* pmsi =
                pmsi_attr->mutable_pmsi_tunnel();
            const std::string& tunnel_id_str =
                !params.pe_addr.empty() ? params.pe_addr : params.nexthop;
            std::uint8_t tunnel_id_bytes[4] = {};

            pmsi->set_flags(0);
            pmsi->set_type(6);
            pmsi->set_label(params.pmsi_label);
            /* GoBGP expects raw IPv4 octets in id (bytes), not an ASCII string. */
            if (ParseIpv4Address(tunnel_id_str, tunnel_id_bytes)) {
                pmsi->set_id(std::string(
                    reinterpret_cast<const char*>(tunnel_id_bytes), 4));
            }
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
        } else if (nlri.has_evpn_macadv()) {
            const api::EVPNMACIPAdvertisementRoute& evpn =
                nlri.evpn_macadv();
            info->prefix = evpn.mac_address();
            if (evpn.has_rd()) {
                info->rd = FormatRouteDistinguisher(evpn.rd());
            }
            if (evpn.labels_size() > 0) {
                info->l3_vpn_label = evpn.labels(0);
                info->l3_vpn_label_present = true;
            }
        } else if (nlri.has_evpn_multicast()) {
            const api::EVPNInclusiveMulticastEthernetTagRoute& imet =
                nlri.evpn_multicast();
            info->prefix = imet.ip_address();
            if (imet.has_rd()) {
                info->rd = FormatRouteDistinguisher(imet.rd());
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
            case api::Attribute::kPmsiTunnel:
                info->pmsi_label = attr.pmsi_tunnel().label();
                info->pmsi_label_present = true;
                info->pmsi_tunnel_type =
                    static_cast<std::uint8_t>(attr.pmsi_tunnel().type());
                break;
            default:
                break;
        }
    }

    FillExtendedCommunities(path, info);

    if (path.has_nlri()) {
        ExtractNlriWire(path.nlri(), safi, info);
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
