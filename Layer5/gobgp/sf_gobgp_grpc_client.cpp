#include "sf_gobgp_grpc_client.h"

#include <cstring>
#include <string>
#include <vector>

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
sf_gobgp_start_bgp(sf_gobgp_grpc_client_t *client,
                    uint32_t asn,
                    const char *router_id,
                    int32_t listen_port)
{
    if (client == nullptr || router_id == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    return to_c_result(client->client.StartBgp(asn, router_id, listen_port));
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_stop_bgp(sf_gobgp_grpc_client_t *client)
{
    if (client == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    return to_c_result(client->client.StopBgp());
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_get_bgp(sf_gobgp_grpc_client_t *client,
                  sf_gobgp_global_info_t *info)
{
    if (client == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    gobgp_client::BgpGlobalInfo cpp_info{};
    auto result = to_c_result(client->client.GetBgp(&cpp_info));

    if (result.ok && info) {
        info->asn = cpp_info.asn;
        std::strncpy(info->router_id, cpp_info.router_id.c_str(),
                     sizeof(info->router_id) - 1);
        info->listen_port = cpp_info.listen_port;
    }

    return result;
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_list_peers(sf_gobgp_grpc_client_t *client,
                    sf_gobgp_peer_info_t *peers,
                    int max_peers,
                    int *num_peers)
{
    if (client == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    std::vector<gobgp_client::PeerInfo> cpp_peers;
    auto result = to_c_result(client->client.ListPeers(&cpp_peers));

    int count = 0;
    if (result.ok && peers) {
        for (const auto& p : cpp_peers) {
            if (count >= max_peers)
                break;
            sf_gobgp_peer_info_t& out = peers[count];
            std::memset(&out, 0, sizeof(out));
            std::strncpy(out.neighbor_address, p.neighbor_address.c_str(),
                         sizeof(out.neighbor_address) - 1);
            out.peer_asn = p.peer_asn;
            std::strncpy(out.router_id, p.router_id.c_str(),
                         sizeof(out.router_id) - 1);
            out.session_state = p.session_state;
            std::strncpy(out.description, p.description.c_str(),
                         sizeof(out.description) - 1);
            count++;
        }
    }

    if (num_peers)
        *num_peers = count;

    return result;
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
sf_gobgp_apply_neighbor_address_families(
    sf_gobgp_grpc_client_t *client,
    const char *neighbor_address,
    uint32_t peer_asn,
    const char *local_address,
    bool ipv4_unicast,
    bool ipv4_vpn,
    bool evpn)
{
    if (client == nullptr || neighbor_address == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    const std::string local = (local_address != nullptr) ? local_address : "";
    return to_c_result(client->client.ApplyNeighborAddressFamilies(
        neighbor_address, peer_asn, local, ipv4_unicast, ipv4_vpn, evpn));
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
sf_gobgp_enable_ipv4_vpn(sf_gobgp_grpc_client_t *client,
                         const char *neighbor_address,
                         uint32_t peer_asn,
                         const char *local_address)
{
    if (client == nullptr || neighbor_address == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    const std::string local = (local_address != nullptr) ? local_address : "";
    return to_c_result(
        client->client.EnableIpv4Vpn(neighbor_address, peer_asn, local));
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_disable_ipv4_vpn(sf_gobgp_grpc_client_t *client,
                          const char *neighbor_address,
                          uint32_t peer_asn,
                          const char *local_address)
{
    if (client == nullptr || neighbor_address == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    const std::string local = (local_address != nullptr) ? local_address : "";
    return to_c_result(
        client->client.DisableIpv4Vpn(neighbor_address, peer_asn, local));
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

/* Wire AFI/SAFI values (RFC 4760 / IANA), same as tcpconst.h. */
static gobgp_client::BgpAfi
to_cpp_afi(int afi)
{
    return (afi == 2) ? gobgp_client::BgpAfi::kIpv6
                      : gobgp_client::BgpAfi::kIpv4;
}

static gobgp_client::BgpSafi
to_cpp_safi(int safi)
{
    switch (safi) {
        case 128: /* SAFI_MPLS_VPN */
            return gobgp_client::BgpSafi::kMplsVpn;
        case 70:  /* SAFI_EVPN */
            return gobgp_client::BgpSafi::kEvpn;
        case 1:   /* SAFI_UNICAST */
        default:
            return gobgp_client::BgpSafi::kUnicast;
    }
}

static gobgp_client::BgpRouteParams
to_cpp_route_params(const sf_gobgp_route_params_t *params)
{
    gobgp_client::BgpRouteParams out{};
    if (params == nullptr) {
        return out;
    }

    out.prefix = params->prefix;
    out.nexthop = params->nexthop;
    out.rd = params->rd;
    out.rt = params->rt;
    out.med = params->med;
    out.local_pref = params->local_pref;
    out.med_present = params->med_present;
    out.local_pref_present = params->local_pref_present;
    out.l3_vpn_label = params->l3_vpn_label;
    out.l3_vpn_label_present = params->l3_vpn_label_present;
    out.mac_addr = params->mac_addr;
    out.evpn_label = params->evpn_label;
    out.evpn_label_present = params->evpn_label_present;
    out.afi = to_cpp_afi(params->afi);
    out.safi = to_cpp_safi(params->safi);
    return out;
}

static void
to_c_route_info(const gobgp_client::BgpRouteInfo& in,
                sf_gobgp_route_info_t *out)
{
    if (out == nullptr) {
        return;
    }

    std::memset(out, 0, sizeof(*out));
    std::strncpy(out->prefix, in.prefix.c_str(), sizeof(out->prefix) - 1);
    std::strncpy(out->nexthop, in.nexthop.c_str(), sizeof(out->nexthop) - 1);
    std::strncpy(out->rd, in.rd.c_str(), sizeof(out->rd) - 1);
    std::strncpy(out->rt, in.rt.c_str(), sizeof(out->rt) - 1);
    out->med = in.med;
    out->local_pref = in.local_pref;
    out->med_present = in.med_present;
    out->local_pref_present = in.local_pref_present;
    out->l3_vpn_label = in.l3_vpn_label;
    out->l3_vpn_label_present = in.l3_vpn_label_present;
    out->best = in.best;
    out->is_from_external = in.is_from_external;
    switch (in.safi) {
        case gobgp_client::BgpSafi::kMplsVpn:
            out->afi = 1;
            out->safi = 128;
            break;
        case gobgp_client::BgpSafi::kEvpn:
            out->afi = 25;
            out->safi = 70;
            break;
        default:
            out->afi = (in.afi == gobgp_client::BgpAfi::kIpv6) ? 2 : 1;
            out->safi = 1;
            break;
    }
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_add_route(sf_gobgp_grpc_client_t *client,
                   const sf_gobgp_route_params_t *params)
{
    if (client == nullptr || params == nullptr) {
        return {false, -1, "invalid arguments"};
    }
    if (params->safi == 70) {
        if (params->mac_addr[0] == '\0') {
            return {false, -1, "invalid arguments"};
        }
    } else if (params->prefix[0] == '\0') {
        return {false, -1, "invalid arguments"};
    }

    return to_c_result(
        client->client.AddRoute(to_cpp_route_params(params)));
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_is_address_family_enabled(sf_gobgp_grpc_client_t *client,
                                   int afi,
                                   int safi,
                                   bool *enabled_out)
{
    if (client == nullptr || enabled_out == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    *enabled_out = false;
    return to_c_result(client->client.IsAddressFamilyEnabledOnAnyPeer(
        to_cpp_afi(afi), to_cpp_safi(safi), enabled_out));
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_delete_route(sf_gobgp_grpc_client_t *client,
                      const sf_gobgp_route_params_t *params)
{
    if (client == nullptr || params == nullptr) {
        return {false, -1, "invalid arguments"};
    }
    if (params->safi == 70) {
        if (params->mac_addr[0] == '\0') {
            return {false, -1, "invalid arguments"};
        }
    } else if (params->prefix[0] == '\0') {
        return {false, -1, "invalid arguments"};
    }

    return to_c_result(
        client->client.DeleteRoute(to_cpp_route_params(params)));
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_walk_routes(sf_gobgp_grpc_client_t *client,
                     int afi,
                     int safi,
                     sf_gobgp_route_walk_cb callback,
                     void *userdata)
{
    if (client == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    auto walk_cb = [callback, userdata](const gobgp_client::BgpRouteInfo& route) {
        if (!callback) {
            return 0;
        }
        sf_gobgp_route_info_t info{};
        to_c_route_info(route, &info);
        return callback(&info, userdata);
    };

    return to_c_result(client->client.WalkRoutes(
        to_cpp_afi(afi), to_cpp_safi(safi), walk_cb));
}

struct sf_gobgp_watch_handle {
    gobgp_client::WatchHandle cpp_handle;
};

extern "C" sf_gobgp_watch_handle_t *
sf_gobgp_watch_handle_create(void)
{
    return new sf_gobgp_watch_handle{};
}

extern "C" void
sf_gobgp_watch_handle_destroy(sf_gobgp_watch_handle_t *handle)
{
    delete handle;
}

extern "C" sf_gobgp_rpc_result_t
sf_gobgp_watch_routes(sf_gobgp_grpc_client_t *client,
                      bool init_rib,
                      sf_gobgp_route_update_cb callback,
                      void *userdata,
                      sf_gobgp_watch_handle_t *handle)
{
    if (client == nullptr) {
        return {false, -1, "invalid arguments"};
    }

    gobgp_client::WatchHandle *cpp_handle =
        (handle != nullptr) ? &handle->cpp_handle : nullptr;

    auto update_cb = [callback, userdata](
        const gobgp_client::BgpRouteUpdate& update) {
        if (!callback) {
            return;
        }
        sf_gobgp_route_update_t c_update{};
        to_c_route_info(update.route, &c_update.route);
        c_update.is_withdraw = update.is_withdraw;
        callback(&c_update, userdata);
    };

    return to_c_result(
        client->client.WatchRoutes(init_rib, update_cb, cpp_handle));
}

extern "C" void
sf_gobgp_watch_cancel(sf_gobgp_watch_handle_t *handle)
{
    if (handle == nullptr) {
        return;
    }
    gobgp_client::GoBgpGrpcClient::CancelWatch(&handle->cpp_handle);
}
