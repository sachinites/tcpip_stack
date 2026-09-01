#include <iostream>
#include "gobgp_grpc.h"

static bool Check(const char* operation,
                  const gobgp_client::RpcResult& result)
{
    if (result.ok) {
        std::cout << operation << " succeeded\n";
        return true;
    }

    std::cerr << operation << " failed: code="
              << static_cast<int>(result.code)
              << ", message=" << result.message << '\n';
    return false;
}

int main()
{
    gobgp_client::GoBgpGrpcClient client("127.0.0.1:50051");

    const std::string neighbor = "100.0.0.2";
    const std::uint32_t peer_asn = 65002;
    const std::string local_address = "100.0.0.1";

    const auto result = client.AddPeer(
        neighbor, peer_asn, local_address,
        true,   // IPv4 unicast
        true);  // L2VPN EVPN

    return Check("AddPeer", result) ? 0 : 1;

    // Other examples:
    // Check("EnableIpv4", client.EnableIpv4(neighbor, peer_asn, local_address));
    // Check("DisableIpv4", client.DisableIpv4(neighbor, peer_asn, local_address));
    // Check("EnableEvpn", client.EnableEvpn(neighbor, peer_asn, local_address));
    // Check("DisableEvpn", client.DisableEvpn(neighbor, peer_asn, local_address));
    // Check("RemovePeer", client.RemovePeer(neighbor));
}
