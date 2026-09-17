#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"
#include "../cmdcodes.h"
#include "../router_init.h"
#include "../tcpconst.h"
#include "../utils.h"
#include "../RTM/rtm_enums.h"
#include "bgp_config.h"
#include "bgp_global_rib.h"
#include "bgp_rib/bgp_nlri_wire.h"
#include "bgp_rib/bgp_rib.h"
#include "bgp_rib/bgp_rib_evpn.h"
#include "bgp_rib/bgp_rib_ipv4.h"
#include "bgp_rib/bgp_rib_vpnv4.h"
#include "bgp_route.h"
#include "bgp_rtr.h"
#include "gobgp/sf_gobgp_grpc_client.h"
#include "../Layer2/Evpn/evpn_bgp.h"
#include "../vrf/mac_vrf.h"

extern void
rtm_build_distribution_policy_cli_tree(
            param_t *mount_point, 
            RTM_PROTO_T exempt_proto) ;

extern graph_t *topo;

/* BGP (GoBGP gRPC) CLI command codes */

/* config node <node-name> protocol bgp <local-asn> [router-id <router-id>] */
#define CMDCODE_CONFIG_BGP_START 1

/* config node <node-name> protocol bgp <local-asn> neighbor <addr> remote-as <asn> */
#define CMDCODE_CONFIG_BGP_NEIGHBOR 2

/* config node <node-name> protocol bgp <local-asn> neighbor <addr> address-family ipv4-unicast */
#define CMDCODE_CONFIG_BGP_NEIGHBOR_AF_IPV4 3

/* show node <node-name> protocol bgp peers */
#define CMDCODE_SHOW_BGP_PEERS 4

/* show node <node-name> protocol bgp summary */
#define CMDCODE_SHOW_BGP_SUMMARY 5

/* show node <node-name> protocol bgp routes <afi> <safi> */
#define CMDCODE_SHOW_BGP_ROUTES_IPV4_UNICAST 7
#define CMDCODE_SHOW_BGP_ROUTES_IPV4_MPLS_VPN 8
#define CMDCODE_SHOW_BGP_ROUTES_IPV6_UNICAST 9

/* show node <node-name> protocol bgp routes l2vpn-evpn mac */
#define CMDCODE_SHOW_BGP_ROUTES_L2VPN_EVPN_MAC 14

/* show node <node-name> protocol bgp routes l2vpn-evpn imet */
#define CMDCODE_SHOW_BGP_ROUTES_L2VPN_EVPN_IMET 17

/* show node <node-name> protocol bgp global-rib <ipv4-vpn|l2vpn-evpn> */
#define CMDCODE_SHOW_BGP_GLOBAL_RIB_IPV4_VPN 15
#define CMDCODE_SHOW_BGP_GLOBAL_RIB_L2VPN_EVPN 16

/* run node <node-name> protocol bgp monitor <afi> <safi> */
#define CMDCODE_RUN_BGP_MONITOR 10

/* show node <node-name> protocol bgp running-config */
#define CMDCODE_SHOW_BGP_RUNNING_CONFIG 11

/* config node <node-name> protocol bgp <local-asn> neighbor <addr> address-family ipv4-vpn */
#define CMDCODE_CONFIG_BGP_NEIGHBOR_AF_IPV4_VPN 12

/* config node <node-name> protocol bgp <local-asn> neighbor <addr> address-family l2vpn-evpn */
#define CMDCODE_CONFIG_BGP_NEIGHBOR_AF_L2VPN_EVPN 13


static sf_gobgp_grpc_client_t *
bgp_get_grpc_client(node_t *node)
{
    bgp_inst_t *bgp = BGP_INST(node);
    if (!bgp) return nullptr;

    if (!bgp->bgp_grpc_client) {
        char endpoint[64];
        unsigned int grpc_port = node->udp_port_number + 1000;

        snprintf(endpoint, sizeof(endpoint), "127.0.0.1:%u", grpc_port);
        bgp->bgp_grpc_client = sf_gobgp_grpc_client_create(endpoint);
    }
    return (sf_gobgp_grpc_client_t *)bgp->bgp_grpc_client;
}

static bgp_node_config_t *
bgp_config_get(node_t *node)
{
    bgp_inst_t *bgp = BGP_INST(node);
    if (!bgp) return nullptr;
    return &bgp->bgp_config;
}

static bgp_neighbor_config_t *
bgp_config_find_neighbor(bgp_node_config_t *cfg, const char *neighbor_addr)
{
    for (int i = 0; i < cfg->num_neighbors; i++) {
        if (strcmp(cfg->neighbors[i].neighbor_address, neighbor_addr) == 0) {
            return &cfg->neighbors[i];
        }
    }
    return NULL;
}

static sf_gobgp_rpc_result_t
bgp_apply_neighbor_address_families(
    sf_gobgp_grpc_client_t *client,
    bgp_neighbor_config_t *nbr,
    const char *local_address)
{
    return sf_gobgp_apply_neighbor_address_families(
        client,
        nbr->neighbor_address,
        nbr->peer_asn,
        local_address,
        nbr->ipv4_unicast,
        nbr->ipv4_vpn,
        nbr->l2vpn_evpn);
}

static void
bgp_on_neighbor_af_disabled(node_t *node, int afi, int safi)
{
    if (!bgp_route_is_af_enabled_on_any_neighbor(node, afi, safi)) {
        bgp_route_withdraw_originated_routes(node, afi, safi);
        bgp_global_rib_af_disable(node, afi, safi);
    }
}

static bgp_neighbor_config_t *
bgp_config_add_neighbor(bgp_node_config_t *cfg, const char *neighbor_addr)
{
    bgp_neighbor_config_t *nbr = bgp_config_find_neighbor(cfg, neighbor_addr);

    if (nbr) {
        return nbr;
    }

    if (cfg->num_neighbors >= SF_GOBGP_MAX_PEERS) {
        return NULL;
    }

    nbr = &cfg->neighbors[cfg->num_neighbors++];
    memset(nbr, 0, sizeof(*nbr));
    strncpy(nbr->neighbor_address, neighbor_addr,
            sizeof(nbr->neighbor_address) - 1);
    return nbr;
}

static void
bgp_config_remove_neighbor(bgp_node_config_t *cfg, const char *neighbor_addr)
{
    for (int i = 0; i < cfg->num_neighbors; i++) {
        if (strcmp(cfg->neighbors[i].neighbor_address, neighbor_addr) != 0) {
            continue;
        }

        for (int j = i + 1; j < cfg->num_neighbors; j++) {
            cfg->neighbors[j - 1] = cfg->neighbors[j];
        }
        cfg->num_neighbors--;
        return;
    }
}

static void
bgp_config_store_global(bgp_node_config_t *cfg,
                        uint32_t local_asn,
                        const char *router_id)
{
    cfg->started = true;
    cfg->local_asn = local_asn;
    strncpy(cfg->router_id, router_id, sizeof(cfg->router_id) - 1);
    cfg->router_id[sizeof(cfg->router_id) - 1] = '\0';
}

static void
bgp_config_clear_global(bgp_node_config_t *cfg)
{
    cfg->started = false;
}

static void
bgp_print_rpc_error(node_t *node, const char *op,
                    const sf_gobgp_rpc_result_t *result)
{
    unsigned int grpc_port = node->udp_port_number + 1000;
    unsigned int pprof_port = node->udp_port_number + 1001;

    cprintf("%s failed: %s\n", op, result->message);

    if (strstr(result->message, "connect") ||
        strstr(result->message, "Connection refused") ||
        strstr(result->message, "UNAVAILABLE")) {
        cprintf("Hint: each node needs its own gobgpd process.\n");
        cprintf("Start gobgpd for node %s in another terminal:\n",
                node->node_name);
        cprintf("  sudo ./gobgpd --api-hosts=127.0.0.1:%u "
                "--pprof-host=127.0.0.1:%u --log-level=debug\n",
                grpc_port, pprof_port);
    }
}

static const char *
bgp_session_state_str(int state)
{
    switch (state) {
        case 0: return "UNSPECIFIED";
        case 1: return "IDLE";
        case 2: return "CONNECT";
        case 3: return "ACTIVE";
        case 4: return "OPENSENT";
        case 5: return "OPENCONFIRM";
        case 6: return "ESTABLISHED";
        default: return "UNKNOWN";
    }
}

static const char *
bgp_peer_af_str(int afi, int safi)
{
    if (afi == AFI_IPV4 && safi == SAFI_UNICAST) {
        return IPV4_UNICAST_AF_STR;
    }
    if (afi == AFI_IPV4 && safi == SAFI_MPLS_VPN) {
        return VPNV4_UNICAST_AF_STR;
    }
    if (afi == AFI_IPV6 && safi == SAFI_UNICAST) {
        return IPV6_UNICAST_AF_STR;
    }
    if (afi == AFI_L2VPN && safi == SAFI_MPLS_EVPN) {
        return L2VPN_EVPN_AF_STR;
    }
    return "unknown";
}

static const char *
bgp_peer_af_status_str(const sf_gobgp_peer_afi_safi_info_t *af)
{
    if (af->enabled) {
        return "active";
    }
    if (af->configured) {
        return "configured";
    }
    return "inactive";
}

static void
bgp_format_peer_uptime(const sf_gobgp_peer_info_t *peer,
                       char *buf,
                       size_t buflen)
{
    byte time_str[HRS_MIN_SEC_FMT_TIME_LEN];

    if (!peer->uptime_valid) {
        snprintf(buf, buflen, "-");
        return;
    }

    hrs_min_sec_format((unsigned int)peer->uptime_seconds,
                       time_str, sizeof(time_str));
    snprintf(buf, buflen, "%s", (char *)time_str);
}

static void
bgp_show_peer_address_families(const sf_gobgp_peer_info_t *peer)
{
    if (peer->num_afi_safis == 0) {
        cprintf("  Address-Families : none configured\n");
        return;
    }

    cprintf("\n  Address-Family       Status       PfxRcd     PfxAcc     PfxAdv\n");
    cprintf("  ----------------     ------       ------     ------     ------\n");

    for (int j = 0; j < peer->num_afi_safis; j++) {
        const sf_gobgp_peer_afi_safi_info_t *af = &peer->afi_safis[j];

        cprintf("  %-20s %-12s %-10llu %-10llu %-10llu\n",
                bgp_peer_af_str(af->afi, af->safi),
                bgp_peer_af_status_str(af),
                (unsigned long long)af->received,
                (unsigned long long)af->accepted,
                (unsigned long long)af->advertised);
    }
}

static void
bgp_monitor_recv_route_processing_cbk(const bgp_unified_rt_t *route,
                              bool is_withdraw,
                              void *userdata);

/* Before firing any BGP config, make sure goBGP gRPC Server is running 
    run this command in separate terminal : 
    sudo ./gobgpd --api-hosts=127.0.0.1:22000 --pprof-host=127.0.0.1:22001 --log-level=debug
    sudo ./gobgpd --api-hosts=127.0.0.1:23000 --pprof-host=127.0.0.1:23001 --log-level=debug
    sudo ./gobgpd --api-hosts=127.0.0.1:24000 --pprof-host=127.0.0.1:24001 --log-level=debug
        - gRPC Server - UDP port No + 1000
        - pprof host number = UDP port No + 1001
*/
static int
bgp_config_handler(int64_t cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable)
{
    node_t *node = NULL;
    c_string node_name = NULL;
    c_string neighbor_addr = NULL;
    uint32_t peer_asn = 0;
    uint32_t local_asn = 0;
    c_string router_id = NULL;
    bool peer_asn_present = false;
    bool local_asn_present = false;
    tlv_struct_t *tlv = NULL;
    c_string vrf_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "bgp-local-asn")) {
            local_asn = (uint32_t)atoi((const char *)tlv->value);
            local_asn_present = true;
        }
        else if (parser_match_leaf_id(tlv->leaf_id, "bgp-router-id"))
            router_id = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "bgp-neighbor-addr"))
            neighbor_addr = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "bgp-peer-asn")) {
            peer_asn = (uint32_t)atoi((const char *)tlv->value);
            peer_asn_present = true;
        }
        else if (parser_match_leaf_id(tlv->leaf_id, "vrf-name"))
            vrf_name = tlv->value;

    } TLV_LOOP_END;

    if (vrf_name) {
        cprintf("Error : BGP Protocol is supported only in default VRF\n");
        return -1;
    }

    node = node_get_node_by_name(topo, node_name);

    sf_gobgp_rpc_result_t result;
    bgp_node_config_t *cfg = nullptr;
    sf_gobgp_grpc_client_t *client = nullptr;

    switch (cmdcode) {

        case CMDCODE_CONFIG_BGP_START:
        {
            /* Intermediate leaf also carries this cmd-code; skip when the
             * command continues into neighbor / address-family. */
            if (neighbor_addr) {
                break;
            }

            if (!local_asn_present) {
                cprintf("Error : AS number required\n");
                return -1;
            }

            const char *rid = router_id ? (const char *)router_id
                                         : (const char *)NODE_RTRID_ADDR(node);

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                {
                    if (!BGP_INST(node)) {
                        ((def_vrf_t *)NODE_DEF_VRF(node))->bgp_inst = bgp_init(node);
                    }

                    cfg = bgp_config_get(node);
                    client = bgp_get_grpc_client(node);

                    if (cfg->started &&
                        cfg->local_asn == local_asn &&
                        strcmp(cfg->router_id, rid) == 0) {
                        cprintf("BGP already configured: AS %u, router-id %s\n",
                                local_asn, rid);
                        break;
                    }

                    if (!client) {
                        cprintf("Error : Failed to create gRPC client\n");
                        return -1;
                    }

                    result = sf_gobgp_start_bgp(client, local_asn,
                                                rid, -1);
                    if (!result.ok) {
                        bgp_print_rpc_error(node, "BGP start", &result);
                        return -1;
                    }
                    bgp_config_store_global(cfg, local_asn, rid);
                    if (bgp_global_rib_af_enable(
                            node, AFI_IPV4, SAFI_UNICAST,
                            bgp_global_rib_export_ipv4_unicast_route_cb) != 0) {
                        cprintf("Error : Failed to initialize IPv4 unicast global RIB\n");
                        return -1;
                    }
                    assert (!bgp_node_monitor_start(node));
                    cprintf("BGP started: AS %u, router-id %s (listen %s:179)\n",
                            local_asn, rid, rid);
                }
                break;

                case CONFIG_DISABLE:
                {
                    if (!BGP_INST(node)) {
                        cprintf("BGP is not running\n");
                        break;
                    }

                    bgp_node_config_t *cfg = bgp_config_get(node);
                    if (!cfg->started) {
                        cprintf("BGP is not running\n");
                        break;
                    }

                    assert (!bgp_node_monitor_stop(node));

                    sf_gobgp_grpc_client_t *client = bgp_get_grpc_client(node);
                    if (client) {
                        result = sf_gobgp_stop_bgp(client);
                        if (!result.ok) {
                            bgp_print_rpc_error(node, "BGP stop", &result);
                            return -1;
                        }
                        sf_gobgp_grpc_client_destroy(client);
                    }

                    bgp_deinit(BGP_INST(node));
                    free(BGP_INST(node));
                    BGP_INST(node) = nullptr;
                    cprintf("BGP stopped\n");
                }
                break;

                default:
                    break;
            }
        }
        break;

        case CMDCODE_CONFIG_BGP_NEIGHBOR:
        {
            if (!neighbor_addr) {
                cprintf("Error : Neighbor address required\n");
                return -1;
            }

            if (!BGP_INST(node)) {
                cprintf("Error : BGP is not running\n");
                return -1;
            }

            cfg = bgp_config_get(node);
            client = bgp_get_grpc_client(node);

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    if (!peer_asn_present) {
                        cprintf("Error : Peer AS number required\n");
                        return -1;
                    }
                    {
                        bgp_neighbor_config_t *nbr =
                            bgp_config_find_neighbor(cfg,
                                                     (const char *)neighbor_addr);
                        if (nbr && nbr->configured &&
                            nbr->peer_asn == peer_asn) {
                            cprintf("BGP neighbor %s AS %u already configured\n",
                                    neighbor_addr, peer_asn);
                            break;
                        }
                    }
                    result = sf_gobgp_add_peer(client,
                                               (const char *)neighbor_addr,
                                               peer_asn,
                                               (const char *)NODE_RTRID_ADDR(node),
                                               false,
                                               false);
                    if (!result.ok) {
                        bgp_print_rpc_error(node, "Add peer", &result);
                        return -1;
                    }
                    {
                        bgp_neighbor_config_t *nbr =
                            bgp_config_add_neighbor(cfg,
                                                    (const char *)neighbor_addr);
                        if (!nbr) {
                            cprintf("Error : BGP neighbor table full\n");
                            return -1;
                        }
                        nbr->peer_asn = peer_asn;
                        nbr->configured = true;
                    }
                    cprintf("BGP neighbor %s AS %u added\n",
                            neighbor_addr, peer_asn);
                    break;

                case CONFIG_DISABLE:
                    if (!bgp_config_find_neighbor(cfg,
                                                  (const char *)neighbor_addr)) {
                        cprintf("BGP neighbor %s is not configured\n",
                                neighbor_addr);
                        break;
                    }
                    result = sf_gobgp_remove_peer(client,
                                                  (const char *)neighbor_addr);
                    if (!result.ok) {
                        bgp_print_rpc_error(node, "Remove peer", &result);
                        return -1;
                    }
                    bgp_config_remove_neighbor(cfg,
                                                 (const char *)neighbor_addr);
                    cprintf("BGP neighbor %s removed\n", neighbor_addr);
                    break;

                default:
                    break;
            }
        }
        break;

        case CMDCODE_CONFIG_BGP_NEIGHBOR_AF_IPV4:
        {
            bgp_neighbor_config_t *nbr;

            if (!neighbor_addr) {
                cprintf("Error : Neighbor address required\n");
                return -1;
            }

            if (!BGP_INST(node)) {
                cprintf("Error : BGP is not running\n");
                return -1;
            }

            cfg = bgp_config_get(node);
            client = bgp_get_grpc_client(node);

            /* AF CLI has no remote-as leaf — reuse ASN from the
             * already-configured neighbor (or from TLV if present). */
            nbr = bgp_config_find_neighbor(cfg, (const char *)neighbor_addr);
            if (!peer_asn_present) {
                if (!nbr || !nbr->configured) {
                    cprintf("Error : Neighbor %s is not configured; "
                            "configure remote-as first\n",
                            neighbor_addr);
                    return -1;
                }
                peer_asn = nbr->peer_asn;
            }

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    if (nbr && nbr->configured &&
                        nbr->peer_asn == peer_asn &&
                        nbr->ipv4_unicast) {
                        cprintf("IPv4 unicast already enabled for neighbor %s\n",
                                neighbor_addr);
                        break;
                    }
                    nbr = bgp_config_add_neighbor(cfg,
                                                  (const char *)neighbor_addr);
                    if (!nbr) {
                        cprintf("Error : BGP neighbor table full\n");
                        return -1;
                    }
                    nbr->peer_asn = peer_asn;
                    nbr->configured = true;
                    nbr->ipv4_unicast = true;
                    result = bgp_apply_neighbor_address_families(
                        client, nbr, (const char *)NODE_RTRID_ADDR(node));
                    if (!result.ok) {
                        bgp_print_rpc_error(node, "Enable IPv4 unicast",
                                            &result);
                        return -1;
                    }
                    if (bgp_global_rib_af_enable(
                            node, AFI_IPV4, SAFI_UNICAST,
                            bgp_global_rib_export_ipv4_unicast_route_cb) != 0) {
                        cprintf("Error : Failed to initialize IPv4 unicast global RIB\n");
                        return -1;
                    }
                    cprintf("IPv4 unicast enabled for neighbor %s\n",
                            neighbor_addr);
                    break;

                case CONFIG_DISABLE:
                    if (!nbr || !nbr->configured || !nbr->ipv4_unicast) {
                        cprintf("IPv4 unicast is not enabled for neighbor %s\n",
                                neighbor_addr);
                        break;
                    }
                    nbr->ipv4_unicast = false;
                    result = bgp_apply_neighbor_address_families(
                        client, nbr, (const char *)NODE_RTRID_ADDR(node));
                    if (!result.ok) {
                        bgp_print_rpc_error(node, "Disable IPv4 unicast",
                                            &result);
                        return -1;
                    }
                    bgp_on_neighbor_af_disabled(node, AFI_IPV4, SAFI_UNICAST);
                    cprintf("IPv4 unicast disabled for neighbor %s\n",
                            neighbor_addr);
                    break;

                default:
                    break;
            }
        }
        break;

        case CMDCODE_CONFIG_BGP_NEIGHBOR_AF_IPV4_VPN:
        {
            bgp_neighbor_config_t *nbr;

            if (!neighbor_addr) {
                cprintf("Error : Neighbor address required\n");
                return -1;
            }

            if (!BGP_INST(node)) {
                cprintf("Error : BGP is not running\n");
                return -1;
            }

            cfg = bgp_config_get(node);
            client = bgp_get_grpc_client(node);

            nbr = bgp_config_find_neighbor(cfg, (const char *)neighbor_addr);
            if (!peer_asn_present) {
                if (!nbr || !nbr->configured) {
                    cprintf("Error : Neighbor %s is not configured; "
                            "configure remote-as first\n",
                            neighbor_addr);
                    return -1;
                }
                peer_asn = nbr->peer_asn;
            }

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    if (nbr && nbr->configured &&
                        nbr->peer_asn == peer_asn &&
                        nbr->ipv4_vpn) {
                        cprintf("%s already enabled for neighbor %s\n",
                                VPNV4_UNICAST_AF_STR, neighbor_addr);
                        break;
                    }
                    nbr = bgp_config_add_neighbor(cfg,
                                                  (const char *)neighbor_addr);
                    if (!nbr) {
                        cprintf("Error : BGP neighbor table full\n");
                        return -1;
                    }
                    nbr->peer_asn = peer_asn;
                    nbr->configured = true;
                    nbr->ipv4_vpn = true;
                    result = bgp_apply_neighbor_address_families(
                        client, nbr, (const char *)NODE_RTRID_ADDR(node));
                    if (!result.ok) {
                        bgp_print_rpc_error(node, "Enable IPv4 VPN",
                                            &result);
                        return -1;
                    }
                    if (bgp_global_rib_af_enable(node, AFI_IPV4,
                                                 SAFI_MPLS_VPN, 
                                                 bgp_global_rib_export_vpnv4_route_cb) != 0) {
                        cprintf("Error : Failed to initialize %s global RIB\n",
                                VPNV4_UNICAST_AF_STR);
                        return -1;
                    }
                    if (!cfg->monitor.running &&
                        bgp_node_monitor_start(node) != 0) {
                        cprintf("Error : Failed to start BGP monitor\n");
                        return -1;
                    }
                    cprintf("%s enabled for neighbor %s\n",
                            VPNV4_UNICAST_AF_STR, neighbor_addr);
                    break;

                case CONFIG_DISABLE:
                    if (!nbr || !nbr->configured || !nbr->ipv4_vpn) {
                        cprintf("%s is not enabled for neighbor %s\n",
                                VPNV4_UNICAST_AF_STR, neighbor_addr);
                        break;
                    }
                    nbr->ipv4_vpn = false;
                    result = bgp_apply_neighbor_address_families(
                        client, nbr, (const char *)NODE_RTRID_ADDR(node));
                    if (!result.ok) {
                        bgp_print_rpc_error(node, "Disable IPv4 VPN",
                                            &result);
                        return -1;
                    }
                    bgp_on_neighbor_af_disabled(node, AFI_IPV4, SAFI_MPLS_VPN);
                    cprintf("%s disabled for neighbor %s\n",
                            VPNV4_UNICAST_AF_STR, neighbor_addr);
                    break;

                default:
                    break;
            }
        }
        break;

        case CMDCODE_CONFIG_BGP_NEIGHBOR_AF_L2VPN_EVPN:
        {
            bgp_neighbor_config_t *nbr;

            if (!neighbor_addr) {
                cprintf("Error : Neighbor address required\n");
                return -1;
            }

            if (!BGP_INST(node)) {
                cprintf("Error : BGP is not running\n");
                return -1;
            }

            cfg = bgp_config_get(node);
            client = bgp_get_grpc_client(node);

            nbr = bgp_config_find_neighbor(cfg, (const char *)neighbor_addr);
            if (!peer_asn_present) {
                if (!nbr || !nbr->configured) {
                    cprintf("Error : Neighbor %s is not configured; "
                            "configure remote-as first\n",
                            neighbor_addr);
                    return -1;
                }
                peer_asn = nbr->peer_asn;
            }

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    if (nbr && nbr->configured &&
                        nbr->peer_asn == peer_asn &&
                        nbr->l2vpn_evpn) {
                        cprintf("%s already enabled for neighbor %s\n",
                                L2VPN_EVPN_AF_STR, neighbor_addr);
                        break;
                    }
                    nbr = bgp_config_add_neighbor(cfg,
                                                  (const char *)neighbor_addr);
                    if (!nbr) {
                        cprintf("Error : BGP neighbor table full\n");
                        return -1;
                    }
                    nbr->peer_asn = peer_asn;
                    nbr->configured = true;
                    nbr->l2vpn_evpn = true;
                    result = bgp_apply_neighbor_address_families(
                        client, nbr, (const char *)NODE_RTRID_ADDR(node));
                    if (!result.ok) {
                        bgp_print_rpc_error(node, "Enable L2VPN EVPN",
                                            &result);
                        return -1;
                    }
                    if (bgp_global_rib_af_enable(node, AFI_L2VPN,
                                                 SAFI_MPLS_EVPN,
                                                 bgp_global_rib_export_evpn_route_cb) != 0) {
                        cprintf("Error : Failed to initialize %s global RIB\n",
                                L2VPN_EVPN_AF_STR);
                        return -1;
                    }
                    if (!cfg->monitor.running &&
                        bgp_node_monitor_start(node) != 0) {
                        cprintf("Error : Failed to start BGP monitor\n");
                        return -1;
                    }
                    cprintf("%s enabled for neighbor %s\n",
                            L2VPN_EVPN_AF_STR, neighbor_addr);
                    mac_vrf_export_all_local_evpn_routes_to_bgp(node);
                    break;

                case CONFIG_DISABLE:
                    if (!nbr || !nbr->configured || !nbr->l2vpn_evpn) {
                        cprintf("%s is not enabled for neighbor %s\n",
                                L2VPN_EVPN_AF_STR, neighbor_addr);
                        break;
                    }
                    nbr->l2vpn_evpn = false;
                    result = bgp_apply_neighbor_address_families(
                        client, nbr, (const char *)NODE_RTRID_ADDR(node));
                    if (!result.ok) {
                        bgp_print_rpc_error(node, "Disable L2VPN EVPN",
                                            &result);
                        return -1;
                    }
                    bgp_on_neighbor_af_disabled(node, AFI_L2VPN,
                                               SAFI_MPLS_EVPN);
                    cprintf("%s disabled for neighbor %s\n",
                            L2VPN_EVPN_AF_STR, neighbor_addr);
                    break;

                default:
                    break;
            }
        }
        break;

        default:
            break;
    }

    return 0;
}


typedef struct bgp_show_route_ctx_ {
    const char *afi;
    const char *safi;
    bool show_label;
    bool evpn_mac;
    bool evpn_imet;
    int count;
} bgp_show_route_ctx_t;

/* EVPN NLRI wire starts with route-type octet (RFC 7432). */
static uint8_t
bgp_show_evpn_route_type(const bgp_unified_rt_t *route)
{
    if (route && route->nlri_wire_len > 0) {
        return route->nlri_wire[0];
    }
    return 0;
}

/* GoBGP may return RD/RT already as "a.b.c.d:N", or as numeric "N:N".
 * Only convert the numeric form; never pass NULL to %s. */
static const char *
bgp_show_format_rd_rt(const char *value,
                      bool is_rd,
                      char *buf,
                      size_t buflen,
                      const char *dash)
{
    const char *converted;

    if (!value || value[0] == '\0') {
        return dash;
    }

    if (strchr(value, '.')) {
        return value;
    }

    converted = is_rd ? rd_type1_to_string(value, buf, buflen)
                      : rt_type1_to_string(value, buf, buflen);
    return converted ? converted : value;
}

static const char *
bgp_show_mac_mobility_seq(uint32_t seq,
                          bool present,
                          char *buf,
                          size_t buflen,
                          const char *dash)
{
    if (!present) {
        return dash;
    }

    snprintf(buf, buflen, "%u", seq);
    return buf;
}

static int
bgp_show_evpn_mac_route_print_cb(const bgp_unified_rt_t *route, void *userdata)
{
    bgp_show_route_ctx_t *ctx = (bgp_show_route_ctx_t *)userdata;
    const char *dash = "-";
    char rd_fmt_buffer[48];
    char rt_fmt_buffer[48];
    char seq_fmt_buffer[16];
    uint8_t rt_type;

    if (!route || !ctx) {
        return 0;
    }

    rt_type = bgp_show_evpn_route_type(route);
    if (rt_type == 3) {
        return 0;
    }
    if (rt_type == 0 && route->prefix[0] &&
        strchr(route->prefix, ':') == NULL) {
        return 0;
    }

    if (ctx->count == 0) {
        cprintf("\nBGP routes (%s %s):\n", ctx->afi, ctx->safi);
        cprintf("%-20s %-14s %-14s %-16s %-8s %-6s %-6s %-10s %s\n",
                "MAC", "RD", "RT", "Nexthop", "Label", "Seq",
                "MED", "LocalPref", "Best");
        cprintf("%-20s %-14s %-14s %-16s %-8s %-6s %-6s %-10s %s\n",
                "---", "--", "--", "-------", "-----", "---",
                "---", "---------", "----");
    }

    cprintf("%-20s %-14s %-14s %-16s ",
            route->prefix[0] ? route->prefix : dash,
            bgp_show_format_rd_rt(route->rd, true, rd_fmt_buffer,
                                  sizeof(rd_fmt_buffer), dash),
            bgp_show_format_rd_rt(route->rt, false, rt_fmt_buffer,
                                  sizeof(rt_fmt_buffer), dash),
            route->nexthop[0] ? route->nexthop : dash);

    if (route->l3_vpn_label_present) {
        cprintf("%-8u ", route->l3_vpn_label);
    } else {
        cprintf("%-8s ", dash);
    }

    cprintf("%-6s ",
            bgp_show_mac_mobility_seq(route->mac_mobility_seq,
                                      route->mac_mobility_seq_present,
                                      seq_fmt_buffer,
                                      sizeof(seq_fmt_buffer),
                                      dash));

    if (route->med_present) {
        cprintf("%-6u ", route->med);
    } else {
        cprintf("%-6s ", dash);
    }

    if (route->local_pref_present) {
        cprintf("%-10u ", route->local_pref);
    } else {
        cprintf("%-10s ", dash);
    }

    cprintf("%s\n", route->best ? "*" : "");
    ctx->count++;
    return 0;
}

static int
bgp_show_evpn_imet_route_print_cb(const bgp_unified_rt_t *route, void *userdata)
{
    bgp_show_route_ctx_t *ctx = (bgp_show_route_ctx_t *)userdata;
    const char *dash = "-";
    char rd_fmt_buffer[48];
    char rt_fmt_buffer[48];
    uint8_t rt_type;
    uint32_t bum_label = 0;
    bool bum_label_present = false;

    if (!route || !ctx) {
        return 0;
    }

    rt_type = bgp_show_evpn_route_type(route);
    if (rt_type != 0 && rt_type != 3) {
        return 0;
    }
    /* Without wire metadata, IMET prefixes are originating PE IPs. */
    if (rt_type == 0 && strchr(route->prefix, ':') != NULL) {
        return 0;
    }

    if (ctx->count == 0) {
        cprintf("\nBGP routes (%s %s):\n", ctx->afi, ctx->safi);
        cprintf("%-16s %-14s %-14s %-16s %-10s %-6s %-10s %s\n",
                "PE-Address", "RD", "RT", "Nexthop", "PMSI-Lbl",
                "MED", "LocalPref", "Best");
        cprintf("%-16s %-14s %-14s %-16s %-10s %-6s %-10s %s\n",
                "----------", "--", "--", "-------", "--------",
                "---", "---------", "----");
    }

    if (route->pmsi_label_present) {
        bum_label = route->pmsi_label;
        bum_label_present = true;
    } else if (route->l3_vpn_label_present) {
        bum_label = route->l3_vpn_label;
        bum_label_present = true;
    }

    cprintf("%-16s %-14s %-14s %-16s ",
            route->prefix[0] ? route->prefix : dash,
            bgp_show_format_rd_rt(route->rd, true, rd_fmt_buffer,
                                  sizeof(rd_fmt_buffer), dash),
            bgp_show_format_rd_rt(route->rt, false, rt_fmt_buffer,
                                  sizeof(rt_fmt_buffer), dash),
            route->nexthop[0] ? route->nexthop : dash);

    if (bum_label_present) {
        cprintf("%-10u ", bum_label);
    } else {
        cprintf("%-10s ", dash);
    }

    if (route->med_present) {
        cprintf("%-6u ", route->med);
    } else {
        cprintf("%-6s ", dash);
    }

    if (route->local_pref_present) {
        cprintf("%-10u ", route->local_pref);
    } else {
        cprintf("%-10s ", dash);
    }

    cprintf("%s\n", route->best ? "*" : "");
    ctx->count++;
    return 0;
}

static int
bgp_show_route_print_cb(const bgp_unified_rt_t *route, void *userdata)
{
    bgp_show_route_ctx_t *ctx = (bgp_show_route_ctx_t *)userdata;
    const char *dash = "-";
    char rd_fmt_buffer[48];
    char rt_fmt_buffer[48];

    if (!route || !ctx) {
        return 0;
    }

    if (ctx->evpn_mac) {
        return bgp_show_evpn_mac_route_print_cb(route, userdata);
    }

    if (ctx->evpn_imet) {
        return bgp_show_evpn_imet_route_print_cb(route, userdata);
    }

    if (ctx->count == 0) {
        cprintf("\nBGP routes (%s %s):\n", ctx->afi, ctx->safi);
        if (ctx->show_label) {
            cprintf("%-22s %-16s %-14s %-14s %-8s %-6s %-10s %s\n",
                    "Prefix", "Nexthop", "RD", "RT", "Label",
                    "MED", "LocalPref", "Best");
            cprintf("%-22s %-16s %-14s %-14s %-8s %-6s %-10s %s\n",
                    "------", "-------", "--", "--", "-----",
                    "---", "---------", "----");
        } else {
            cprintf("%-22s %-16s %-14s %-14s %-6s %-10s %s\n",
                    "Prefix", "Nexthop", "RD", "RT",
                    "MED", "LocalPref", "Best");
            cprintf("%-22s %-16s %-14s %-14s %-6s %-10s %s\n",
                    "------", "-------", "--", "--",
                    "---", "---------", "----");
        }
    }

    cprintf("%-22s %-16s %-14s %-14s ",
            route->prefix,
            route->nexthop[0] ? route->nexthop : dash,
            bgp_show_format_rd_rt(route->rd, true, rd_fmt_buffer,
                                  sizeof(rd_fmt_buffer), dash),
            bgp_show_format_rd_rt(route->rt, false, rt_fmt_buffer,
                                  sizeof(rt_fmt_buffer), dash));

    if (ctx->show_label) {
        if (route->l3_vpn_label_present) {
            cprintf("%-8u ", route->l3_vpn_label);
        } else {
            cprintf("%-8s ", dash);
        }
    }

    if (route->med_present) {
        cprintf("%-6u ", route->med);
    } else {
        cprintf("%-6s ", dash);
    }

    if (route->local_pref_present) {
        cprintf("%-10u ", route->local_pref);
    } else {
        cprintf("%-10s ", dash);
    }

    cprintf("%s\n", route->best ? "*" : "");
    ctx->count++;
    return 0;
}

typedef struct bgp_show_global_rib_ctx_ {
    uint8_t afi;
    uint8_t safi;
    const char *af_label;
    int count;
} bgp_show_global_rib_ctx_t;

static const char *
bgp_tunnel_encap_type_str(uint16_t tunnel_type)
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

static void
bgp_show_global_rib_print_evpn_detail(const bgp_nlri_key_t *key,
                                      const bgp_rib_attrs_t *attrs)
{
    bgp_evpn_nlri_t nlri;
    char esi_hex[21];
    uint8_t i;
    uint32_t label1 = 0;
    bool label1_present = false;

    if (!key || !attrs ||
        bgp_evpn_nlri_decode(key, &nlri) != BGP_RIB_OK) {
        return;
    }

    for (i = 0; i < 10; i++) {
        snprintf(esi_hex + (i * 2), 3, "%02x", nlri.esi[i]);
    }

    if (attrs->evpn_label1_present && attrs->evpn_label1_from_ext_comm) {
        label1 = attrs->evpn_label1;
        label1_present = true;
    } else if (nlri.label_present) {
        label1 = nlri.label;
        label1_present = true;
    }

    if (label1_present) {
        cprintf("      EVPN ESI: %s, Label1 %u\n", esi_hex, label1);
    } else {
        cprintf("      EVPN ESI: %s\n", esi_hex);
    }

    if (attrs->mac_mobility_seq_present) {
        cprintf("      MAC Mobility Sequence: %u\n",
                attrs->mac_mobility_seq);
    }

    if (attrs->tunnel_encap_present) {
        cprintf("      Tunnel Type: %s (%u)\n",
                bgp_tunnel_encap_type_str(attrs->tunnel_encap_type),
                attrs->tunnel_encap_type);
    }
}

static void
bgp_show_global_rib_print_vpn_detail(const bgp_nlri_key_t *key,
                                     const bgp_rib_attrs_t *attrs)
{
    bgp_vpnv4_nlri_t nlri;

    if (!key) {
        return;
    }

    if (bgp_vpnv4_nlri_decode(key, &nlri) == BGP_RIB_OK &&
        nlri.label_present) {
        cprintf("      Label: %u\n", nlri.label);
    }

    if (attrs && attrs->tunnel_encap_present) {
        cprintf("      Tunnel Type: %s (%u)\n",
                bgp_tunnel_encap_type_str(attrs->tunnel_encap_type),
                attrs->tunnel_encap_type);
    }
}

static void
bgp_show_global_rib_print_ext_comms(const bgp_rib_attrs_t *attrs)
{
    uint8_t i;

    if (!attrs) {
        return;
    }

    for (i = 0; i < attrs->ext_comm_count; i++) {
        const bgp_rib_ext_comm_t *ec = &attrs->ext_comms[i];

        cprintf("      Extended Community: %s (type 0x%04x subtype 0x%04x)\n",
                ec->text[0] ? ec->text : "-",
                ec->type, ec->subtype);
    }
}

static void
bgp_show_global_rib_strip_nh_mask(char *nh, size_t nhlen)
{
    char *slash;

    if (!nh || nhlen == 0) {
        return;
    }

    slash = strchr(nh, '/');
    if (slash) {
        *slash = '\0';
    }
}

static int
bgp_show_global_rib_print_cb(const bgp_nlri_key_t *key,
                             const bgp_rib_attrs_t *attrs,
                             void *userdata)
{
    bgp_show_global_rib_ctx_t *ctx =
        (bgp_show_global_rib_ctx_t *)userdata;
    char network[256];
    char nexthop[64];
    uint32_t metric = 0;
    uint32_t local_pref = 0;
    const char *path = "?";

    if (!key || !ctx) {
        return 0;
    }

    if (ctx->count == 0) {
        cprintf("\nBGP global RIB (%s):\n", ctx->af_label);
        /* Two-line route layout: Network alone, then NH/attrs indented. */
        cprintf("    %-17s %-20s %6s %6s %6s %s\n",
                "Network", "Next Hop", "Metric", "LocPrf", "Weight", "Path");
    } else {
        cprintf("\n");
    }

    if (bgp_nlri_wire_format_network(ctx->afi, ctx->safi,
                                     key, network, sizeof(network)) != 0) {
        snprintf(network, sizeof(network), "<format-error>");
    }

    nexthop[0] = '\0';
    if (attrs && attrs->nexthop[0] != '\0') {
        strncpy(nexthop, attrs->nexthop, sizeof(nexthop) - 1);
        bgp_show_global_rib_strip_nh_mask(nexthop, sizeof(nexthop));
    }

    if (attrs) {
        if (attrs->med_present) {
            metric = attrs->med;
        }
        if (attrs->local_pref_present) {
            local_pref = attrs->local_pref;
        }
        if (!attrs->is_from_external) {
            path = "i";
        }
    }

    cprintf("  %s\n", network);
    cprintf("                      %-20s %6u %6u %6u %s\n",
            nexthop[0] ? nexthop : "-",
            metric, local_pref, 0U, path);

    if (attrs) {
        if (ctx->safi == SAFI_MPLS_EVPN) {
            bgp_show_global_rib_print_evpn_detail(key, attrs);
        } else if (ctx->safi == SAFI_MPLS_VPN) {
            bgp_show_global_rib_print_vpn_detail(key, attrs);
        } else if (attrs->tunnel_encap_present) {
            cprintf("      Tunnel Type: %s (%u)\n",
                    bgp_tunnel_encap_type_str(attrs->tunnel_encap_type),
                    attrs->tunnel_encap_type);
        }
        bgp_show_global_rib_print_ext_comms(attrs);
    }

    ctx->count++;
    return 0;
}

static int
bgp_show_global_rib(node_t *node, int afi, int safi, const char *af_label)
{
    bgp_rib_t *rib;
    bgp_show_global_rib_ctx_t ctx;

    if (!BGP_INST(node)) {
        cprintf("Error : BGP is not running on %s\n", node->node_name);
        return -1;
    }

    rib = bgp_global_rib_get(node, afi, safi);
    if (!rib) {
        cprintf("BGP global RIB for %s is not initialized\n", af_label);
        return 0;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.afi = (uint8_t)afi;
    ctx.safi = (uint8_t)safi;
    ctx.af_label = af_label;

    bgp_rib_route_walk(rib, bgp_show_global_rib_print_cb, &ctx);

    if (ctx.count == 0) {
        cprintf("No routes in BGP global RIB for %s\n", af_label);
    } else {
        cprintf("\nTotal routes: %u\n", bgp_rib_route_count(rib));
    }

    return 0;
}

static int
bgp_show_routes(node_t *node, const char *afi, const char *safi)
{
    bgp_show_route_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.afi = afi;
    ctx.safi = safi;
    ctx.show_label = (safi && strcmp(safi, "vpn") == 0);
    ctx.evpn_mac = (afi && strcmp(afi, "l2vpn-evpn") == 0 &&
                    safi && strcmp(safi, "mac") == 0);
    ctx.evpn_imet = (afi && strcmp(afi, "l2vpn-evpn") == 0 &&
                     safi && strcmp(safi, "imet") == 0);

    if (bgp_node_walk_routes(node, afi, safi, bgp_show_route_print_cb, &ctx) != 0) {
        cprintf("ListPath RPC failed for %s %s\n", afi, safi);
        return -1;
    }

    if (ctx.count == 0) {
        cprintf("No BGP routes found for %s %s\n", afi, safi);
    }

    return 0;
}

/* Cisco-style hierarchical dump of local bgp_node_config_t. */
static void
bgp_show_running_config(node_t *node)
{
    bgp_node_config_t *cfg;
    int i;
    int af_ipv4_printed = 0;
    int af_ipv4_vpn_printed = 0;
    int af_l2vpn_evpn_printed = 0;

    cfg = bgp_config_get(node);
    if (!cfg || !cfg->started) {
        cprintf("BGP is not configured on node %s\n", node->node_name);
        return;
    }

    cprintf("!\n");
    cprintf("router bgp %u\n", cfg->local_asn);
    if (cfg->router_id[0] != '\0') {
        cprintf(" bgp router-id %s\n", cfg->router_id);
    }

    for (i = 0; i < cfg->num_neighbors; i++) {
        bgp_neighbor_config_t *nbr = &cfg->neighbors[i];

        if (!nbr->configured) {
            continue;
        }
        cprintf(" neighbor %s remote-as %u\n",
                nbr->neighbor_address, nbr->peer_asn);
    }

    for (i = 0; i < cfg->num_neighbors; i++) {
        bgp_neighbor_config_t *nbr = &cfg->neighbors[i];

        if (!nbr->configured || !nbr->ipv4_unicast) {
            continue;
        }
        if (!af_ipv4_printed) {
            cprintf(" !\n");
            cprintf(" address-family ipv4\n");
            af_ipv4_printed = 1;
        }
        cprintf("  neighbor %s activate\n", nbr->neighbor_address);
    }
    if (af_ipv4_printed) {
        cprintf(" exit-address-family\n");
    }

    for (i = 0; i < cfg->num_neighbors; i++) {
        bgp_neighbor_config_t *nbr = &cfg->neighbors[i];

        if (!nbr->configured || !nbr->ipv4_vpn) {
            continue;
        }
        if (!af_ipv4_vpn_printed) {
            cprintf(" !\n");
            cprintf(" address-family ipv4-vpn\n");
            af_ipv4_vpn_printed = 1;
        }
        cprintf("  neighbor %s activate\n", nbr->neighbor_address);
    }
    if (af_ipv4_vpn_printed) {
        cprintf(" exit-address-family\n");
    }

    for (i = 0; i < cfg->num_neighbors; i++) {
        bgp_neighbor_config_t *nbr = &cfg->neighbors[i];

        if (!nbr->configured || !nbr->l2vpn_evpn) {
            continue;
        }
        if (!af_l2vpn_evpn_printed) {
            cprintf(" !\n");
            cprintf(" address-family %s\n", L2VPN_EVPN_AF_STR);
            af_l2vpn_evpn_printed = 1;
        }
        cprintf("  neighbor %s activate\n", nbr->neighbor_address);
    }
    if (af_l2vpn_evpn_printed) {
        cprintf(" exit-address-family\n");
    }

    cprintf("!\n");
}

static int
bgp_show_handler(int64_t cmdcode,
                 Stack_t *tlv_stack,
                 op_mode enable_or_disable)
{
    node_t *node = NULL;
    c_string node_name = NULL;
    tlv_struct_t *tlv = NULL;

    (void)enable_or_disable;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    if (!node) {
        cprintf("Error : Node not found\n");
        return -1;
    }

    if (cmdcode == CMDCODE_SHOW_BGP_RUNNING_CONFIG) {
        bgp_show_running_config(node);
        return 0;
    }

    switch (cmdcode) {
        case CMDCODE_SHOW_BGP_GLOBAL_RIB_IPV4_VPN:
            return bgp_show_global_rib(node, AFI_IPV4, SAFI_MPLS_VPN,
                                       "ipv4-vpn");

        case CMDCODE_SHOW_BGP_GLOBAL_RIB_L2VPN_EVPN:
            return bgp_show_global_rib(node, AFI_L2VPN, SAFI_MPLS_EVPN,
                                       "l2vpn-evpn");

        default:
            break;
    }

    sf_gobgp_grpc_client_t *client = bgp_get_grpc_client(node);
    if (!client) {
        cprintf("Error : Failed to create gRPC client\n");
        return -1;
    }

    switch (cmdcode) {

        case CMDCODE_SHOW_BGP_PEERS:
        {
            sf_gobgp_peer_info_t peers[SF_GOBGP_MAX_PEERS];
            int num_peers = 0;

            sf_gobgp_rpc_result_t result =
                sf_gobgp_list_peers(client, peers, SF_GOBGP_MAX_PEERS,
                                    &num_peers);
            if (!result.ok) {
                cprintf("ListPeer RPC failed: %s\n", result.message);
                return -1;
            }

            if (num_peers == 0) {
                cprintf("No BGP peers configured\n");
                return 0;
            }

            cprintf("\n%-20s %-10s %-16s %-14s %-14s %s\n",
                    "Neighbor", "AS", "Router-ID",
                    "State", "Uptime", "Description");
            cprintf("%-20s %-10s %-16s %-14s %-14s %s\n",
                    "--------", "--", "---------",
                    "-----", "------", "-----------");

            for (int i = 0; i < num_peers; i++) {
                char uptime_str[32];

                bgp_format_peer_uptime(&peers[i], uptime_str, sizeof(uptime_str));
                cprintf("%-20s %-10u %-16s %-14s %-14s %s\n",
                        peers[i].neighbor_address,
                        peers[i].peer_asn,
                        peers[i].router_id,
                        bgp_session_state_str(peers[i].session_state),
                        uptime_str,
                        peers[i].description);
                bgp_show_peer_address_families(&peers[i]);
                if (i + 1 < num_peers) {
                    cprintf("\n");
                }
            }
        }
        break;

        case CMDCODE_SHOW_BGP_SUMMARY:
        {
            sf_gobgp_global_info_t info;
            memset(&info, 0, sizeof(info));

            sf_gobgp_rpc_result_t result = sf_gobgp_get_bgp(client, &info);
            if (!result.ok) {
                cprintf("GetBgp RPC failed: %s\n", result.message);
                return -1;
            }

            cprintf("\nBGP Global Configuration:\n");
            cprintf("  Local AS      : %u\n", info.asn);
            cprintf("  Router ID     : %s\n", info.router_id);
            cprintf("  Listen Port   : %d\n", info.listen_port);

            sf_gobgp_peer_info_t peers[SF_GOBGP_MAX_PEERS];
            int num_peers = 0;

            result = sf_gobgp_list_peers(client, peers, SF_GOBGP_MAX_PEERS,
                                         &num_peers);
            if (!result.ok) {
                cprintf("ListPeer RPC failed: %s\n", result.message);
                return -1;
            }

            cprintf("  Total Peers   : %d\n\n", num_peers);

            if (num_peers > 0) {
                cprintf("%-20s %-10s %-16s %-14s\n",
                        "Neighbor", "AS", "Router-ID", "State");
                cprintf("%-20s %-10s %-16s %-14s\n",
                        "--------", "--", "---------", "-----");

                for (int i = 0; i < num_peers; i++) {
                    cprintf("%-20s %-10u %-16s %-14s\n",
                            peers[i].neighbor_address,
                            peers[i].peer_asn,
                            peers[i].router_id,
                            bgp_session_state_str(peers[i].session_state));
                }
            }
        }
        break;

        case CMDCODE_SHOW_BGP_ROUTES_IPV4_UNICAST:
            return bgp_show_routes(node, "ipv4", "unicast");

        case CMDCODE_SHOW_BGP_ROUTES_IPV4_MPLS_VPN:
            return bgp_show_routes(node, "ipv4", "vpn");

        case CMDCODE_SHOW_BGP_ROUTES_IPV6_UNICAST:
            return bgp_show_routes(node, "ipv6", "unicast");

        case CMDCODE_SHOW_BGP_ROUTES_L2VPN_EVPN_MAC:
            return bgp_show_routes(node, "l2vpn-evpn", "mac");

        case CMDCODE_SHOW_BGP_ROUTES_L2VPN_EVPN_IMET:
            return bgp_show_routes(node, "l2vpn-evpn", "imet");

        default:
            break;
    }

    return 0;
}

/* config node <node-name> protocol bgp <local-asn> [router-id <router-id>]
 * config node <node-name> protocol bgp <local-asn> neighbor <neighbor-addr> remote-as <peer-asn>
 * config node <node-name> protocol bgp <local-asn> neighbor <neighbor-addr> address-family ipv4-unicast
 *
 * All support [no] negation.
 */
int
bgp_config_cli_tree(param_t *param)
{
    {
        /* config node <node-name> protocol bgp */
        static param_t bgp;
        init_param(&bgp, CMD, "bgp", 0, 0, INVALID, 0, "BGP protocol");
        libcli_register_param(param, &bgp);

        {
            /* config node <node-name> protocol bgp <local-asn> */
            static param_t local_asn;
            init_param(&local_asn, LEAF, NULL, bgp_config_handler,
                       0, INT, "bgp-local-asn",
                       "Local AS number (1-4294967295)");
            libcli_register_param(&bgp, &local_asn);
            libcli_set_param_cmd_code(&local_asn, CMDCODE_CONFIG_BGP_START);
            //libcli_disable_batch_processing(&local_asn);

            {
                /* config node <node-name> protocol bgp <local-asn> router-id <router-id> */
                static param_t router_id_kw;
                init_param(&router_id_kw, CMD, "router-id", 0, 0,
                           INVALID, 0, "BGP Router ID");
                libcli_register_param(&local_asn, &router_id_kw);
                {
                    static param_t router_id_val;
                    init_param(&router_id_val, LEAF, NULL,
                               bgp_config_handler, 0, IPV4,
                               "bgp-router-id", "Router ID (IPv4 format)");
                    libcli_register_param(&router_id_kw, &router_id_val);
                    libcli_set_param_cmd_code(&router_id_val,
                                              CMDCODE_CONFIG_BGP_START);
                    //libcli_disable_batch_processing(&router_id_val);
                }
            }

            {
                /* config node <node-name> protocol bgp <local-asn> neighbor <addr> ... */
                static param_t neighbor_kw;
                init_param(&neighbor_kw, CMD, "neighbor", 0, 0,
                           INVALID, 0, "BGP neighbor");
                libcli_register_param(&local_asn, &neighbor_kw);
                {
                    static param_t neighbor_addr;
                    init_param(&neighbor_addr, LEAF, NULL, 0, 0,
                               IPV4, "bgp-neighbor-addr",
                               "Neighbor IPv4 address");
                    libcli_register_param(&neighbor_kw, &neighbor_addr);
                    {
                        /* ... remote-as <peer-asn> */
                        static param_t remote_as_kw;
                        init_param(&remote_as_kw, CMD, "remote-as", 0, 0,
                                   INVALID, 0, "Remote AS number");
                        libcli_register_param(&neighbor_addr, &remote_as_kw);
                        {
                            static param_t peer_asn;
                            init_param(&peer_asn, LEAF, NULL,
                                       bgp_config_handler, 0, INT,
                                       "bgp-peer-asn",
                                       "Peer AS number (1-4294967295)");
                            libcli_register_param(&remote_as_kw, &peer_asn);
                            libcli_set_param_cmd_code(
                                &peer_asn, CMDCODE_CONFIG_BGP_NEIGHBOR);
                        }
                    }
                    {
                        /* ... address-family ipv4-unicast */
                        static param_t af_kw;
                        init_param(&af_kw, CMD, "address-family",
                                   0, 0, INVALID, 0,
                                   "Address family");
                        libcli_register_param(&neighbor_addr, &af_kw);
                        {
                            static param_t ipv4_uni;
                            init_param(&ipv4_uni, CMD,
                                       IPV4_UNICAST_AF_STR,
                                       bgp_config_handler,
                                       0, INVALID, 0,
                                       "IPv4 Unicast AF");
                            libcli_register_param(&af_kw, &ipv4_uni);
                            libcli_set_param_cmd_code(
                                &ipv4_uni,
                                CMDCODE_CONFIG_BGP_NEIGHBOR_AF_IPV4);
                            {
                                rtm_build_distribution_policy_cli_tree(&ipv4_uni, RTM_PROTO_BGP);
                            }
                        }
                        {
                            static param_t ipv4_vpn;
                            init_param(&ipv4_vpn, CMD,
                                       "ipv4-vpn",
                                       bgp_config_handler,
                                       0, INVALID, 0,
                                       "IPv4 VPN AF");
                            libcli_register_param(&af_kw, &ipv4_vpn);
                            libcli_set_param_cmd_code(
                                &ipv4_vpn,
                                CMDCODE_CONFIG_BGP_NEIGHBOR_AF_IPV4_VPN);
                            {
                                rtm_build_distribution_policy_cli_tree(&ipv4_vpn, RTM_PROTO_BGP);
                            }
                        }

                        {
                            static param_t l2vpn_evpn;
                            init_param(&l2vpn_evpn, CMD,
                                       "l2vpn-evpn",
                                       bgp_config_handler,
                                       0, INVALID, 0,
                                       "L2VPN EVPN AF");
                            libcli_register_param(&af_kw, &l2vpn_evpn);
                            libcli_set_param_cmd_code(
                                &l2vpn_evpn,
                                CMDCODE_CONFIG_BGP_NEIGHBOR_AF_L2VPN_EVPN);
                        }                        
                    }
                }
            }
        }
    }

    return 0;
}

/*
 * show node <node-name> protocol bgp peers
 * show node <node-name> protocol bgp summary
 * show node <node-name> protocol bgp running-config
 * show node <node-name> protocol bgp routes <afi> <safi>
 * show node <node-name> protocol bgp routes l2vpn-evpn mac
 * show node <node-name> protocol bgp routes l2vpn-evpn imet
 * show node <node-name> protocol bgp global-rib <ipv4-vpn|l2vpn-evpn>
 */
int
bgp_show_cli_tree(param_t *param)
{
    {
        static param_t bgp;
        init_param(&bgp, CMD, "bgp", 0, 0, INVALID, 0, "BGP protocol");
        libcli_register_param(param, &bgp);
        {
            /* show node <node-name> protocol bgp peers */
            static param_t peers;
            init_param(&peers, CMD, "peers", bgp_show_handler,
                       0, INVALID, 0, "Show BGP peers");
            libcli_register_param(&bgp, &peers);
            libcli_set_param_cmd_code(&peers, CMDCODE_SHOW_BGP_PEERS);
        }
        {
            /* show node <node-name> protocol bgp summary */
            static param_t summary;
            init_param(&summary, CMD, "summary", bgp_show_handler,
                       0, INVALID, 0, "Show BGP summary");
            libcli_register_param(&bgp, &summary);
            libcli_set_param_cmd_code(&summary, CMDCODE_SHOW_BGP_SUMMARY);
        }
        {
            /* show node <node-name> protocol bgp running-config */
            static param_t running_config;
            init_param(&running_config, CMD, "running-config",
                       bgp_show_handler, 0, INVALID, 0,
                       "Show BGP running configuration");
            libcli_register_param(&bgp, &running_config);
            libcli_set_param_cmd_code(&running_config,
                                      CMDCODE_SHOW_BGP_RUNNING_CONFIG);
        }
        {
            /* show node <node-name> protocol bgp routes <afi> <safi> */
            static param_t routes;
            init_param(&routes, CMD, "routes", 0, 0, INVALID, 0,
                       "Show BGP routes");
            libcli_register_param(&bgp, &routes);
            {
                static param_t afi_ipv4;
                init_param(&afi_ipv4, CMD, "ipv4", 0, 0, INVALID, 0,
                           "IPv4 routes");
                libcli_register_param(&routes, &afi_ipv4);
                {
                    static param_t safi_unicast;
                    init_param(&safi_unicast, CMD, "unicast", bgp_show_handler,
                               0, INVALID, 0, "IPv4 unicast routes");
                    libcli_register_param(&afi_ipv4, &safi_unicast);
                    libcli_set_param_cmd_code(
                        &safi_unicast, CMDCODE_SHOW_BGP_ROUTES_IPV4_UNICAST);

                    static param_t safi_mpls_vpn;
                    init_param(&safi_mpls_vpn, CMD, "vpn",
                               bgp_show_handler, 0, INVALID, 0,
                               "IPv4 VPN routes");
                    libcli_register_param(&afi_ipv4, &safi_mpls_vpn);
                    libcli_set_param_cmd_code(
                        &safi_mpls_vpn,
                        CMDCODE_SHOW_BGP_ROUTES_IPV4_MPLS_VPN);
                }

                static param_t afi_ipv6;
                init_param(&afi_ipv6, CMD, "ipv6", 0, 0, INVALID, 0,
                           "IPv6 routes");
                libcli_register_param(&routes, &afi_ipv6);
                {
                    static param_t safi_unicast6;
                    init_param(&safi_unicast6, CMD, "unicast",
                               bgp_show_handler, 0, INVALID, 0,
                               "IPv6 unicast routes");
                    libcli_register_param(&afi_ipv6, &safi_unicast6);
                    libcli_set_param_cmd_code(
                        &safi_unicast6,
                        CMDCODE_SHOW_BGP_ROUTES_IPV6_UNICAST);
                }

                static param_t afi_l2vpn_evpn;
                init_param(&afi_l2vpn_evpn, CMD, "l2vpn-evpn", 0, 0,
                           INVALID, 0, "L2VPN EVPN routes");
                libcli_register_param(&routes, &afi_l2vpn_evpn);
                {
                    static param_t safi_mac;
                    init_param(&safi_mac, CMD, "mac", bgp_show_handler,
                               0, INVALID, 0,
                               "EVPN Type-2 MAC routes");
                    libcli_register_param(&afi_l2vpn_evpn, &safi_mac);
                    libcli_set_param_cmd_code(
                        &safi_mac,
                        CMDCODE_SHOW_BGP_ROUTES_L2VPN_EVPN_MAC);

                    static param_t safi_imet;
                    init_param(&safi_imet, CMD, "imet", bgp_show_handler,
                               0, INVALID, 0,
                               "EVPN Type-3 IMET routes");
                    libcli_register_param(&afi_l2vpn_evpn, &safi_imet);
                    libcli_set_param_cmd_code(
                        &safi_imet,
                        CMDCODE_SHOW_BGP_ROUTES_L2VPN_EVPN_IMET);
                }
            }
        }
        {
            /* show node <node-name> protocol bgp global-rib <af> */
            static param_t global_rib;
            init_param(&global_rib, CMD, "global-rib", 0, 0, INVALID, 0,
                       "Show local BGP global RIB");
            libcli_register_param(&bgp, &global_rib);
            {
                static param_t ipv4_vpn;
                init_param(&ipv4_vpn, CMD, "ipv4-vpn", bgp_show_handler,
                           0, INVALID, 0, "IPv4 VPN global RIB");
                libcli_register_param(&global_rib, &ipv4_vpn);
                libcli_set_param_cmd_code(
                    &ipv4_vpn, CMDCODE_SHOW_BGP_GLOBAL_RIB_IPV4_VPN);

                static param_t l2vpn_evpn;
                init_param(&l2vpn_evpn, CMD, "l2vpn-evpn", bgp_show_handler,
                           0, INVALID, 0, "L2VPN EVPN global RIB");
                libcli_register_param(&global_rib, &l2vpn_evpn);
                libcli_set_param_cmd_code(
                    &l2vpn_evpn, CMDCODE_SHOW_BGP_GLOBAL_RIB_L2VPN_EVPN);
            }
        }
    }

    return 0;
}

/*
 * run node <node-name> protocol bgp monitor <afi> <safi>
 */
int
bgp_run_cli_tree(param_t *param)
{
    return 0;
}
