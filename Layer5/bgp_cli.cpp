#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"
#include "../cmdcodes.h"
#include "../router_init.h"
#include "../tcpconst.h"
#include "../RTM/rtm_enums.h"
#include "bgp_config.h"
#include "bgp_route.h"
#include "bgp_rtr.h"
#include "gobgp/sf_gobgp_grpc_client.h"

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

/* run node <node-name> protocol bgp monitor <afi> <safi> */
#define CMDCODE_RUN_BGP_MONITOR 10

/* show node <node-name> protocol bgp running-config */
#define CMDCODE_SHOW_BGP_RUNNING_CONFIG 11

/* config node <node-name> protocol bgp <local-asn> neighbor <addr> address-family ipv4-vpn */
#define CMDCODE_CONFIG_BGP_NEIGHBOR_AF_IPV4_VPN 12


static sf_gobgp_grpc_client_t *
bgp_get_grpc_client(node_t *node)
{
    bgp_inst_t *bgp = bgp_get_instance(node);
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
    bgp_inst_t *bgp = bgp_get_instance(node);
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
        false);
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

static void
bgp_monitor_recv_route_processing_cbk(const bgp_route_info_t *route,
                              bool is_withdraw,
                              void *userdata);

static void
bgp_monitor_recv_vpn_route_processing_cbk(const bgp_route_info_t *route,
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
                    if (!bgp_get_instance(node)) {
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
                    bgp_node_monitor_subscribe_af(node, AFI_IPV4, SAFI_UNICAST,
                                                  bgp_monitor_recv_route_processing_cbk,
                                                  node);
                    assert (!bgp_node_monitor_start(node));
                    cprintf("BGP started: AS %u, router-id %s (listen %s:179)\n",
                            local_asn, rid, rid);
                }
                break;

                case CONFIG_DISABLE:
                {
                    if (!bgp_get_instance(node)) {
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

            if (!bgp_get_instance(node)) {
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
                    if (bgp_node_monitor_subscribe_af(
                            node, AFI_IPV4, SAFI_MPLS_VPN,
                            bgp_monitor_recv_vpn_route_processing_cbk,
                            node) != 0) {
                        cprintf("Error : Failed to register %s monitor callback\n",
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
                    cprintf("%s disabled for neighbor %s\n",
                            VPNV4_UNICAST_AF_STR, neighbor_addr);
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
    int count;
} bgp_show_route_ctx_t;

static int
bgp_show_route_print_cb(const bgp_route_info_t *route, void *userdata)
{
    bgp_show_route_ctx_t *ctx = (bgp_show_route_ctx_t *)userdata;
    const char *dash = "-";

    if (!route || !ctx) {
        return 0;
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
            route->rd[0] ? route->rd : dash,
            route->rt[0] ? route->rt : dash);

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

static int
bgp_show_routes(node_t *node, const char *afi, const char *safi)
{
    bgp_show_route_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.afi = afi;
    ctx.safi = safi;
    ctx.show_label = (safi && strcmp(safi, "vpn") == 0);

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

            cprintf("\n%-20s %-10s %-16s %-14s %s\n",
                    "Neighbor", "AS", "Router-ID",
                    "State", "Description");
            cprintf("%-20s %-10s %-16s %-14s %s\n",
                    "--------", "--", "---------",
                    "-----", "-----------");

            for (int i = 0; i < num_peers; i++) {
                cprintf("%-20s %-10u %-16s %-14s %s\n",
                        peers[i].neighbor_address,
                        peers[i].peer_asn,
                        peers[i].router_id,
                        bgp_session_state_str(peers[i].session_state),
                        peers[i].description);
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

        default:
            break;
    }

    return 0;
}

/* --- Monitor CLI --- */

static void
bgp_monitor_recv_route_processing_cbk(
                              const bgp_route_info_t *route,
                              bool is_withdraw,
                              void *userdata)
{
    node_t *node = (node_t *)userdata;
    bgp_schedule_route_processing_job (node, route, !is_withdraw);
}

static void
bgp_monitor_recv_vpn_route_processing_cbk(
                              const bgp_route_info_t *route,
                              bool is_withdraw,
                              void *userdata)
{
    node_t *node = (node_t *)userdata;
    bgp_schedule_vpn_route_processing_job(node, route, !is_withdraw);
}

static int
bgp_monitor_handler(int64_t cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable)
{
    node_t *node = NULL;
    c_string node_name = NULL;
    c_string afi_str = NULL;
    c_string safi_str = NULL;
    tlv_struct_t *tlv = NULL;

    (void)cmdcode;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "bgp-mon-afi"))
            afi_str = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "bgp-mon-safi"))
            safi_str = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    if (!node) {
        cprintf("Error : Node not found\n");
        return -1;
    }

    if (enable_or_disable == CONFIG_ENABLE) {

        if (bgp_node_monitor_subscribe(node,
                                        afi_str ? (const char *)afi_str : NULL,
                                        safi_str ? (const char *)safi_str : NULL,
                                        bgp_monitor_recv_route_processing_cbk,
                                        node) != 0) {
            cprintf("Error : Failed to register monitor callback\n");
            return -1;
        }

        if (bgp_node_monitor_start(node) != 0) {
            cprintf("Error : Failed to start BGP monitor\n");
            return -1;
        }

        cprintf("BGP monitor started on %s (%s/%s)\n",
                node->node_name,
                afi_str ? (const char *)afi_str : "any",
                safi_str ? (const char *)safi_str : "any");
        return 0;
    }

    if (bgp_node_monitor_stop(node) != 0) {
        cprintf("Error : Failed to stop BGP monitor\n");
        return -1;
    }

    cprintf("BGP monitor stopped on %s\n", node->node_name);
    return 0;
}

/*
 * config node <node-name> protocol bgp <local-asn> [router-id <router-id>]
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
            }
        }
    }

    return 0;
}

/*
 * run node <node-name> protocol bgp monitor <afi> <safi>
 * [no] run node <node-name> protocol bgp monitor
 */
int
bgp_run_cli_tree(param_t *param)
{
    {
        static param_t bgp;
        init_param(&bgp, CMD, "bgp", 0, 0, INVALID, 0, "BGP protocol");
        libcli_register_param(param, &bgp);
        {
            static param_t monitor;
            init_param(&monitor, CMD, "monitor", bgp_monitor_handler,
                       0, INVALID, 0, "BGP route monitor");
            libcli_register_param(&bgp, &monitor);
            libcli_set_param_cmd_code(&monitor, CMDCODE_RUN_BGP_MONITOR);
            {
                static param_t mon_afi;
                init_param(&mon_afi, LEAF, NULL, 0, 0, STRING,
                           "bgp-mon-afi",
                           "Address family (ipv4|ipv6)");
                libcli_register_param(&monitor, &mon_afi);
                {
                    static param_t mon_safi;
                    init_param(&mon_safi, LEAF, NULL, bgp_monitor_handler,
                               0, STRING, "bgp-mon-safi",
                               "Sub-address family (unicast|vpn|evpn)");
                    libcli_register_param(&mon_afi, &mon_safi);
                    libcli_set_param_cmd_code(&mon_safi,
                                              CMDCODE_RUN_BGP_MONITOR);
                }
            }
        }
    }

    return 0;
}
