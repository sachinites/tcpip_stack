#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "../../CLIBuilder/libcli.h"
#include "../../CLIBuilder/cmdtlv.h"
#include "../../router_init.h"
#include "../../tcpconst.h"
#include "../../utils.h"
#include "../../Interface/InterfaceUApi.h"
#include "evpn.h"

/* config node <node-name> protocol l2vpn evpn instance <id> */
#define CMDCODE_CONFIG_EVPN_CREATE 1

/* config node <node-name> protocol l2vpn evpn instance <id> route-distinguisher <rd>*/
#define CMDCODE_CONFIG_EVPN_IMPORT_RD 2

/* config node <node-name> protocol l2vpn evpn instance <id> route-target import <rt> */
#define CMDCODE_CONFIG_EVPN_IMPORT_RT 3

/* config node <node-name> protocol l2vpn evpn instance <id> route-target export <rt> */
#define CMDCODE_CONFIG_EVPN_EXPORT_RT 4

/* config node <node-name> protocol l2vpn evpn instance <id> bridge-domain <bd-id> */
#define CMDCODE_CONFIG_EVPN_CONNECT_BD 5

extern graph_t *topo;

static int
validate_evpn_id (Stack_t *tlv_stack, unsigned char *leaf_value)
{
    char *endptr;
    unsigned long id;

    (void)tlv_stack;

    if (!leaf_value || !leaf_value[0])
        return LEAF_VALIDATION_FAILED;

    errno = 0;
    id = strtoul ((const char *)leaf_value, &endptr, 10);
    if (errno || *endptr != '\0' || id >= MAX_EVPN_INDEX)
        return LEAF_VALIDATION_FAILED;

    return LEAF_VALIDATION_SUCCESS;
}

static int
validate_2B_4B_format (const char *str)
{
    char *colon;
    char *endptr;
    unsigned long v1, v2;

    if (!str || !*str)
        return LEAF_VALIDATION_FAILED;

    colon = (char *)strchr (str, ':');
    if (!colon || strchr (colon + 1, ':'))
        return LEAF_VALIDATION_FAILED;

    errno = 0;
    v1 = strtoul (str, &endptr, 10);
    if (errno || endptr != colon)
        return LEAF_VALIDATION_FAILED;

    if (v1 > 0xFFFF)
        return LEAF_VALIDATION_FAILED;

    errno = 0;
    v2 = strtoul (colon + 1, &endptr, 10);
    if (errno || *endptr != '\0')
        return LEAF_VALIDATION_FAILED;

    if (v2 > 0xFFFFFFFFUL)
        return LEAF_VALIDATION_FAILED;

    return LEAF_VALIDATION_SUCCESS;
}

static int
rd_validator_cbk (Stack_t *tlv_stack, unsigned char *value)
{
    (void)tlv_stack;
    return validate_2B_4B_format ((const char *)value);
}

static int
rt_validator_cbk (Stack_t *tlv_stack, unsigned char *value)
{
    (void)tlv_stack;
    return validate_2B_4B_format ((const char *)value);
}

static bool
parse_2b_4b (const char *str, uint16_t *asn, uint32_t *number)
{
    char temp_str[64];
    char *colon;
    char *endptr;
    unsigned long v1, v2;

    if (!str || !*str)
        return false;

    strncpy (temp_str, str, sizeof (temp_str) - 1);
    temp_str[sizeof (temp_str) - 1] = '\0';

    colon = strchr (temp_str, ':');
    if (!colon)
        return false;

    v1 = strtoul (temp_str, &endptr, 10);
    v2 = strtoul (colon + 1, &endptr, 10);
    *asn = (uint16_t)v1;
    *number = (uint32_t)v2;
    return true;
}

static evpn_inst_t *
evpn_cli_get_instance (node_t *node, uint8_t evpn_id, bool create)
{
    if (evpn_id >= MAX_EVPN_INDEX) {
        cprintf ("Error : EVPN instance id must be 0-%d\n", MAX_EVPN_INDEX - 1);
        return NULL;
    }

    if (node->evpn[evpn_id])
        return node->evpn[evpn_id];

    if (!create)
        return NULL;

    return evpn_instance_init (node, evpn_id);
}

static Interface *
evpn_cli_lookup_bd (node_t *node, uint32_t bd_id)
{
    char intf_name[IF_NAME_SIZE];
    Interface *intf;

    snprintf (intf_name, IF_NAME_SIZE, "bd%u", bd_id);
    intf = node_interface_lookup_by_name (node, intf_name);

    if (!intf || intf->iftype != INTF_TYPE_BD) {
        cprintf ("Error : Bridge-domain %u does not exist\n", bd_id);
        return NULL;
    }

    return intf;
}

static int
evpn_config_handler (int64_t cmdcode,
                     Stack_t *tlv_stack,
                     op_mode enable_or_disable)
{
    node_t *node = NULL;
    tlv_struct_t *tlv;
    c_string node_name = NULL;
    c_string rd_str = NULL;
    c_string rt_str = NULL;
    uint8_t evpn_id = 0;
    uint32_t bd_id = 0;
    bool evpn_id_present = false;
    evpn_inst_t *evpn_inst;

    TLV_LOOP_STACK_BEGIN (tlv_stack, tlv) {

        if (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "evpn-id")) {
            evpn_id = (uint8_t)atoi ((const char *)tlv->value);
            evpn_id_present = true;
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "rd"))
            rd_str = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "rt"))
            rt_str = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "bd-id"))
            bd_id = (uint32_t)atoi ((const char *)tlv->value);

    } TLV_LOOP_END;

    node = node_get_node_by_name (topo, node_name);
    if (!node) {
        cprintf ("Error : Node not found\n");
        return -1;
    }

    if (!evpn_id_present) {
        cprintf ("Error : EVPN instance id required\n");
        return -1;
    }

    switch (cmdcode) {

        case CMDCODE_CONFIG_EVPN_CREATE:
            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    evpn_inst = evpn_cli_get_instance (node, evpn_id, true);
                    if (!evpn_inst)
                        return -1;
                    break;

                case CONFIG_DISABLE:
                    evpn_inst = evpn_cli_get_instance (node, evpn_id, false);
                    if (!evpn_inst) {
                        cprintf ("Error : EVPN instance %u does not exist\n", evpn_id);
                        return -1;
                    }
                    evpn_instance_deinit (&evpn_inst);
                    break;

                default:
                    break;
            }
            break;

        case CMDCODE_CONFIG_EVPN_IMPORT_RD:
        {
            rd_t rd;

            if (!rd_str || !parse_2b_4b ((const char *)rd_str, &rd.asn, &rd.number)) {
                cprintf ("Error : Invalid route-distinguisher format\n");
                return -1;
            }

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    evpn_inst = evpn_cli_get_instance (node, evpn_id, true);
                    if (!evpn_inst)
                        return -1;
                    if (!evpn_config_rd (evpn_inst, rd)) {
                        cprintf ("Error : Failed to configure route-distinguisher\n");
                        return -1;
                    }
                    break;

                case CONFIG_DISABLE:
                    evpn_inst = evpn_cli_get_instance (node, evpn_id, false);
                    if (!evpn_inst) {
                        cprintf ("Error : EVPN instance %u does not exist\n", evpn_id);
                        return -1;
                    }
                    if (!evpn_unconfig_rd (evpn_inst, rd)) {
                        cprintf ("Error : Mis-matched Route Distinguisher value specified\n");
                        return -1;
                    }
                    break;

                default:
                    break;
            }
        }
        break;

        case CMDCODE_CONFIG_EVPN_IMPORT_RT:
        case CMDCODE_CONFIG_EVPN_EXPORT_RT:
        {
            rt_t rt;
            bool import = (cmdcode == CMDCODE_CONFIG_EVPN_IMPORT_RT);

            if (!rt_str || !parse_2b_4b ((const char *)rt_str, &rt.asn, &rt.number)) {
                cprintf ("Error : Invalid route-target format\n");
                return -1;
            }

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    evpn_inst = evpn_cli_get_instance (node, evpn_id, true);
                    if (!evpn_inst)
                        return -1;
                    if (!evpn_config_rt (evpn_inst, rt, import)) {
                        cprintf ("Error : Failed to configure route-target\n");
                        return -1;
                    }
                    break;

                case CONFIG_DISABLE:
                    evpn_inst = evpn_cli_get_instance (node, evpn_id, false);
                    if (!evpn_inst) {
                        cprintf ("Error : EVPN instance %u does not exist\n", evpn_id);
                        return -1;
                    }
                    if (!evpn_unconfig_rt (evpn_inst, rt, import)) {
                        cprintf ("Error : Mis-matched Route Target value specified\n");
                        return -1;
                    }
                    break;

                default:
                    break;
            }
        }
        break;

        case CMDCODE_CONFIG_EVPN_CONNECT_BD:
        {
            Interface *bd_intf;

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    evpn_inst = evpn_cli_get_instance (node, evpn_id, true);
                    if (!evpn_inst)
                        return -1;

                    bd_intf = evpn_cli_lookup_bd (node, bd_id);
                    if (!bd_intf)
                        return -1;

                    if (evpn_inst->bd_index == bd_intf->ifindex)
                        return 0;

                    if (evpn_inst->bd_index) {
                        cprintf ("Error : EVPN instance %u already connected to a bridge-domain\n",
                                 evpn_id);
                        return -1;
                    }

                    evpn_connect_bd (evpn_inst, bd_intf->ifindex);
                    break;

                case CONFIG_DISABLE:
                    evpn_inst = evpn_cli_get_instance (node, evpn_id, false);
                    if (!evpn_inst) {
                        cprintf ("Error : EVPN instance %u does not exist\n", evpn_id);
                        return -1;
                    }

                    bd_intf = evpn_cli_lookup_bd (node, bd_id);
                    if (!bd_intf)
                        return -1;

                    if (!evpn_disconnect_bd (evpn_inst, bd_intf->ifindex)) {
                        cprintf ("Error : EVPN instance %u is not connected to bridge-domain %u\n",
                                 evpn_id, bd_id);
                        return -1;
                    }
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

int
evpn_config_cli_tree (param_t *param)
{
    {
        static param_t l2vpn;
        init_param (&l2vpn, CMD, "l2vpn", 0, 0, INVALID, 0, "L2VPN");
        libcli_register_param (param, &l2vpn);
        {
            static param_t evpn;
            init_param (&evpn, CMD, "evpn", 0, 0, INVALID, 0, "EVPN");
            libcli_register_param (&l2vpn, &evpn);
            {
                static param_t instance;
                init_param (&instance, CMD, "instance", 0, 0, INVALID, 0, "EVPN instance");
                libcli_register_param (&evpn, &instance);
                {
                    static param_t evpn_id;
                    init_param (&evpn_id, LEAF, NULL, evpn_config_handler,
                                validate_evpn_id, INT, "evpn-id",
                                "EVPN instance id (0-7)");
                    libcli_register_param (&instance, &evpn_id);
                    libcli_set_param_cmd_code (&evpn_id, CMDCODE_CONFIG_EVPN_CREATE);

                    {
                        static param_t rd;
                        init_param (&rd, CMD, "route-distinguisher", 0, 0, INVALID, 0,
                                    "Route Distinguisher");
                        libcli_register_param (&evpn_id, &rd);
                        {
                            static param_t rd_value;
                            init_param (&rd_value, LEAF, NULL, evpn_config_handler,
                                        rd_validator_cbk, STRING, "rd",
                                        "RD in <2B:4B> fmt");
                            libcli_register_param (&rd, &rd_value);
                            libcli_set_param_cmd_code (&rd_value, CMDCODE_CONFIG_EVPN_IMPORT_RD);
                        }
                    }
                    {
                        static param_t route_target;
                        init_param (&route_target, CMD, "route-target", 0, 0, INVALID, 0,
                                    "Route Target");
                        libcli_register_param (&evpn_id, &route_target);
                        {
                            static param_t import_kw;
                            init_param (&import_kw, CMD, "import", 0, 0, INVALID, 0,
                                        "Import Route-Target");
                            libcli_register_param (&route_target, &import_kw);
                            {
                                static param_t import_rt;
                                init_param (&import_rt, LEAF, NULL, evpn_config_handler,
                                            rt_validator_cbk, STRING, "rt",
                                            "RT value in <2B:4B> fmt");
                                libcli_register_param (&import_kw, &import_rt);
                                libcli_set_param_cmd_code (&import_rt, CMDCODE_CONFIG_EVPN_IMPORT_RT);
                            }
                        }
                        {
                            static param_t export_kw;
                            init_param (&export_kw, CMD, "export", 0, 0, INVALID, 0,
                                        "Export Route-Target");
                            libcli_register_param (&route_target, &export_kw);
                            {
                                static param_t export_rt;
                                init_param (&export_rt, LEAF, NULL, evpn_config_handler,
                                            rt_validator_cbk, STRING, "rt",
                                            "RT value in <2B:4B> fmt");
                                libcli_register_param (&export_kw, &export_rt);
                                libcli_set_param_cmd_code (&export_rt, CMDCODE_CONFIG_EVPN_EXPORT_RT);
                            }
                        }
                    }
                    {
                        static param_t bridge_domain;
                        init_param (&bridge_domain, CMD, "bridge-domain", 0, 0, INVALID, 0,
                                    "Attach bridge-domain");
                        libcli_register_param (&evpn_id, &bridge_domain);
                        {
                            static param_t bd_id;
                            init_param (&bd_id, LEAF, NULL, evpn_config_handler,
                                        0, INT, "bd-id", "bridge-domain id");
                            libcli_register_param (&bridge_domain, &bd_id);
                            libcli_set_param_cmd_code (&bd_id, CMDCODE_CONFIG_EVPN_CONNECT_BD);
                        }
                    }
                }
            }
        }
    }

    return 0;
}
