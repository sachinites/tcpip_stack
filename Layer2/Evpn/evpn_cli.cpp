#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../CLIBuilder/libcli.h"
#include "../../CLIBuilder/cmdtlv.h"
#include "../../router_init.h"
#include "../../tcpconst.h"
#include "../../utils.h"
#include "../../Interface/InterfaceUApi.h"
#include "../../datapath/enums/l2_enums.h"
#include "../../dpal/cp2dp.h"
#include "../../libs/common/mpls_lstack.h"
#include "../../libs/c-hashtable/hashtable.h"
#include "../../libs/c-hashtable/hashtable_itr.h"
#include "../../vrf/mac_vrf.h"
#include "evpn.h"
#include "evpn_rt.h"

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

/* debug node <node-name> install bridge-domain <bd-id> route <MAC-ADDRESS> mpls-label <label1> <label2> ... */
#define CMDCODE_CONFIG_BD_MAC_ONLY_RT_INSTALL 6

/* show node <node-name> protocol l2vpn evpn instance <id> */
#define CMDCODE_SHOW_EVPN_INSTANCE 7

/* show node <node-name> protocol l2vpn evpn instance <id> mac-routes [<mac>] */
#define CMDCODE_SHOW_EVPN_MAC_ROUTES 8

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
evpn_get_instance (node_t *node, uint8_t evpn_id, bool create)
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

static BDInterface *
evpn_cli_lookup_bd (node_t *node, uint32_t bd_id)
{
    char intf_name[IF_NAME_SIZE];
    BDInterface *intf;

    snprintf (intf_name, IF_NAME_SIZE, "bd%u", bd_id);
    intf = dynamic_cast<BDInterface *>(node_interface_lookup_by_name (node, intf_name));

    if (!intf || intf->iftype != INTF_TYPE_BD) {
        cprintf ("Error : Bridge-domain %u does not exist\n", bd_id);
        return NULL;
    }

    return intf;
}

static bool
evpn_cli_build_mpls_stack (mpls_lstack_t *lstack,
                             uint32_t *labels,
                             uint8_t label_count)
{
    uint8_t i;
    mpls_label_t lbl;

    mpls_lstack_init(lstack);

    for (i = 0; i < label_count; i++) {
        mpls_label_init(&lbl);
        mpls_label_set_value(&lbl.label_val, labels[i]);
        lbl.op = MPLS_OP_PUSH;
        mpls_lstack_push(lstack, lbl);
    }

    if (lstack->curr_index >= 0)
        mpls_label_set_stack_bottom(&lstack->labels[0].label_val);

    return true;
}

static int
evpn_debug_handler (int64_t cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable)
{
    node_t *node = NULL;
    tlv_struct_t *tlv;
    c_string node_name = NULL;
    c_string mac_address = NULL;
    uint32_t bd_id = 0;
    uint32_t labels[MAX_LBL_DEPTH];
    uint8_t label_count = 0;
    BDInterface *bd_intf;
    mac_addr_t mac_addr;
    mpls_lstack_t lstack;

    TLV_LOOP_STACK_BEGIN (tlv_stack, tlv) {

        if (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "bd-id"))
            bd_id = (uint32_t)atoi ((const char *)tlv->value);
        else if (parser_match_leaf_id (tlv->leaf_id, "mac-addr"))
            mac_address = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "mpls-label-val")) {
            if (label_count < MAX_LBL_DEPTH) {
                unsigned long plain_label = strtoul ((const char *)tlv->value, NULL, 10);
                labels[label_count++] = (uint32_t)plain_label;
            }
        }

    } TLV_LOOP_END;

    node = node_get_node_by_name (topo, node_name);
    if (!node) {
        cprintf ("Error : Node not found\n");
        return -1;
    }

    if (cmdcode != CMDCODE_CONFIG_BD_MAC_ONLY_RT_INSTALL)
        return 0;

    if (!mac_address) {
        cprintf ("Error : MAC address required\n");
        return -1;
    }

    if (sscanf ((const char *)mac_address,
                "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                &mac_addr.mac[0], &mac_addr.mac[1], &mac_addr.mac[2],
                &mac_addr.mac[3], &mac_addr.mac[4], &mac_addr.mac[5]) != 6) {
        cprintf ("Error : Failed to parse MAC address %s\n", mac_address);
        return -1;
    }

    bd_intf = evpn_cli_lookup_bd (node, bd_id);
    if (!bd_intf)
        return -1;

    if (!label_count) {
        cprintf ("Error : At least one MPLS label required\n");
        return -1;
    }

    mac_fwd_object_spec_t fwd_spec;

    evpn_cli_build_mpls_stack (&lstack, labels, label_count);
    mac_fwd_object_spec_from_mpls_tunnel (&fwd_spec, &lstack, 0, 0);

    switch (enable_or_disable) {

        case CONFIG_ENABLE:
        case OPERATIONAL:
            cp2dp_bd_mac_table_entry_add_mpls (node, (uint8_t *)mac_addr.mac,
                                               bd_intf->ifindex, &fwd_spec,
                                               MAC_STATIC, true);
            break;

        case CONFIG_DISABLE:
            cp2dp_bd_mac_table_entry_del_mpls (node, (uint8_t *)mac_addr.mac,
                                               bd_intf->ifindex, &fwd_spec,
                                               true);
            break;

        default:
            break;
    }

    return 0;
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
                    evpn_inst = evpn_get_instance (node, evpn_id, true);
                    if (!evpn_inst)
                        return -1;
                    break;

                case CONFIG_DISABLE:
                    evpn_inst = evpn_get_instance (node, evpn_id, false);
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
            rd.type = 1;
#if 0
            if (!rd_str || !parse_2b_4b ((const char *)rd_str, &rd.rtr_id, &rd.vrf_id)) {
                cprintf ("Error : Invalid route-distinguisher format\n");
                return -1;
            }
#endif
            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    evpn_inst = evpn_get_instance (node, evpn_id, true);
                    if (!evpn_inst)
                        return -1;
                    if (!evpn_config_rd (evpn_inst, rd)) {
                        cprintf ("Error : Failed to configure route-distinguisher\n");
                        return -1;
                    }
                    break;

                case CONFIG_DISABLE:
                    evpn_inst = evpn_get_instance (node, evpn_id, false);
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
#if 0
            if (!rt_str || !parse_2b_4b ((const char *)rt_str, &rt.asn, &rt.number)) {
                cprintf ("Error : Invalid route-target format\n");
                return -1;
            }
#endif
            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    evpn_inst = evpn_get_instance (node, evpn_id, true);
                    if (!evpn_inst)
                        return -1;
                    if (!evpn_config_rt (evpn_inst, rt, import)) {
                        cprintf ("Error : Failed to configure route-target\n");
                        return -1;
                    }
                    break;

                case CONFIG_DISABLE:
                    evpn_inst = evpn_get_instance (node, evpn_id, false);
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
            BDInterface *bd_intf;

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    evpn_inst = evpn_get_instance (node, evpn_id, true);
                    if (!evpn_inst)
                        return -1;

                    bd_intf = evpn_cli_lookup_bd (node, bd_id);
                    if (!bd_intf)
                        return -1;

                    if (evpn_inst->bd_intf.get() == bd_intf)
                        return 0;

                    if (evpn_inst->bd_intf) {
                        cprintf ("Error : EVPN instance %u already connected to a bridge-domain\n",
                                 evpn_id);
                        return -1;
                    }

                    evpn_connect_bd (evpn_inst, bd_intf);
                    bd_intf->enable_lmac_queue();
                    cp2dp_enable_bd_lmac_learning_queue(bd_intf, true);
                    mac_vrf_create(bd_intf->vrf, bd_intf->bd_id, evpn_inst);
                    break;

                case CONFIG_DISABLE:
                    evpn_inst = evpn_get_instance (node, evpn_id, false);
                    if (!evpn_inst) {
                        cprintf ("Error : EVPN instance %u does not exist\n", evpn_id);
                        return -1;
                    }

                    bd_intf = evpn_cli_lookup_bd (node, bd_id);
                    if (!bd_intf)
                        return -1;

                    if (!evpn_disconnect_bd (evpn_inst, bd_intf)) {
                        cprintf ("Error : EVPN instance %u is not connected to bridge-domain %u\n",
                                 evpn_id, bd_id);
                        return -1;
                    }
                    bd_intf->disable_lmac_queue();
                    cp2dp_enable_bd_lmac_learning_queue(bd_intf, false);
                    mac_vrf_destroy(bd_intf->vrf, bd_intf->bd_id);
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
evpn_debug_cli_tree (param_t *param)
{
    static param_t evpn;
    init_param (&evpn, CMD, "evpn", 0, 0, INVALID, 0,
                "Debug Evpn");
    libcli_register_param (param, &evpn);

    static param_t install;
    init_param (&install, CMD, "install", 0, 0, INVALID, 0,
                "Install debug datapath state");
    libcli_register_param (&evpn, &install);
    {
        static param_t bridge_domain;
        init_param (&bridge_domain, CMD, "bridge-domain", 0, 0, INVALID, 0,
                    "Bridge-domain");
        libcli_register_param (&install, &bridge_domain);
        {
            static param_t bd_id;
            init_param (&bd_id, LEAF, NULL, 0,
                        0, INT, "bd-id", "Bridge-domain id");
            libcli_register_param (&bridge_domain, &bd_id);
            {
                static param_t route;
                init_param (&route, CMD, "route", 0, 0, INVALID, 0,
                            "MAC route");
                libcli_register_param (&bd_id, &route);
                {
                    static param_t mac_addr;
                    init_param (&mac_addr, LEAF, NULL, 0,
                                0, MAC, "mac-addr", "MAC address");
                    libcli_register_param (&route, &mac_addr);
                    {
                        static param_t mpls_label;
                        init_param (&mpls_label, CMD, "mpls-label", 0, 0,
                                    INVALID, 0, "MPLS label stack");
                        libcli_register_param (&mac_addr, &mpls_label);
                        {
                            static param_t mpls_label_val;
                            init_param (&mpls_label_val, LEAF, NULL,
                                        evpn_debug_handler, 0, INT,
                                        "mpls-label-val",
                                        "L2VPN MPLS label value");
                            libcli_register_param (&mpls_label, &mpls_label_val);
                            libcli_param_recursive (&mpls_label_val);
                            libcli_set_param_cmd_code (&mpls_label_val,
                                                       CMDCODE_CONFIG_BD_MAC_ONLY_RT_INSTALL);
                            libcli_disable_batch_processing (&mpls_label_val);
                        }
                    }
                }
            }
        }
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

static void
evpn_print_type2_route (evpn_rt_t *evpn_rt,
                        uint32_t bd_id,
                        uint32_t bd_label)
{
    char nh_str[16];
    char mac_str[18];
    char label_str[16];
    const char *flags_str;
    const unsigned char *mac = evpn_rt->u.mac_only.mac.mac;
    bool is_local = (evpn_rt->flags & EVPN_RT_F_LOCAL) != 0;

    snprintf(mac_str, sizeof(mac_str), "%02x%02x.%02x%02x.%02x%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    flags_str = is_local ? "L" : "R";

    if (is_local) {
        snprintf(nh_str, sizeof(nh_str), "0.0.0.0");
        snprintf(label_str, sizeof(label_str), "%u", bd_label);
    } else {
        ip_ntop(evpn_rt->vtep_ip, (c_string)nh_str);
        snprintf(label_str, sizeof(label_str), "%u", evpn_rt->u.mac_only.label);
    }

    /* BD  Mac Address       Flags  Seq No  Next-Hops      Label   ESI */
    cprintf ("%-5u %-17s %-5s  %-6u  %-14s %-7s %s\n",
             bd_id,
             mac_str,
             flags_str,
             0,          /* Seq No */
             nh_str,
             label_str,
             "0");       /* ESI */
}

static void
evpn_show_instance (evpn_inst_t *evpn_inst)
{
    char rd_buf[64];
    char import_rt_buf[64];
    char export_rt_buf[64];
    BDInterface *bd_intf;

    cprintf ("EVPN Instance %u\n", evpn_inst->evi);

    if (evpn_inst->rd.rtr_id || evpn_inst->rd.vrf_id) {
        cprintf ("  Route Distinguisher : %s\n",
                 rd_type1_to_str(&evpn_inst->rd, rd_buf, sizeof(rd_buf)));
    } else {
        cprintf ("  Route Distinguisher : None\n");
    }

    if (evpn_inst->import_rt.rtr_id || evpn_inst->import_rt.vrf_id) {
        cprintf ("  Import Route-Target : %s\n",
                 rt_type1_to_str(&evpn_inst->import_rt,
                                 import_rt_buf, sizeof(import_rt_buf)));
    } else {
        cprintf ("  Import Route-Target : None\n");
    }

    if (evpn_inst->export_rt.rtr_id || evpn_inst->export_rt.vrf_id) {
        cprintf ("  Export Route-Target : %s\n",
                 rt_type1_to_str(&evpn_inst->export_rt,
                                 export_rt_buf, sizeof(export_rt_buf)));
    } else {
        cprintf ("  Export Route-Target : None\n");
    }

    bd_intf = evpn_inst->bd_intf.get();
    if (!bd_intf) {
        cprintf ("  Bridge-Domain       : None\n");
        cprintf ("  BD Admin Status     : N/A\n");
        cprintf ("  BD EVPN Label       : N/A\n");
        cprintf ("  L3 VRF              : N/A\n");
        return;
    }

    cprintf ("  Bridge-Domain       : %u\n", bd_intf->bd_id);
    cprintf ("  BD Admin Status     : %s\n",
             bd_intf->is_up ? "up" : "down");
    cprintf ("  BD EVPN Label       : %u\n", bd_intf->vpn_svc_label);
    cprintf ("  L3 VRF              : %s\n",
             (bd_intf->vrf && bd_intf->vrf->vrf_name[0]) ?
             bd_intf->vrf->vrf_name : "None");
}

static void
evpn_show_mac_routes (evpn_inst_t *evpn_inst, mac_addr_t *mac_filter)
{
    BDInterface *bd_intf;
    mac_vrf_t *mac_vrf;
    struct hashtable_itr *itr;
    evpn_rt_t *evpn_rt;
    uint32_t count = 0;

    bd_intf = evpn_inst->bd_intf.get();
    if (!bd_intf || !bd_intf->vrf) {
        cprintf ("EVPN instance %u : no bridge-domain attached\n", evpn_inst->evi);
        return;
    }

    mac_vrf = bd_intf->vrf->mac_vrf[bd_intf->bd_id];
    if (!mac_vrf || !mac_vrf->type2_rib) {
        cprintf ("EVPN instance %u BD %u : MAC VRF not present\n",
                 evpn_inst->evi, bd_intf->bd_id);
        return;
    }

    cprintf ("\nFlags - (S):Sticky (L):Local (R):Remote (Dup):Duplicate\n");
    cprintf ("%-5s %-17s %-5s  %-6s  %-14s %-7s %s\n",
             "BD", "Mac Address", "Flags", "Seq No",
             "Next-Hops", "Label", "ESI");
    cprintf ("--------------------------------------------------------------------------------------\n");

    if (mac_filter) {
        evpn_rt = (evpn_rt_t *)hashtable_search(mac_vrf->type2_rib, mac_filter);
        if (evpn_rt) {
            evpn_print_type2_route(evpn_rt, bd_intf->bd_id,
                                   bd_intf->vpn_svc_label);
            count = 1;
        }
    } else {
        if (hashtable_count(mac_vrf->type2_rib) == 0) {
            cprintf ("(none)\n");
            return;
        }

        itr = hashtable_iterator(mac_vrf->type2_rib);
        if (!itr) {
            return;
        }

        do {
            evpn_rt = (evpn_rt_t *)hashtable_iterator_value(itr);
            if (evpn_rt) {
                evpn_print_type2_route(evpn_rt, bd_intf->bd_id,
                                       bd_intf->vpn_svc_label);
                count++;
            }
        } while (hashtable_iterator_advance(itr));

        free(itr);
    }

    cprintf ("Total : %u\n", count);
}

static int
evpn_show_handler (int64_t cmdcode,
                   Stack_t *tlv_stack,
                   op_mode enable_or_disable)
{
    node_t *node = NULL;
    tlv_struct_t *tlv;
    c_string node_name = NULL;
    c_string mac_address = NULL;
    uint8_t evpn_id = 0;
    bool evpn_id_present = false;
    bool mac_filter_present = false;
    mac_addr_t mac_filter;
    evpn_inst_t *evpn_inst;

    (void)enable_or_disable;

    TLV_LOOP_STACK_BEGIN (tlv_stack, tlv) {

        if (parser_match_leaf_id (tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "evpn-id")) {
            evpn_id = (uint8_t)atoi ((const char *)tlv->value);
            evpn_id_present = true;
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "mac-addr")) {
            mac_address = tlv->value;
            mac_filter_present = true;
        }

    } TLV_LOOP_END;

    node = node_get_node_by_name (topo, node_name);
    if (!node) {
        cprintf ("Error : Node not found\n");
        return -1;
    }

    switch (cmdcode) {

        case CMDCODE_SHOW_EVPN_INSTANCE:
            if (!evpn_id_present) {
                cprintf ("Error : EVPN instance id required\n");
                return -1;
            }

            evpn_inst = evpn_get_instance (node, evpn_id, false);
            if (!evpn_inst) {
                cprintf ("Error : EVPN instance %u does not exist\n", evpn_id);
                return -1;
            }

            evpn_show_instance (evpn_inst);
            break;

        case CMDCODE_SHOW_EVPN_MAC_ROUTES:
            if (!evpn_id_present) {
                cprintf ("Error : EVPN instance id required\n");
                return -1;
            }

            evpn_inst = evpn_get_instance (node, evpn_id, false);
            if (!evpn_inst) {
                cprintf ("Error : EVPN instance %u does not exist\n", evpn_id);
                return -1;
            }

            if (mac_filter_present) {
                if (sscanf ((const char *)mac_address,
                            "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                            &mac_filter.mac[0], &mac_filter.mac[1],
                            &mac_filter.mac[2], &mac_filter.mac[3],
                            &mac_filter.mac[4], &mac_filter.mac[5]) != 6) {
                    cprintf ("Error : Failed to parse MAC address %s\n",
                             mac_address);
                    return -1;
                }
                evpn_show_mac_routes (evpn_inst, &mac_filter);
            } else {
                evpn_show_mac_routes (evpn_inst, NULL);
            }
            break;

        default:
            break;
    }

    return 0;
}

int
evpn_show_cli_tree (param_t *param)
{
    {
        /* show node <node-name> protocol l2vpn */
        static param_t l2vpn;
        init_param (&l2vpn, CMD, "l2vpn", 0, 0, INVALID, 0, "L2VPN");
        libcli_register_param (param, &l2vpn);
        {
            /* show node <node-name> protocol l2vpn evpn */
            static param_t evpn;
            init_param (&evpn, CMD, "evpn", 0, 0, INVALID, 0, "EVPN");
            libcli_register_param (&l2vpn, &evpn);
            {
                /* show node <node-name> protocol l2vpn evpn instance */
                static param_t instance;
                init_param (&instance, CMD, "instance", 0, 0, INVALID, 0,
                            "EVPN instance");
                libcli_register_param (&evpn, &instance);
                {
                    /* show ... evpn instance <evpn-id> */
                    static param_t evpn_id;
                    init_param (&evpn_id, LEAF, NULL, evpn_show_handler,
                                validate_evpn_id, INT,
                                "evpn-id", "EVPN instance id (0-7)");
                    libcli_register_param (&instance, &evpn_id);
                    libcli_set_param_cmd_code (&evpn_id,
                                               CMDCODE_SHOW_EVPN_INSTANCE);
                    {
                        /* show ... instance <id> mac-routes */
                        static param_t mac_routes;
                        init_param (&mac_routes, CMD, "mac-routes",
                                    evpn_show_handler, 0, INVALID, 0,
                                    "Show EVPN Type-2 MAC routes");
                        libcli_register_param (&evpn_id, &mac_routes);
                        libcli_set_param_cmd_code (&mac_routes,
                                                   CMDCODE_SHOW_EVPN_MAC_ROUTES);
                        {
                            /* show ... mac-routes <mac-addr> */
                            static param_t mac_addr;
                            init_param (&mac_addr, LEAF, NULL, evpn_show_handler,
                                        0, MAC, "mac-addr",
                                        "Filter by MAC address");
                            libcli_register_param (&mac_routes, &mac_addr);
                            libcli_set_param_cmd_code (
                                &mac_addr, CMDCODE_SHOW_EVPN_MAC_ROUTES);
                        }
                    }
                }
            }
        }
    }

    return 0;
}
