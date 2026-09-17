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
#include "../../Layer5/bgp_rtr.h"
#include "../../Layer5/bgp_global_rib.h"
#include "../../RTM/rtm_nb_integ.h"
#include "evpn.h"
#include "evpn_rt.h"

/* config node <node-name> protocol l2vpn evpn instance <id> */
#define CMDCODE_CONFIG_EVPN_CREATE 1

/* config node <node-name> protocol l2vpn evpn instance <id> route-distinguisher <rd>*/
#define CMDCODE_CONFIG_EVPN_IMPORT_RD 2

/* config node <node-name> protocol l2vpn evpn instance <id>
 *   import-rt <ipv4-address> <uint16> */
#define CMDCODE_CONFIG_EVPN_IMPORT_RT 3

/* config node <node-name> protocol l2vpn evpn instance <id>
 *   export-rt <ipv4-address> <uint16> */
#define CMDCODE_CONFIG_EVPN_EXPORT_RT 4

/* config node <node-name> protocol l2vpn evpn instance <id> bridge-domain <bd-id> */
#define CMDCODE_CONFIG_EVPN_CONNECT_BD 5

/* debug node <node-name> install bridge-domain <bd-id> route <MAC-ADDRESS> mpls-label <label1> <label2> ... */
#define CMDCODE_CONFIG_BD_MAC_ONLY_RT_INSTALL 6

/* show node <node-name> protocol l2vpn evpn instance <id> */
#define CMDCODE_SHOW_EVPN_INSTANCE 7

/* show node <node-name> protocol l2vpn evpn instance <id> mac-routes [<mac>] */
#define CMDCODE_SHOW_EVPN_MAC_ROUTES 8

/* show node <node-name> protocol l2vpn evpn instance <id> imet-routes */
#define CMDCODE_SHOW_EVPN_IMET_ROUTES 9

/* show node <node-name> protocol l2vpn evpn instance <id> arp-suppression-cache */
#define CMDCODE_SHOW_EVPN_ARP_SUPPRESSION_CACHE 10

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

/* Type-1 RT assigned number is a 16-bit integer. */
static int
rt_type1_assigned_validator_cbk(Stack_t *tlv_stack, unsigned char *value)
{
    char *endptr;
    unsigned long v;

    (void)tlv_stack;

    if (!value || !*value) {
        return LEAF_VALIDATION_FAILED;
    }

    errno = 0;
    v = strtoul((const char *)value, &endptr, 10);
    if (errno || endptr == (const char *)value || *endptr != '\0') {
        return LEAF_VALIDATION_FAILED;
    }
    if (v > 0xFFFFUL) {
        return LEAF_VALIDATION_FAILED;
    }

    return LEAF_VALIDATION_SUCCESS;
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
    c_string rt_ip = NULL;
    c_string rt_assigned = NULL;
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
        else if (parser_match_leaf_id (tlv->leaf_id, "import-rt-ip") ||
                 parser_match_leaf_id (tlv->leaf_id, "export-rt-ip"))
            rt_ip = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "import-rt-asn") ||
                 parser_match_leaf_id (tlv->leaf_id, "export-rt-asn"))
            rt_assigned = tlv->value;
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

    if (evpn_id == 0) {
        cprintf ("Error : EVPN instance id 0 is not allowed\n");
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
            rt_t new_rt;
            bool import = (cmdcode == CMDCODE_CONFIG_EVPN_IMPORT_RT);

            if (!rt_ip || !rt_assigned) {
                cprintf ("Error : Type-1 %s requires "
                         "<ipv4-address> <uint16>\n",
                         import ? "import-rt" : "export-rt");
                return -1;
            }

            rt_type1_fill(&new_rt,
                          ip_pton((c_string)rt_ip),
                          (uint16_t)strtoul((const char *)rt_assigned,
                                            NULL, 10));

            switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    evpn_inst = evpn_get_instance (node, evpn_id, false);
                    if (!evpn_inst) {
                        cprintf ("Error : EVPN instance %u does not exist\n",
                                 evpn_id);
                        return -1;
                    }

                    if (import) {
                        if (evpn_inst->import_rt.rtr_id == new_rt.rtr_id &&
                            evpn_inst->import_rt.vrf_id == new_rt.vrf_id &&
                            evpn_inst->import_rt.type == new_rt.type) {
                            return 0;
                        }

                        evpn_inst->import_rt = new_rt;

                        if (evpn_inst->mac_vrf) {
                            mac_vrf_delete_all_remote_evpn_routes(evpn_inst->mac_vrf);
                            if (BGP_INST(node)) {
                                bgp_global_rib_export_all(
                                    BGP_INST(node),
                                    AFI_L2VPN,
                                    SAFI_MPLS_EVPN,
                                    evpn_inst->evi);
                            }
                        }
                    } else {
                        if (evpn_inst->export_rt.rtr_id == new_rt.rtr_id &&
                            evpn_inst->export_rt.vrf_id == new_rt.vrf_id &&
                            evpn_inst->export_rt.type == new_rt.type) {
                            return 0;
                        }

                        evpn_inst->export_rt = new_rt;
                    }
                    break;

                case CONFIG_DISABLE:
                    evpn_inst = evpn_get_instance (node, evpn_id, false);
                    if (!evpn_inst) {
                        cprintf ("Error : EVPN instance %u does not exist\n",
                                 evpn_id);
                        return -1;
                    }

                    if (import) {
                        if (evpn_inst->import_rt.rtr_id == 0 &&
                            evpn_inst->import_rt.vrf_id == 0) {
                            return 0;
                        }

                        if (new_rt.rtr_id != evpn_inst->import_rt.rtr_id ||
                            new_rt.vrf_id != evpn_inst->import_rt.vrf_id) {
                            cprintf ("Error : Mis-matched Route Import value "
                                     "specified\n");
                            return -1;
                        }

                        /* Restore default Type-1 RT (0:<bd-id>) when BD attached */
                        if (evpn_inst->bd_intf) {
                            rt_type1_fill(&evpn_inst->import_rt,
                                          0,
                                          (uint16_t)evpn_inst->bd_intf->bd_id);
                        } else {
                            evpn_inst->import_rt.rtr_id = 0;
                            evpn_inst->import_rt.sub_type = 0;
                            evpn_inst->import_rt.vrf_id = 0;
                        }

                        if (evpn_inst->mac_vrf) {
                            mac_vrf_delete_all_remote_evpn_routes(evpn_inst->mac_vrf);
                            if (BGP_INST(node)) {
                                bgp_global_rib_export_all(
                                    BGP_INST(node),
                                    AFI_L2VPN,
                                    SAFI_MPLS_EVPN,
                                    evpn_inst->evi);
                            }
                        }
                    } else {
                        if (evpn_inst->export_rt.rtr_id == 0 &&
                            evpn_inst->export_rt.vrf_id == 0) {
                            return 0;
                        }

                        if (new_rt.rtr_id != evpn_inst->export_rt.rtr_id ||
                            new_rt.vrf_id != evpn_inst->export_rt.vrf_id) {
                            cprintf ("Error : Mis-matched Route Export value "
                                     "specified\n");
                            return -1;
                        }

                        if (evpn_inst->bd_intf) {
                            rt_type1_fill(&evpn_inst->export_rt,
                                          0,
                                          (uint16_t)evpn_inst->bd_intf->bd_id);
                        } else {
                            evpn_inst->export_rt.rtr_id = 0;
                            evpn_inst->export_rt.sub_type = 0;
                            evpn_inst->export_rt.vrf_id = 0;
                        }
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

                    if (!bd_intf->vrf) {
                        cprintf ("Error : Bridge-domain %u does not have a VRF\n", bd_id);
                        return -1;
                    }

                    evpn_connect_bd (evpn_inst, bd_intf);
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
                        /* config ... evpn instance <id> import-rt
                         *   <ipv4-address> <uint16> */
                        static param_t import_rt;
                        init_param (&import_rt, CMD, "import-rt", NULL, NULL,
                                    INVALID, NULL,
                                    "Import Route-Target (Type-1)");
                        libcli_register_param (&evpn_id, &import_rt);
                        {
                            static param_t import_rt_ip;
                            init_param (&import_rt_ip, LEAF, NULL, 0, 0, IPV4,
                                        "import-rt-ip",
                                        "Type-1 RT administrator (IPv4 address)");
                            libcli_register_param (&import_rt, &import_rt_ip);
                            {
                                static param_t import_rt_asn;
                                init_param (&import_rt_asn, LEAF, NULL,
                                            evpn_config_handler,
                                            rt_type1_assigned_validator_cbk, INT,
                                            "import-rt-asn",
                                            "Type-1 RT assigned number (0-65535)");
                                libcli_register_param (&import_rt_ip, &import_rt_asn);
                                libcli_set_param_cmd_code (&import_rt_asn,
                                                           CMDCODE_CONFIG_EVPN_IMPORT_RT);
                            }
                        }
                    }
                    {
                        /* config ... evpn instance <id> export-rt
                         *   <ipv4-address> <uint16> */
                        static param_t export_rt;
                        init_param (&export_rt, CMD, "export-rt", NULL, NULL,
                                    INVALID, NULL,
                                    "Export Route-Target (Type-1)");
                        libcli_register_param (&evpn_id, &export_rt);
                        {
                            static param_t export_rt_ip;
                            init_param (&export_rt_ip, LEAF, NULL, 0, 0, IPV4,
                                        "export-rt-ip",
                                        "Type-1 RT administrator (IPv4 address)");
                            libcli_register_param (&export_rt, &export_rt_ip);
                            {
                                static param_t export_rt_asn;
                                init_param (&export_rt_asn, LEAF, NULL,
                                            evpn_config_handler,
                                            rt_type1_assigned_validator_cbk, INT,
                                            "export-rt-asn",
                                            "Type-1 RT assigned number (0-65535)");
                                libcli_register_param (&export_rt_ip, &export_rt_asn);
                                libcli_set_param_cmd_code (&export_rt_asn,
                                                           CMDCODE_CONFIG_EVPN_EXPORT_RT);
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
evpn_print_type2_route (evpn_exp_rt_t *evpn_rt,
                        uint32_t bd_id,
                        uint32_t bd_label)
{
    char nh_str[16];
    char mac_str[18];
    char ip_str[16];
    char label_str[16];
    const char *flags_str;
    const unsigned char *mac = evpn_rt->u.mac_only.mac.mac;
    bool is_local = (evpn_rt->flags & EVPN_RT_F_LOCAL) != 0;

    snprintf(mac_str, sizeof(mac_str), "%02x%02x.%02x%02x.%02x%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    if (evpn_rt->u.mac_only.ip_addr)
        ip_ntop(evpn_rt->u.mac_only.ip_addr, (c_string)ip_str);
    else
        snprintf(ip_str, sizeof(ip_str), "-");

    flags_str = is_local ? "L" : "R";

    if (is_local) {
        snprintf(nh_str, sizeof(nh_str), "0.0.0.0");
        snprintf(label_str, sizeof(label_str), "%u", bd_label);
    } else {
        ip_ntop(evpn_rt->vtep_ip, (c_string)nh_str);
        snprintf(label_str, sizeof(label_str), "%u", evpn_rt->u.mac_only.label);
    }

    /* BD  Mac Address       IP Address     Flags  Seq No  Next-Hops      Label   ESI */
    cprintf ("%-5u %-17s %-15s %-5s  %-6u  %-14s %-7s %s\n",
             bd_id,
             mac_str,
             ip_str,
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
        cprintf ("  BD BUM Label        : N/A\n");
        cprintf ("  L3 VRF              : N/A\n");
        return;
    }

    cprintf ("  Bridge-Domain       : %u\n", bd_intf->bd_id);
    cprintf ("  BD Admin Status     : %s\n",
             bd_intf->is_up ? "up" : "down");
    cprintf ("  BD EVPN Label       : %u\n", bd_intf->vpn_svc_label);
    cprintf ("  BD BUM Label        : %u\n", bd_intf->vpn_bum_label);
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
    evpn_exp_rt_t *evpn_rt;
    uint32_t count = 0;

    bd_intf = evpn_inst->bd_intf.get();
    if (!bd_intf || !bd_intf->vrf) {
        cprintf ("EVPN instance %u : no bridge-domain attached\n", evpn_inst->evi);
        return;
    }

    mac_vrf = evpn_inst->mac_vrf;
    
    if (!mac_vrf || !mac_vrf->type2_rib) {
        cprintf ("EVPN instance %u BD %u : MAC VRF not present\n",
                 evpn_inst->evi, bd_intf->bd_id);
        return;
    }

    cprintf ("\nFlags - (S):Sticky (L):Local (R):Remote (Dup):Duplicate\n");
    cprintf ("%-5s %-17s %-15s %-5s  %-6s  %-14s %-7s %s\n",
             "BD", "Mac Address", "IP Address", "Flags", "Seq No",
             "Next-Hops", "Label", "ESI");
    cprintf ("----------------------------------------------------------------------------------------------------\n");

    if (mac_filter) {
        evpn_rt = (evpn_exp_rt_t *)hashtable_search(mac_vrf->type2_rib, mac_filter);
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
            evpn_rt = (evpn_exp_rt_t *)hashtable_iterator_value(itr);
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

static void
evpn_print_type3_route (evpn_exp_rt_t *evpn_rt,
                        uint32_t bd_id,
                        uint32_t bd_bum_label)
{
    char pe_str[16];
    char nh_str[16];
    char label_str[16];
    const char *flags_str;
    bool is_local = (evpn_rt->flags & EVPN_RT_F_LOCAL) != 0;

    ip_ntop(evpn_rt->u.imet.pe_addr, (c_string)pe_str);
    flags_str = is_local ? "L" : "R";

    if (is_local) {
        snprintf(nh_str, sizeof(nh_str), "0.0.0.0");
        snprintf(label_str, sizeof(label_str), "%u", bd_bum_label);
    } else {
        ip_ntop(evpn_rt->vtep_ip, (c_string)nh_str);
        snprintf(label_str, sizeof(label_str), "%u",
                 evpn_rt->u.imet.evpn_label);
    }

    /* BD  PE-Address       Flags  Next-Hops      BUM-Lbl */
    cprintf ("%-5u %-16s %-5s  %-14s %-7s\n",
             bd_id,
             pe_str,
             flags_str,
             nh_str,
             label_str);
}

static void
evpn_show_imet_routes (evpn_inst_t *evpn_inst)
{
    BDInterface *bd_intf;
    mac_vrf_t *mac_vrf;
    struct hashtable_itr *itr;
    evpn_exp_rt_t *evpn_rt;
    uint32_t count = 0;

    bd_intf = evpn_inst->bd_intf.get();
    if (!bd_intf || !bd_intf->vrf) {
        cprintf ("EVPN instance %u : no bridge-domain attached\n",
                 evpn_inst->evi);
        return;
    }

    mac_vrf = evpn_inst->mac_vrf;
    if (!mac_vrf || !mac_vrf->type3_rib) {
        cprintf ("EVPN instance %u BD %u : MAC VRF IMET RIB not present\n",
                 evpn_inst->evi, bd_intf->bd_id);
        return;
    }

    cprintf ("\nFlags - (L):Local (R):Remote\n");
    cprintf ("%-5s %-16s %-5s  %-14s %-7s\n",
             "BD", "PE-Address", "Flags", "Next-Hops", "BUM-Lbl");
    cprintf ("---------------------------------------------------------------\n");

    if (hashtable_count(mac_vrf->type3_rib) == 0) {
        cprintf ("(none)\n");
        return;
    }

    itr = hashtable_iterator(mac_vrf->type3_rib);
    if (!itr) {
        return;
    }

    do {
        evpn_rt = (evpn_exp_rt_t *)hashtable_iterator_value(itr);
        if (evpn_rt) {
            evpn_print_type3_route(evpn_rt, bd_intf->bd_id,
                                   bd_intf->vpn_bum_label);
            count++;
        }
    } while (hashtable_iterator_advance(itr));

    free(itr);
    cprintf ("Total : %u\n", count);
}

static void
evpn_show_arp_suppression_cache (evpn_inst_t *evpn_inst)
{
    mac_vrf_t *mac_vrf;
    struct hashtable_itr *itr;
    uint32_t count = 0;

    mac_vrf = evpn_inst->mac_vrf;
    if (!mac_vrf || !mac_vrf->mac_ip_binding) {
        cprintf ("EVPN instance %u : ARP suppression cache not available\n",
                 evpn_inst->evi);
        return;
    }

    cprintf ("EVPN Instance %u ARP Suppression Cache\n", evpn_inst->evi);
    cprintf ("%-16s  %-17s\n", "IP Address", "MAC Address");
    cprintf ("%-16s  %-17s\n", "----------------", "-----------------");

    if (hashtable_count(mac_vrf->mac_ip_binding) == 0) {
        cprintf ("(empty)\n");
        return;
    }

    itr = hashtable_iterator(mac_vrf->mac_ip_binding);
    if (!itr) {
        cprintf ("(empty)\n");
        return;
    }

    do {
        uint32_t *ip_key = (uint32_t *)hashtable_iterator_key(itr);
        mac_addr_t *mac = (mac_addr_t *)hashtable_iterator_value(itr);
        char ip_str[16];
        char mac_str[18];

        if (!ip_key || !mac)
            break;

        ip_ntop(*ip_key, (c_string)ip_str);
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac->mac[0], mac->mac[1], mac->mac[2],
                 mac->mac[3], mac->mac[4], mac->mac[5]);
        cprintf ("%-16s  %-17s\n", ip_str, mac_str);
        count++;
    } while (hashtable_iterator_advance(itr));

    free(itr);
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

        case CMDCODE_SHOW_EVPN_IMET_ROUTES:
            if (!evpn_id_present) {
                cprintf ("Error : EVPN instance id required\n");
                return -1;
            }

            evpn_inst = evpn_get_instance (node, evpn_id, false);
            if (!evpn_inst) {
                cprintf ("Error : EVPN instance %u does not exist\n", evpn_id);
                return -1;
            }

            evpn_show_imet_routes (evpn_inst);
            break;

        case CMDCODE_SHOW_EVPN_ARP_SUPPRESSION_CACHE:
            if (!evpn_id_present) {
                cprintf ("Error : EVPN instance id required\n");
                return -1;
            }

            evpn_inst = evpn_get_instance (node, evpn_id, false);
            if (!evpn_inst) {
                cprintf ("Error : EVPN instance %u does not exist\n", evpn_id);
                return -1;
            }

            evpn_show_arp_suppression_cache (evpn_inst);
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

                        /* show ... instance <id> imet-routes */
                        static param_t imet_routes;
                        init_param (&imet_routes, CMD, "imet-routes",
                                    evpn_show_handler, 0, INVALID, 0,
                                    "Show EVPN Type-3 IMET routes");
                        libcli_register_param (&evpn_id, &imet_routes);
                        libcli_set_param_cmd_code (&imet_routes,
                                                   CMDCODE_SHOW_EVPN_IMET_ROUTES);

                        /* show ... instance <id> arp-suppression-cache */
                        static param_t arp_sup_cache;
                        init_param (&arp_sup_cache, CMD,
                                    "arp-suppression-cache",
                                    evpn_show_handler, 0, INVALID, 0,
                                    "Show EVPN ARP suppression IP-MAC cache");
                        libcli_register_param (&evpn_id, &arp_sup_cache);
                        libcli_set_param_cmd_code (
                            &arp_sup_cache,
                            CMDCODE_SHOW_EVPN_ARP_SUPPRESSION_CACHE);
                    }
                }
            }
        }
    }

    return 0;
}
