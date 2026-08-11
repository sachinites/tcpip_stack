#include "../../tcp_public.h"
#include "isis_cmdcodes.h"
#include "isis_const.h"
#include "isis_rtr.h"
#include "isis_sr.h"
#include "isis_tlv_struct.h"

/* config node <node-name> [no] protocol isis source-packet-routing mpls ... */
static int
isis_sr_mpls_config_handler (int64_t cmdcode,
                              Stack_t *tlv_stack,
                              op_mode enable_or_disable) {

    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;
    c_string vrf_name = NULL;
    uint32_t srgb_base = 0;
    uint32_t srgb_range = 0;
    uint32_t sid_index = 0;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "vrf-name"))
            vrf_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "srgb-base"))
            srgb_base = (uint32_t)atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "srgb-range"))
            srgb_range = (uint32_t)atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "sid-index"))
            sid_index = (uint32_t)atoi((const char *)tlv->value);

    } TLV_LOOP_END;

    node_t *node = node_get_node_by_name(topo, node_name);
    vrf_t *vrf = vrf_name ? vrf_get_by_name(node, (char *)vrf_name) : NODE_DEF_VRF(node);

    if (!isis_is_protocol_enable_on_node(vrf)) {
        cprintf("\n"ISIS_ERROR_PROTO_NOT_ENABLE);
        return -1;
    }

    isis_node_info_t *node_info = vrf->isis_node_info;

    switch (cmdcode) {

        case CMDCODE_CONF_NODE_ISIS_PROTO_SR_MPLS:

            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    isis_sr_mpls_enable(node_info);
                    break;
                case CONFIG_DISABLE:
                    isis_sr_mpls_disable(node_info);
                    break;
                default: ;
            }
            break;

        case CMDCODE_CONF_NODE_ISIS_PROTO_SR_MPLS_SRGB:

            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    if (!srgb_base || !srgb_range) {
                        cprintf("Error : Specify srgb <base> <range>\n");
                        return -1;
                    }
                    return isis_sr_mpls_set_srgb(node_info, srgb_base, srgb_range);
                case CONFIG_DISABLE:
                    /* SRGB cannot be deleted — reset to defaults and refresh routes */
                    return isis_sr_mpls_reset_srgb(node_info);
                default: ;
            }
            break;

        case CMDCODE_CONF_NODE_ISIS_PROTO_SR_MPLS_NODE_SID:

            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    return isis_sr_mpls_advertise_node_sid(node_info, sid_index, NODE_SID_FLAG_N);
                case CONFIG_DISABLE:
                    isis_sr_mpls_withdraw_node_sid(node_info);
                    break;
                default: ;
            }
            break;

        default: ;
    }

    return 0;
}

/* show node <node-name> protocol isis segment-routing */
static int
isis_sr_mpls_show_handler (int64_t cmdcode,
                            Stack_t *tlv_stack,
                            op_mode enable_or_disable) {

    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;
    c_string vrf_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "vrf-name"))
            vrf_name = tlv->value;

    } TLV_LOOP_END;

    node_t *node = node_get_node_by_name(topo, node_name);
    vrf_t *vrf = vrf_name ? vrf_get_by_name(node, (char *)vrf_name) : NODE_DEF_VRF(node);

    if (!isis_is_protocol_enable_on_node(vrf)) {
        cprintf("\n"ISIS_ERROR_PROTO_NOT_ENABLE);
        return -1;
    }

    switch (cmdcode) {
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_SR_MPLS:
            isis_sr_mpls_show_config(vrf->isis_node_info);
            break;
        default: ;
    }

    return 0;
}

/* Hookup fn : attaches the "mpls" SR-MPLS config subtree under
    "... protocol isis source-packet-routing" */
void
isis_sr_mpls_build_config_cli_tree (param_t *spring) {

    /* config node <node-name> [no] protocol isis source-packet-routing mpls */
    static param_t mpls;
    init_param(&mpls, CMD, "mpls", isis_sr_mpls_config_handler, 0, INVALID, 0,
                "Segment Routing MPLS ( SR-MPLS )");
    libcli_register_param(spring, &mpls);
    libcli_set_param_cmd_code(&mpls, CMDCODE_CONF_NODE_ISIS_PROTO_SR_MPLS);
    {
        /* config node <node-name> [no] protocol isis source-packet-routing mpls srgb [<base> <range>]
            "no srgb" does not delete the SRGB — it resets to the ISIS default
            range and refreshes inet.3 / mpls.0 SR routes. */
        static param_t srgb;
        init_param(&srgb, CMD, "srgb", isis_sr_mpls_config_handler, 0, INVALID, 0,
                    "Segment Routing Global Block (no = reset to default)");
        libcli_register_param(&mpls, &srgb);
        libcli_set_param_cmd_code(&srgb, CMDCODE_CONF_NODE_ISIS_PROTO_SR_MPLS_SRGB);
        {
            static param_t srgb_base;
            init_param(&srgb_base, LEAF, 0, 0, 0, INT, "srgb-base", "SRGB Start Label");
            libcli_register_param(&srgb, &srgb_base);
            {
                static param_t srgb_range;
                init_param(&srgb_range, LEAF, 0, isis_sr_mpls_config_handler, 0, INT,
                            "srgb-range", "SRGB Range/Size");
                libcli_register_param(&srgb_base, &srgb_range);
                libcli_set_param_cmd_code(&srgb_range, CMDCODE_CONF_NODE_ISIS_PROTO_SR_MPLS_SRGB);
            }
        }
    }
    {
        /* config node <node-name> [no] protocol isis source-packet-routing mpls node-sid <sid-index> */
        static param_t node_sid;
        init_param(&node_sid, CMD, "node-sid", 0, 0, INVALID, 0, "Node Segment Id");
        libcli_register_param(&mpls, &node_sid);
        {
            static param_t sid_index;
            init_param(&sid_index, LEAF, 0, isis_sr_mpls_config_handler, 0, INT,
                        "sid-index", "SID Index ( relative to local SRGB )");
            libcli_register_param(&node_sid, &sid_index);
            libcli_set_param_cmd_code(&sid_index, CMDCODE_CONF_NODE_ISIS_PROTO_SR_MPLS_NODE_SID);
        }
    }
}

/* Hookup fn : attaches "show node <node-name> protocol isis segment-routing" */
void
isis_sr_mpls_build_show_cli_tree (param_t *isis_proto) {

    static param_t segment_routing;
    init_param(&segment_routing, CMD, "segment-routing", isis_sr_mpls_show_handler, 0, INVALID, 0,
                "Segment Routing ( SR-MPLS ) State");
    libcli_register_param(isis_proto, &segment_routing);
    libcli_set_param_cmd_code(&segment_routing, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_SR_MPLS);
}
