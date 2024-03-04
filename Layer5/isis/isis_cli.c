#include "../../tcp_public.h"
#include "isis_cmdcodes.h"
#include "isis_pkt.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_const.h"
#include "isis_lspdb.h"
#include "isis_flood.h"
#include "isis_intf_group.h"
#include "isis_layer2map.h"
#include "../../ted/ted.h"
#include "isis_ted.h"
#include "isis_spf.h"
#include "isis_policy.h"
#include "isis_advt.h"
#include "isis_dis.h"
#include "isis_tlv_struct.h"
#include "isis_utils.h"

static int
isis_config_traceoption_handler (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

    if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
        node_name = tlv->value;

     } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    if (!isis_is_protocol_enable_on_node(node)) {
        cprintf("\n"ISIS_ERROR_PROTO_NOT_ENABLE);
        return -1;
    }

    tracer_t *tr = ISIS_TR (node);

    switch (cmdcode) {

        case CMDCODE_CONF_ISIS_LOG_CONSOLE:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    tracer_enable_console_logging (tr, true);
                break;
                case CONFIG_DISABLE:
                    tracer_enable_console_logging (tr, false);
                break;
            }
            break;

        case CMDCODE_CONF_ISIS_LOG_FILE:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    tracer_enable_file_logging (tr, true);
                break;
                case CONFIG_DISABLE:
                    tracer_enable_file_logging (tr, false);
                break;
            }
            break;

        case CMDCODE_CONF_ISIS_LOG_SPF:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    tracer_log_bit_set (tr, TR_ISIS_SPF);
                break;
                case CONFIG_DISABLE:
                    tracer_log_bit_unset (tr, TR_ISIS_SPF);
                break;
            }
            break;

        case CMDCODE_CONF_ISIS_LOG_LSDB:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    tracer_log_bit_set (tr, TR_ISIS_LSDB);
                break;
                case CONFIG_DISABLE:
                    tracer_log_bit_unset (tr, TR_ISIS_LSDB);
                break;
            }
            break;

        case CMDCODE_CONF_ISIS_LOG_PACKET:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    tracer_log_bit_set (tr, TR_ISIS_PKT);
                    tracer_log_bit_set (tr, TR_ISIS_PKT_HELLO);
                    tracer_log_bit_set (tr, TR_ISIS_PKT_LSP);
                break;
                case CONFIG_DISABLE:
                    tracer_log_bit_unset (tr, TR_ISIS_PKT);
                    tracer_log_bit_unset (tr, TR_ISIS_PKT_HELLO);
                    tracer_log_bit_unset (tr, TR_ISIS_PKT_LSP);
                break;
            }
            break;

        case CMDCODE_CONF_ISIS_LOG_PACKET_HELLO:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    tracer_log_bit_set (tr, TR_ISIS_PKT_HELLO);
                break;
                case CONFIG_DISABLE:
                    tracer_log_bit_unset (tr, TR_ISIS_PKT_HELLO);
                break;
            }
            break;

        case CMDCODE_CONF_ISIS_LOG_PACKET_LSP:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    tracer_log_bit_set (tr, TR_ISIS_PKT_LSP);
                break;
                case CONFIG_DISABLE:
                    tracer_log_bit_unset (tr, TR_ISIS_PKT_LSP);
                break;
            }
            break;

        case CMDCODE_CONF_ISIS_LOG_ADJ:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    tracer_log_bit_set (tr, TR_ISIS_ADJ);
                break;
                case CONFIG_DISABLE:
                    tracer_log_bit_set (tr, TR_ISIS_ADJ);
                break;
            }
            break;

        case CMDCODE_CONF_ISIS_LOG_ROUTE:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    tracer_log_bit_set (tr, TR_ISIS_ROUTE);
                break;
                case CONFIG_DISABLE:
                    tracer_log_bit_unset (tr, TR_ISIS_ROUTE);
                break;
            }
            break;

        case CMDCODE_CONF_ISIS_LOG_POLICY:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    tracer_log_bit_set (tr, TR_ISIS_POLICY);
                break;
                case CONFIG_DISABLE:
                    tracer_log_bit_unset (tr, TR_ISIS_POLICY);
                break;
            }
            break;

        case CMDCODE_CONF_ISIS_LOG_EVENTS:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    tracer_log_bit_set (tr, TR_ISIS_EVENTS);
                break;
                case CONFIG_DISABLE:
                    tracer_log_bit_unset (tr, TR_ISIS_EVENTS);
                break;
            }
            break;

        case CMDCODE_CONF_ISIS_LOG_ERRORS:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    tracer_log_bit_set (tr, TR_ISIS_ERRORS);
                break;
                case CONFIG_DISABLE:
                    tracer_log_bit_unset (tr, TR_ISIS_ERRORS);
                break;
            }
            break;

        case CMDCODE_CONF_ISIS_LOG_ALL:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    tracer_log_bit_set (tr, TR_ISIS_ALL);
                break;
                case CONFIG_DISABLE:
                    tracer_log_bit_unset (tr, TR_ISIS_ALL);
                break;
            }
            break;            
    }
    return 0;
}

static int
isis_config_handler(int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable){

    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;
    char *if_grp_name = NULL;
    const char *prefix_lst_name = NULL;
    
    uint32_t ovl_timeout_val = 0;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if  (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "timeout-val"))
            ovl_timeout_val = atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "if-grp-name"))
            if_grp_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "prefix-list-name"))
            prefix_lst_name = tlv->value;
   } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch(cmdcode) {
        case ISIS_CONFIG_NODE_ENABLE:
            switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    if (isis_is_protocol_enable_on_node(node)) return 0;
                    isis_init(node);
                    break;
                case CONFIG_DISABLE:
                    if (!isis_is_protocol_enable_on_node(node)) return 0;
                    isis_de_init(node);
                    break;
                default: ;
            }
        break;
        case CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD:
         switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    SET_BIT(ISIS_NODE_INFO(node)->event_control_flags, 
                        ISIS_EVENT_DEVICE_OVERLOAD_BY_ADMIN_BIT);
                    return isis_set_overload(node, 0, cmdcode);
                    break;
                case CONFIG_DISABLE:
                    UNSET_BIT64(ISIS_NODE_INFO(node)->event_control_flags, 
                        ISIS_EVENT_DEVICE_OVERLOAD_BY_ADMIN_BIT);
                    if (IS_BIT_SET (ISIS_NODE_INFO(node)->event_control_flags,  ISIS_EVENT_DEVICE_DYNAMIC_OVERLOAD_BIT)) return 0;
                    return isis_unset_overload(node, 0,  cmdcode);
                    break;
                default: ;
         }
        break;
        case CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD_TIMEOUT:
        switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    return isis_set_overload(node, ovl_timeout_val,  cmdcode);
                    break;
                case CONFIG_DISABLE:
                    return isis_unset_overload(node, ovl_timeout_val,  cmdcode);
                    break;
                default: ;
         }
        break;
        case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_GRP:
            switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    return isis_config_intf_grp(node, if_grp_name);
                case CONFIG_DISABLE:
                    return isis_un_config_intf_grp(node, if_grp_name);
                default: ;
         }
         break;
         case CMDCODE_CONF_NODE_ISIS_PROTO_DYN_IGRP:
             switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    return isis_config_dynamic_intf_grp(node);
                case CONFIG_DISABLE:
                    return isis_un_config_dynamic_intf_grp(node);
                default: ;
         }
         break;
         case CMDCODE_CONF_NODE_ISIS_PROTO_LAYER2_MAP:
            switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    return isis_config_layer2_map(node);
                case CONFIG_DISABLE:
                    return isis_un_config_layer2_map(node);
                default: ;
         }
         break;
         case CMDCODE_CONF_NODE_ISIS_PROTO_IMPORT_POLICY:
            switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    return isis_config_import_policy(node, prefix_lst_name);
                case CONFIG_DISABLE:
                    return isis_unconfig_import_policy(node, prefix_lst_name);
                default: ;
            }
            break;
         case CMDCODE_CONF_NODE_ISIS_PROTO_EXPORT_POLICY:
             switch (enable_or_disable) {
             case CONFIG_ENABLE:
                 return isis_config_export_policy(node, prefix_lst_name);
             case CONFIG_DISABLE:
                 return isis_unconfig_export_policy(node, prefix_lst_name);
             default:;
             }
             break;
         default:;
    }
    return 0;
}

static int
isis_intf_config_handler(int cmdcode, 
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable){

    uint16_t priority;
    uint32_t metric;
    node_t *node = NULL;
    char *intf_name = NULL;
    Interface *intf = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;
    isis_intf_group_t *intf_grp = NULL;
    char *if_grp_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if  (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "if-name"))
            intf_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "if-grp-name"))
            if_grp_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "priority"))
            priority = atoi(tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "metric"))
            metric = atoi(tlv->value);            
   } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    
    if (!isis_is_protocol_enable_on_node(node)) {
        cprintf ("\n"ISIS_ERROR_PROTO_NOT_ENABLE);
        return -1;
    }
    
    switch(cmdcode) {
        case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ENABLE:
           intf = node_get_intf_by_name(node, intf_name);

            if(!intf) {
                cprintf("\n"ISIS_ERROR_NON_EXISTING_INTF);
                refresh();
                return -1;
            }
            switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    isis_enable_protocol_on_interface(intf);
                    break;
                case CONFIG_DISABLE:
                    isis_disable_protocol_on_interface(intf);
                    break;
                default: ;
            }
        break;
        case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ALL_ENABLE:
            switch(enable_or_disable) {
                case CONFIG_ENABLE:
                   ITERATE_NODE_INTERFACES_BEGIN(node, intf) {
                        isis_enable_protocol_on_interface(intf);
                    } ITERATE_NODE_INTERFACES_END(node, intf);
                    break;
                case CONFIG_DISABLE:
                     ITERATE_NODE_INTERFACES_BEGIN(node, intf) {
                        isis_disable_protocol_on_interface(intf);
                    } ITERATE_NODE_INTERFACES_END(node, intf);
                    break;
                default: ;
            }
            break;
            case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_GROUP_MEMBERSHIP:
                intf = node_get_intf_by_name(node, intf_name);
                if (!intf) {
                    cprintf("\n"ISIS_ERROR_NON_EXISTING_INTF);
                    return -1;
                }

                intf_grp = isis_intf_grp_look_up(node, if_grp_name);
                
                if (!intf_grp) {
                    cprintf("Error : Interface Group do not exist\n");
                    return -1;
                }

                switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    if (!isis_node_intf_is_enable(intf)) {
                        cprintf ("\n"ISIS_ERROR_PROTO_NOT_ENABLE_ON_INTF);
                        return -1;
                    }
                    return isis_intf_group_add_intf_membership(intf_grp, intf);    
                case CONFIG_DISABLE:
                    return isis_intf_group_remove_intf_membership(intf_grp, intf);
                default:;
                }
        break;
        case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_P2P:
            intf = node_get_intf_by_name(node, intf_name);
            if (!intf) {
                    cprintf("\n"ISIS_ERROR_NON_EXISTING_INTF);
                    return -1;
            }
            if (!isis_node_intf_is_enable(intf)) {
                    cprintf("\n"ISIS_ERROR_PROTO_NOT_ENABLE_ON_INTF);
                    return -1;
            }            
            return isis_config_interface_link_type(intf, isis_intf_type_p2p);
            break;
        case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_LAN:
            intf = node_get_intf_by_name(node, intf_name);
            if (!intf) {
                    cprintf("\n"ISIS_ERROR_NON_EXISTING_INTF);
                    return -1;
            }
            if (!isis_node_intf_is_enable(intf)) {
                    cprintf("\n"ISIS_ERROR_PROTO_NOT_ENABLE_ON_INTF);
                    return -1;
            }
            return isis_config_interface_link_type(intf, isis_intf_type_lan);
            break;
        case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_PRIORITY:
            intf = node_get_intf_by_name(node, intf_name);
            if (!intf) {
                    cprintf("\n"ISIS_ERROR_NON_EXISTING_INTF);
                    return -1;
            }
            if (!isis_node_intf_is_enable(intf)) {
                    cprintf("\n"ISIS_ERROR_PROTO_NOT_ENABLE_ON_INTF);
                    return -1;
            }
            return isis_interface_set_priority (intf, priority, 
                        enable_or_disable == CONFIG_ENABLE ? true : false);
            break;
        case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_METRIC:
            intf = node_get_intf_by_name(node, intf_name);
            if (!intf) {
                    cprintf("\n"ISIS_ERROR_NON_EXISTING_INTF);
                    return -1;
            }
            if (!isis_node_intf_is_enable(intf)) {
                    cprintf("\n"ISIS_ERROR_PROTO_NOT_ENABLE_ON_INTF);
                    return -1;
            }
            return isis_interface_set_metric (intf, metric,
                    enable_or_disable == CONFIG_ENABLE ? true : false);
        default: ;
    }
    return 0;
}

int
isis_run_handler (int cmdcode, 
                             Stack_t *tlv_stack,
                             op_mode enable_or_disable) ;

int
isis_run_handler (int cmdcode, 
                             Stack_t *tlv_stack,
                             op_mode enable_or_disable) {

    node_t *node;
    uint8_t fr_no;
    uint32_t rtr_id;
    pn_id_t pn_no;
    tlv_struct_t *tlv = NULL;
    c_string ip_addr = NULL;
    c_string node_name = NULL;
    isis_lsp_pkt_t *lsp_pkt = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {

            if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
                    node_name = tlv->value;
            else if (parser_match_leaf_id(tlv->leaf_id, "rtr-id"))
                    ip_addr = tlv->value;
            else if (parser_match_leaf_id(tlv->leaf_id, "pn-id"))
                    pn_no = atoi(tlv->value);

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {

        case CMDCODE_RUN_ISIS_LSP_TED_INSTALL:
            {
                rtr_id = tcp_ip_covert_ip_p_to_n (ip_addr);
                lsp_pkt = isis_lookup_lsp_from_lsdb (node, rtr_id, pn_no, 0);
                if (!lsp_pkt) {
                    cprintf ("Error: No LSP found\n");
                    return 0;
                }
                ted_db_t *ted_db = ISIS_TED_DB(node);
                if (!ted_db) {
                    cprintf ("Error : TED-DB not initialized\n");
                    return 0;
                }
                isis_ted_update_or_install_lsp (node, lsp_pkt);
            }
            break;
        case CMDCODE_RUN_ISIS_LSP_TED_UNINSTALL:
            {
                rtr_id = tcp_ip_covert_ip_p_to_n (ip_addr);
                lsp_pkt = isis_lookup_lsp_from_lsdb (node, rtr_id, pn_no, 0);
                if (!lsp_pkt) {
                    cprintf ("Error: No LSP found\n");
                    return 0;
                }
                ted_db_t *ted_db = ISIS_TED_DB(node);
                if (!ted_db) {
                    cprintf ("Error : TED-DB not initialized\n");
                    return 0;
                }
                ted_node_t *ted_node = ted_lookup_node (ted_db, rtr_id, pn_no);
                if (!ted_node) {
                    cprintf ("LSP not installed in TED\n");
                    return 0;
                }
                isis_lsp_pkt_prevent_premature_deletion (lsp_pkt);
                isis_remove_lsp_pkt_from_lspdb (node, lsp_pkt);
                isis_ted_uninstall_lsp (node, lsp_pkt);
                if (isis_our_lsp (node, lsp_pkt)) {
                    isis_schedule_lsp_flood (node, lsp_pkt, NULL);
                }
                 isis_lsp_pkt_relieve_premature_deletion(node, lsp_pkt);
            }
        default :
            break;
    }

    return 0;
}

/* run node <node-name> protocol ... */
int
isis_run_cli_tree (param_t *param) {

    {
        static param_t isis_proto;
	    init_param(&isis_proto, CMD, "isis", 0, 0, INVALID, 0, "isis protocol");
	    libcli_register_param(param, &isis_proto);
        {
            static param_t lsp;
            init_param(&lsp, CMD, "lsp", 0, 0, INVALID, 0, "Link State Pkt");
            libcli_register_param(&isis_proto, &lsp);
            {
                static param_t rtr_id;
                init_param(&rtr_id, LEAF, 0, 0, 0, IPV4, "rtr-id", "Router IPV4 ID");
                libcli_register_param(&lsp, &rtr_id);
                {
                    static param_t pn_id;
                    init_param(&pn_id, LEAF, 0, 0, 0, INT, "pn-id", "PN ID[0-255]");
                    libcli_register_param(&rtr_id, &pn_id);
                    {
                        static param_t install;
                        init_param(&install, CMD, "install", isis_run_handler, 0, INVALID, 0, "Install LSP in TED");
                        libcli_register_param(&pn_id, &install);
                        libcli_set_param_cmd_code(&install, CMDCODE_RUN_ISIS_LSP_TED_INSTALL);
                    }
                    {
                        static param_t uninstall;
                        init_param(&uninstall, CMD, "uninstall", isis_run_handler, 0, INVALID, 0, "Un-Install LSP from TED");
                        libcli_register_param(&pn_id, &uninstall);
                        libcli_set_param_cmd_code(&uninstall, CMDCODE_RUN_ISIS_LSP_TED_UNINSTALL);
                    }
                }
            }
        }
    }
    return 0;
}

int
isis_show_handler (int cmdcode,
                  Stack_t *tlv_stack,
                  op_mode enable_or_disable);

extern void
isis_compute_spf (node_t *spf_root);

int
isis_show_handler (int cmdcode,
                  Stack_t *tlv_stack,
                  op_mode enable_or_disable) {

    uint8_t fr_no;
    uint32_t rc = 0;
    pn_id_t pn_id;
    node_t *node = NULL;
    Interface *intf = NULL;
    char *rtr_id_str = NULL;
    char *intf_name = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if  (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "if-name"))
            intf_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "rtr-id"))
            rtr_id_str = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "pn-id"))
            pn_id = atoi(tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "fr-no"))
            fr_no = atoi(tlv->value);            
   } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    
    switch(cmdcode) {
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_SPF_RESULT:
            isis_show_spf_results (node);
        break;
        case CMDCODE_RUN_SPF:
            isis_compute_spf (node);
            break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL:
           isis_show_node_protocol_state (node);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_INTF:
            intf = node_get_intf_by_name (node, intf_name);
            if (!intf) {
                cprintf("\n"ISIS_ERROR_NON_EXISTING_INTF "\n");
                return -1;
            }
            isis_show_one_intf_stats (intf, 0);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_INTF:
             isis_show_all_intf_stats (node);
            break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_LSDB:
            isis_show_lspdb (node);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_EVENT_COUNTERS:
            isis_show_event_counters (node);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_LSP:
            {
                isis_lsp_pkt_t *lsp_pkt = isis_lookup_lsp_from_lsdb(node,
                                                            tcp_ip_covert_ip_p_to_n(rtr_id_str), pn_id, fr_no);
                if (!lsp_pkt) return 0;
                isis_show_one_lsp_pkt_detail_info (node->print_buff, lsp_pkt);
            }
            break;
        case CMDCODE_SHOW_NODE_ISIS_PROTO_INTF_GROUPS:
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            rc = isis_show_all_interface_group (node);
            break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_TED:
            if (!isis_is_protocol_enable_on_node(node)) break;
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            ted_show_ted_db(ISIS_TED_DB(node), 0, 0, node->print_buff, false);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_TED_ENTRY:
            if (!isis_is_protocol_enable_on_node(node)) break;
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            ted_show_ted_db(ISIS_TED_DB(node),
                                                tcp_ip_covert_ip_p_to_n(rtr_id_str), pn_id, node->print_buff, false);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_TED_DETAIL:
            if (!isis_is_protocol_enable_on_node(node)) break;
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            ted_show_ted_db(ISIS_TED_DB(node), 0, 0, node->print_buff, true);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_TED_ENTRY_DETAIL:
            if (!isis_is_protocol_enable_on_node(node)) break;
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            ted_show_ted_db(ISIS_TED_DB(node),
                                                tcp_ip_covert_ip_p_to_n(rtr_id_str), pn_id, node->print_buff, true);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_ADJACENCY:
            if (!isis_is_protocol_enable_on_node(node)) break;
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            isis_show_all_adjacencies (node);
        break;
        case  CMDCODE_SHOW_NODE_ISIS_PROTOCOL_SPF_LOG:
            isis_show_spf_logs(node);
            break;
        case CMCODE_SHOW_ISIS_ADVT_DB:
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            isis_show_advt_db (node);
            break;
        case CMCODE_SHOW_ISIS_TRACEOPTIONS:
            isis_show_traceoptions (node);
            break;
        default: ;
    }
    return 0;
}

/* CLI format */

/* config CLI format */

static void 
isis_config_buid_traceoptions (param_t *param) {

    {
        static param_t traceoptions;
	    init_param(&traceoptions, CMD, "traceoptions", 0, 0, INVALID, 0, "isis traceoptions");
	    libcli_register_param(param, &traceoptions);
        {
            /* ... traceoptions console */
            static param_t console;
            init_param(&console, CMD, "console", isis_config_traceoption_handler, 0, INVALID, 0, "Enable Console logging");
            libcli_register_param(&traceoptions, &console);
            libcli_set_param_cmd_code (&console, CMDCODE_CONF_ISIS_LOG_CONSOLE);
            libcli_set_tail_config_batch_processing (&console);
        }
        {
            /* ... traceoptions file-logging */
            static param_t filel;
            init_param(&filel, CMD, "file-logging", isis_config_traceoption_handler, 0, INVALID, 0, "Enable File logging (check logs/ dir)");
            libcli_register_param(&traceoptions, &filel);
            libcli_set_param_cmd_code (&filel, CMDCODE_CONF_ISIS_LOG_FILE);
             libcli_set_tail_config_batch_processing (&filel);
        }
        {
            /* ... traceoptions spf */
            static param_t spf;
            init_param(&spf, CMD, "spf", isis_config_traceoption_handler, 0, INVALID, 0, "Enable SPF logging");
            libcli_register_param(&traceoptions, &spf);
            libcli_set_param_cmd_code (&spf, CMDCODE_CONF_ISIS_LOG_SPF);      
             libcli_set_tail_config_batch_processing (&spf);      
        }
        {
            /* ... traceoptions lsdb */
            static param_t lsdb;
            init_param(&lsdb, CMD, "lsdb", isis_config_traceoption_handler, 0, INVALID, 0, "Enable LSDB logging");
            libcli_register_param(&traceoptions, &lsdb);
            libcli_set_param_cmd_code (&lsdb, CMDCODE_CONF_ISIS_LOG_LSDB);
             libcli_set_tail_config_batch_processing (&lsdb);
        }
        {
            /* ... traceoptions packet */
            static param_t packet;
            init_param(&packet, CMD, "packet", isis_config_traceoption_handler, 0, INVALID, 0, "Enable Packet logging");
            libcli_register_param(&traceoptions, &packet);
            libcli_set_param_cmd_code (&packet, CMDCODE_CONF_ISIS_LOG_PACKET);
            {
                /* ... traceoptions packet hello*/
                static param_t hello;
                init_param(&hello, CMD, "hello", isis_config_traceoption_handler, 0, INVALID, 0, "Enable Hello Packet logging");
                libcli_register_param(&packet, &hello);
                libcli_set_param_cmd_code(&hello, CMDCODE_CONF_ISIS_LOG_PACKET_HELLO);
                libcli_set_tail_config_batch_processing (&hello);
            }
            {
                /* ... traceoptions packet lsp*/
                static param_t lsp;
                init_param(&lsp, CMD, "lsp", isis_config_traceoption_handler, 0, INVALID, 0, "Enable LSP Packet logging");
                libcli_register_param(&packet, &lsp);
                libcli_set_param_cmd_code(&lsp, CMDCODE_CONF_ISIS_LOG_PACKET_LSP);
                 libcli_set_tail_config_batch_processing (&lsp);
            }            
        }
        {
            /* ... traceoptions adj */
            static param_t adj;
            init_param(&adj, CMD, "adjacency", isis_config_traceoption_handler, 0, INVALID, 0, "Enable Adjacency logging");
            libcli_register_param(&traceoptions, &adj);
            libcli_set_param_cmd_code(&adj, CMDCODE_CONF_ISIS_LOG_ADJ);
             libcli_set_tail_config_batch_processing (&adj);
        }
        {
            /* ... traceoptions route */
            static param_t route;
            init_param(&route, CMD, "route", isis_config_traceoption_handler, 0, INVALID, 0, "Enable Route logging");
            libcli_register_param(&traceoptions, &route);
            libcli_set_param_cmd_code(&route, CMDCODE_CONF_ISIS_LOG_ROUTE);
             libcli_set_tail_config_batch_processing (&route);
        }
        {
            /* ... traceoptions all */
            static param_t all;
            init_param(&all, CMD, "all", isis_config_traceoption_handler, 0, INVALID, 0, "Enable All logging");
            libcli_register_param(&traceoptions, &all);
            libcli_set_param_cmd_code(&all, CMDCODE_CONF_ISIS_LOG_ALL);
             libcli_set_tail_config_batch_processing (&all);
        }
        {
            /* ... traceoptions policy */
            static param_t policy;
            init_param(&policy, CMD, "policy", isis_config_traceoption_handler, 0, INVALID, 0, "Enable Policy logging");
            libcli_register_param(&traceoptions, &policy);
            libcli_set_param_cmd_code(&policy, CMDCODE_CONF_ISIS_LOG_POLICY);
             libcli_set_tail_config_batch_processing (&policy);
        }
        {
            /* ... traceoptions events */
            static param_t events;
            init_param(&events, CMD, "events", isis_config_traceoption_handler, 0, INVALID, 0, "Enable Events logging");
            libcli_register_param(&traceoptions, &events);
            libcli_set_param_cmd_code(&events, CMDCODE_CONF_ISIS_LOG_EVENTS);
             libcli_set_tail_config_batch_processing (&events);
        }
        {
            /* ... traceoptions errors */
            static param_t errors;
            init_param(&errors, CMD, "errors", isis_config_traceoption_handler, 0, INVALID, 0, "Enable Errors logging");
            libcli_register_param(&traceoptions, &errors);
            libcli_set_param_cmd_code(&errors, CMDCODE_CONF_ISIS_LOG_ERRORS);
             libcli_set_tail_config_batch_processing (&errors);
        }
         libcli_support_cmd_negation (&traceoptions);
    }
}


/* conf node <node-name> protocol ... */
int
isis_config_cli_tree(param_t *param) {

    {
        static param_t isis_proto;
	    init_param(&isis_proto, CMD, "isis", isis_config_handler, 0, INVALID, 0, "isis protocol");
	    libcli_register_param(param, &isis_proto);
	    libcli_set_param_cmd_code(&isis_proto, ISIS_CONFIG_NODE_ENABLE);
        {
            isis_config_buid_traceoptions (&isis_proto);
        }
        {
             static param_t import_policy;
             init_param(&import_policy, CMD, "import-policy", 0, 0, INVALID, 0, "import policy");
             libcli_register_param(&isis_proto, &import_policy);
             //libcli_register_display_callback(&import_policy, access_list_show_all_brief);
             {
                 static param_t policy_name;
                 init_param(&policy_name, LEAF, 0, isis_config_handler, 0, STRING, "prefix-list-name",
                            ("Prefix List Name"));
                 libcli_register_param(&import_policy, &policy_name);
                 libcli_param_recursive(&policy_name);
                 libcli_set_param_cmd_code(&policy_name, CMDCODE_CONF_NODE_ISIS_PROTO_IMPORT_POLICY);
                 libcli_set_tail_config_batch_processing (&policy_name);
             }
        }
        {
            static param_t export_policy;
            init_param(&export_policy, CMD, "export-policy", 0, 0, INVALID, 0, "export policy");
            libcli_register_param(&isis_proto, &export_policy);
            //libcli_register_display_callback(&import_policy, access_list_show_all_brief);
            {
                static param_t policy_name;
                init_param(&policy_name, LEAF, 0, isis_config_handler, 0, STRING, "prefix-list-name",
                           ("Prefix List Name"));
                libcli_register_param(&export_policy, &policy_name);
                libcli_param_recursive(&policy_name);
                libcli_set_param_cmd_code(&policy_name, CMDCODE_CONF_NODE_ISIS_PROTO_EXPORT_POLICY);
                libcli_set_tail_config_batch_processing (&policy_name);
            }
        }
        {
             /* conf node <node-name> [no] protocol isis overload */
            static param_t ovl;
            init_param(&ovl, CMD, "overload", isis_config_handler, 0, INVALID, 0,
                        ("Overload Device"));
            libcli_register_param(&isis_proto, &ovl);
            libcli_set_param_cmd_code(&ovl, CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD);
            {
                static param_t timeout;
                init_param(&timeout, CMD, "timeout", 0, 0, INVALID, 0,
                        ("Overload Timeout "));
                libcli_register_param(&ovl, &timeout);
                {
                    static param_t timeout_val;
                    init_param(&timeout_val, LEAF,  0, isis_config_handler, 0,  INT, "timeout-val",
                        ("timeout in sec"));
                    libcli_register_param(&timeout, &timeout_val);
                    libcli_set_param_cmd_code(&timeout_val, CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD_TIMEOUT);
                     libcli_set_tail_config_batch_processing (&timeout_val);
                }
            }
        }

        {
            /* conf node <node-name> [no] protocol isis layer2-map*/
            static param_t layer2_map;
            init_param(&layer2_map, CMD, "layer2-map", isis_config_handler, 0, INVALID, 0,
                        ("Layer 2 Map"));
            libcli_register_param(&isis_proto, &layer2_map);
            libcli_set_param_cmd_code(&layer2_map, CMDCODE_CONF_NODE_ISIS_PROTO_LAYER2_MAP);
            libcli_set_tail_config_batch_processing (&layer2_map);
        }
        
        {
            /* conf node <node-name> [no] protocol isis interface-group ... */
            static param_t interface_group;
            init_param(&interface_group, CMD, "interface-group", 0, 0, INVALID, 0, "interface-group");
            libcli_register_param(&isis_proto, &interface_group);
            {
                /* conf node <node-name> [no] protocol isis interface-group <if-grp-name> */
                static param_t if_grp_name;
                init_param(&if_grp_name, LEAF, 0, isis_config_handler, 0, STRING, "if-grp-name",
                        ("Interface Group Name"));
                libcli_register_param(&interface_group, &if_grp_name);
                libcli_param_recursive(&if_grp_name);
                libcli_set_param_cmd_code(&if_grp_name, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_GRP);
                libcli_set_tail_config_batch_processing (&if_grp_name);
            }
        }
        {
             static param_t dynamic_interface_group;
            init_param(&dynamic_interface_group, CMD, "dynamic-interface-group", isis_config_handler, 0, INVALID, 0, 
                "dynamic-interface-group");
            libcli_register_param(&isis_proto, &dynamic_interface_group);
            libcli_set_param_cmd_code(&dynamic_interface_group,  CMDCODE_CONF_NODE_ISIS_PROTO_DYN_IGRP);
             libcli_set_tail_config_batch_processing (&dynamic_interface_group);
        }

        {
            /* conf node <node-name> [no] protocol isis interface ... */
            static param_t interface;
            init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "interface");
            libcli_register_param(&isis_proto, &interface);
            {
                /*  conf node <node-name> [no] protocol isis interface <intf-name>
                    * Behavior : 
                    1. Device must start sending Hello out of this interface provided interface
                        is operating in L3 mode
                    2. Device must start processing Hellos recvd on this interface provided intf is
                        operating in L3 mode
                    3. Once nbrship is established on this interface, interface becomes eligible
                        for receiving and sending LSPs
                    * Negation : 
                    1. Device must stop sending hellos
                    2. Once nbrship is broken on this interface, interface becomes non-eligible
                        for receiving and sending LSPs
                */
                static param_t if_name;
                init_param(&if_name, LEAF, 0, isis_intf_config_handler, 0, STRING, "if-name",
                        ("Interface Name"));
                libcli_register_param(&interface, &if_name);
                libcli_register_display_callback(&if_name, display_node_interfaces);
                libcli_set_param_cmd_code(&if_name, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ENABLE);
                {
                    /*  conf node <node-name> [no] protocol isis interface <if-name> interface-group */
                    static param_t intf_grp;
                    init_param(&intf_grp, CMD, "interface-group", 0, 0, INVALID, 0, "interface-group");
                    libcli_register_param(&if_name, &intf_grp);
                    {
                        /*  conf node <node-name> [no] protocol isis interface <if-name> interface-group <if-grp-name>*/
                        static param_t if_grp_name;
                        init_param(&if_grp_name, LEAF, 0, isis_intf_config_handler, 0, STRING, "if-grp-name",
                                   ("Interface Group Name"));
                        libcli_register_param(&intf_grp, &if_grp_name);
                        libcli_set_param_cmd_code(&if_grp_name, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_GROUP_MEMBERSHIP);
                        libcli_set_tail_config_batch_processing (&if_grp_name);
                    }
                }
                {
                    /* config node <node-name> protocol isis interface <if-name> p2p */
                    static param_t p2p;
                    init_param(&p2p, CMD, "point-to-point", isis_intf_config_handler, 0, INVALID, 0, "Point to Point Interface");
                    libcli_register_param(&if_name, &p2p);
                    libcli_set_param_cmd_code(&p2p,  CMDCODE_CONF_NODE_ISIS_PROTO_INTF_P2P);
                    libcli_set_tail_config_batch_processing (&p2p);
                }
                {
                    /* config node <node-name> protocol isis interface <if-name> lan */
                    static param_t lan;
                    init_param(&lan, CMD, "broadcast", isis_intf_config_handler, 0, INVALID, 0, "Broadcast Interface");
                    libcli_register_param(&if_name, &lan);
                    libcli_set_param_cmd_code(&lan, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_LAN);
                    libcli_set_tail_config_batch_processing (&lan);
                }
                {
                    /* config node <node-name> protocol isis interface <if-name> priority... */
                    static param_t priority;
                    init_param(&priority, CMD, "priority", NULL, 0, INVALID, 0, "Interface Priority (0 - 65535)");
                    libcli_register_param(&if_name, &priority);
                    {
                        /* config node <node-name> protocol isis interface <if-name> priority <val>*/
                        static param_t priority_val;
                        init_param(&priority_val, LEAF, 0, isis_intf_config_handler, 0, INT, "priority",
                        ("Intf Priority Value"));
                        libcli_register_param(&priority, &priority_val);
                        libcli_set_param_cmd_code(&priority_val, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_PRIORITY);
                        libcli_set_tail_config_batch_processing (&priority_val);
                    }
                }
                {
                    /* config node <node-name> protocol isis interface <if-name> metric... */
                    static param_t metric;
                    init_param(&metric, CMD, "metric", NULL, 0, INVALID, 0, "Interface metric (0 - 65535)");
                    libcli_register_param(&if_name, &metric);
                    {
                        /* config node <node-name> protocol isis interface <if-name> metric <val>*/
                        static param_t metric_val;
                        init_param(&metric_val, LEAF, 0, isis_intf_config_handler, 0, INT, "metric",
                                   ("Intf Metric Value"));
                        libcli_register_param(&metric, &metric_val);
                        libcli_set_param_cmd_code(&metric_val, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_METRIC);
                        libcli_set_tail_config_batch_processing (&metric);
                    }
                }
            }
            {
                /*  conf node <node-name> [no] protocol isis interface all */
                static param_t all;
                init_param(&all, CMD, "all", isis_intf_config_handler, 0, INVALID, 0,
                        ("All Interfaces"));
                libcli_register_param(&interface, &all);
                libcli_set_param_cmd_code(&all, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ALL_ENABLE);
                libcli_set_tail_config_batch_processing (&all);
            }
        }
    }
    return 0;
}

/* show node <node-name> protocol ... */
int
isis_show_cli_tree(param_t *param) {

    {
        static param_t isis_proto;
	    init_param(&isis_proto, CMD, "isis", isis_show_handler, 0, INVALID, 0, "isis protocol");
	    libcli_register_param(param, &isis_proto);
	    libcli_set_param_cmd_code(&isis_proto, CMDCODE_SHOW_NODE_ISIS_PROTOCOL);
        {
            /* show node <node-name> protocol isis interface */
            static param_t interface;
            init_param(&interface, CMD, "interface",  isis_show_handler, 0, INVALID, 0, "interface");
            libcli_register_param(&isis_proto, &interface);
            libcli_set_param_cmd_code(&interface, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_INTF);
            {
                /* show node <node-name> protocol isis adjacency */
                static param_t adjacency;
                init_param(&adjacency, CMD, "adjacency", isis_show_handler, 0, INVALID, 0, "adjacency");
                libcli_register_param(&isis_proto, &adjacency);
                libcli_set_param_cmd_code(&adjacency, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_ADJACENCY);
            }
            {
                 /* show node <node-name> protocol isis spf-result */
                 static param_t spf_result;
                 init_param(&spf_result, CMD, "spf-result", isis_show_handler, 0, INVALID, 0, "Raw SPF Result");
                 libcli_register_param(&isis_proto, &spf_result);
                 libcli_set_param_cmd_code(&spf_result, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_SPF_RESULT);
            }
            {
                /* show node <node-name> protocol isis interface <if-name> */
                static param_t if_name;
                init_param(&if_name, LEAF, 0, isis_show_handler, 0, STRING, "if-name",
                        ("Interface Name"));
                libcli_register_param(&interface, &if_name);
                libcli_register_display_callback(&if_name, display_node_interfaces);
                libcli_set_param_cmd_code(&if_name, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_INTF);
            }
            {
                 /* show node <node-name> protocol isis lsdb */
                static param_t lsdb;
	            init_param(&lsdb, CMD, "lsdb", isis_show_handler, 0, INVALID, 0, "isis protocol");
	            libcli_register_param(&isis_proto, &lsdb);
	            libcli_set_param_cmd_code(&lsdb, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_LSDB);
                {
                    static param_t rtr_id;
                    init_param(&rtr_id, LEAF, 0, 0, 0, IPV4, "rtr-id", "Router-id in A.B.C.D format");
                    libcli_register_param(&lsdb, &rtr_id);
                    {
                        static param_t pn_id;
                        init_param(&pn_id, LEAF, 0, 0, 0, INT, "pn-id", "PN Id [0-255]");
                        libcli_register_param(&rtr_id, &pn_id);
                        {
                            /* show node <node-name> protocol isis lsdb <A.B.C.D> <PN-ID> <Fr-No>*/
                            static param_t fr_no;
                            init_param(&fr_no, LEAF, 0, isis_show_handler, 0, INT, "fr-no", "Fr No [0-255]");
                            libcli_register_param(&pn_id, &fr_no);
                            libcli_set_param_cmd_code(&fr_no, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_LSP);
                        }
                    }
                }
            }
            {
                /* show node <node-name> protocol isis ted*/
                static param_t ted;
	            init_param(&ted, CMD, "ted", isis_show_handler, 0, INVALID, 0, "TED database");
	            libcli_register_param(&isis_proto, &ted);
	            libcli_set_param_cmd_code(&ted, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_TED);
                 {
                    static param_t rtr_id;
                    init_param(&rtr_id, LEAF, 0, NULL, 0, IPV4, "rtr-id",
                        "Router-id in A.B.C.D format");
                    libcli_register_param(&ted, &rtr_id);
                    {
                         /* show node <node-name> protocol isis ted <rtr-id> <pn-id>*/
                        static param_t pn_id;
                        init_param(&pn_id, LEAF, 0, isis_show_handler, 0, INT, "pn-id",
                                   "PN id [0-255]");
                        libcli_register_param(&rtr_id, &pn_id);
                        libcli_set_param_cmd_code(&pn_id, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_TED_ENTRY);
                        {
                            static param_t detail;
                            init_param(&detail, CMD, "detail", isis_show_handler, 0, INVALID, 0,
                                       "Detailed output");
                            libcli_register_param(&pn_id, &detail);
                            libcli_set_param_cmd_code(&detail, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_TED_ENTRY_DETAIL);
                        }
                    }
                }
                  {
                    static param_t detail;
                    init_param(&detail, CMD, "detail", isis_show_handler, 0, INVALID, 0,
                        "Detailed output");
                    libcli_register_param(&ted, &detail);
                    libcli_set_param_cmd_code(&detail, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_TED_DETAIL);
                }
            }
            {
                /* show node <node-name> protocol isis advt-db*/
                static param_t advtdb;
                init_param(&advtdb, CMD, "advt-db", isis_show_handler, 0, INVALID, 0, "Advertisement database");
                libcli_register_param(&isis_proto, &advtdb);
                libcli_set_param_cmd_code(&advtdb, CMCODE_SHOW_ISIS_ADVT_DB);
            }
            {
                /* show node <node-name> protocol isis traceoptions*/
                static param_t traceoptions;
                init_param(&traceoptions, CMD, "traceoptions", isis_show_handler, 0, INVALID, 0, "logging status");
                libcli_register_param(&isis_proto, &traceoptions);
                libcli_set_param_cmd_code(&traceoptions, CMCODE_SHOW_ISIS_TRACEOPTIONS);
            }
        }
        {
                /*show node <node-name> protocol isis event-counters*/
                static param_t event_counters;
	            init_param(&event_counters, CMD, "event-counters", isis_show_handler, 0, INVALID, 0, "event counters");
	            libcli_register_param(&isis_proto, &event_counters);
	            libcli_set_param_cmd_code(&event_counters, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_EVENT_COUNTERS);
        }
         {
                /*show node <node-name> protocol isis spf-log*/
                static param_t spf_log;
	            init_param(&spf_log, CMD, "spf-log", isis_show_handler, 0, INVALID, 0, "spf_log");
	            libcli_register_param(&isis_proto, &spf_log);
	            libcli_set_param_cmd_code(&spf_log, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_SPF_LOG);
        }
        {
            static param_t intf_grps;
            init_param(&intf_grps, CMD, "interface-groups", isis_show_handler, 0, INVALID, 0, "interface-groups");
            libcli_register_param(&isis_proto, &intf_grps);
            libcli_set_param_cmd_code(&intf_grps, CMDCODE_SHOW_NODE_ISIS_PROTO_INTF_GROUPS);
        }
    }
    return 0;
}

int
isis_clear_handler(int cmdcode,
                   Stack_t *tlv_stack,
                   op_mode enable_or_disable) {

    node_t *node;
    tlv_struct_t *tlv;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if  (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
            
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    
    if (!isis_is_protocol_enable_on_node(node)) {
        cprintf ("\n"ISIS_ERROR_PROTO_NOT_ENABLE);
        return;
    }

    switch(cmdcode) {

        case CMDCODE_CLEAR_NODE_ISIS_LSDB:
        {
            isis_cleanup_lsdb (node, true);
            isis_schedule_all_fragment_regen_job (node);
        }
        break;
        case CMDCODE_CLEAR_NODE_ISIS_ADJACENCY:
        {
            Interface *intf;
            ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

                if (!isis_node_intf_is_enable(intf)) continue;
                isis_delete_all_adjacencies(intf);  
                if (isis_intf_is_lan(intf)) isis_intf_resign_dis (intf);

            }  ITERATE_NODE_INTERFACES_END(node, intf);
        }
        break;
        case CMDCODE_RESET_NODE_ISIS_LOG_FILE:
            tracer_clear_log_file (ISIS_TR(node));
            break;
        default: ;
    }
    return 0;
}

/* clear node <node-name> protocol ... */
int
isis_clear_cli_tree(param_t *param) {

    {
        /* clear node <node-name> protocol isis ...*/
        static param_t isis_proto;
	    init_param(&isis_proto, CMD, "isis", 0, 0, INVALID, 0, "isis protocol");
	    libcli_register_param(param, &isis_proto);
        {
            /* clear node <node-name> protocol isis lsdb */
            static param_t lsdb;
            init_param(&lsdb, CMD, "lsdb", isis_clear_handler, 0, INVALID, 0, "lsdb");
            libcli_register_param(&isis_proto, &lsdb);
            libcli_set_param_cmd_code(&lsdb, CMDCODE_CLEAR_NODE_ISIS_LSDB);
        }
        {
             /* clear node <node-name> protocol isis adjacency */
            static param_t adjacency;
            init_param(&adjacency, CMD, "adjacency", isis_clear_handler, 0, INVALID, 0, "adjacency");
            libcli_register_param(&isis_proto, &adjacency);
            libcli_set_param_cmd_code(&adjacency, CMDCODE_CLEAR_NODE_ISIS_ADJACENCY);
        }
        {
             /* clear node <node-name> protocol isis reset-log-file */
            static param_t reset_log_file;
            init_param(&reset_log_file, CMD, "reset-log-file", isis_clear_handler, 0, INVALID, 0, "Reset Log File logs/*-isis-log.txt");
            libcli_register_param(&isis_proto, &reset_log_file);
            libcli_set_param_cmd_code(&reset_log_file, CMDCODE_RESET_NODE_ISIS_LOG_FILE);
        }        
    }
    return 0;
}


int
isis_debug_handler(int cmdcode,
                   Stack_t *tlv_stack,
                   op_mode enable_or_disable) {

    node_t *node;
    tlv_struct_t *tlv;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if  (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    
    if (!isis_is_protocol_enable_on_node(node)) {
        cprintf ("\n"ISIS_ERROR_PROTO_NOT_ENABLE);
        return;
    }

    switch(cmdcode) {

        case CMDCODE_DEBUG_NODE_ISIS_TOGGLE_LSDB_ADVT:
        {
            node_info->lsdb_advt_block = !node_info->lsdb_advt_block;
            cprintf ("%s : %s\n", node_name, node_info->lsdb_advt_block ? \
                "LSDB Advt Block" : "LSDB Advt UnBlock");
        }
        break;

        default: ;
    }
    return 0;
}


/* debug node <node-name> protocol ... */
int
isis_debug_cli_tree(param_t *param) {

    {
        /* debug node <node-name> protocol isis ...*/
        static param_t isis_proto;
	    init_param(&isis_proto, CMD, "isis", 0, 0, INVALID, 0, "isis protocol");
	    libcli_register_param(param, &isis_proto);
        {
            /* debug node <node-name> protocol isis toggle-lsdb-advt */
            static param_t toggle_lsdb_advt;
            init_param(&toggle_lsdb_advt, CMD, "toggle-lsdb-advt", isis_debug_handler, 0, INVALID, 0, "toggle-lsdb-advt");
            libcli_register_param(&isis_proto, &toggle_lsdb_advt);
            libcli_set_param_cmd_code(&toggle_lsdb_advt, CMDCODE_DEBUG_NODE_ISIS_TOGGLE_LSDB_ADVT);
        } 
    }
    return 0;
}


