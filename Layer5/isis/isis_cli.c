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

static int
isis_config_handler(param_t *param, 
                    ser_buff_t *tlv_buf,
                    op_mode enable_or_disable){

    int cmdcode = -1;
    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;
    char *if_grp_name = NULL;
    const char *prefix_lst_name = NULL;
    
    uint32_t ovl_timeout_val = 0;

    cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if (tlv->tlv_type != TLV_TYPE_NORMAL ) continue;

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
                    if (isis_is_protocol_enable_on_node(node)) return -1;
                    isis_init(node);
                    break;
                case CONFIG_DISABLE:
                    if (!isis_is_protocol_enable_on_node(node)) return -1;
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
isis_intf_config_handler(param_t *param, 
                    ser_buff_t *tlv_buf,
                    op_mode enable_or_disable){

    int cmdcode = -1;
    uint16_t priority;
    node_t *node = NULL;
    char *intf_name = NULL;
    Interface *intf = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;
    isis_intf_group_t *intf_grp = NULL;
    char *if_grp_name = NULL;

    cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if  (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "if-name"))
            intf_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "if-grp-name"))
            if_grp_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "priority"))
            priority = atoi(tlv->value);
   } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    
    if (!isis_is_protocol_enable_on_node(node)) {
        printf(ISIS_ERROR_PROTO_NOT_ENABLE "\n");
        return -1;
    }
    
    switch(cmdcode) {
        case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ENABLE:
           intf = node_get_intf_by_name(node, intf_name);

            if(!intf) {
                printf(ISIS_ERROR_NON_EXISTING_INTF "\n");
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
                    printf(ISIS_ERROR_NON_EXISTING_INTF "\n");
                    return -1;
                }

                intf_grp = isis_intf_grp_look_up(node, if_grp_name);
                
                if (!intf_grp) {
                    printf("Error : Interface Group do not exist\n");
                    return -1;
                }

                switch (enable_or_disable) {

                case CONFIG_ENABLE:
                    if (!isis_node_intf_is_enable(intf)) {
                        printf (ISIS_ERROR_PROTO_NOT_ENABLE_ON_INTF "\n");
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
                    printf(ISIS_ERROR_NON_EXISTING_INTF "\n");
                    return -1;
            }
            return isis_config_interface_link_type(intf, isis_intf_type_p2p);
            break;
        case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_LAN:
            intf = node_get_intf_by_name(node, intf_name);
            if (!intf) {
                    printf(ISIS_ERROR_NON_EXISTING_INTF "\n");
                    return -1;
            }
            return isis_config_interface_link_type(intf, isis_intf_type_lan);
            break;
        case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_PRIORITY:
            intf = node_get_intf_by_name(node, intf_name);
            if (!intf) {
                    printf(ISIS_ERROR_NON_EXISTING_INTF "\n");
                    return -1;
            }
            return isis_interface_set_priority (intf, priority);
            break;
        default: ;
    }
    return 0;
}

int
isis_show_handler (param_t *param, 
                  ser_buff_t *tlv_buf,
                  op_mode enable_or_disable);

extern void
isis_compute_spf (node_t *spf_root);

int
isis_show_handler (param_t *param, 
                  ser_buff_t *tlv_buf,
                  op_mode enable_or_disable){

    uint32_t rc = 0;
    pn_id_t pn_id;
    uint8_t fr_no;
    int cmdcode = -1;
    node_t *node = NULL;
    char *rtr_id_str = NULL;
    char *intf_name = NULL;
    Interface *intf = NULL;
    tlv_struct_t *tlv = NULL;

    c_string node_name = NULL;

    cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

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
        case CMDCODE_RUN_SPF:
            isis_compute_spf (node);
            break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL:
           isis_show_node_protocol_state (node);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_INTF:
            intf = node_get_intf_by_name (node, intf_name);
            if (!intf) {
                printf(ISIS_ERROR_NON_EXISTING_INTF "\n");
                return -1;
            }
            rc = isis_show_one_intf_stats (intf, 0);
            cli_out (node->print_buff, rc);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_INTF:
            rc =  isis_show_all_intf_stats (node);
            cli_out (node->print_buff, rc);
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
                rc = isis_show_one_lsp_pkt_detail_info (node->print_buff, lsp_pkt);
                cli_out (node->print_buff, rc);
            }
            break;
        case CMDCODE_SHOW_NODE_ISIS_PROTO_INTF_GROUPS:
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            rc = isis_show_all_interface_group (node);
            assert ( rc < NODE_PRINT_BUFF_LEN);
            cli_out (node->print_buff, rc);
            break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_TED:
            if (!isis_is_protocol_enable_on_node(node)) break;
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            rc = ted_show_ted_db(ISIS_TED_DB(node), 0, 0, node->print_buff, false);
            assert ( rc < NODE_PRINT_BUFF_LEN);
            cli_out (node->print_buff, rc);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_TED_ENTRY:
            if (!isis_is_protocol_enable_on_node(node)) break;
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            rc = ted_show_ted_db(ISIS_TED_DB(node),
                                                tcp_ip_covert_ip_p_to_n(rtr_id_str), pn_id, node->print_buff, false);
            assert ( rc < NODE_PRINT_BUFF_LEN);
            cli_out (node->print_buff, rc);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_TED_DETAIL:
            if (!isis_is_protocol_enable_on_node(node)) break;
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            rc = ted_show_ted_db(ISIS_TED_DB(node), 0, 0, node->print_buff, true);
            assert ( rc < NODE_PRINT_BUFF_LEN);
            cli_out (node->print_buff, rc);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_TED_ENTRY_DETAIL:
            if (!isis_is_protocol_enable_on_node(node)) break;
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            rc = ted_show_ted_db(ISIS_TED_DB(node),
                                                tcp_ip_covert_ip_p_to_n(rtr_id_str), pn_id, node->print_buff, true);
            assert ( rc < NODE_PRINT_BUFF_LEN);
            cli_out (node->print_buff, rc);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_ADJACENCY:
            if (!isis_is_protocol_enable_on_node(node)) break;
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            rc = isis_show_all_adjacencies (node);
             assert ( rc < NODE_PRINT_BUFF_LEN);
            cli_out (node->print_buff, rc);
        break;
        case  CMDCODE_SHOW_NODE_ISIS_PROTOCOL_SPF_LOG:
            isis_show_spf_logs(node);
            break;
        case CMCODE_SHOW_ISIS_ADVT_DB:
            memset(node->print_buff, 0, NODE_PRINT_BUFF_LEN);
            rc = isis_show_advt_db (node);
            assert ( rc < NODE_PRINT_BUFF_LEN);
            cli_out (node->print_buff, rc);
            break;
        default: ;
    }
    return 0;
}

/* CLI format */

/* config CLI format */

/* conf node <node-name> protocol ... */
int
isis_config_cli_tree(param_t *param) {

    {
        static param_t isis_proto;
	    init_param(&isis_proto, CMD, "isis", isis_config_handler, 0, INVALID, 0, "isis protocol");
	    libcli_register_param(param, &isis_proto);
	    set_param_cmd_code(&isis_proto, ISIS_CONFIG_NODE_ENABLE);
        {
             static param_t import_policy;
             init_param(&import_policy, CMD, "import-policy", 0, 0, INVALID, 0, "import policy");
             libcli_register_param(&isis_proto, &import_policy);
             //libcli_register_display_callback(&import_policy, access_list_show_all_brief);
             {
                 static param_t policy_name;
                 init_param(&policy_name, LEAF, 0, isis_config_handler, 0, STRING, "prefix-list-name",
                            ("Access List Name"));
                 libcli_register_param(&import_policy, &policy_name);
                 set_param_cmd_code(&policy_name, CMDCODE_CONF_NODE_ISIS_PROTO_IMPORT_POLICY);
             }
        }
        {
            static param_t export_policy;
            init_param(&export_policy, CMD, "export-policy", 0, 0, INVALID, 0, "export policy");
            libcli_register_param(&isis_proto, &export_policy);
            // libcli_register_display_callback(&import_policy, access_list_show_all_brief);
            {
                static param_t policy_name;
                init_param(&policy_name, LEAF, 0, isis_config_handler, 0, STRING, "prefix-list-name",
                           ("Prefix List Name"));
                libcli_register_param(&export_policy, &policy_name);
                set_param_cmd_code(&policy_name, CMDCODE_CONF_NODE_ISIS_PROTO_EXPORT_POLICY);
            }
        }
        {
             /* conf node <node-name> [no] protocol isis overload */
            static param_t ovl;
            init_param(&ovl, CMD, "overload", isis_config_handler, 0, INVALID, 0,
                        ("Overload Device"));
            libcli_register_param(&isis_proto, &ovl);
            set_param_cmd_code(&ovl, CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD);
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
                    set_param_cmd_code(&timeout_val, CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD_TIMEOUT);
                }
            }
        }

        {
            /* conf node <node-name> [no] protocol isis layer2-map*/
            static param_t layer2_map;
            init_param(&layer2_map, CMD, "layer2-map", isis_config_handler, 0, INVALID, 0,
                        ("Layer 2 Map"));
            libcli_register_param(&isis_proto, &layer2_map);
            set_param_cmd_code(&layer2_map, CMDCODE_CONF_NODE_ISIS_PROTO_LAYER2_MAP);
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
                set_param_cmd_code(&if_grp_name, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_GRP);
            }
        }
        {
             static param_t dynamic_interface_group;
            init_param(&dynamic_interface_group, CMD, "dynamic-interface-group", isis_config_handler, 0, INVALID, 0, 
                "dynamic-interface-group");
            libcli_register_param(&isis_proto, &dynamic_interface_group);
            set_param_cmd_code(&dynamic_interface_group,  CMDCODE_CONF_NODE_ISIS_PROTO_DYN_IGRP);
        }

        {
            /* conf node <node-name> [no] protocol isis interface ... */
            static param_t interface;
            init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "interface");
            libcli_register_display_callback(&interface, display_node_interfaces);
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
                set_param_cmd_code(&if_name, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ENABLE);
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
                        set_param_cmd_code(&if_grp_name, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_GROUP_MEMBERSHIP);
                    }
                }
                {
                    /* config node <node-name> protocol isis interface <if-name> p2p */
                    static param_t p2p;
                    init_param(&p2p, CMD, "point-to-point", isis_intf_config_handler, 0, INVALID, 0, "Point to Point Interface");
                    libcli_register_param(&if_name, &p2p);
                    set_param_cmd_code(&p2p,  CMDCODE_CONF_NODE_ISIS_PROTO_INTF_P2P);
                }
                {
                    /* config node <node-name> protocol isis interface <if-name> lan */
                    static param_t lan;
                    init_param(&lan, CMD, "broadcast", isis_intf_config_handler, 0, INVALID, 0, "Broadcast Interface");
                    libcli_register_param(&if_name, &lan);
                    set_param_cmd_code(&lan, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_LAN);
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
                        set_param_cmd_code(&priority_val, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_PRIORITY);
                    }
                }
            }
            {
                /*  conf node <node-name> [no] protocol isis interface all */
                static param_t all;
                init_param(&all, CMD, "all", isis_intf_config_handler, 0, INVALID, 0,
                        ("All Interfaces"));
                libcli_register_param(&interface, &all);
                set_param_cmd_code(&all, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ALL_ENABLE);
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
	    set_param_cmd_code(&isis_proto, CMDCODE_SHOW_NODE_ISIS_PROTOCOL);
        {
            /* show node <node-name> protocol isis interface */
            static param_t interface;
            init_param(&interface, CMD, "interface",  isis_show_handler, 0, INVALID, 0, "interface");
            libcli_register_display_callback(&interface, display_node_interfaces);
            libcli_register_param(&isis_proto, &interface);
            set_param_cmd_code(&interface, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_INTF);
            {
                /* show node <node-name> protocol isis adjacency */
                static param_t adjacency;
                init_param(&adjacency, CMD, "adjacency", isis_show_handler, 0, INVALID, 0, "adjacency");
                libcli_register_param(&isis_proto, &adjacency);
                set_param_cmd_code(&adjacency, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_ADJACENCY);
            }
            {
                /* show node <node-name> protocol isis interface <if-name> */
                static param_t if_name;
                init_param(&if_name, LEAF, 0, isis_show_handler, 0, STRING, "if-name",
                        ("Interface Name"));
                libcli_register_param(&interface, &if_name);
                set_param_cmd_code(&if_name, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_INTF);
            }
            {
                 /* show node <node-name> protocol isis lsdb */
                static param_t lsdb;
	            init_param(&lsdb, CMD, "lsdb", isis_show_handler, 0, INVALID, 0, "isis protocol");
	            libcli_register_param(&isis_proto, &lsdb);
	            set_param_cmd_code(&lsdb, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_LSDB);
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
                            set_param_cmd_code(&fr_no, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_LSP);
                        }
                    }
                }
            }
            {
                /* show node <node-name> protocol isis ted*/
                static param_t ted;
	            init_param(&ted, CMD, "ted", isis_show_handler, 0, INVALID, 0, "TED database");
	            libcli_register_param(&isis_proto, &ted);
	            set_param_cmd_code(&ted, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_TED);
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
                        set_param_cmd_code(&pn_id, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_TED_ENTRY);
                        {
                            static param_t detail;
                            init_param(&detail, CMD, "detail", isis_show_handler, 0, INVALID, 0,
                                       "Detailed output");
                            libcli_register_param(&pn_id, &detail);
                            set_param_cmd_code(&detail, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_TED_ENTRY_DETAIL);
                        }
                    }
                }
                  {
                    static param_t detail;
                    init_param(&detail, CMD, "detail", isis_show_handler, 0, INVALID, 0,
                        "Detailed output");
                    libcli_register_param(&ted, &detail);
                    set_param_cmd_code(&detail, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_TED_DETAIL);
                }
            }
            {
                /* show node <node-name> protocol isis advt-db*/
                static param_t advtdb;
                init_param(&advtdb, CMD, "advt-db", isis_show_handler, 0, INVALID, 0, "Advertisement database");
                libcli_register_param(&isis_proto, &advtdb);
                set_param_cmd_code(&advtdb, CMCODE_SHOW_ISIS_ADVT_DB);
            }
        }
        {
                /*show node <node-name> protocol isis event-counters*/
                static param_t event_counters;
	            init_param(&event_counters, CMD, "event-counters", isis_show_handler, 0, INVALID, 0, "event counters");
	            libcli_register_param(&isis_proto, &event_counters);
	            set_param_cmd_code(&event_counters, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_EVENT_COUNTERS);
        }
         {
                /*show node <node-name> protocol isis spf-log*/
                static param_t spf_log;
	            init_param(&spf_log, CMD, "spf-log", isis_show_handler, 0, INVALID, 0, "spf_log");
	            libcli_register_param(&isis_proto, &spf_log);
	            set_param_cmd_code(&spf_log, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_SPF_LOG);
        }
        {
            static param_t intf_grps;
            init_param(&intf_grps, CMD, "interface-groups", isis_show_handler, 0, INVALID, 0, "interface-groups");
            libcli_register_param(&isis_proto, &intf_grps);
            set_param_cmd_code(&intf_grps, CMDCODE_SHOW_NODE_ISIS_PROTO_INTF_GROUPS);
        }
    }
    return 0;
}

int
isis_clear_handler(param_t *param, 
                   ser_buff_t *tlv_buf,
                   op_mode enable_or_disable) {

    node_t *node;
    tlv_struct_t *tlv;
    c_string node_name = NULL;

    int cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if  (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
            
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch(cmdcode) {

        case CMDCODE_CLEAR_NODE_ISIS_LSDB:
        {
            isis_node_info_t *node_info = ISIS_NODE_INFO(node);
            if (!isis_is_protocol_enable_on_node(node)) break;
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
            set_param_cmd_code(&lsdb, CMDCODE_CLEAR_NODE_ISIS_LSDB);
        }
        {
             /* clear node <node-name> protocol isis adjacency */
            static param_t adjacency;
            init_param(&adjacency, CMD, "adjacency", isis_clear_handler, 0, INVALID, 0, "adjacency");
            libcli_register_param(&isis_proto, &adjacency);
            set_param_cmd_code(&adjacency, CMDCODE_CLEAR_NODE_ISIS_ADJACENCY);
        }
    }
    return 0;
}
