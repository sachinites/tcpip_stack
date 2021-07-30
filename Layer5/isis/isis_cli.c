#include "../../tcp_public.h"
#include "isis_cmdcodes.h"
#include "isis_pkt.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_const.h"
#include "isis_lspdb.h"

static int
isis_config_handler(param_t *param, 
                    ser_buff_t *tlv_buf,
                    op_mode enable_or_disable){

    int cmdcode = -1;
    node_t *node = NULL;
    char *node_name = NULL;
    tlv_struct_t *tlv = NULL;

    cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if  (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else
            assert(0);
   } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch(cmdcode) {
        case ISIS_CONFIG_NODE_ENABLE:
            switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    isis_init(node);
                    break;
                case CONFIG_DISABLE:
                    isis_de_init(node);
                    break;
                default: ;
            }
        break;
        default: ;
    }
    return 0;
}


static int
isis_intf_config_handler(param_t *param, 
                    ser_buff_t *tlv_buf,
                    op_mode enable_or_disable){

    int cmdcode = -1;
    node_t *node = NULL;
    char *node_name = NULL;
    char *intf_name = NULL;
    interface_t *intf = NULL;
    tlv_struct_t *tlv = NULL;

    cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if  (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else if (strncmp(tlv->leaf_id, "if-name", strlen("if-name")) ==0)
            intf_name = tlv->value;
        else
            assert(0);
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
        default: ;
    }
    return 0;
}


static int
isis_show_handler(param_t *param, 
                  ser_buff_t *tlv_buf,
                  op_mode enable_or_disable){

    int cmdcode = -1;
    node_t *node = NULL;
    char *node_name = NULL;
    char *intf_name = NULL;
    interface_t *intf = NULL;
    tlv_struct_t *tlv = NULL;

    cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if  (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else if (strncmp(tlv->leaf_id, "if-name", strlen("if-name")) ==0)
            intf_name = tlv->value;
        else
            assert(0);
   } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    
    switch(cmdcode) {
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL:
           isis_show_node_protocol_state(node);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_INTF:
            intf = node_get_intf_by_name(node, intf_name);
            if(!intf) {
                printf(ISIS_ERROR_NON_EXISTING_INTF "\n");
                return -1;
            }
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_LSDB:
            isis_show_lspdb(node);
        break;
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_EVENT_COUNTERS:
            isis_show_event_counters(node);
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

        /* Enable ISIS on the device at node level
        conf node <node-name> protocol isis
        * Behavior : 
            1. Device must register for all interested pkts 
            2. Device must generate LSP paclet and install in ISIS LSP DB
            
        * Negation : 
            1. protocol must de-register for all ISIS pkts
            2. Complete shutdown the protocol.
                Must clean up all dynamic ISIS Data Structures,
                and stop advertising Hellos and LSPs.
                clean up node->isis_node_info and intf->isis_intf_info for all interfaces.
        */
        static param_t isis_proto;
	    init_param(&isis_proto, CMD, "isis", isis_config_handler, 0, INVALID, 0, "isis protocol");
	    libcli_register_param(param, &isis_proto);
	    set_param_cmd_code(&isis_proto, ISIS_CONFIG_NODE_ENABLE);
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
                        for recveiving and sending LSPs
                    * Negation : 
                    1. Device must stop sending hellos
                    2. Once nbrship is broken on this interface, interface becomes non-eligible
                        for recveiving and sending LSPs
                */
                static param_t if_name;
                init_param(&if_name, LEAF, 0, isis_intf_config_handler, 0, STRING, "if-name",
                        ("Interface Name"));
                libcli_register_param(&interface, &if_name);
                set_param_cmd_code(&if_name, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ENABLE);
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
            /* show node <node-name> [no] protocol isis interface ... */
            static param_t interface;
            init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "interface");
            libcli_register_display_callback(&interface, display_node_interfaces);
            libcli_register_param(&isis_proto, &interface);
            {
                /* show node <node-name> protocol isis interface <if-name> */
                static param_t if_name;
                init_param(&if_name, LEAF, 0, isis_show_handler, 0, STRING, "if-name",
                        ("Interface Name"));
                libcli_register_param(&interface, &if_name);
                set_param_cmd_code(&if_name, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_INTF);
            }
            {
                static param_t lsdb;
	            init_param(&lsdb, CMD, "lsdb", isis_show_handler, 0, INVALID, 0, "isis protocol");
	            libcli_register_param(&isis_proto, &lsdb);
	            set_param_cmd_code(&lsdb, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_LSDB);
            }
        }
        {
                /*show node <node-name> protocol isis event-counters*/
                static param_t event_counters;
	            init_param(&event_counters, CMD, "event-counters", isis_show_handler, 0, INVALID, 0, "event counters");
	            libcli_register_param(&isis_proto, &event_counters);
	            set_param_cmd_code(&event_counters, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_EVENT_COUNTERS);
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
    char *node_name = NULL;

    int cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if  (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else
            assert(0);
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch(cmdcode) {

        case CMDCODE_CLEAR_NODE_ISIS_LSDB:
            isis_cleanup_lsdb(node);
            isis_schedule_lsp_pkt_generation(node, isis_event_admin_action);
            break;
        default: ;
    return 0;
    }
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
    
    }
    return 0;
}