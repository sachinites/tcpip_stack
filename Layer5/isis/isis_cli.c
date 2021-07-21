#include "../../tcp_public.h"
#include "isis_cmdcodes.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_nbrship.h"

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
                case CONFIG_DISABLE:
                    isis_de_init(node);
                default: ;
            }
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
    }
    return 0;
}