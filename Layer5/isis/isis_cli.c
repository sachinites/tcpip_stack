#include <assert.h>
#include "../../tcp_public.h"
#include "isis_cmdcodes.h"
#include "isis_rtr.h"

/* show node <node-name> protocol isis */
static int
isis_show_handler(param_t *param,
                                 ser_buff_t *tlv_buff,
                                 op_mode enable_or_disable)  {


    
    int cmdcode = - 1;
     tlv_struct_t *tlv = NULL;
     char *node_name = NULL;
     node_t *node;

     cmdcode = EXTRACT_CMD_CODE(tlv_buff);

     TLV_LOOP_BEGIN (tlv_buff, tlv) {

            if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0) {
                node_name = tlv->value;
            }
            else {
                assert(0);
            }
     } TLV_LOOP_END;

     node = node_get_node_by_name(topo, node_name);

     switch (cmdcode) {

         case CMDCODE_SHOW_NODE_ISIS_PROTOCOL:
            isis_show_node_protocol_state(node);
            break;
            default: ;
     }

     return 0;
}

/* conf node <node-name> protocol isis */

static int
isis_config_handler(param_t *param,
                                 ser_buff_t *tlv_buff,
                                 op_mode enable_or_disable) {

     int cmdcode = - 1;
     tlv_struct_t *tlv = NULL;
     char *node_name = NULL;
     node_t *node;

     cmdcode = EXTRACT_CMD_CODE(tlv_buff);

     TLV_LOOP_BEGIN (tlv_buff, tlv) {

            if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0) {
                node_name = tlv->value;
            }
            else {
                assert(0);
            }
     } TLV_LOOP_END;

     node = node_get_node_by_name(topo, node_name);

     switch (cmdcode) {

         case ISIS_CONFIG_NODE_ENABLE:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:

                    isis_init (node);

                break;
                case CONFIG_DISABLE:

                    isis_de_init (node);

                break;
                default: ;
            }
     }

     return 0;
}

int isis_config_cli_tree(param_t *param) {
    {
        static param_t isis_proto;
	    init_param(&isis_proto, CMD, "isis", isis_config_handler, 0, INVALID, 0, "isis protocol");
	    libcli_register_param(param, &isis_proto);
	    set_param_cmd_code(&isis_proto, ISIS_CONFIG_NODE_ENABLE);
    }
    return 0;
}

int
isis_show_cli_tree(param_t *param) {
    {
        /* show node <node-name> protocol ... */
        static param_t isis_proto;
	    init_param(&isis_proto, CMD, "isis", isis_show_handler, 0, INVALID, 0, "isis protocol");
	    libcli_register_param(param, &isis_proto);
	    set_param_cmd_code(&isis_proto, CMDCODE_SHOW_NODE_ISIS_PROTOCOL);
    }
    return 0;
}


