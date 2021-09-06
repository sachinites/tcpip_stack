#include <assert.h>
#include "../../tcp_public.h"
#include "isis_cmdcodes.h"
#include "isis_rtr.h"
#include "isis_intf.h"

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


static int
isis_intf_config_handler(param_t *param,
                                 ser_buff_t *tlv_buff,
                                 op_mode enable_or_disable) {

     int cmdcode = - 1;
     tlv_struct_t *tlv = NULL;
     char *node_name = NULL;
     node_t *node;
     char *if_name;
     interface_t *interface = NULL;

     cmdcode = EXTRACT_CMD_CODE(tlv_buff);

     TLV_LOOP_BEGIN (tlv_buff, tlv) {

            if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0) {
                node_name = tlv->value;
            }
            else if (strncmp(tlv->leaf_id, "if-name", strlen("if-name")) == 0) {
                if_name =  tlv->value;
            }
            else {
                assert(0);
            }
     } TLV_LOOP_END;

     node = node_get_node_by_name(topo, node_name);
    interface = node_get_intf_by_name(node, if_name);

    if (!interface) {
        printf("Error : Interface do not exist\n");
        return -1;
    }

     switch (cmdcode) {

         case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ALL_ENABLE:
            switch (enable_or_disable) {

                /* config node <node-name> protocol isis interface all */
                case CONFIG_ENABLE:

                   printf("config enabled on all interfaces \n");

                break;
                /* config node <node-name> [no] protocol isis interface all */
                case CONFIG_DISABLE:

                   printf("config disabled on all interfaces \n");

                break;
                default: ;
            }
            break;
            case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ENABLE:
                switch (enable_or_disable) {
                    case CONFIG_ENABLE:
                        isis_enable_protocol_on_interface(interface);
                    break;
                    case CONFIG_DISABLE:
                        isis_disable_protocol_on_interface(interface);
                    break;
                    default: ;
                }
            break;
     }

     return 0;
}



int
isis_config_cli_tree(param_t *param) {
    {
        /* config node <node-name> protocol isis */
        static param_t isis_proto;
	    init_param(&isis_proto, CMD, "isis", isis_config_handler, 0, INVALID, 0, "isis protocol");
	    libcli_register_param(param, &isis_proto);
	    set_param_cmd_code(&isis_proto, ISIS_CONFIG_NODE_ENABLE);
        {
            /* config node <node-name> protocol isis interface ...*/
            static param_t interface;
            init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "interface");
            libcli_register_param(&isis_proto, &interface);
            {
                 /* config node <node-name> protocol isis interface all*/
                  static param_t all;
                 init_param(&all, CMD, "all", isis_intf_config_handler, 0, INVALID, 0, "all Interfaces");
                 libcli_register_param(&interface, &all);
                 set_param_cmd_code(&all, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ALL_ENABLE);
            }
            {
                /* config node <node-name> protocol isis interface <if-name>*/
                static param_t if_name;
                init_param(&if_name, LEAF, 0, isis_intf_config_handler, 0, STRING, "if-name", "interface name");
                libcli_register_param(&interface, &if_name);
                set_param_cmd_code(&if_name, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ENABLE);
            }
        }
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


