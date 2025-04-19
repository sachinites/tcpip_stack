#include "../../../tcp_public.h"
#include "lfa.h"
#include "lfa_isis.h"

/*  to Globally enable/disable FRR 
config node <node-name> protocol frr */
#define CONFIG_LFA_ENABLE 1

/* show node <node-name> protocol frr database isis */
#define SHOW_LFA_DB_ISIS 2

/* show node <node-name> protocol frr database ospf */
#define SHOW_LFA_DB_OSPF 3

/* conf node <node-name> protocol ... */

extern graph_t *topo;

static int 
lfa_config_handler(int cmdcode,
                     Stack_t *tlv_stack,
                     op_mode enable_or_disable) {

    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {

        case CONFIG_LFA_ENABLE:

            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    lfa_init (node, &LFA_NODE_INFO(node));
                    break;
                case CONFIG_DISABLE:
                    lfa_deinit (node, &LFA_NODE_INFO(node));
                    break;
                default:
                    break;
            }
            break;


        default:
            break;
    }
    return 0;
}


int
lfa_config_cli_tree(param_t *param) {

    {
        /* config node <node-name> protocol frr */
        static param_t frr;
        init_param(&frr, CMD, "frr", lfa_config_handler, 0, INVALID, 0, "FRR protocol");
        libcli_register_param(param, &frr);
        libcli_set_param_cmd_code(&frr, CONFIG_LFA_ENABLE);
    }

    return 0;
}

static int 
lfa_show_handler(int cmdcode,
                        Stack_t *tlv_stack,
                        op_mode enable_or_disable) {

    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv) {
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {
        case SHOW_LFA_DB_ISIS:
            ted_show_ted_db( lfa_get_isis_teddb (node, 1), 0, 0, 0, false);
            ted_show_ted_db( lfa_get_isis_teddb (node, 2), 0, 0, 0, false);
            break;
        case SHOW_LFA_DB_OSPF:
            break;
        default:
            break;
    }
    return 0;
}

int
lfa_show_cli_tree(param_t *param) {

    {
        /* show node <node-name> protocol frr database isis */
        static param_t frr;
        init_param(&frr, CMD, "frr", 0, 0, INVALID, 0, "FRR protocol");
        libcli_register_param(param, &frr);
        {
            static param_t database;
            init_param(&database, CMD, "database", 0, 0, INVALID, 0, "FRR database");
            libcli_register_param(&frr, &database);
            {
                static param_t isis;
                init_param(&isis, CMD, "isis", lfa_show_handler, 0, INVALID, 0, "ISIS protocol");
                libcli_register_param(&database, &isis);
                libcli_set_param_cmd_code(&isis, SHOW_LFA_DB_ISIS);
            }
            {
                static param_t ospf;
                init_param(&ospf, CMD, "ospf", lfa_show_handler, 0, INVALID, 0, "OSPF protocol");
                libcli_register_param(&database, &ospf);
                libcli_set_param_cmd_code(&ospf, SHOW_LFA_DB_OSPF);
            }            
        }
    }

    return 0;
} 