#include "../../CLIBuilder/libcli.h"
#include "../../graph.h"
#include "../../Interface/InterfaceUApi.h"

extern graph_t *topo;

/* config node <node-name> ipv6 route [no] <ipv6-address> <mask>  srv6 endpoint end [flavor [psp|usp|usd]]*/
#define IPV6_SRV6_PREFIX_SID_CONFIG  1

/* config node <node-name> ipv6 route [no] <ipv6-address> <mask>  srv6 endpoint end-x <oif-name> [flavor [psp|usp|usd]]*/
#define IPV6_SRV6_ADJ_SID_CONFIG  2

#define IPV6_SRV6_PREFIX_SID_FLAVOR_CONFIG  3
#define IPV6_SRV6_ADJ_SID_FLAVOR_CONFIG  4


static int
srv6_prefix_sid_config_handler 
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    return 0;
}

static int
srv6_adjacency_sid_config_handler 
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    return 0;
}

static int
srv6_flavor_prefix_sid_config_handler 
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    return 0;
}

static int
srv6_flavor_adjacency_sid_config_handler 
                    (int cmdcode,
                    Stack_t *tlv_stack,
                    op_mode enable_or_disable) {

    return 0;
}


static int 
srv6_flavor_validation (Stack_t *tlv_stack, unsigned char *leaf_value) {

    if (strncmp((const char *)leaf_value, "psp", 3) == 0) return LEAF_VALIDATION_SUCCESS;
    if (strncmp((const char *)leaf_value, "usp", 3) == 0) return LEAF_VALIDATION_SUCCESS;
    if (strncmp((const char *)leaf_value, "usd", 3) == 0) return LEAF_VALIDATION_SUCCESS;
    return LEAF_VALIDATION_FAILED;
}

static void 
srv6_flavor_cli_subtree_hookup (param_t *root, int cmdcode, cmd_callback cbk) {

    param_t *flavor = (param_t *)calloc(1, sizeof(param_t));
    init_param(flavor, CMD, "flavor", NULL, NULL, INVALID, NULL, "Configure SRv6 EndPoint Flavor");
    libcli_register_param(root, flavor);
    {
        param_t *flavors_value = (param_t *)calloc(1, sizeof(param_t));
        init_param(flavors_value, LEAF, NULL, cbk, 
            srv6_flavor_validation , 
            STRING, "flavor", "Flavor Values [ psp | usp | usd ]");
        libcli_register_param( flavor , flavors_value);
        libcli_param_recursive(flavors_value);
        libcli_set_param_cmd_code(flavors_value, cmdcode);
        libcli_set_tail_config_batch_processing (flavors_value);
    }
}

void 
srv6_build_cli_tree (param_t *root)
{
    /*...  srv6 endpoint end-sid ... */
    static param_t srv6;
    init_param(&srv6, CMD, "srv6", NULL, NULL, INVALID, NULL, "Configure SRv6");
    libcli_register_param(root, &srv6);
    {
        static param_t endpoint;
        init_param(&endpoint, CMD, "endpoint", NULL, NULL, INVALID, NULL, "Configure SRv6 Endpoint");
        libcli_register_param(&srv6, &endpoint);
        {
            /* config node <node-name> ipv6 route [no] <ipv6-address> <mask>  srv6 endpoint end ...*/
            static param_t end;
            init_param(&end, CMD, "end-sid", srv6_prefix_sid_config_handler , 
                NULL, INVALID, NULL, "Configure SRv6 Endpoint: END");
            libcli_register_param(&endpoint, &end);
            libcli_set_param_cmd_code(&end, IPV6_SRV6_PREFIX_SID_CONFIG);
            srv6_flavor_cli_subtree_hookup (&end, IPV6_SRV6_PREFIX_SID_FLAVOR_CONFIG, srv6_flavor_prefix_sid_config_handler);
        }

        {
            /* config node <node-name> ipv6 route [no] <ipv6-address> <mask>  srv6 endpoint end-x-sid  . .. */
            static param_t end_x;
            init_param(&end_x, CMD, "end-x-sid", NULL, 
                NULL, INVALID, NULL, "Configure SRv6 Endpoint: END-X");
            libcli_register_param(&endpoint, &end_x);
            {
                /* config node <node-name> ipv6 route [no] <ipv6-address> <mask>  srv6 endpoint end-x <oif-name> ... */
                static param_t oif_name;
                init_param(&oif_name, LEAF, NULL, srv6_adjacency_sid_config_handler, NULL, STRING, "oif-name", "Outgoing Interface Name");
                libcli_register_param(&end_x, &oif_name);
                libcli_set_param_cmd_code(&oif_name, IPV6_SRV6_ADJ_SID_CONFIG);
                srv6_flavor_cli_subtree_hookup (&oif_name, IPV6_SRV6_ADJ_SID_FLAVOR_CONFIG, srv6_flavor_adjacency_sid_config_handler);
            }
        }

    }
}