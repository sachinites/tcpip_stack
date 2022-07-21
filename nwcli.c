#include "CommandParser/libcli.h"
#include "CommandParser/cmdtlv.h"
#include "graph.h"
#include <stdio.h>
#include "cmdcode.h"

extern graph_t *topo;

static int
show_nw_topology_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){

    int CMDCODE = -1;
    CMDCODE = EXTRACT_CMD_CODE(tlv_buf);
    switch(CMDCODE)
    {
        case CMDCODE_SHOW_NW_TOPOLOGY:
            dump_nw_graph(topo);
            break;
        default:
            ;
    }
}

static int
validate_node_name(char *value)
{
    return 1;
}

extern void
send_arp_broadcast_request(node_t *node, interface_t *oif, char *ip_address);
static int
arp_handler(param_t *param, ser_buff_t *tlv_buf,
                op_mode enable_or_disable){

    int cmd_code = EXTRACT_CMD_CODE(tlv_buf);
    printf("cmd code is %d\n", cmd_code);
    tlv_struct_t *tlv = NULL;
    node_t *node;
    char *node_name = NULL;
    char *ip_address = NULL;
    TLV_LOOP_BEGIN(tlv_buf, tlv)
    {
        if(strncmp(tlv->leaf_id, "node_name", strlen("node_name")) == 0)
            node_name = tlv -> value;
        if(strncmp(tlv->leaf_id, "ip_address", strlen("ip_address")) == 0)
            ip_address = tlv -> value;
    }TLV_LOOP_END;
    
    switch (cmd_code)
    {
        case CMDCODE_RESOLVE_IP:
            printf("Node name is %s, IP address is %s", node_name, ip_address);
            break;
        
        default:
            break;
    }

    node = get_node_by_node_name(topo, node_name);
    send_arp_broadcast_request(node, NULL, ip_address);
    return 0;
}
void
nw_init_cli(){

    init_libcli();
    param_t *show   = libcli_get_show_hook();
    param_t *debug  = libcli_get_debug_hook();
    param_t *config = libcli_get_config_hook();
    param_t *clear  = libcli_get_clear_hook();
    param_t *debug_show = libcli_get_debug_show_hook();
    param_t *run = libcli_get_run_hook();
    param_t *root    = libcli_get_root();

    /* show topology */
    {
        static param_t topology;
        init_param(&topology, CMD, "topology", show_nw_topology_handler, 0, INVALID,
        0, "Dump complete NW topology");

        libcli_register_param(show, &topology);
        set_param_cmd_code(&topology, CMDCODE_SHOW_NW_TOPOLOGY);
    }

    {
        static param_t node;
        init_param(&node, CMD, "node", 0, 0, INVALID,
        0, "Help: node");

        libcli_register_param(run, &node);

        {
            static param_t node_name;
            init_param(&node_name, LEAF, 0, 0, 0, STRING,
            "node_name", "Help: node_name");
            libcli_register_param(&node, &node_name);
            //set_param_cmd_code(&node_name, CMDCODE_RUN_NODE);
            {
                static param_t resolve_arp;
                init_param(&resolve_arp, CMD, "resolve_arp", 0, 0, INVALID,
                0, "Help: resolve_arp");
                libcli_register_param(&node_name, &resolve_arp);

                {
                    static param_t ip_address;
                    init_param(&ip_address, LEAF, 0, arp_handler, 0, STRING,
                    "ip_address", "Help: ip_address");
                    libcli_register_param(&resolve_arp, &ip_address);
                    set_param_cmd_code(&ip_address, CMDCODE_RESOLVE_IP);
                }
            }
        }
        
    }

    support_cmd_negation(config);

}