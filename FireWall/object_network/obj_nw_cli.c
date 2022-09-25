#include <assert.h>
#include "../../graph.h"
#include "objnw.h"
#include "../../CommandParser/libcli.h"
#include "../../CommandParser/cmdtlv.h"

extern graph_t *topo;

#define NW_OBJ_CONFIG_HOST 1
/* network-object <name> host <host-ip> */
#define NW_OBJ_CONFIG_SUBNET 2
/* network-object <name> subnet <subnet-ip> <subnet-mask>*/
#define NW_OBJ_CONFIG_RANGE 3
/* network-object <name> range <ip1> <ip2>*/
#define NW_OBJ_SHOW_ALL 4
/* show node <node-name> network-object */
#define NW_OBJ_SHOW_ONE 5
/* show node <node-name> network-object <nw-obj-name>*/

static int
network_object_config_handler (param_t *param, 
                                                     ser_buff_t *tlv_buf,
                                                     op_mode enable_or_disable) {

    node_t *node;
    tlv_struct_t *tlv = NULL;
    char *node_name = NULL;
    char *ip_addr1 = NULL;
    char *nw_obj_name = NULL;

    int cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        
    if (parser_match_leaf_id (tlv->leaf_id, "network-object-name"))
	    nw_obj_name = tlv->value;
    else if (parser_match_leaf_id (tlv->leaf_id, "ip"))
	    ip_addr1 = tlv->value;
    else if (parser_match_leaf_id (tlv->leaf_id, "node-name"))
        node_name = tlv->value;
    else
        assert(0);
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {
        case  NW_OBJ_CONFIG_HOST:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    {
                        obj_nw_t *obj_nw = network_object_lookup_by_name(node->object_network_ght, nw_obj_name);
                        if (obj_nw) {
                            printf ("Error : Object Network Already defined\n");
                            return -1;
                        }
                        obj_nw = network_object_create_new(nw_obj_name, OBJ_NW_TYPE_HOST);
                        obj_nw->u.host = tcp_ip_covert_ip_p_to_n(ip_addr1);
                        assert (network_object_insert_into_ht(node->object_network_ght, obj_nw));
                    }
                    break;
                case CONFIG_DISABLE:
                {
                    obj_nw_t *obj_nw = network_object_lookup_by_name(node->object_network_ght, nw_obj_name);
                    if (!obj_nw)
                    {
                        printf("Error : Object Network Do not Exist\n");
                        return -1;
                    }
                    assert(network_object_remove_from_ht_by_name(node->object_network_ght, nw_obj_name) == obj_nw);
                    if (!network_object_check_and_delete (obj_nw)) {
                        printf ("Error : Network Object Could not be deleted\n");
                        return -1;
                    }
                }
                break;
            }
        break;
        case NW_OBJ_CONFIG_SUBNET:
        break;
        case NW_OBJ_CONFIG_RANGE:
        break;
        default:
            assert(0);
    }
    return 0;
}

void
network_object_build_config_cli (param_t *root) {

    /* network-object ...*/
    static param_t nw_obj;
    init_param (&nw_obj, CMD, "network-object", NULL, NULL, INVALID, NULL, "Network Object Configurations");
    libcli_register_param(root, &nw_obj);

    {
        /* network-object <name> ...*/
        static param_t name;
        init_param(&name, LEAF, 0,  NULL, 0, STRING, "network-object-name", "Network Object Name");
        libcli_register_param(&nw_obj, &name);
        
        {
                /* network-object <name> host ... */
                static param_t host;
                init_param(&host, CMD, "host", 0, 0, INVALID, 0, "specify host IP Address");
                libcli_register_param(&name, &host);
                {
                     /* network-object <name> host <ip-addr> */
                     static param_t ip;
                     init_param(&ip, LEAF, 0, network_object_config_handler, 0, IPV4, "ip", "specify Host IPV4 Address");
                    libcli_register_param(&host, &ip);
                    set_param_cmd_code(&ip, NW_OBJ_CONFIG_HOST);
                }
        }
    }
}

static int
network_object_show_handler (param_t *param, 
                                                     ser_buff_t *tlv_buf,
                                                     op_mode enable_or_disable) {

    node_t *node;
    tlv_struct_t *tlv = NULL;
    char *node_name = NULL;
    char *nw_obj_name = NULL;

    int cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){
        
    if (parser_match_leaf_id (tlv->leaf_id, "network-object-name"))
	    nw_obj_name = tlv->value;
    else if (parser_match_leaf_id (tlv->leaf_id, "node-name"))
        node_name = tlv->value;
    else
        assert(0);
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {

        case NW_OBJ_SHOW_ALL:
            network_object_hashtable_print (node->object_network_ght);
            break;
        case NW_OBJ_SHOW_ONE:
            break;
        default:
            assert(0);
    }

    return 0;
}

void
network_object_build_show_cli (param_t *root) {
   
    {
        /* show node <node-name> network-object */
        static param_t nw_obj;
        init_param(&nw_obj, CMD, "network-object", network_object_show_handler, NULL, INVALID, NULL, "Network Object Configurations");
        libcli_register_param(root, &nw_obj);
        set_param_cmd_code(&nw_obj, NW_OBJ_SHOW_ALL);
        {
             /* show node <node-name> network-object <name>*/
             static param_t name;
             init_param(&name, LEAF, 0, network_object_show_handler, 0, STRING, "network-object-name", "Network Object Name");
             libcli_register_param(&nw_obj, &name);
             set_param_cmd_code(&name, NW_OBJ_SHOW_ONE);
        }
    }
}