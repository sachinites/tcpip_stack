#include <assert.h>
#include "../../LinuxMemoryManager/uapi_mm.h"
#include "../../graph.h"
#include "objnw.h"
#include "../../CLIBuilder/libcli.h"

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
network_object_config_handler (int cmdcode,
                                                     Stack_t *tlv_stack,
                                                     op_mode enable_or_disable) {

    node_t *node;
    tlv_struct_t *tlv = NULL;
    uint32_t lb, ub;
    c_string node_name = NULL;
    char *host_addr = NULL;
    char *subnet_addr = NULL;
    char *subnet_mask = NULL;
    char *nw_obj_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){
        
    if (parser_match_leaf_id (tlv->leaf_id, "network-object-name"))
	    nw_obj_name = tlv->value;
    else if (parser_match_leaf_id (tlv->leaf_id, "host-addr"))
	    host_addr = tlv->value;
    else if (parser_match_leaf_id (tlv->leaf_id, "node-name"))
        node_name = tlv->value;
    else if (parser_match_leaf_id (tlv->leaf_id, "subnet-addr"))
        subnet_addr = tlv->value;        
    else if (parser_match_leaf_id (tlv->leaf_id, "subnet-mask"))
        subnet_mask = tlv->value;           
    else if (parser_match_leaf_id (tlv->leaf_id, "range-lb"))
        lb = tcp_ip_covert_ip_p_to_n(tlv->value);       
    else if (parser_match_leaf_id (tlv->leaf_id, "range-ub")) {
        ub = tcp_ip_covert_ip_p_to_n(tlv->value);             
        if (ub < lb) {
            cprintf ("Error : Invalid Range\n");
            return -1;
        }
    }
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {
        case  NW_OBJ_CONFIG_HOST:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    {
                        obj_nw_t *obj_nw = network_object_lookup_by_name(node->object_network_ght, nw_obj_name);

                        if (obj_nw) {
                            
                            if (obj_nw->type != OBJ_NW_TYPE_HOST) {
                                cprintf ("Error : Object Network Type cannot be changed\n");
                                return -1;
                            }

                            if (object_network_apply_change_host_address(node, obj_nw, host_addr)) {
                                return 0;
                            }
                            
                            cprintf ("Error : Conflicting Changes, Configuration aborted\n");
                            return -1;
                        }
                        obj_nw = network_object_create_new(nw_obj_name, OBJ_NW_TYPE_HOST);
                        obj_nw->u.host = tcp_ip_covert_ip_p_to_n(host_addr);
                        assert (network_object_insert_into_ht(node->object_network_ght, obj_nw));
                    }
                    break;
                case CONFIG_DISABLE:
                {
                    obj_nw_t *obj_nw = network_object_lookup_by_name(node->object_network_ght, nw_obj_name);
                    if (!obj_nw)
                    {
                        cprintf("Error : Object Network Do not Exist\n");
                        return -1;
                    }
                    if (obj_nw->type != OBJ_NW_TYPE_HOST)
                    {
                        cprintf("Error : Object Network Type cannot be changed\n");
                        return -1;
                    }

                    if (obj_nw->ref_count > 0) {
                        cprintf ("Error : Network Object in Use\n");
                        return -1;
                    }
                    assert(network_object_remove_from_ht_by_name(node->object_network_ght, nw_obj_name) == obj_nw);
                    if (!network_object_check_and_delete (obj_nw)) {
                        assert(0);
                    }
                }
                break;
            }
        break;
        case NW_OBJ_CONFIG_SUBNET:
        switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    {
                        obj_nw_t *obj_nw =
                            network_object_lookup_by_name(node->object_network_ght, nw_obj_name);

                        if (obj_nw) {

                            if (obj_nw->type != OBJ_NW_TYPE_SUBNET) {
                                cprintf("Error : Object Network Type cannot be changed\n");
                                return -1;
                            }

                            if (object_network_apply_change_subnet(node, obj_nw, subnet_addr, subnet_mask)) {
                                return 0;
                            }

                            cprintf ("Error : Conflicting Changes, Configuration aborted\n");
                            return -1;
                        }

                        obj_nw = network_object_create_new(nw_obj_name, OBJ_NW_TYPE_SUBNET);
                        obj_nw->u.subnet.network = tcp_ip_covert_ip_p_to_n(subnet_addr);
                        obj_nw->u.subnet.subnet = tcp_ip_covert_ip_p_to_n(subnet_mask);                        
                        assert (network_object_insert_into_ht(node->object_network_ght, obj_nw));
                    }
                    break;
                case CONFIG_DISABLE:
                {
                    obj_nw_t *obj_nw = network_object_lookup_by_name(node->object_network_ght, nw_obj_name);
                    if (!obj_nw)
                    {
                        cprintf("Error : Object Network Do not Exist\n");
                        return -1;
                    }
                    if (obj_nw->type != OBJ_NW_TYPE_SUBNET)
                    {
                        cprintf("Error : Object Network Type cannot be changed\n");
                        return -1;
                    }
                    if (obj_nw->ref_count > 0) {
                        cprintf("Error : Network Object in Use\n");
                        return -1;
                    }
                    assert(network_object_remove_from_ht_by_name(node->object_network_ght, nw_obj_name) == obj_nw);
                    if (!network_object_check_and_delete (obj_nw)) {
                        assert(0);
                    }
                }
                break;
            }
        break;
        case NW_OBJ_CONFIG_RANGE:
         switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    {
                        obj_nw_t *obj_nw = network_object_lookup_by_name(node->object_network_ght, nw_obj_name);

                        if (obj_nw) {

                            if (obj_nw->type != OBJ_NW_TYPE_RANGE) {
                                cprintf("Error : Object Network Type cannot be changed\n");
                                return -1;
                            }

                            if (object_network_apply_change_range(node, obj_nw, lb, ub)) {
                                return 0;
                            }

                            cprintf ("Error : Conflicting Changes, Configuration aborted\n");
                            return -1;
                        }

                        obj_nw = network_object_create_new(nw_obj_name, OBJ_NW_TYPE_RANGE);
                        obj_nw->u.range.lb = lb;
                        obj_nw->u.range.ub = ub;
                        assert (network_object_insert_into_ht(node->object_network_ght, obj_nw));
                    }
                    break;
                case CONFIG_DISABLE:
                {
                    obj_nw_t *obj_nw = network_object_lookup_by_name(node->object_network_ght, nw_obj_name);
                    if (!obj_nw)
                    {
                        cprintf("Error : Object Network Do not Exist\n");
                        return -1;
                    }
                    if (obj_nw->type != OBJ_NW_TYPE_RANGE)
                    {
                        cprintf("Error : Object Network Type cannot be changed\n");
                        return -1;
                    }
                    if (obj_nw->ref_count > 0) {
                        cprintf("Error : Network Object in Use\n");
                        return -1;
                    }
                    assert(network_object_remove_from_ht_by_name(
                            node->object_network_ght, nw_obj_name) == obj_nw);
                    if (!network_object_check_and_delete (obj_nw)) {
                        assert(0);
                    }
                }
                break;
            }
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
    init_param (&nw_obj, CMD, "object-network", NULL, NULL, INVALID, NULL, "Object Network Configurations");
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
                     init_param(&ip, LEAF, 0, network_object_config_handler, 0, IPV4, "host-addr", "specify Host IPV4 Address");
                    libcli_register_param(&host, &ip);
                    libcli_set_param_cmd_code(&ip, NW_OBJ_CONFIG_HOST);
                }
        }
        {
             /* network-object <name> <subnet-ip-addr> ...*/
             static param_t subnet_ip;
             init_param(&subnet_ip, LEAF, 0, 0, 0, IPV4, "subnet-addr", "specify Subnet IPV4 Prefix Address");
             libcli_register_param(&name, &subnet_ip);
             {
                 /* network-object <name> <subnet-ip-addr> <subnet-mask> */
                 static param_t subnet_mask;
                 init_param(&subnet_mask, LEAF, 0, network_object_config_handler, 0, IPV4, "subnet-mask", "specify Subnet IPV4 MaskAddress in A.B.C.D format");
                 libcli_register_param(&subnet_ip, &subnet_mask);
                 libcli_set_param_cmd_code(&subnet_mask, NW_OBJ_CONFIG_SUBNET);
             }
        }
        {
                /* network-object <name>range .... */
                static param_t range;
                init_param(&range, CMD, "range", 0, 0, INVALID, 0, "specify IP Address Range A.B.C.D E.F.G.H");
                libcli_register_param(&name, &range);
                {
                     /* network-object <name> range <range-lb> ...*/
                    static param_t range_lb;
                    init_param(&range_lb, LEAF, 0, 0, 0, IPV4, "range-lb", "specify IPV4 Lower Range Address");
                    libcli_register_param(&range, &range_lb);
                    {
                        /* network-object <name> range <range-lb> <range-ub>*/
                        static param_t range_ub;
                        init_param(&range_ub, LEAF, 0, network_object_config_handler, 0, IPV4, "range-ub", "specify IPV4 Upper Range Address");
                        libcli_register_param(&range_lb, &range_ub);
                        libcli_set_param_cmd_code(&range_ub, NW_OBJ_CONFIG_RANGE);
                    }
                }
        }
    }
}

static int
network_object_show_handler (int cmdcode,
                                                     Stack_t *tlv_stack,
                                                     op_mode enable_or_disable) {

    node_t *node;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;
    char *nw_obj_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){
        
    if (parser_match_leaf_id (tlv->leaf_id, "network-object-name"))
	    nw_obj_name = tlv->value;
    else if (parser_match_leaf_id (tlv->leaf_id, "node-name"))
        node_name = tlv->value;
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
        init_param(&nw_obj, CMD, "object-network", network_object_show_handler, NULL, INVALID, NULL, "Network Object Configurations");
        libcli_register_param(root, &nw_obj);
        libcli_set_param_cmd_code(&nw_obj, NW_OBJ_SHOW_ALL);
        {
             /* show node <node-name> network-object <name>*/
             static param_t name;
             init_param(&name, LEAF, 0, network_object_show_handler, 0, STRING, "network-object-name", "Network Object Name");
             libcli_register_param(&nw_obj, &name);
             libcli_set_param_cmd_code(&name, NW_OBJ_SHOW_ONE);
        }
    }
}
