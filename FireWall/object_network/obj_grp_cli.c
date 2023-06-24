#include <assert.h>
#include "../../LinuxMemoryManager/uapi_mm.h"
#include "../../CLIBuilder/libcli.h"
#include "../../graph.h"
#include "object_group.h"
#include "object_grp_update.h"

extern graph_t *topo;

typedef struct obj_nw_ obj_nw_t;
extern obj_nw_t *
network_object_lookup_by_name (hashtable_t *ht, const char *name);

#define OBJ_GRP_CONFIG_HOST 1
/* object-group network <og-name> host <host-ip> */
#define OBJ_GRP_CONFIG_SUBNET 2
/* object-group network <og-name> subnet <subnet-ip> <subnet-mask>*/
#define OBJ_GRP_CONFIG_RANGE 3
/* object-group network  <og-name> range <ip1> <ip2>*/
#define OBJ_GRP_CONFIG_NESTED   4
/* object-group network <og-name> group-object <og-name>*/
#define OBJ_GRP_SHOW_ALL 5
/* show node <node-name> object-group */
#define OBJ_GRP_SHOW_ONE 6
/* show node <node-name> object-group <og-name>*/
#define OBJ_GRP_CONFIG_NAME 7
/* conf node <node-name> [no] object-group network <og-name> */

void
object_group_build_config_cli (param_t *root);

extern void
object_group_display_name_cli_callback (param_t *param, Stack_t *tlv_stack);

static int
object_group_config_handler (int cmdcode,
                                                  Stack_t *tlv_stack,
                                                  op_mode enable_or_disable) {

    node_t *node;
    tlv_struct_t *tlv = NULL;
    uint32_t lb, ub;
    c_string node_name = NULL;
    c_string host_addr = NULL;
    c_string subnet_addr = NULL;
    c_string subnet_mask = NULL;
    c_string objgrp_name = NULL;
    c_string nested_objgrp_name = NULL;

    byte c_obj_grp_name[OBJ_GRP_NAME_LEN]; 

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

    if (parser_match_leaf_id (tlv->leaf_id, "object-group-name"))
	    objgrp_name = tlv->value;
    else if (parser_match_leaf_id (tlv->leaf_id, "nested-og-name"))
	    nested_objgrp_name = tlv->value;
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

        case OBJ_GRP_CONFIG_NAME:
            switch(enable_or_disable) {
                case CONFIG_ENABLE:
                    /* CLI : object-group network <og-name> */ 
                    cprintf ("Error : Incomplete Command\n");
                    return -1;
                case CONFIG_DISABLE:
                    /* CLI : [no] object-group network <og-name> */ 
                    {
                        if (network_object_lookup_by_name(node->object_network_ght, objgrp_name))
                        {
                            cprintf("Error : Attempt to perform operation on Network Object\n");
                            return -1;
                        }

                        object_group_t *og = object_group_lookup_ht_by_name(node, node->object_group_ght, objgrp_name);
                        if (!og) {
                            cprintf ("Error : Object Group Do not Exist\n");
                            return -1;
                        }
                        if (object_group_in_use_by_other_og(og) ||
                                og->ref_count) {
                            cprintf ("Error : Cannot Delete, Object Group is in Use\n");
                            return -1;
                        }
                        object_group_delete(node, og);
                        return 0;
                    }
                    break;
            }
            break;
        case OBJ_GRP_CONFIG_HOST:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    {
                        uint32_t host_addr_int;

                        /* CLI Triggered : object-group network <og-name> host <A.B.C.D> */
                        if (network_object_lookup_by_name (node->object_network_ght, objgrp_name)) {
                            cprintf ("Error : Network Object already exist by this name\n");
                            return -1;
                        }

                        object_group_t *p_og = object_group_lookup_ht_by_name(node, node->object_group_ght, objgrp_name);

                        if (p_og) {
                            host_addr_int = tcp_ip_covert_ip_p_to_n(host_addr);
                            object_group_network_construct_name(OBJECT_GRP_NET_HOST, host_addr_int, 0, c_obj_grp_name);
                            object_group_t *c_og = object_group_find_child_object_group(p_og, c_obj_grp_name);
                            if (c_og) {
                                return 0;
                            }
                            c_og = object_group_malloc(c_obj_grp_name, OBJECT_GRP_NET_HOST);
                            c_og->u.host = host_addr_int;
                            //object_group_bind (p_og, c_og);
                            object_group_update_referenced_acls(node, p_og, c_og, false);
                            return 0;
                        }

                        host_addr_int = tcp_ip_covert_ip_p_to_n(host_addr);
                        object_group_network_construct_name(OBJECT_GRP_NET_HOST, host_addr_int, 0, c_obj_grp_name);
                        object_group_t *c_og = object_group_malloc(c_obj_grp_name, OBJECT_GRP_NET_HOST);
                        c_og->u.host = host_addr_int;
                        p_og = object_group_malloc(objgrp_name, OBJECT_GRP_NESTED);
                        object_group_bind (p_og, c_og);
                        object_group_insert_into_ht(node, node->object_group_ght, p_og);
                        return 0;
                    }
                    break;
                case CONFIG_DISABLE:
                {
                    /* CLI Triggered : [no] object-group network <og-name> host <A.B.C.D> */
                    object_group_t *og = object_group_lookup_ht_by_name(
                                                        node, node->object_group_ght, objgrp_name);
                    if (!og) {
                        cprintf ("Error : Object Group Do not Exist\n");
                        return -1;
                    }

                    glthread_t *curr;
                    uint32_t host_addr_int = tcp_ip_covert_ip_p_to_n(host_addr);
                    obj_grp_list_node_t *obj_grp_list_node;

                     ITERATE_GLTHREAD_BEGIN(&og->u.nested_og_list_head, curr) {

                        obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                        if (obj_grp_list_node->og->og_type != OBJECT_GRP_NET_HOST) continue;
                        if (obj_grp_list_node->og->u.host != host_addr_int) continue;
                        object_group_update_referenced_acls(node, og, obj_grp_list_node->og, true);
                        //object_group_delete(node, obj_grp_list_node->og);
                        return 0;
                     }  ITERATE_GLTHREAD_END(&og->u.nested_og_list_head, curr);
                     cprintf ("Error : Configuration do not exist\n");
                     return -1;
                }
                break;
            }
            break;
        case OBJ_GRP_CONFIG_SUBNET:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    {
                        uint32_t host_addr_int1, host_addr_int2;

                        /* CLI Triggered : object-group network <og-name>  <A.B.C.D> <A.B.C.D>*/
                        if (network_object_lookup_by_name (node->object_network_ght, objgrp_name)) {
                            cprintf ("Error : Network Object already exist by this name\n");
                            return -1;
                        }

                        object_group_t *p_og = object_group_lookup_ht_by_name(node, node->object_group_ght, objgrp_name);

                        if (p_og) {
                            host_addr_int1 = tcp_ip_covert_ip_p_to_n(subnet_addr);
                            host_addr_int2 = tcp_ip_covert_ip_p_to_n(subnet_mask);
                            object_group_network_construct_name(OBJECT_GRP_NET_ADDR, host_addr_int1, host_addr_int2, c_obj_grp_name);
                            object_group_t *c_og = object_group_find_child_object_group(p_og, c_obj_grp_name);
                            if (c_og) {
                                return 0;
                            }
                            c_og = object_group_malloc(c_obj_grp_name, OBJECT_GRP_NET_ADDR);
                            c_og->u.subnet.network = host_addr_int1;
                            c_og->u.subnet.subnet = host_addr_int2;
                            object_group_update_referenced_acls(node, p_og, c_og, false);
                            //object_group_bind (p_og, c_og);
                            return 0;
                        }

                        host_addr_int1 = tcp_ip_covert_ip_p_to_n(subnet_addr);
                        host_addr_int2 = tcp_ip_covert_ip_p_to_n(subnet_mask);
                        object_group_network_construct_name(OBJECT_GRP_NET_HOST, host_addr_int1, host_addr_int2, c_obj_grp_name);
                        object_group_t *c_og = object_group_malloc(c_obj_grp_name, OBJECT_GRP_NET_ADDR);
                        c_og->u.subnet.network = host_addr_int1;
                        c_og->u.subnet.subnet = host_addr_int2;
                        p_og = object_group_malloc(objgrp_name, OBJECT_GRP_NESTED);
                        object_group_bind (p_og, c_og);
                        object_group_insert_into_ht(node, node->object_group_ght, p_og);
                        return 0;
                    }
                    break;
                case CONFIG_DISABLE:
                {
                    /* CLI Triggered : [no] object-group network <og-name> <A.B.C.D> <A.B.C.D>*/
                    object_group_t *og = object_group_lookup_ht_by_name(
                                                        node, node->object_group_ght, objgrp_name);
                    if (!og) {
                        cprintf ("Error : Object Group Do not Exist\n");
                        return -1;
                    }

                    glthread_t *curr;
                    uint32_t host_addr_int1 = tcp_ip_covert_ip_p_to_n(subnet_addr);
                    uint32_t host_addr_int2 = tcp_ip_covert_ip_p_to_n(subnet_mask);
                    obj_grp_list_node_t *obj_grp_list_node;

                     ITERATE_GLTHREAD_BEGIN(&og->u.nested_og_list_head, curr) {

                        obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                        if (obj_grp_list_node->og->og_type != OBJECT_GRP_NET_ADDR) continue;
                        if (obj_grp_list_node->og->u.subnet.network != host_addr_int1) continue;
                        if (obj_grp_list_node->og->u.subnet.subnet != host_addr_int2) continue;
                        object_group_update_referenced_acls(node, og, obj_grp_list_node->og, true);
                        //object_group_delete(node, obj_grp_list_node->og);
                        return 0;
                     }  ITERATE_GLTHREAD_END(&og->u.nested_og_list_head, curr);
                     cprintf ("Error : Configuration do not exist\n");
                     return -1;
                }
                break;
            }
            break;
        case OBJ_GRP_CONFIG_RANGE:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    {
                        /* CLI Triggered : object-group network <og-name>  range <A.B.C.D> <A.B.C.D>*/
                        if (network_object_lookup_by_name (node->object_network_ght, objgrp_name)) {
                            cprintf ("Error : Network Object already exist by this name\n");
                            return -1;
                        }

                        object_group_t *p_og = object_group_lookup_ht_by_name(node, node->object_group_ght, objgrp_name);

                        if (p_og) {
                            object_group_network_construct_name(OBJECT_GRP_NET_RANGE, lb, ub, c_obj_grp_name);
                            object_group_t *c_og = object_group_find_child_object_group(p_og, c_obj_grp_name);
                            if (c_og) {
                                return 0;
                            }
                             c_og = object_group_malloc(c_obj_grp_name, OBJECT_GRP_NET_RANGE);
                             c_og->u.range.lb = lb;
                             c_og->u.range.ub = ub;
                             object_group_update_referenced_acls(node, p_og, c_og, false);
                            //object_group_bind (p_og, c_og);
                            return 0;
                        }

                        object_group_network_construct_name(OBJECT_GRP_NET_RANGE, lb, ub, c_obj_grp_name);
                        object_group_t *c_og = object_group_malloc(c_obj_grp_name, OBJECT_GRP_NET_RANGE);
                        c_og->u.range.lb = lb;
                        c_og->u.range.ub = ub;                        
                        p_og = object_group_malloc(objgrp_name, OBJECT_GRP_NESTED);
                        object_group_bind (p_og, c_og);
                        object_group_insert_into_ht(node, node->object_group_ght, p_og);
                        return 0;
                    }
                    break;
                case CONFIG_DISABLE:
                {
                    /* CLI Triggered : [no] object-group network <og-name> range <A.B.C.D> <A.B.C.D>*/
                    object_group_t *og = object_group_lookup_ht_by_name(
                                                        node, node->object_group_ght, objgrp_name);
                    if (!og) {
                        cprintf ("Error : Object Group Do not Exist\n");
                        return -1;
                    }

                    glthread_t *curr;
                    obj_grp_list_node_t *obj_grp_list_node;

                     ITERATE_GLTHREAD_BEGIN(&og->u.nested_og_list_head, curr) {

                        obj_grp_list_node = glue_to_obj_grp_list_node(curr);
                        if (obj_grp_list_node->og->og_type != OBJECT_GRP_NET_RANGE) continue;
                        if (obj_grp_list_node->og->u.range.lb != lb) continue;
                        if (obj_grp_list_node->og->u.range.ub != ub) continue;
                        object_group_update_referenced_acls(node, og, obj_grp_list_node->og,  true);
                        //object_group_delete(node, obj_grp_list_node->og);
                        return 0;
                     }  ITERATE_GLTHREAD_END(&og->u.nested_og_list_head, curr);
                     cprintf ("Error : Configuration do not exist\n");
                     return -1;
                }
                break;
            }
            break;
        case OBJ_GRP_CONFIG_NESTED:
            switch (enable_or_disable) {
                case CONFIG_ENABLE:
                    {
                        /* CLI Triggered : object-group network <og-name>  group-object <og-name>*/
                        if (network_object_lookup_by_name (node->object_network_ght, objgrp_name)) {
                            cprintf ("Error : Network Object already exist by name %s\n", objgrp_name);
                            return -1;
                        }

                        if (network_object_lookup_by_name (node->object_network_ght, nested_objgrp_name)) {
                            cprintf ("Error : Network Object already exist name %s\n", nested_objgrp_name);
                            return -1;
                        }

                        object_group_t *c_og = object_group_lookup_ht_by_name(node, node->object_group_ght, nested_objgrp_name);

                        if (!c_og) {
                            cprintf ("Error : Nested Object Group Do not exist\n");
                            return -1;
                        }

                        object_group_t *p_og = object_group_lookup_ht_by_name(node, node->object_group_ght, objgrp_name);

                        if (p_og) {
                            if (object_group_find_child_object_group(p_og, nested_objgrp_name)) {
                                return 0;
                            }
                            object_group_update_referenced_acls(node, p_og, c_og, false);
                            //object_group_bind (p_og, c_og);
                            return 0;
                        }

                        p_og = object_group_malloc(objgrp_name, OBJECT_GRP_NESTED);
                        object_group_bind (p_og, c_og);
                        object_group_insert_into_ht(node, node->object_group_ght, p_og);
                        return 0;
                    }
                    break;
                case CONFIG_DISABLE:
                {
                    /* CLI Triggered : [no] object-group network <og-name> group-object <og-name> */
                        object_group_t *p_og = object_group_lookup_ht_by_name(node, node->object_group_ght, objgrp_name);
                        if (!p_og) {
                            cprintf ("Error : Object Group %s Do not exist\n", objgrp_name);
                            return -1;
                        }
                        object_group_t *c_og = object_group_lookup_ht_by_name(node, node->object_group_ght, nested_objgrp_name);                        
                        if (!c_og) {
                            cprintf ("Error : Object Group %s Do not exist\n", nested_objgrp_name);
                            return -1;
                        }
                         object_group_update_referenced_acls(node, p_og, c_og, true);
                        //object_group_unbind_parent (p_og, c_og);
                        //object_group_unbind_child (p_og, c_og);
                        return 0;
                }
                break;
            }
            break;
        default: ;
    }

    return 0;
}

void object_group_build_config_cli (param_t *root)
{
    /* object-group ...*/
    static param_t obj_grp;
    init_param(&obj_grp, CMD, "object-group", NULL, NULL, INVALID, NULL, "Object Group Configurations");
    libcli_register_param(root, &obj_grp);
    {
        /* object-group network ...*/
        static param_t network;
        init_param(&network, CMD, "network", NULL, NULL, INVALID, NULL, "Object Group Network");
        libcli_register_param(&obj_grp, &network);
        libcli_register_display_callback(&network, object_group_display_name_cli_callback);
        {
            /* object-group network <og-name> ...*/
            static param_t name;
            init_param(&name, LEAF, 0, object_group_config_handler, 0, STRING, "object-group-name", "Object Group Name");
            libcli_register_param(&network, &name);
            libcli_set_param_cmd_code(&name, OBJ_GRP_CONFIG_NAME);

            {
                /* object-group network <og-name> host ... */
                static param_t host;
                init_param(&host, CMD, "host", 0, 0, INVALID, 0, "specify host IP Address");
                libcli_register_param(&name, &host);
                {
                    /* object-group network <og-name> host <ip-addr> */
                    static param_t ip;
                    init_param(&ip, LEAF, 0, object_group_config_handler, 0, IPV4, "host-addr", "specify Host IPV4 Address");
                    libcli_register_param(&host, &ip);
                    libcli_set_param_cmd_code(&ip, OBJ_GRP_CONFIG_HOST);
                }
            }
            {
                /* object-group network  <og-name> <subnet-ip-addr> ...*/
                static param_t subnet_ip;
                init_param(&subnet_ip, LEAF, 0, 0, 0, IPV4, "subnet-addr", "specify Subnet IPV4 Prefix Address");
                libcli_register_param(&name, &subnet_ip);
                {
                    /* object-group network <og-name> <subnet-ip-addr> <subnet-mask> */
                    static param_t subnet_mask;
                    init_param(&subnet_mask, LEAF, 0, object_group_config_handler, 0, IPV4, "subnet-mask", "specify Subnet IPV4 MaskAddress in A.B.C.D format");
                    libcli_register_param(&subnet_ip, &subnet_mask);
                    libcli_set_param_cmd_code(&subnet_mask, OBJ_GRP_CONFIG_SUBNET);
                }
            }
            {
                /* object-group network <og-name> range .... */
                static param_t range;
                init_param(&range, CMD, "range", 0, 0, INVALID, 0, "specify IP Address Range A.B.C.D E.F.G.H");
                libcli_register_param(&name, &range);
                {
                    /* object-group network <og-name> range <range-lb> ...*/
                    static param_t range_lb;
                    init_param(&range_lb, LEAF, 0, 0, 0, IPV4, "range-lb", "specify IPV4 Lower Range Address");
                    libcli_register_param(&range, &range_lb);
                    {
                        /* object-group network <og-name> range <range-lb> <range-ub>*/
                        static param_t range_ub;
                        init_param(&range_ub, LEAF, 0, object_group_config_handler, 0, IPV4, "range-ub", "specify IPV4 Upper Range Address");
                        libcli_register_param(&range_lb, &range_ub);
                        libcli_set_param_cmd_code(&range_ub, OBJ_GRP_CONFIG_RANGE);
                    }
                }
            }
            {
                /* object-group network  <og-name> group-object .... */
                static param_t grp_object;
                init_param(&grp_object, CMD, "group-object", 0, 0, INVALID, 0, "specify Object-Group Name");
                libcli_register_param(&name, &grp_object);
                {
                    /* object-group network <og-name> group-object <og-name> */
                    static param_t og_name;
                    init_param(&og_name, LEAF, 0, object_group_config_handler, 0, STRING, "nested-og-name", "specify Object-Group Name");
                    libcli_register_param(&grp_object, &og_name);
                    libcli_set_param_cmd_code(&og_name, OBJ_GRP_CONFIG_NESTED);
                }
            }
        }
    }
}

static int
object_group_show_handler (int cmdcode, 
                                                     Stack_t *tlv_stack,
                                                     op_mode enable_or_disable) {

    node_t *node;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;
    char *nw_obj_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){
        
    if (parser_match_leaf_id (tlv->leaf_id, "object-group-name"))
	    nw_obj_name = tlv->value;
    else if (parser_match_leaf_id (tlv->leaf_id, "node-name"))
        node_name = tlv->value;

    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {

        case OBJ_GRP_SHOW_ALL:
            object_group_hashtable_print (node, node->object_group_ght);
            break;
        case OBJ_GRP_SHOW_ONE:
            break;
    }

    return 0;
}

void
object_group_build_show_cli (param_t *root) {
   
    {
        /* show node <node-name> object-group */
        static param_t og;
        init_param(&og, CMD, "object-group", object_group_show_handler, NULL, INVALID, NULL, "Object Group Display");
        libcli_register_param(root, &og);
        libcli_set_param_cmd_code(&og, OBJ_GRP_SHOW_ALL);
        {
             /* show node <node-name> object-group <name>*/
             static param_t name;
             init_param(&name, LEAF, 0,  object_group_show_handler, 0, STRING, "object-group-name", "Object Group Name");
             libcli_register_param(&og, &name);
             libcli_set_param_cmd_code(&name, OBJ_GRP_SHOW_ONE);
        }
    }
}

void
object_group_display_name_cli_callback (param_t *param, Stack_t *tlv_stack){

    node_t *node;
    hashtable_t *og_ght;
    struct hashtable_itr *itr;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;
    
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if (parser_match_leaf_id (tlv->leaf_id, "node-name")) {
            node_name = tlv->value;
            break;
        }

    } TLV_LOOP_END;

    if (!node_name) return;

    node = node_get_node_by_name(topo, node_name);

    og_ght = node->object_group_ght;
    
    if (!og_ght) return;

    itr = hashtable_iterator(og_ght);

    do {
        char *key = (char *)hashtable_iterator_key(itr);
        object_group_t *og = (object_group_t *)hashtable_iterator_value(itr);
        cprintf ("%s\n", og->og_name);
        
    } while (hashtable_iterator_advance(itr));

    free(itr);  
}
