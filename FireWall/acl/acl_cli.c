#include "../../CLIBuilder/libcli.h"
#include "../../LinuxMemoryManager/uapi_mm.h"
#include "../../graph.h"
#include "../../Interface/Interface.h"
#include "acldb.h"
#include "../../mtrie/mtrie.h"
#include "../../utils.h"
#include "../../tcpconst.h"
#include "../object_network/objnw.h"
#include "../object_network/object_group.h"

extern graph_t *topo;
extern void display_node_interfaces(param_t *param, Stack_t *tlv_stack);
extern void object_group_display_name_cli_callback (param_t *param, Stack_t *tlv_stack);

#define ACL_CMD_CONFIG  1
#define ACL_CMD_SHOW 2
#define ACL_CMD_ACCESS_GROUP_CONFIG 3

static int
acl_action_validation_cbk(Stack_t *tlv_stack, unsigned char *value) {

    if (string_compare(value, "permit", 6) == 0 || 
            string_compare(value, "deny", 4) == 0) {

        return LEAF_VALIDATION_SUCCESS;
    }
    return LEAF_VALIDATION_FAILED;
}

static int
acl_proto_validation_cbk(Stack_t *tlv_stack, unsigned char *value) {

    acl_proto_t proto = acl_string_to_proto(value);
    if (proto == ACL_PROTO_NONE) return LEAF_VALIDATION_FAILED;
    return LEAF_VALIDATION_SUCCESS;
}

static void
acl_display_supported_protocols(param_t *param, Stack_t *tlv_stack) {

}

static int
acl_port_no_validation (Stack_t *tlv_stack, unsigned char *value) {

    int64_t val_num = atoi((const char *)value);
    if (val_num >= 0 && val_num <= ACL_PROTO_MAX)
        return LEAF_VALIDATION_SUCCESS;
    cprintf ("%s is Invalid. Valid Value Range : [0 %d]\n", value, ACL_PROTO_MAX);
    return LEAF_VALIDATION_FAILED;
}

static bool
acl_parse_ace_config_entries(
                             acl_entry_t *acl_entry,
                             uint32_t seq_no,
                             char *action_name,
                             char *proto,
                             char *host_src_ip,
                             char *subnet_src_ip,
                             char *subnet_src_mask,
                             obj_nw_t *obj_nw_src,
                             object_group_t *og_src,
                             uint16_t src_port_no1,
                             uint16_t src_port_no2,
                             char *host_dst_ip,
                             char *subnet_dst_ip,
                             char *subnet_dst_mask,
                             obj_nw_t *obj_nw_dst,
                             object_group_t *og_dst,
                             uint16_t dst_port_no1,
                             uint16_t dst_port_no2) {

    acl_entry->seq_no = seq_no;

    /* Action */
    if (string_compare(action_name, "permit", 6) == 0 && strlen(action_name) == 6) {
        acl_entry->action = ACL_PERMIT;
    }
    else if (string_compare(action_name, "deny", 4) == 0 && strlen(action_name) == 4) {
        acl_entry->action = ACL_DENY;
    }
    else {
        cprintf ("Error : Bad ACL Action Name %s\n", action_name);
        return false;
    }

    /* Protocol */
    acl_entry->proto = acl_string_to_proto(proto);

    /* Src ip */
    acl_entry->src_addr.acl_addr_format = ACL_ADDR_NOT_SPECIFIED;
    if (host_src_ip) {
        acl_entry->src_addr.acl_addr_format = ACL_ADDR_HOST;
        acl_entry->src_addr.u.host_addr = tcp_ip_covert_ip_p_to_n(host_src_ip);
    }
    else if (subnet_src_ip && subnet_src_mask) {
         acl_entry->src_addr.acl_addr_format = ACL_ADDR_SUBNET_MASK;
         acl_entry->src_addr.u.subnet.subnet_addr =  tcp_ip_covert_ip_p_to_n(subnet_src_ip);
         acl_entry->src_addr.u.subnet.subnet_mask =  tcp_ip_covert_ip_p_to_n(subnet_src_mask);
    }
    else if (obj_nw_src) {
        acl_entry_link_src_object_networks(acl_entry, obj_nw_src);
    }
    else if (og_src) {
        acl_entry_link_src_object_group(acl_entry, og_src);
    }

    /* Src Port Number */
    acl_entry->sport.lb = src_port_no1;
    acl_entry->sport.ub = src_port_no2;

    /* Drc ip */
    acl_entry->dst_addr.acl_addr_format = ACL_ADDR_NOT_SPECIFIED;
    if (host_dst_ip) {
        acl_entry->dst_addr.acl_addr_format = ACL_ADDR_HOST;
        acl_entry->dst_addr.u.host_addr = tcp_ip_covert_ip_p_to_n(host_dst_ip);
    }
    else if (subnet_dst_ip && subnet_dst_mask) {
         acl_entry->dst_addr.acl_addr_format = ACL_ADDR_SUBNET_MASK;
         acl_entry->dst_addr.u.subnet.subnet_addr =  tcp_ip_covert_ip_p_to_n(subnet_dst_ip);
         acl_entry->dst_addr.u.subnet.subnet_mask =  tcp_ip_covert_ip_p_to_n(subnet_dst_mask);
    }
    else if (obj_nw_dst) {
        acl_entry_link_dst_object_networks(acl_entry, obj_nw_dst);
    }
    else if (og_dst) {
        acl_entry_link_dst_object_group(acl_entry, og_dst);
    }

    /* Drc Port Number */
    acl_entry->dport.lb = dst_port_no1;
    acl_entry->dport.ub = dst_port_no2;

    return true;
}

static int
access_list_config (node_t *node, 
                    char *access_list_name,
                    uint32_t seq_no,
                    char *action_name,
                    char *proto,
                    char *host_src_ip,
                    char *subnet_src_ip,
                    char *subnet_src_mask,
                    obj_nw_t *obj_nw_src,
                    object_group_t *og_src,
                    uint16_t src_port_no1,
                    uint16_t src_port_no2,
                    char *host_dst_ip,
                    char *subnet_dst_ip,
                    char *subnet_dst_mask,
                    obj_nw_t *obj_nw_dst,
                    object_group_t *og_dst,
                    uint16_t dst_port_no1,
                    uint16_t dst_port_no2) {

   acl_entry_t *acl_entry = NULL;

    if (!action_name &&
         !proto &&
         !host_src_ip && !subnet_src_ip && !subnet_src_mask && !obj_nw_src && !og_src &&
         !host_dst_ip && !subnet_dst_ip && !subnet_dst_mask && !obj_nw_dst && !og_dst) {

        return 0;
    }
    
    acl_entry = (acl_entry_t *)XCALLOC(0, 1, acl_entry_t);

   if (!acl_parse_ace_config_entries(
                    acl_entry, 
                    seq_no,
                    action_name,
                    proto,
                    host_src_ip,
                    subnet_src_ip,
                    subnet_src_mask,
                    obj_nw_src,
                    og_src,
                    src_port_no1,
                    src_port_no2,
                    host_dst_ip,
                    subnet_dst_ip,
                    subnet_dst_mask,
                    obj_nw_dst,
                    og_dst,
                    dst_port_no1,
                    dst_port_no2)) {

        acl_entry_free(acl_entry);
        return -1;
    }

    if (acl_process_user_config(
            node, access_list_name, acl_entry)) {
        return 0;
    }

    acl_entry_free(acl_entry);
    return -1;
}

static int
access_list_unconfig(node_t *node, 
                    char *access_list_name,
                    uint32_t seq_no,
                    char *action_name,
                    char *proto,
                    char *host_src_ip,
                    char *subnet_src_ip,
                    char *subnet_src_mask,
                    obj_nw_t *obj_nw_src,
                    object_group_t *og_src,
                    uint16_t src_port_no1,
                    uint16_t src_port_no2,
                    char *host_dst_ip,
                    char *subnet_dst_ip,
                    char *subnet_dst_mask,
                    obj_nw_t *obj_nw_dst,
                    object_group_t *og_dst,
                    uint16_t dst_port_no1,
                    uint16_t dst_port_no2) {

   int rc = 0;
   access_list_t *access_list = access_list_lookup_by_name(node, access_list_name);

    if (!access_list) {
        cprintf ("Error : Access List do not Exist\n");
        return -1;
    }

    /* If user has triggered only no <access-list-name>, then delete the entire access list */
        if (seq_no == ~0) {
            if(!access_list_delete_complete(node, access_list)) return -1;
        }
        else {
        /* If user has triggered only no <access-list-name> <seq_no>, then delete the acl_entry 
            from the access list , uninstall it as well*/
            if (!access_list_delete_acl_entry_by_seq_no(node, access_list, seq_no)) {
                cprintf ("Error : ACL with this Seq Number do not exist\n");
                return -1;
            }

            access_list_notify_clients(node, access_list);

            if (access_list->ref_count == 1 && 
                    IS_GLTHREAD_LIST_EMPTY (&access_list->head)) {
                    rc = 0 ? access_list_delete_complete(node, access_list) : -1;
            }
        }
        return rc;
}

static int
acl_config_handler (int cmdcode, 
                                 Stack_t *tlv_stack,
                                 op_mode enable_or_disable) {

    char ip[16];
    uint32_t seq_no = ~0;
    char *proto = NULL;
    char *src_ip = NULL;
    char *dst_ip = NULL;
    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    char *host_src_ip = NULL;
    char *host_dst_ip = NULL;
    c_string node_name = NULL;
    char *action_name = NULL;
    char *subnet_src_ip = NULL;
    char *subnet_dst_ip = NULL;
    obj_nw_t *obj_nw_src = NULL;
    obj_nw_t *obj_nw_dst = NULL;
    char *subnet_dst_mask = NULL;
    char *subnet_src_mask = NULL;
    char *access_list_name = NULL;
    char *obj_nw_name_src = NULL;
    char *obj_nw_name_dst = NULL;
    object_group_t *obj_grp_src = NULL;
    object_group_t *obj_grp_dst = NULL;
    c_string obj_grp_name_src = NULL;
    c_string obj_grp_name_dst = NULL;

    uint16_t src_port_no_eq = 0,
                  src_port_no_lt = 0,
                  src_port_no_gt = 0,
                  src_port_no1 = 0,
                  src_port_no2 = 0,
                  dst_port_no_eq = 0,
                  dst_port_no_lt = 0,
                  dst_port_no_gt = 0,
                  dst_port_no1 = 0,
                  dst_port_no2 = 0;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "access-list-name"))
            access_list_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "seq-no"))
            seq_no = atoi((const char *)tlv->value);
        else if (parser_match_leaf_id(tlv->leaf_id, "permit|deny"))
            action_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "protocol"))
            proto = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "host-src-ip"))
            host_src_ip = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "host-dst-ip"))
            host_dst_ip = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "src-mask"))
            subnet_src_mask = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "dst-mask"))
            subnet_dst_mask = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "subnet-src-ip"))
            subnet_src_ip = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "subnet-dst-ip"))
            subnet_dst_ip = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "object-network-name-src"))
            obj_nw_name_src = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "object-network-name-dst"))
            obj_nw_name_dst = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "object-group-name-src"))
            obj_grp_name_src = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "object-group-name-dst"))
            obj_grp_name_dst = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "src-port-no-eq")) {
            src_port_no_eq = atoi((const char *)tlv->value);
            if (!(src_port_no_eq > 0 && src_port_no_eq < ACL_MAX_PORTNO)) {
                cprintf("Error : Invalid Src lt value. Supported (0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "src-port-no-lt")) {
            src_port_no_lt = atoi((const char *)tlv->value);
            if (src_port_no_lt <= 0 || src_port_no_lt > ACL_MAX_PORTNO) {
                cprintf ("Error : Invalid Src lt value. Supported (0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "src-port-no-gt")) {
            src_port_no_gt = atoi((const char *)tlv->value);
            if (src_port_no_gt < 0 || src_port_no_gt >= ACL_MAX_PORTNO) {
                cprintf ("Error : Invalid Src gt value. Supported [0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "src-port-no1")) {
            src_port_no1 = atoi((const char *)tlv->value);
            if (!(src_port_no1 >= 0 && src_port_no1 <= ACL_MAX_PORTNO)) {
                cprintf ("Error : Invalid Src Port Range value. Supported [0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "src-port-no2")) {
            src_port_no2 = atoi((const char *)tlv->value);         
            if (!(src_port_no2 >= 0 && src_port_no2 <= ACL_MAX_PORTNO)) {
                cprintf ("Error : Invalid Src Port Range value. Supported [0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }                           
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "dst-port-no-eq")) {
            dst_port_no_eq = atoi((const char *)tlv->value);
            if (!(dst_port_no_eq > 0 && dst_port_no_eq < ACL_MAX_PORTNO)) {
                cprintf ("Error : Invalid Dst lt value. Supported (0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "dst-port-no-lt")) {
            dst_port_no_lt = atoi((const char *)tlv->value);
            if (dst_port_no_lt <= 0 || dst_port_no_lt > ACL_MAX_PORTNO) {
                cprintf ("Error : Invalid Dst lt value. Supported (0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "dst-port-no-gt")) {
            dst_port_no_gt = atoi((const char *)tlv->value);
            if (dst_port_no_gt < 0 || dst_port_no_gt >= ACL_MAX_PORTNO) {
                cprintf ("Error : Invalid Dst gt value. Supported [0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "dst-port-no1")) {
            dst_port_no1 = atoi((const char *)tlv->value);
            if (!(dst_port_no1 >= 0 && dst_port_no1 <= ACL_MAX_PORTNO)) {
                cprintf ("Error : Invalid Dst Port Range value. Supported [0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "dst-port-no2")) {
            dst_port_no2 = atoi((const char *)tlv->value);         
            if (!(dst_port_no2 >= 0 && dst_port_no2 <= ACL_MAX_PORTNO)) {
                cprintf ("Error : Invalid Dst Port Range value. Supported [0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }                           
        }
   } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    /* Validation checks */
    if (obj_nw_name_src) {
        if (!(obj_nw_src = network_object_lookup_by_name(node->object_network_ght, obj_nw_name_src))) {
            cprintf ("Error : Network Object %s do not exist\n", obj_nw_name_src);
            return -1;
        }
    }

    if (obj_nw_name_dst) {
        if (!(obj_nw_dst = network_object_lookup_by_name(node->object_network_ght, obj_nw_name_dst))) {
            cprintf ("Error : Network Object %s do not exist\n", obj_nw_name_dst);
            return -1;
        }
    }    

    /* Validation checks */
    if (obj_grp_name_src) {
        if (!(obj_grp_src = object_group_lookup_ht_by_name(node, node->object_group_ght, obj_grp_name_src))) {
            cprintf ("Error : Network Group Object %s do not exist\n", obj_grp_name_src);
            return -1;
        }
    }

    if (obj_grp_name_dst) {
        if (!(obj_grp_dst = object_group_lookup_ht_by_name(node, node->object_group_ght, obj_grp_name_dst))) {
            cprintf ("Error : Network Group Object %s do not exist\n", obj_grp_name_dst);
            return -1;
        }
    }    

    /* Sanity Checks */
    if (  src_port_no_eq || 
           src_port_no_lt || 
           src_port_no_gt || 
           src_port_no1 || 
           src_port_no2 ||
           dst_port_no_eq || 
           dst_port_no_lt || 
           dst_port_no_gt || 
           dst_port_no1 || 
           dst_port_no2) {

        acl_proto_t protocol = acl_string_to_proto(proto);
        switch(protocol) {
            case ACL_UDP:
            case ACL_TCP:
            break;
            default:
                cprintf ("Error : Port number is supported only with udp/tcp protocols\n");
                return -1;
        }
    }

    if ((src_port_no1 > src_port_no2) || (dst_port_no1 > dst_port_no2)) {

        cprintf ("Error : Port Number Ranges specified is incorrect\n");
        return -1;
    }

    /* Handling port numbers */
    if ( src_port_no_eq ) {

        src_port_no1 = src_port_no2 =  src_port_no_eq;
    }
    else if  ( src_port_no_lt ) {

        src_port_no1 = 0;
        src_port_no2 = src_port_no_lt;
    }
    else if  ( src_port_no_gt ) {

        src_port_no1 = src_port_no_gt;
        src_port_no2 = ACL_MAX_PORTNO;
    }

    if ( dst_port_no_eq ) {

        dst_port_no1 = dst_port_no2 =  dst_port_no_eq;
    }
    else if  ( dst_port_no_lt ) {

        dst_port_no1 = 0;
        dst_port_no2 = dst_port_no_lt;
    }
    else if  ( dst_port_no_gt ) {

        dst_port_no1 = dst_port_no_gt;
        dst_port_no2 = ACL_MAX_PORTNO;
    }

    switch(cmdcode) {
        case ACL_CMD_CONFIG:
        switch (enable_or_disable) {
            case CONFIG_ENABLE:
                return access_list_config (node,
                                                         access_list_name,
                                                         seq_no,
                                                         action_name,
                                                         proto,
                                                         host_src_ip,
                                                         subnet_src_ip,
                                                         subnet_src_mask,
                                                         obj_nw_src,
                                                         obj_grp_src,
                                                         src_port_no1,
                                                         src_port_no2,
                                                         host_dst_ip,
                                                         subnet_dst_ip,
                                                         subnet_dst_mask,
                                                         obj_nw_dst,
                                                         obj_grp_dst,
                                                         dst_port_no1,
                                                         dst_port_no2);
            case CONFIG_DISABLE:
                return access_list_unconfig (node,
                                                            access_list_name,
                                                            seq_no,
                                                            action_name,
                                                            proto,
                                                            host_src_ip,
                                                            subnet_src_ip,
                                                            subnet_src_mask,
                                                            obj_nw_src,
                                                            obj_grp_src,
                                                            src_port_no1,
                                                            src_port_no2,
                                                            host_dst_ip,
                                                            subnet_dst_ip,
                                                            subnet_dst_mask,
                                                            obj_nw_dst,
                                                            obj_grp_dst,
                                                            dst_port_no1,
                                                            dst_port_no2);
        }
        break;
        default: ;
    }
    return 0;
}

static int
access_group_config_handler(int cmdcode, 
                  Stack_t *tlv_stack,
                  op_mode enable_or_disable) {
    
    char *dirn = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;
    char *if_name = NULL;
    char *access_list_name = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "access-list-name"))
            access_list_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "dirn"))
            dirn = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "if-name"))
            if_name = tlv->value;
   } TLV_LOOP_END;

    node_t *node = node_get_node_by_name(topo, node_name);
    Interface *intf = node_get_intf_by_name(node, if_name);
    
    if (!intf) {
        cprintf ("Error : Interface do not exist\n");
        return -1;
    }

    access_list_t *acc_lst = access_list_lookup_by_name(node, access_list_name);
    if (!acc_lst) {
        cprintf ("Error : Access List not configured\n");
        return -1;
    } 

    switch(enable_or_disable) {
        case CONFIG_ENABLE:
            return access_group_config(node, intf, dirn, acc_lst);
        case CONFIG_DISABLE:
            return access_group_unconfig(node, intf, dirn, acc_lst);
    }
    return 0;
}

static int
acl_direction_validation(Stack_t *, unsigned char *leaf_value) {

    if ((string_compare(leaf_value, "in" , 2) == 0 && strlen(leaf_value) == 2) || 
         (string_compare(leaf_value, "out" , 3) == 0 && strlen(leaf_value) == 3))
        return LEAF_VALIDATION_SUCCESS;
    return LEAF_VALIDATION_FAILED;
}

static void
acl_build_config_cli_object_group_destination (param_t *root) {

    param_t *obj_grp = (param_t *)calloc(1, sizeof(param_t));
    init_param(obj_grp, CMD, "object-group", 0, 0, STRING, 0, "Network Object Group");
    libcli_register_param(root, obj_grp);
    libcli_register_display_callback(obj_grp, object_group_display_name_cli_callback);
    {
        /* access-list <name> <action> <proto> object-group <object-group-name>*/
        param_t *obj_grp_name = (param_t *)calloc(1, sizeof(param_t));
        init_param(obj_grp_name, LEAF, 0, acl_config_handler, 0, STRING, "object-group-name-dst", "specify Dst Network Object Group Name");
        libcli_register_param(obj_grp, obj_grp_name);
        libcli_set_param_cmd_code(obj_grp_name, ACL_CMD_CONFIG);
        {
            /* access-list <name> <action> <proto> object-group <object-group-name> eq ...*/
            param_t *eq = (param_t *)calloc(1, sizeof(param_t));
            init_param(eq, CMD, "eq", 0, 0, INVALID, 0, "eq equal");
            libcli_register_param(obj_grp_name, eq);
            {
                /* access-list <name> <action> <proto> object-group <object-group-name> eq <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-eq", "specify Dst Port Number");
                libcli_register_param(eq, dst_port_no);
                libcli_set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }
        {
            /* access-list <name> <action> <proto> object-group <object-group-name> lt ...*/
            param_t *lt = (param_t *)calloc(1, sizeof(param_t));
            init_param(lt, CMD, "lt", 0, 0, INVALID, 0, "lt less than");
            libcli_register_param(obj_grp_name, lt);
            {
                /* access-list <name> <action> <proto> object-group <object-group-name> lt <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-lt", "specify Dst Port Number");
                libcli_register_param(lt, dst_port_no);
                libcli_set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }
        {
            /* access-list <name> <action> <proto> object-group <object-group-name> gt ...*/
            param_t *gt = (param_t *)calloc(1, sizeof(param_t));
            init_param(gt, CMD, "gt", 0, 0, INVALID, 0, "gt greater than");
            libcli_register_param(obj_grp_name, gt);
            {
                /* access-list <name> <action> <proto> object-group <object-group-name> lt <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-gt", "specify Dst Port Number");
                libcli_register_param(gt, dst_port_no);
                libcli_set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }        
        {
            /* access-list <name> <action> <proto> object-group <object-group-name> range ...*/
            param_t *range = (param_t *)calloc(1, sizeof(param_t));
            init_param(range, CMD, "range", 0, 0, INVALID, 0, "range p1 p2");
            libcli_register_param(obj_grp_name, range);
            {
                /* access-list <name> <action> <proto> object-group <object-group-name> range <dst-port-no1>*/
                param_t *dst_port_no1 = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no1, LEAF, 0, NULL, acl_port_no_validation, INT, "dst-port-no1", "specify Dst Port Number Lower Bound");
                libcli_register_param(range, dst_port_no1);
                {
                    /* access-list <name> <action> <proto> object-group <object-group-name> range <dst-port-no1> <dst-port-no2>*/
                    param_t *dst_port_no2 = (param_t *)calloc(1, sizeof(param_t));
                    init_param(dst_port_no2, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no2", "specify Dst Port Number Upper Bound");
                    libcli_register_param(dst_port_no1, dst_port_no2);
                    libcli_set_param_cmd_code(dst_port_no2, ACL_CMD_CONFIG);
                }
            }
        }
    }
}

static void
acl_build_config_cli_object_network_destination (param_t *root) {

    param_t *obj_nw = (param_t *)calloc(1, sizeof(param_t));
    init_param(obj_nw, CMD, "object-network", 0, 0, STRING, 0, "Network Object");
    libcli_register_param(root, obj_nw);
    {
        /* access-list <name> <action> <proto> object-network <object-network-name>*/
        param_t *obj_nw_name = (param_t *)calloc(1, sizeof(param_t));
        init_param(obj_nw_name, LEAF, 0, acl_config_handler, 0, STRING, "object-network-name-dst", "specify Dst Network Object Name");
        libcli_register_param(obj_nw, obj_nw_name);
        libcli_set_param_cmd_code(obj_nw_name, ACL_CMD_CONFIG);
        {
            /* access-list <name> <action> <proto> object-network <object-network-name> eq ...*/
            param_t *eq = (param_t *)calloc(1, sizeof(param_t));
            init_param(eq, CMD, "eq", 0, 0, INVALID, 0, "eq equal");
            libcli_register_param(obj_nw_name, eq);
            {
                /* access-list <name> <action> <proto> object-network <object-network-name> eq <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-eq", "specify Dst Port Number");
                libcli_register_param(eq, dst_port_no);
                libcli_set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }
        {
            /* access-list <name> <action> <proto> object-network <object-network-name> lt ...*/
            param_t *lt = (param_t *)calloc(1, sizeof(param_t));
            init_param(lt, CMD, "lt", 0, 0, INVALID, 0, "lt less than");
            libcli_register_param(obj_nw_name, lt);
            {
                /* access-list <name> <action> <proto> object-network <object-network-name> lt <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-lt", "specify Dst Port Number");
                libcli_register_param(lt, dst_port_no);
                libcli_set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }
        {
            /* access-list <name> <action> <proto> object-network <object-network-name> gt ...*/
            param_t *gt = (param_t *)calloc(1, sizeof(param_t));
            init_param(gt, CMD, "gt", 0, 0, INVALID, 0, "gt greater than");
            libcli_register_param(obj_nw_name, gt);
            {
                /* access-list <name> <action> <proto> object-network <object-network-name> lt <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-gt", "specify Dst Port Number");
                libcli_register_param(gt, dst_port_no);
                libcli_set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }        
        {
            /* access-list <name> <action> <proto> object-network <object-network-name> range ...*/
            param_t *range = (param_t *)calloc(1, sizeof(param_t));
            init_param(range, CMD, "range", 0, 0, INVALID, 0, "range p1 p2");
            libcli_register_param(obj_nw_name, range);
            {
                /* access-list <name> <action> <proto> object-network <object-network-name> range <dst-port-no1>*/
                param_t *dst_port_no1 = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no1, LEAF, 0, NULL, acl_port_no_validation, INT, "dst-port-no1", "specify Dst Port Number Lower Bound");
                libcli_register_param(range, dst_port_no1);
                {
                    /* access-list <name> <action> <proto> object-network <object-network-name> range <dst-port-no1> <dst-port-no2>*/
                    param_t *dst_port_no2 = (param_t *)calloc(1, sizeof(param_t));
                    init_param(dst_port_no2, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no2", "specify Dst Port Number Upper Bound");
                    libcli_register_param(dst_port_no1, dst_port_no2);
                    libcli_set_param_cmd_code(dst_port_no2, ACL_CMD_CONFIG);
                }
            }
        }
    }


    param_t *host = (param_t *)calloc(1, sizeof(param_t));
    init_param(host, CMD, "host", 0, 0, STRING, 0, "specify host IP Address");
    libcli_register_param(root, host);
    {
        /* access-list <name> <action> <proto> host <dst-ip> */
        param_t *dst_ip = (param_t *)calloc(1, sizeof(param_t));
        init_param(dst_ip, LEAF, 0, acl_config_handler, 0, IPV4, "host-dst-ip", "specify Host Dst IPV4 Address");
        libcli_register_param(host, dst_ip);
        libcli_set_param_cmd_code(dst_ip, ACL_CMD_CONFIG);
        {
            /* access-list <name> <action> <proto> host <dst-ip> eq ...*/
            param_t *eq = (param_t *)calloc(1, sizeof(param_t));
            init_param(eq, CMD, "eq", 0, 0, INVALID, 0, "eq equal");
            libcli_register_param(dst_ip, eq);
            {
                /* access-list <name> <action> <proto> host <dst-ip> eq <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-eq", "specify Dst Port Number");
                libcli_register_param(eq, dst_port_no);
                libcli_set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }
        {
            /* access-list <name> <action> <proto> host <dst-ip> lt ...*/
            param_t *lt = (param_t *)calloc(1, sizeof(param_t));
            init_param(lt, CMD, "lt", 0, 0, INVALID, 0, "lt less than");
            libcli_register_param(dst_ip, lt);
            {
                /* access-list <name> <action> <proto> host <dst-ip> lt <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-lt", "specify Dst Port Number");
                libcli_register_param(lt, dst_port_no);
                libcli_set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }
        {
            /* access-list <name> <action> <proto> host <dst-ip> gt ...*/
            param_t *gt = (param_t *)calloc(1, sizeof(param_t));
            init_param(gt, CMD, "gt", 0, 0, INVALID, 0, "gt greater than");
            libcli_register_param(dst_ip, gt);
            {
                /* access-list <name> <action> <proto> host <dst-ip> lt <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-gt", "specify Dst Port Number");
                libcli_register_param(gt, dst_port_no);
                libcli_set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }        
        {
            /* access-list <name> <action> <proto> host <dst-ip> range ...*/
            param_t *range = (param_t *)calloc(1, sizeof(param_t));
            init_param(range, CMD, "range", 0, 0, INVALID, 0, "range p1 p2");
            libcli_register_param(dst_ip, range);
            {
                /* access-list <name> <action> <proto> host <dst-ip> range <dst-port-no1>*/
                param_t *dst_port_no1 = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no1, LEAF, 0, NULL, acl_port_no_validation, INT, "dst-port-no1", "specify Dst Port Number Lower Bound");
                libcli_register_param(range, dst_port_no1);
                {
                    /* access-list <name> <action> <proto> host <src-ip> range <dst-port-no1> <dst-port-no2>*/
                    param_t *dst_port_no2 = (param_t *)calloc(1, sizeof(param_t));
                    init_param(dst_port_no2, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no2", "specify Dst Port Number Upper Bound");
                    libcli_register_param(dst_port_no1, dst_port_no2);
                    libcli_set_param_cmd_code(dst_port_no2, ACL_CMD_CONFIG);
                }
            }
        }
    }

   /* access-list <name> <action> <proto> <dst-ip> ...*/
    param_t *dst_ip =  (param_t *)calloc(1, sizeof(param_t));
    init_param(dst_ip, LEAF, 0, 0, 0, IPV4, "subnet-dst-ip", "specify Dst IPV4 Address");
    libcli_register_param(root, dst_ip);
    {
        /* access-list <name> <action> <proto> <dst-ip> <dst-mask>*/
        param_t *dst_mask = (param_t *)calloc(1, sizeof(param_t));
        init_param(dst_mask, LEAF, 0, acl_config_handler, 0, IPV4, "dst-mask", "specify Dst IPV4 Mask");
        libcli_register_param(dst_ip, dst_mask);
        libcli_set_param_cmd_code(dst_mask, ACL_CMD_CONFIG);
        {
            /*access-list <name> <action> <proto> <dst-ip> <dst-mask> eq ...*/
            param_t *eq = (param_t *)calloc(1, sizeof(param_t));
            init_param(eq, CMD, "eq", 0, 0, INVALID, 0, "eq equal");
            libcli_register_param(dst_mask, eq);
            {
                /* access-list <name> <action> <proto> <dst-ip> <dst-mask> eq <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-eq", "specify Dst Port Number");
                libcli_register_param(eq, dst_port_no);
                libcli_set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }
        {
            /* access-list <name> <action> <proto> <dst-ip> <dst-mask> lt ...*/
            param_t *lt = (param_t *)calloc(1, sizeof(param_t));
            init_param(lt, CMD, "lt", 0, 0, INVALID, 0, "lt less than");
            libcli_register_param(dst_mask, lt);
            {
                /* access-list <name> <action> <proto> host <dst-ip> lt <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-lt", "specify Dst Port Number");
                libcli_register_param(lt, dst_port_no);
                libcli_set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }
        {
            /*  access-list <name> <action> <proto> <dst-ip> <dst-mask> gt ...*/
            param_t *gt = (param_t *)calloc(1, sizeof(param_t));
            init_param(gt, CMD, "gt", 0, 0, INVALID, 0, "gt greater than");
            libcli_register_param(dst_mask, gt);
            {
                /* access-list <name> <action> <proto> host <dst-ip> lt <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-gt", "specify Dst Port Number");
                libcli_register_param(gt, dst_port_no);
                libcli_set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }
        {
            /*  access-list <name> <action> <proto> <dst-ip> <dst-mask> range ...*/
            param_t *range = (param_t *)calloc(1, sizeof(param_t));
            init_param(range, CMD, "range", 0, 0, INVALID, 0, "range <p1> <p2>");
            libcli_register_param(dst_mask, range);
            {
                /* access-list <name> <action> <proto> <dst-ip> <dst-mask> range <dst-port-no1>*/
                param_t *dst_port_no1 = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no1, LEAF, 0, NULL, acl_port_no_validation, INT, "dst-port-no1", "specify Dst Port Number Lower Bound");
                libcli_register_param(range, dst_port_no1);
                {
                    /* access-list <name> <action> <proto> <dst-ip> <dst-mask> range <dst-port-no1> <dst-port-no2>*/
                    param_t *dst_port_no2 = (param_t *)calloc(1, sizeof(param_t));
                    init_param(dst_port_no2, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no2", "specify Dst Port Number Upper Bound");
                    libcli_register_param(dst_port_no1, dst_port_no2);
                    libcli_set_param_cmd_code(dst_port_no2, ACL_CMD_CONFIG);
                }
            }
        }
    }
}

void
acl_build_config_cli(param_t *root) {
    {
           /* access-list .... */
        static param_t access_list;
        init_param(&access_list, CMD, "access-list", 0, 0, INVALID, 0, "Access Policy");
        libcli_register_param(root, &access_list);
        {
            /* access-list <name>... */
            static param_t access_list_name;
            init_param(&access_list_name, LEAF, 0,  acl_config_handler, 0, STRING, "access-list-name", "Access List Name");
            libcli_register_param(&access_list, &access_list_name);
            libcli_set_param_cmd_code(&access_list_name, ACL_CMD_CONFIG);
            {
                /* access-list <name> <seq-no> ...*/
                static param_t seq_no;
                init_param(&seq_no, LEAF, 0, acl_config_handler, 0, INT, "seq-no", "Sequence no");
                libcli_register_param(&access_list_name, &seq_no);
                libcli_set_param_cmd_code(&seq_no, ACL_CMD_CONFIG);
            {
                 /* access-list <name> <action> ...*/
                static param_t action;
                init_param(&action, LEAF, 0, 0, acl_action_validation_cbk, STRING, "permit|deny", "permit/deny");
                libcli_register_param(&seq_no, &action);
                libcli_register_display_callback(&action, acl_display_supported_protocols);
                {
                     /* access-list <name> <action> <proto>*/
                    static param_t proto;
                    init_param(&proto, LEAF, 0, acl_config_handler, acl_proto_validation_cbk, STRING, "protocol", "specify protocol");
                    libcli_register_param(&action, &proto);
                    libcli_set_param_cmd_code(&proto, ACL_CMD_CONFIG);

                    {
                        /* access-list <name> <action> <proto> object-group ...*/
                        static param_t obj_grp;
                        init_param(&obj_grp, CMD, "object-group", 0, 0, INVALID, 0, "Network Object Group");
                        libcli_register_param(&proto, &obj_grp);
                        libcli_register_display_callback(&obj_grp, object_group_display_name_cli_callback);
                        {
                            /* access-list <name> <action> <proto> object-group <object-group-name>*/
                            static param_t obj_grp_name;
                            init_param(&obj_grp_name, LEAF, 0, acl_config_handler, 0, STRING, "object-group-name-src", "specify Src Network Object Group Name");
                            libcli_register_param(&obj_grp, &obj_grp_name);
                            libcli_set_param_cmd_code(&obj_grp_name, ACL_CMD_CONFIG);
                            {
                                /* access-list <name> <action> <proto> object-group <object-group-name> eq ...*/
                                static param_t eq;
                                init_param(&eq, CMD, "eq", 0, 0, INVALID, 0, "eq equal");
                                libcli_register_param(&obj_grp_name, &eq);
                                {
                                    /* access-list <name> <action> <proto> object-group <object-group-name> eq <src-port-no>*/
                                    static param_t src_port_no;
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no-eq", "specify Src Port Number");
                                    libcli_register_param(&eq, &src_port_no);
                                    libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                    acl_build_config_cli_object_network_destination(&src_port_no);
                                    acl_build_config_cli_object_group_destination(&src_port_no);
                                }
                            }
                            {
                                /* access-list <name> <action> <proto> object-group <object-group-name> lt ...*/
                                static param_t lt;
                                init_param(&lt, CMD, "lt", 0, 0, INVALID, 0, "lt less than");
                                libcli_register_param(&obj_grp_name, &lt);
                                {
                                    /* access-list <name> <action> <proto> host <src-ip> lt <src-port-no>*/
                                    static param_t src_port_no;
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, 0, INT, "src-port-no-lt", "specify Src Port Number");
                                    libcli_register_param(&lt, &src_port_no);
                                    libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                    acl_build_config_cli_object_network_destination(&src_port_no);
                                    acl_build_config_cli_object_group_destination(&src_port_no);
                                }
                            }
                            {
                                /* access-list <name> <action> <proto> object-group <object-group-name> gt ...*/
                                static param_t gt;
                                init_param(&gt, CMD, "gt", 0, 0, INVALID, 0, "gt greater than");
                                libcli_register_param(&obj_grp_name, &gt);
                                {
                                    /* access-list <name> <action> <proto> object-network <object-network-name> gt <src-port-no>*/
                                    static param_t src_port_no;
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no-gt", "specify Src Port Number");
                                    libcli_register_param(&gt, &src_port_no);
                                    libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                    acl_build_config_cli_object_network_destination(&src_port_no);
                                    acl_build_config_cli_object_group_destination(&src_port_no);
                                }
                            }
                            {
                                /* access-list <name> <action> <proto> object-group <object-group-name> range ...*/
                                static param_t range;
                                init_param(&range, CMD, "range", 0, 0, INVALID, 0, "range <p1> <p2>");
                                libcli_register_param(&obj_grp_name, &range);
                                {
                                    /* access-list <name> <action> <proto> object-group <object-group-name> range <src-port-no1>*/
                                    static param_t src_port_no1;
                                    init_param(&src_port_no1, LEAF, 0, NULL, acl_port_no_validation, INT, "src-port-no1", "specify Src Port Number Lower Bound");
                                    libcli_register_param(&range, &src_port_no1);
                                    {
                                        /* access-list <name> <action> <proto> object-group <object-group-name> range <src-port-no1> <src-port-no2>*/
                                        static param_t src_port_no2;
                                        init_param(&src_port_no2, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no2", "specify Src Port Number Upper Bound");
                                        libcli_register_param(&src_port_no1, &src_port_no2);
                                        libcli_set_param_cmd_code(&src_port_no2, ACL_CMD_CONFIG);
                                        acl_build_config_cli_object_network_destination(&src_port_no2);
                                        acl_build_config_cli_object_group_destination(&src_port_no2);
                                    }
                                }
                            }
                            acl_build_config_cli_object_network_destination(&obj_grp_name);
                            acl_build_config_cli_object_group_destination(&obj_grp_name);
                        }
                    }

                    {
                         /* access-list <name> <action> <proto> object-network...*/
                        static param_t obj_nw;
                        init_param(&obj_nw, CMD, "object-network", 0, 0, INVALID, 0, "Network Object");
                        libcli_register_param(&proto, &obj_nw);
                        {
                             /* access-list <name> <action> <proto> object-network <object-network-name>*/
                            static param_t obj_nw_name;
                            init_param(&obj_nw_name, LEAF, 0, acl_config_handler, 0, STRING, "object-network-name-src", "specify Src Network Object Name");
                            libcli_register_param(&obj_nw, &obj_nw_name);
                            libcli_set_param_cmd_code(&obj_nw_name, ACL_CMD_CONFIG);
                            {
                                 /* access-list <name> <action> <proto> object-network <object-network-name> eq ...*/
                                 static param_t eq;
                                 init_param(&eq, CMD, "eq", 0, 0, INVALID, 0, "eq equal");
                                  libcli_register_param(&obj_nw_name, &eq);
                                  {
                                     /* access-list <name> <action> <proto> object-network <object-network-name> eq <src-port-no>*/
                                      static param_t src_port_no;
                                      init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no-eq", "specify Src Port Number");
                                      libcli_register_param(&eq, &src_port_no);
                                      libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                      acl_build_config_cli_object_network_destination(&src_port_no);
                                      acl_build_config_cli_object_group_destination(&src_port_no);
                                  }
                            }
                            {
                                /* access-list <name> <action> <proto> object-network <object-network-name> lt ...*/
                                static param_t lt;
                                init_param(&lt, CMD, "lt", 0, 0, INVALID, 0, "lt less than");
                                libcli_register_param(&obj_nw_name, &lt);
                                {
                                    /* access-list <name> <action> <proto> host <src-ip> lt <src-port-no>*/
                                    static param_t src_port_no;
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, 0, INT, "src-port-no-lt", "specify Src Port Number");
                                    libcli_register_param(&lt, &src_port_no);
                                    libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                    acl_build_config_cli_object_network_destination(&src_port_no);
                                    acl_build_config_cli_object_group_destination(&src_port_no);
                                }
                            }
                            {
                                /* access-list <name> <action> <proto> object-network <object-network-name> gt ...*/
                                static param_t gt;
                                init_param(&gt, CMD, "gt", 0, 0, INVALID, 0, "gt greater than");
                                libcli_register_param(&obj_nw_name, &gt);
                                {
                                    /* access-list <name> <action> <proto> object-network <object-network-name> gt <src-port-no>*/
                                    static param_t src_port_no;
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no-gt", "specify Src Port Number");
                                    libcli_register_param(&gt, &src_port_no);
                                    libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                    acl_build_config_cli_object_network_destination(&src_port_no);
                                    acl_build_config_cli_object_group_destination(&src_port_no);
                                }
                            }  
                            {
                                /* access-list <name> <action> <proto> object-network <object-network-name> range ...*/
                                static param_t range;
                                init_param(&range, CMD, "range", 0, 0, INVALID, 0, "range <p1> <p2>");
                                libcli_register_param(&obj_nw_name, &range);
                                {
                                    /* access-list <name> <action> <proto> object-network <object-network-name> range <src-port-no1>*/
                                    static param_t src_port_no1;
                                    init_param(&src_port_no1, LEAF, 0, NULL, acl_port_no_validation, INT, "src-port-no1", "specify Src Port Number Lower Bound");
                                    libcli_register_param(&range, &src_port_no1);
                                    {
                                        /* access-list <name> <action> <proto> object-network <object-network-name> range <src-port-no1> <src-port-no2>*/
                                        static param_t src_port_no2;
                                        init_param(&src_port_no2, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no2", "specify Src Port Number Upper Bound");
                                        libcli_register_param(&src_port_no1, &src_port_no2);
                                        libcli_set_param_cmd_code(&src_port_no2, ACL_CMD_CONFIG);
                                        acl_build_config_cli_object_network_destination(&src_port_no2);
                                        acl_build_config_cli_object_group_destination(&src_port_no2);
                                    }
                                }
                            }
                            acl_build_config_cli_object_network_destination(&obj_nw_name);
                            acl_build_config_cli_object_group_destination(&obj_nw_name);
                        }
                    }
                    {
                         /* access-list <name> <action> <proto> host...*/
                        static param_t host;
                        init_param(&host, CMD, "host", 0, 0, INVALID, 0, "specify host IP Address");
                        libcli_register_param(&proto, &host);
                        {
                             /* access-list <name> <action> <proto> host <src-ip>*/
                            static param_t src_ip;
                            init_param(&src_ip, LEAF, 0, acl_config_handler, 0, IPV4, "host-src-ip", "specify Host Src IPV4 Address");
                            libcli_register_param(&host, &src_ip);
                            libcli_set_param_cmd_code(&src_ip, ACL_CMD_CONFIG);
                            {
                                 /* access-list <name> <action> <proto> host <src-ip> eq ...*/
                                 static param_t eq;
                                 init_param(&eq, CMD, "eq", 0, 0, INVALID, 0, "eq equal");
                                  libcli_register_param(&src_ip, &eq);
                                  {
                                      /* access-list <name> <action> <proto> host <src-ip> eq <src-port-no>*/
                                      static param_t src_port_no;
                                      init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no-eq", "specify Src Port Number");
                                      libcli_register_param(&eq, &src_port_no);
                                      libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                      acl_build_config_cli_object_network_destination(&src_port_no);
                                      acl_build_config_cli_object_group_destination(&src_port_no);
                                  }
                            }
                            {
                                /* access-list <name> <action> <proto> host <src-ip> lt ...*/
                                static param_t lt;
                                init_param(&lt, CMD, "lt", 0, 0, INVALID, 0, "lt less than");
                                libcli_register_param(&src_ip, &lt);
                                {
                                    /* access-list <name> <action> <proto> host <src-ip> lt <src-port-no>*/
                                    static param_t src_port_no;
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, 0, INT, "src-port-no-lt", "specify Src Port Number");
                                    libcli_register_param(&lt, &src_port_no);
                                    libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                    acl_build_config_cli_object_network_destination(&src_port_no);
                                    acl_build_config_cli_object_group_destination(&src_port_no);
                                }
                            }           
                            {
                                /* access-list <name> <action> <proto> host <src-ip> gt ...*/
                                static param_t gt;
                                init_param(&gt, CMD, "gt", 0, 0, INVALID, 0, "gt greater than");
                                libcli_register_param(&src_ip, &gt);
                                {
                                    /* access-list <name> <action> <proto> host <src-ip> gt <src-port-no>*/
                                    static param_t src_port_no;
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no-gt", "specify Src Port Number");
                                    libcli_register_param(&gt, &src_port_no);
                                    libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                    acl_build_config_cli_object_network_destination(&src_port_no);
                                    acl_build_config_cli_object_group_destination(&src_port_no);
                                }
                            }  
                            {
                                /* access-list <name> <action> <proto> host <src-ip> range ...*/
                                static param_t range;
                                init_param(&range, CMD, "range", 0, 0, INVALID, 0, "range <p1> <p2>");
                                libcli_register_param(&src_ip, &range);
                                {
                                    /* access-list <name> <action> <proto> host <src-ip> range <src-port-no1>*/
                                    static param_t src_port_no1;
                                    init_param(&src_port_no1, LEAF, 0, NULL, acl_port_no_validation, INT, "src-port-no1", "specify Src Port Number Lower Bound");
                                    libcli_register_param(&range, &src_port_no1);
                                    {
                                        /* access-list <name> <action> <proto> host <src-ip> range <src-port-no1> <src-port-no2>*/
                                        static param_t src_port_no2;
                                        init_param(&src_port_no2, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no2", "specify Src Port Number Upper Bound");
                                        libcli_register_param(&src_port_no1, &src_port_no2);
                                        libcli_set_param_cmd_code(&src_port_no2, ACL_CMD_CONFIG);
                                        acl_build_config_cli_object_network_destination(&src_port_no2);
                                        acl_build_config_cli_object_group_destination(&src_port_no2);
                                    }
                                }
                            }
                            acl_build_config_cli_object_network_destination(&src_ip);
                            acl_build_config_cli_object_group_destination(&src_ip);
                        }
                    }
                    {
                         /* access-list <name> <action> <proto> <src-ip>...*/
                        static param_t src_ip;
                        init_param(&src_ip, LEAF, 0, 0, 0, IPV4, "subnet-src-ip", "specify Src IPV4 Address");
                        libcli_register_param(&proto, &src_ip);
                        {
                             /* access-list <name> <action> <proto> <src-ip> <src-mask>*/
                            static param_t src_mask;
                            init_param(&src_mask, LEAF, 0, acl_config_handler, 0, IPV4, "src-mask", "specify Src IPV4 Mask");
                            libcli_register_param(&src_ip, &src_mask);
                            libcli_set_param_cmd_code(&src_mask, ACL_CMD_CONFIG);
                            acl_build_config_cli_object_network_destination(&src_mask);
                            acl_build_config_cli_object_group_destination(&src_mask);
                               {
                                 /* access-list <name> <action> <proto> <src-ip> <src-mask> eq ...*/
                                 static param_t eq;
                                 init_param(&eq, CMD, "eq", 0, 0, INVALID, 0, "eq equal");
                                  libcli_register_param(&src_mask, &eq);
                                  {
                                      /* access-list <name> <action> <proto> <src-ip> <src-mask> eq <src-port-no>*/
                                      static param_t src_port_no;
                                      init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no-eq", "specify Src Port Number");
                                      libcli_register_param(&eq, &src_port_no);
                                      libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                      acl_build_config_cli_object_network_destination(&src_port_no);
                                      acl_build_config_cli_object_group_destination(&src_port_no);
                                  }
                            }
                            {
                                /* access-list <name> <action> <proto> <src-ip> <src-mask> lt ...*/
                                static param_t lt;
                                init_param(&lt, CMD, "lt", 0, 0, INVALID, 0, "lt less than");
                                libcli_register_param(&src_mask, &lt);
                                {
                                    /* access-list <name> <action> <proto> host <src-ip> lt <src-port-no>*/
                                    static param_t src_port_no;
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no-lt", "specify Src Port Number");
                                    libcli_register_param(&lt, &src_port_no);
                                    libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG );
                                    acl_build_config_cli_object_network_destination(&src_port_no );
                                    acl_build_config_cli_object_group_destination(&src_port_no);
                                }
                            }
                            {
                                /* access-list <name> <action> <proto> <src-ip> <src-mask> gt ...*/
                                static param_t gt;
                                init_param(&gt, CMD, "gt", 0, 0, INVALID, 0, "gt greater than");
                                libcli_register_param(&src_mask, &gt);
                                {
                                    /* access-list <name> <action> <proto> host <src-ip> gt <src-port-no>*/
                                    static param_t src_port_no;
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no-gt", "specify Src Port Number");
                                    libcli_register_param(&gt, &src_port_no);
                                    libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                    acl_build_config_cli_object_network_destination(&src_port_no);
                                    acl_build_config_cli_object_group_destination(&src_port_no);
                                }
                            }
                            {
                                /* access-list <name> <action> <proto> <src-ip> <src-mask> range ...*/
                                static param_t range;
                                init_param(&range, CMD, "range", 0, 0, INVALID, 0, "range p1 p2");
                                libcli_register_param(&src_mask, &range);
                                {
                                    /* access-list <name> <action> <proto> host <src-ip> range <src-port-no1>*/
                                    static param_t src_port_no1;
                                    init_param(&src_port_no1, LEAF, 0, NULL, acl_port_no_validation, INT, "src-port-no1", "specify Src Port Number Lower Bound");
                                    libcli_register_param(&range, &src_port_no1);
                                    {
                                        /* access-list <name> <action> <proto> host <src-ip> range <src-port-no1> <src-port-no2>*/
                                        static param_t src_port_no2;
                                        init_param(&src_port_no2, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no2", "specify Src Port Number Upper Bound");
                                        libcli_register_param(&src_port_no1, &src_port_no2);
                                        libcli_set_param_cmd_code(&src_port_no2, ACL_CMD_CONFIG);
                                        acl_build_config_cli_object_network_destination(&src_port_no2);
                                        acl_build_config_cli_object_group_destination(&src_port_no2);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            }
        }
    }

    {
        /* access-group ...*/
        static param_t access_grp;
        init_param(&access_grp, CMD, "access-group", 0, 0, INVALID, 0, "Access Group");
        libcli_register_param(root, &access_grp);
        {
             /* access-group access-list <name>... */
            static param_t access_list_name;
            init_param(&access_list_name, LEAF, 0, 0, 0, STRING, "access-list-name", "Access List Name");
            libcli_register_param(&access_grp, &access_list_name);
            {
                /* access-group access-list <name> [in | out] ... */
                static param_t dirn;
                init_param(&dirn, LEAF, 0, 0, acl_direction_validation, STRING, "dirn", " in | out - Access List Direction");
                libcli_register_param(&access_list_name, &dirn);
                {
                    /* access-group access-list <name> [in | out] interface ... */
                    static param_t intf;
                    init_param(&intf, CMD, "interface", 0, 0, INVALID, "interface", "Interface");
                    libcli_register_param(&dirn, &intf);
                    libcli_register_display_callback(&intf, display_node_interfaces);
                    {
                        static param_t if_name;
                        init_param(&if_name, LEAF, 0, access_group_config_handler, 0, STRING, "if-name", "Interface Name");
                        libcli_register_param(&intf, &if_name);
                        libcli_set_param_cmd_code(&if_name, ACL_CMD_ACCESS_GROUP_CONFIG);
                    }
                }
            }
        }
    }
}

void
acl_print (acl_entry_t *acl_entry) {

    byte ip_addr[16];
    c_string time_str;
    byte time_buff[HRS_MIN_SEC_FMT_TIME_LEN];

    cprintf (" %u %s %s",
        acl_entry->seq_no,
        acl_entry->action == ACL_PERMIT ? "permit" : "deny" , 
        proto_name_str( acl_entry->proto));

    switch (acl_entry->src_addr.acl_addr_format)
    {
    case ACL_ADDR_NOT_SPECIFIED:
        break;
    case ACL_ADDR_HOST:
        cprintf(" host %s", tcp_ip_covert_ip_n_to_p(acl_entry->src_addr.u.host_addr, ip_addr));
        break;
    case ACL_ADDR_SUBNET_MASK:
        cprintf(" %s", tcp_ip_covert_ip_n_to_p(acl_entry->src_addr.u.subnet.subnet_addr, ip_addr));
        cprintf(" %s", tcp_ip_covert_ip_n_to_p(acl_entry->src_addr.u.subnet.subnet_mask, ip_addr));
        break;
    case ACL_ADDR_OBJECT_NETWORK:
        cprintf(" object-network %s", acl_entry->src_addr.u.obj_nw->name);
        break;
    case ACL_ADDR_OBJECT_GROUP:
         cprintf(" object-group %s", acl_entry->src_addr.u.og->og_name);
         break;
    }

    switch (acl_entry->proto)
    {
    case ACL_UDP:
    case ACL_TCP:
        if (acl_entry->sport.lb == 0 && acl_entry->sport.ub == 0)
            break;
        else if (acl_entry->sport.lb == 0 && acl_entry->sport.ub < ACL_MAX_PORTNO)
            cprintf(" lt %d", acl_entry->sport.ub);
        else if (acl_entry->sport.lb > 0 && acl_entry->sport.ub == ACL_MAX_PORTNO)
            cprintf(" gt %d", acl_entry->sport.lb);
        else if (acl_entry->sport.lb == acl_entry->sport.ub)
            cprintf(" eq %d", acl_entry->sport.lb);
        else
            cprintf(" range %d %d", acl_entry->sport.lb, acl_entry->sport.ub);
        break;
    default:;
    }

    switch (acl_entry->dst_addr.acl_addr_format)
    {
    case ACL_ADDR_NOT_SPECIFIED:
        break;
    case ACL_ADDR_HOST:
        cprintf(" host %s", tcp_ip_covert_ip_n_to_p(acl_entry->dst_addr.u.host_addr, ip_addr));
        break;
    case ACL_ADDR_SUBNET_MASK:
        cprintf(" %s", tcp_ip_covert_ip_n_to_p(acl_entry->dst_addr.u.subnet.subnet_addr, ip_addr));
        cprintf(" %s", tcp_ip_covert_ip_n_to_p(acl_entry->dst_addr.u.subnet.subnet_mask, ip_addr));
        break;
    case ACL_ADDR_OBJECT_NETWORK:
        cprintf(" object-network %s", acl_entry->dst_addr.u.obj_nw->name);
        break;
    case ACL_ADDR_OBJECT_GROUP:
         cprintf(" object-group %s", acl_entry->dst_addr.u.og->og_name);
         break;        
    }

    switch (acl_entry->proto)
    {
    case ACL_UDP:
    case ACL_TCP:
        if (acl_entry->dport.lb == 0 && acl_entry->dport.ub == 0)
            break;
        else if (acl_entry->dport.lb == 0 && acl_entry->dport.ub < ACL_MAX_PORTNO)
            cprintf(" lt %d", acl_entry->dport.ub);
        else if (acl_entry->dport.lb > 0 && acl_entry->dport.ub == ACL_MAX_PORTNO)
            cprintf(" gt %d", acl_entry->dport.lb);
        else if (acl_entry->dport.lb == acl_entry->dport.ub)
            cprintf(" eq %d", acl_entry->dport.lb);
        else
            cprintf(" range %d %d", acl_entry->dport.lb, acl_entry->dport.ub);
        break;
        break;
    default:;
    }

    cprintf("\n   (Hits[%lu] Tcam-Count[T:%u Sc:%u Oc:%u])",
           acl_entry->hit_count,
           acl_entry->tcam_total_count,
           acl_entry->tcam_self_conflicts_count,
           acl_entry->tcam_other_conflicts_count);

    time_str = acl_entry_get_installation_time_duration(acl_entry, time_buff, sizeof(time_buff));
    cprintf (  "    [Install Duration : %s]  %u%c\n", time_str ? time_str : (c_string) "NA",
    acl_entry->expected_tcam_count ? (acl_entry->tcam_total_count * 100) / acl_entry->expected_tcam_count : 0, PERCENT_ASCII_CODE);
}

static void
access_list_show_all(node_t *node) {

    glthread_t *curr, *curr1;
    acl_entry_t *acl_entry;
    access_list_t *access_list;
    byte time_buff[HRS_MIN_SEC_FMT_TIME_LEN];
    c_string time_str;

    ITERATE_GLTHREAD_BEGIN(&node->access_lists_db, curr) {

        access_list = glthread_to_access_list(curr);
        cprintf ("Access-list : %s" , access_list->name);
        time_str = access_list_get_installation_time_duration(access_list, time_buff, sizeof(time_buff));
        cprintf (  "    [Install Duration : %s]\n", time_str ? time_str : (c_string) "NA");

         ITERATE_GLTHREAD_BEGIN (&access_list->head, curr1) {

                acl_entry = glthread_to_acl_entry(curr1);
                cprintf(" access-list %s", access_list->name);

                acl_print(acl_entry);
                cprintf ("\n");

         } ITERATE_GLTHREAD_END(&access_list->head, curr1);

    } ITERATE_GLTHREAD_END(&node->access_lists_db, curr)
}


static int
acl_show_handler(int cmdcode,
                 Stack_t *tlv_stack,
                 op_mode enable_or_disable) {

    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    c_string node_name = NULL;
   
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv)
    {
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
    }
    TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);
    access_list_show_all(node);
    return 0;
}

void
acl_build_show_cli(param_t *root) {

    {
        static param_t access_list;
        init_param(&access_list, CMD, "access-list", acl_show_handler, 0, INVALID, 0, "Access Policy");
        libcli_register_param(root, &access_list);
        libcli_set_param_cmd_code(&access_list, ACL_CMD_SHOW);
    }
}
