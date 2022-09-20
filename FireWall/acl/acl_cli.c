#include "../../CommandParser/libcli.h"
#include "../../CommandParser/cmdtlv.h"
#include "../../graph.h"
#include "acldb.h"
#include "../../mtrie/mtrie.h"
#include "../../utils.h"
#include "../../tcpconst.h"

extern graph_t *topo;
extern void
display_node_interfaces(param_t *param, ser_buff_t *tlv_buf);


#define ACL_CMD_CONFIG  1
#define ACL_CMD_SHOW 2
#define ACL_CMD_ACCESS_GROUP_CONFIG 3

/* ACL CLI format (Cisco Like ) :
    <permit/deny> <protocol> <src ip> <src mask> <dst ip> <dst mask> <eq | lt | gt | range> <port1> <port2> 
    <permit/deny> <protocol> host <src ip> host <dst ip> <eq | lt | gt | range> <port1> <port2> 

*/
static int
acl_action_validation_cbk(char *value) {

    if (strncmp(value, "permit", 6) == 0 || 
            strncmp(value, "deny", 4) == 0) {

        return VALIDATION_SUCCESS;
    }
    return VALIDATION_FAILED;
}

static int
acl_proto_validation_cbk(char *value) {

    acl_proto_t proto = acl_string_to_proto(value);
    if (proto == ACL_PROTO_NONE) return VALIDATION_FAILED;
    return VALIDATION_SUCCESS;
}

static void
acl_display_supported_protocols(param_t *param, ser_buff_t *tlv_buf) {

}

static int
acl_port_no_validation (char *value) {

    int64_t val_num = atoi(value);
    if (val_num >= 0 && val_num <= ACL_PROTO_MAX)
        return VALIDATION_SUCCESS;
    printf ("%s is Invalid. Valid Value Range : [0 %d]\n", value, ACL_PROTO_MAX);
    return VALIDATION_FAILED;
}

static bool
acl_parse_ace_config_entries(
                              acl_entry_t *acl_entry,
                             char *action_name,
                             char *proto,
                             char *src_ip,
                             char *src_mask,
                             uint16_t src_port_no1,
                             uint16_t src_port_no2,
                             char *dst_ip,
                             char *dst_mask,
                             uint16_t dst_port_no1,
                             uint16_t dst_port_no2) {

                                  /* Action */
    if (strncmp(action_name, "permit", 6) == 0 ) {
        acl_entry->action = ACL_PERMIT;
    }
    else if (strncmp(action_name, "deny", 4) == 0 ) {
        acl_entry->action = ACL_DENY;
    }
    else {
        return false;
    }

    /* Protocol */
   
    acl_entry->proto = acl_string_to_proto(proto);

    /* Src ip */
    if (src_ip == NULL) {
        acl_entry->saddr.ip4.prefix = 0;
        acl_entry->saddr.ip4.mask = 0;
    }
    else {
        acl_entry->saddr.ip4.prefix =  tcp_ip_covert_ip_p_to_n(src_ip);
    }
   
    /* Src mask */
    if (src_ip) {
        if (src_mask) {
            acl_entry->saddr.ip4.mask =  tcp_ip_covert_ip_p_to_n(src_mask);
        }
        else {
            acl_entry->saddr.ip4.mask = ~0;
        }
    }
    else {
         if (src_mask) {
           assert(0);
        }
        else {
            acl_entry->saddr.ip4.mask = 0;
        }
    }

    /* Src Port Number */
    acl_entry->sport.lb = src_port_no1;
    acl_entry->sport.ub = src_port_no2;

    /* Dst ip */
    if (dst_ip == NULL) {
        acl_entry->daddr.ip4.prefix = 0;
        acl_entry->daddr.ip4.mask = 0;
    }
    else {
        acl_entry->daddr.ip4.prefix =  tcp_ip_covert_ip_p_to_n(dst_ip);
    }

    /* Dst Mask */
    if (dst_ip) {
        if (dst_mask) {
            acl_entry->daddr.ip4.mask =  tcp_ip_covert_ip_p_to_n(dst_mask);
        }
        else {
            acl_entry->daddr.ip4.mask = ~0;
        }
    }
    else {
         if (dst_mask) {
           assert(0);
        }
        else {
            acl_entry->daddr.ip4.mask = 0;
        }
    }

    /* Drc Port Number */
    acl_entry->dport.lb = dst_port_no1;
    acl_entry->dport.ub = dst_port_no2;

    return true;
}

static int
access_list_config(node_t *node, 
                    char *access_list_name,
                    char *action_name,
                    char *proto,
                    char *src_ip,
                    char *src_mask,
                    uint16_t src_port_no1,
                    uint16_t src_port_no2,
                    char *dst_ip,
                    char *dst_mask,
                    uint16_t dst_port_no1,
                    uint16_t dst_port_no2) {

   acl_entry_t *acl_entry = NULL;

    if (!action_name &&
         !proto &&
         !src_ip && !src_mask &&
         !dst_ip && !dst_mask) {

        return 0;
    }
    
    acl_entry = (acl_entry_t *)calloc(1, sizeof(acl_entry_t));

   if (!acl_parse_ace_config_entries(
                    acl_entry, 
                    action_name,
                    proto,
                    src_ip,
                    src_mask,
                    src_port_no1,
                    src_port_no2,
                    dst_ip,
                    dst_mask,
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
                    char *action_name,
                    char *proto,
                    char *src_ip,
                    char *src_mask,
                    uint16_t src_port_no1,
                    uint16_t src_port_no2,
                    char *dst_ip,
                    char *dst_mask,
                    uint16_t dst_port_no1,
                    uint16_t dst_port_no2) {

   acl_entry_t acl_entry; 

   memset(&acl_entry, 0, sizeof(acl_entry_t));

   access_list_t *access_list = acl_lookup_access_list(node, access_list_name);

    if (!access_list) {
        printf ("Error : Access List do not Exist\n");
        return false;
    }

    /* If USer has triggered only no <access-list-name>, then delete the entire access 
        list */
    if (!action_name &&
         !proto &&
         !src_ip && !src_mask &&
         !dst_ip && !dst_mask) {

        access_list_delete_complete(access_list);
        return 0;
    }


   if (!acl_parse_ace_config_entries(
                    &acl_entry, 
                    action_name,
                    proto,
                    src_ip,
                    src_mask,
                    src_port_no1,
                    src_port_no2,
                    dst_ip,
                    dst_mask,
                    dst_port_no1,
                    dst_port_no2)) {

        return -1;
    }

    if (acl_process_user_config_for_deletion (
            node, access_list, &acl_entry) == 0) {
        return 0;
    }

    return -1;
}

static int
acl_config_handler(param_t *param, 
                  ser_buff_t *tlv_buf,
                  op_mode enable_or_disable) {

    char *proto = NULL;
    char *src_ip = NULL;
    char *dst_ip = NULL;
    node_t *node = NULL;
    char *dst_mask = NULL;
    char *src_mask = NULL;
    tlv_struct_t *tlv = NULL;
    char *host_src_ip = NULL;
    char *host_dst_ip = NULL;
    char *node_name = NULL;
    char *action_name = NULL;
    char *access_list_name = NULL;
    uint16_t src_port_no_eq = 0,
                  src_port_no_neq = 0,
                  src_port_no_lt = 0,
                  src_port_no_gt = 0,
                  src_port_no1 = 0,
                  src_port_no2 = 0,
                  dst_port_no_eq = 0,
                  dst_port_no_neq = 0,
                  dst_port_no_lt = 0,
                  dst_port_no_gt = 0,
                  dst_port_no1 = 0,
                  dst_port_no2 = 0;

    int cmdcode = -1;

    cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if (parser_match_leaf_id (tlv->leaf_id, "node-name"))
	    node_name = tlv->value;
	else if (parser_match_leaf_id (tlv->leaf_id, "access-list-name"))
	    access_list_name = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "permit|deny"))
            action_name = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "protocol"))
            proto = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "src-ip"))
            src_ip = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "host-src-ip"))
            host_src_ip = tlv->value;            
        else if (parser_match_leaf_id (tlv->leaf_id, "src-mask"))
            src_mask = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "dst-ip"))
            dst_ip = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "host-dst-ip"))
            host_dst_ip = tlv->value;                  
        else if (parser_match_leaf_id (tlv->leaf_id, "dst-mask"))
            dst_mask = tlv->value;
        else if (parser_match_leaf_id (tlv->leaf_id, "src-port-no-eq")) {
            src_port_no_eq = atoi(tlv->value);
            if (!(src_port_no_eq > 0 && src_port_no_eq < ACL_MAX_PORTNO)) {
                printf ("Error : Invalid Src lt value. Supported (0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "src-port-no-neq")) {
            src_port_no_neq = atoi(tlv->value);
            if (!(src_port_no_neq > 0 && src_port_no_neq < ACL_MAX_PORTNO)) {
                printf ("Error : Invalid Src neq value. Supported (0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "src-port-no-lt")) {
            src_port_no_lt = atoi(tlv->value);
            if (src_port_no_lt <= 0 || src_port_no_lt > ACL_MAX_PORTNO) {
                printf ("Error : Invalid Src lt value. Supported (0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "src-port-no-gt")) {
            src_port_no_gt = atoi(tlv->value);
            if (src_port_no_gt < 0 || src_port_no_gt >= ACL_MAX_PORTNO) {
                printf ("Error : Invalid Src gt value. Supported [0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "src-port-no1")) {
            src_port_no1 = atoi(tlv->value);
            if (!(src_port_no1 >= 0 && src_port_no1 <= ACL_MAX_PORTNO)) {
                printf ("Error : Invalid Src Port Range value. Supported [0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "src-port-no2")) {
            src_port_no2 = atoi(tlv->value);         
            if (!(src_port_no2 >= 0 && src_port_no2 <= ACL_MAX_PORTNO)) {
                printf ("Error : Invalid Src Port Range value. Supported [0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }                           
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "dst-port-no-eq")) {
            dst_port_no_eq = atoi(tlv->value);
            if (!(dst_port_no_eq > 0 && dst_port_no_eq < ACL_MAX_PORTNO)) {
                printf ("Error : Invalid Dst lt value. Supported (0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "dst-port-no-neq")) {
            dst_port_no_neq = atoi(tlv->value);
            if (!(dst_port_no_neq > 0 && dst_port_no_neq < ACL_MAX_PORTNO)) {
                printf ("Error : Invalid Dst neq value. Supported (0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "dst-port-no-lt")) {
            dst_port_no_lt = atoi(tlv->value);
            if (dst_port_no_lt <= 0 || dst_port_no_lt > ACL_MAX_PORTNO) {
                printf ("Error : Invalid Dst lt value. Supported (0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "dst-port-no-gt")) {
            dst_port_no_gt = atoi(tlv->value);
            if (dst_port_no_gt < 0 || dst_port_no_gt >= ACL_MAX_PORTNO) {
                printf ("Error : Invalid Dst gt value. Supported [0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "dst-port-no1")) {
            dst_port_no1 = atoi(tlv->value);
            if (!(dst_port_no1 >= 0 && dst_port_no1 <= ACL_MAX_PORTNO)) {
                printf ("Error : Invalid Dst Port Range value. Supported [0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "dst-port-no2")) {
            dst_port_no2 = atoi(tlv->value);         
            if (!(dst_port_no2 >= 0 && dst_port_no2 <= ACL_MAX_PORTNO)) {
                printf ("Error : Invalid Dst Port Range value. Supported [0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }                           
        }
        else
            assert(0);
   } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    if (host_src_ip) {
        src_ip = host_src_ip;
        src_mask = "255.255.255.255";
    }

    if (host_dst_ip) {
        dst_ip = host_dst_ip;
        dst_mask = "255.255.255.255";
    }

    /* Sanity Checks */
    if (  src_port_no_eq || 
           src_port_no_neq || 
           src_port_no_lt || 
           src_port_no_gt || 
           src_port_no1 || 
           src_port_no2 ||
           dst_port_no_eq || 
           dst_port_no_neq || 
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
                printf ("Error : Port number is supported only with udp/tcp protocols\n");
                return -1;
        }
    }

    if ((src_port_no1 > src_port_no2) || (dst_port_no1 > dst_port_no2)) {

        printf ("Error : Port Number Ranges specified is incorrect\n");
        return -1;
    }

    if (src_port_no_neq || dst_port_no_neq) {

         printf ("Error : Port Number Not Equal specifier is not supported\n");
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
                return access_list_config(node, access_list_name, action_name, proto, src_ip, src_mask, src_port_no1, src_port_no2, dst_ip, dst_mask, dst_port_no1, dst_port_no2);
            case CONFIG_DISABLE:
                return access_list_unconfig(node, access_list_name, action_name, proto, src_ip, src_mask, src_port_no1, src_port_no2, dst_ip, dst_mask, dst_port_no1, dst_port_no2);
        }
        break;
        default: ;
    }
    return 0;
}

static int
access_group_config_handler(param_t *param, 
                  ser_buff_t *tlv_buf,
                  op_mode enable_or_disable) {
    
    char *dirn = NULL;
    tlv_struct_t *tlv = NULL;
    char *node_name = NULL;
    char *if_name = NULL;
    char *access_list_name = NULL;

    int cmdcode = -1;

    cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0)
            node_name = tlv->value;
        else if (strncmp(tlv->leaf_id, "access-list-name", strlen("access-list-name")) == 0)
            access_list_name = tlv->value;
        else if (strncmp(tlv->leaf_id, "dirn", strlen("dirn")) == 0)
            dirn = tlv->value;
                    else if (strncmp(tlv->leaf_id, "if-name", strlen("if-name")) == 0)
            if_name = tlv->value;
        else
            assert(0);
   } TLV_LOOP_END;

    node_t *node = node_get_node_by_name(topo, node_name);
    interface_t *intf = node_get_intf_by_name(node, if_name);
    
    if (!intf) {
        printf ("Error : Interface do not exist\n");
        return -1;
    }

    access_list_t *acc_lst = acl_lookup_access_list(node, access_list_name);
    if (!acc_lst) {
        printf ("Error : Access List not configured\n");
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
acl_direction_validation(char *value) {

    if ((strncmp(value, "in" , 2) == 0 && strlen(value) == 2) || 
         (strncmp(value, "out" , 3) == 0 && strlen(value) == 3))
        return VALIDATION_SUCCESS;
    return VALIDATION_FAILED;
}

static void
acl_build_config_cli_destination (param_t *root) {

    param_t *host = (param_t *)calloc(1, sizeof(param_t));
    init_param(host, CMD, "host", 0, 0, STRING, 0, "specify host IP Address");
    libcli_register_param(root, host);
    {
        /* access-list <name> <action> <proto> host <dst-ip> */
        param_t *dst_ip = (param_t *)calloc(1, sizeof(param_t));
        init_param(dst_ip, LEAF, 0, acl_config_handler, 0, IPV4, "host-dst-ip", "specify Host Dst IPV4 Address");
        libcli_register_param(host, dst_ip);
        set_param_cmd_code(dst_ip, ACL_CMD_CONFIG);
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
                set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }
        {
            /* access-list <name> <action> <proto> host <dst-ip> neq ...*/
            param_t *neq = (param_t *)calloc(1, sizeof(param_t));
            init_param(neq, CMD, "neq", 0, 0, INVALID, 0, "neq not equal");
            libcli_register_param(dst_ip, neq);
            {
                /* access-list <name> <action> <proto> host <src-ip> neq <src-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-neq", "specify Dst Port Number");
                libcli_register_param(neq, dst_port_no);
                set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
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
                set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
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
                set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
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
                    set_param_cmd_code(dst_port_no2, ACL_CMD_CONFIG);
                }
            }
        }
    }

   /* access-list <name> <action> <proto> <dst-ip> ...*/
    param_t *dst_ip =  (param_t *)calloc(1, sizeof(param_t));
    init_param(dst_ip, LEAF, 0, 0, 0, IPV4, "dst-ip", "specify Dst IPV4 Address");
    libcli_register_param(root, dst_ip);
    {
        /* access-list <name> <action> <proto> <dst-ip> <dst-mask>*/
        param_t *dst_mask = (param_t *)calloc(1, sizeof(param_t));
        init_param(dst_mask, LEAF, 0, acl_config_handler, 0, IPV4, "dst-mask", "specify Dst IPV4 Mask");
        libcli_register_param(dst_ip, dst_mask);
        set_param_cmd_code(dst_mask, ACL_CMD_CONFIG);
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
                set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }
        {
            /* access-list <name> <action> <proto> <dst-ip> <dst-mask> neq ...*/
            param_t *neq = (param_t *)calloc(1, sizeof(param_t));
            init_param(neq, CMD, "neq", 0, 0, INVALID, 0, "neq not equal");
            libcli_register_param(dst_mask, neq);
            {
                /*access-list <name> <action> <proto> <dst-ip> <dst-mask> neq <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-neq", "specify Dst Port Number");
                libcli_register_param(neq, dst_port_no);
                set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
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
                set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }
        {
            /*  access-list <name> <action> <proto> <dst-ip> <dst-mask> gt ...*/
            param_t *gt = (param_t *)calloc(1, sizeof(param_t));
            init_param(gt, CMD, "lt", 0, 0, INVALID, 0, "gt greater than");
            libcli_register_param(dst_mask, gt);
            {
                /* access-list <name> <action> <proto> host <dst-ip> lt <dst-port-no>*/
                param_t *dst_port_no = (param_t *)calloc(1, sizeof(param_t));
                init_param(dst_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "dst-port-no-gt", "specify Dst Port Number");
                libcli_register_param(gt, dst_port_no);
                set_param_cmd_code(dst_port_no, ACL_CMD_CONFIG);
            }
        }
        {
            /*  access-list <name> <action> <proto> <dst-ip> <dst-mask> range ...*/
            param_t *range = (param_t *)calloc(1, sizeof(param_t));
            init_param(range, CMD, "range", 0, 0, INVALID, 0, "range p1 p2");
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
                    set_param_cmd_code(dst_port_no2, ACL_CMD_CONFIG);
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
            set_param_cmd_code(&access_list_name, ACL_CMD_CONFIG);
            {
                 /* access-list <name> <action> ...*/
                static param_t action;
                init_param(&action, LEAF, 0, 0, acl_action_validation_cbk, STRING, "permit|deny", "permit/deny");
                libcli_register_param(&access_list_name, &action);
                libcli_register_display_callback(&action, acl_display_supported_protocols);
                {
                     /* access-list <name> <action> <proto>*/
                    static param_t proto;
                    init_param(&proto, LEAF, 0, acl_config_handler, acl_proto_validation_cbk, STRING, "protocol", "specify protocol");
                    libcli_register_param(&action, &proto);
                    set_param_cmd_code(&proto, ACL_CMD_CONFIG);
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
                            set_param_cmd_code(&src_ip, ACL_CMD_CONFIG);
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
                                      set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                      acl_build_config_cli_destination(&src_port_no);
                                  }
                            }
                            {
                                /* access-list <name> <action> <proto> host <src-ip> neq ...*/
                                static param_t neq;
                                init_param(&neq, CMD, "neq", 0, 0, INVALID, 0, "neq not equal");
                                libcli_register_param(&src_ip, &neq);
                                {
                                    /* access-list <name> <action> <proto> host <src-ip> neq <src-port-no>*/
                                    static param_t src_port_no;
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no-neq", "specify Src Port Number");
                                    libcli_register_param(&neq, &src_port_no);
                                    set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                    acl_build_config_cli_destination(&src_port_no);
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
                                    set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                    acl_build_config_cli_destination(&src_port_no);
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
                                    set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                    acl_build_config_cli_destination(&src_port_no);
                                }
                            }  
                            {
                                /* access-list <name> <action> <proto> host <src-ip> range ...*/
                                static param_t range;
                                init_param(&range, CMD, "range", 0, 0, INVALID, 0, "range p1 p2");
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
                                        set_param_cmd_code(&src_port_no2, ACL_CMD_CONFIG);
                                         acl_build_config_cli_destination(&src_port_no2);
                                    }
                                }
                            }
                            acl_build_config_cli_destination(&src_ip);
                        }
                    }
                    {
                         /* access-list <name> <action> <proto> <src-ip>...*/
                        static param_t src_ip;
                        init_param(&src_ip, LEAF, 0, 0, 0, IPV4, "src-ip", "specify Src IPV4 Address");
                        libcli_register_param(&proto, &src_ip);
                        {
                             /* access-list <name> <action> <proto> <src-ip> <src-mask>*/
                            static param_t src_mask;
                            init_param(&src_mask, LEAF, 0, acl_config_handler, 0, IPV4, "src-mask", "specify Src IPV4 Mask");
                            libcli_register_param(&src_ip, &src_mask);
                            set_param_cmd_code(&src_mask, ACL_CMD_CONFIG);
                            acl_build_config_cli_destination(&src_mask);
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
                                      set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                      acl_build_config_cli_destination(&src_port_no);
                                  }
                            }
                            {
                                /* access-list <name> <action> <proto> <src-ip> <src-mask> neq ...*/
                                static param_t neq;
                                init_param(&neq, CMD, "neq", 0, 0, INVALID, 0, "neq not equal");
                                libcli_register_param(&src_mask, &neq);
                                {
                                    /*access-list <name> <action> <proto> <src-ip> <src-mask> neq <src-port-no>*/
                                    static param_t src_port_no;
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_validation, INT, "src-port-no-neq", "specify Src Port Number");
                                    libcli_register_param(&neq, &src_port_no);
                                    set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                    acl_build_config_cli_destination(&src_port_no);
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
                                    set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG );
                                    acl_build_config_cli_destination(&src_port_no );
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
                                    set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
                                    acl_build_config_cli_destination(&src_port_no);
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
                                        set_param_cmd_code(&src_port_no2, ACL_CMD_CONFIG);
                                         acl_build_config_cli_destination(&src_port_no2);
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
                        set_param_cmd_code(&if_name, ACL_CMD_ACCESS_GROUP_CONFIG);
                    }
                }
            }
        }
    }
}

static void
acl_entry_show_one_acl_entry(mtrie_t *mtrie, mtrie_node_t *node, void *data) {

    char ip_addr[16];
    access_list_t *acc_lst = (access_list_t *)data;
    acl_entry_t *acl_entry = (acl_entry_t *)node->data;

    if (!acl_entry) return;
    
    printf (" access-list %s %s %s %s ",
        acc_lst->name,
        acl_entry->action == ACL_PERMIT ? "permit" : "deny" , 
        proto_name_str( acl_entry->proto),
        tcp_ip_covert_ip_n_to_p(acl_entry->saddr.ip4.prefix, ip_addr));
    printf ("%s ", tcp_ip_covert_ip_n_to_p(acl_entry->saddr.ip4.mask, ip_addr));

    switch(acl_entry->proto) {
        case ACL_UDP:
        case ACL_TCP:
            if (acl_entry->sport.lb == 0 && acl_entry->sport.ub == 0)
                break;
            else if (acl_entry->sport.lb == 0 && acl_entry->sport.ub < ACL_MAX_PORTNO)
                printf ("lt %d ", acl_entry->sport.ub);
            else if (acl_entry->sport.lb > 0 && acl_entry->sport.ub == ACL_MAX_PORTNO)
                printf ("gt %d ", acl_entry->sport.lb);
            else if  (acl_entry->sport.lb == acl_entry->sport.ub)
                printf ("eq %d ", acl_entry->sport.lb);
            else
                printf ("range %d %d ", acl_entry->sport.lb, acl_entry->sport.ub);
            break;            
        default:;
    }
   
    printf ("%s ", tcp_ip_covert_ip_n_to_p(acl_entry->daddr.ip4.prefix , ip_addr));
    printf ("%s ", tcp_ip_covert_ip_n_to_p(acl_entry->daddr.ip4.mask, ip_addr));

    switch(acl_entry->proto) {
        case ACL_UDP:
        case ACL_TCP:
            if (acl_entry->dport.lb == 0 && acl_entry->dport.ub == 0)
                break;
            else if (acl_entry->dport.lb == 0 && acl_entry->dport.ub < ACL_MAX_PORTNO)
                printf ("lt %d ", acl_entry->dport.ub);
            else if (acl_entry->dport.lb > 0 && acl_entry->dport.ub == ACL_MAX_PORTNO)
                printf ("gt %d ", acl_entry->dport.lb);
            else if  (acl_entry->dport.lb == acl_entry->dport.ub)
                printf ("eq %d ", acl_entry->dport.lb);                
            else
                printf ("range %d %d ", acl_entry->dport.lb, acl_entry->dport.ub);
                break;            
            break;
        default:;
    }

    printf("(hits %lu)\n", acl_entry->hit_count);
}

static void
access_list_show_all(node_t *node) {

    glthread_t *curr, *curr1;
    acl_entry_t *acl_entry;
    access_list_t *acc_lst;

    ITERATE_GLTHREAD_BEGIN(&node->access_lists_db, curr) {

        acc_lst = glthread_to_access_list(curr);
        printf ("Access-list : %s\n" , acc_lst->name);
        mtrie_longest_prefix_first_traverse(acc_lst->mtrie, 
                                                                  acl_entry_show_one_acl_entry,
                                                                  (void *)acc_lst);
    #if 0
    /* Debugging */
    mtrie_longest_prefix_first_traverse(acc_lst->mtrie, 
                                                                  mtrie_print_node,
                                                                  NULL);
    #endif

    } ITERATE_GLTHREAD_END(&node->access_lists_db, curr)
}


static int
acl_show_handler(param_t *param,
                 ser_buff_t *tlv_buf,
                 op_mode enable_or_disable) {

    node_t *node = NULL;
    tlv_struct_t *tlv = NULL;
    char *node_name = NULL;
   
    TLV_LOOP_BEGIN(tlv_buf, tlv)
    {
        if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0)
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
        set_param_cmd_code(&access_list, ACL_CMD_SHOW);
    }
}
