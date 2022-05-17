#include "../../CommandParser/libcli.h"
#include "../CommandParser/cmdtlv.h"
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

static bool
acl_parse_ace_config_entries(
                              acl_entry_t *acl_entry,
                             char *action_name,
                             char *proto,
                             char *src_ip,
                             char *src_mask,
                             char *dst_ip,
                             char *dst_mask) {

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

    bitmap_init(&acl_entry->prefix, ACL_PREFIX_LEN);
    bitmap_init(&acl_entry->mask, ACL_PREFIX_LEN);

    return true;
}

static int
access_list_config(node_t *node, 
                    char *access_list_name,
                    char *action_name,
                    char *proto,
                    char *src_ip,
                    char *src_mask,
                    char *dst_ip,
                    char *dst_mask) {

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
                    dst_ip,
                    dst_mask)) {

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
                    char *dst_ip,
                    char *dst_mask) {

   acl_entry_t acl_entry; 

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
                    dst_ip,
                    dst_mask)) {

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
    char *node_name = NULL;
    char *action_name = NULL;
    char *access_list_name = NULL;

    int cmdcode = -1;

    cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){

        if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0)
            node_name = tlv->value;
        else if (strncmp(tlv->leaf_id, "access-list-name", strlen("access-list-name")) == 0)
            access_list_name = tlv->value;
        else if (strncmp(tlv->leaf_id, "action", strlen("action")) == 0)
            action_name = tlv->value;
        else if (strncmp(tlv->leaf_id, "protocol", strlen("protocol")) == 0)
            proto = tlv->value;
        else if (strncmp(tlv->leaf_id, "src-ip", strlen("src-ip")) == 0)
            src_ip = tlv->value;
        else if (strncmp(tlv->leaf_id, "src-mask", strlen("src-mask")) == 0)
            src_mask = tlv->value;
        else if (strncmp(tlv->leaf_id, "dst-ip", strlen("dst-ip")) == 0)
            dst_ip = tlv->value;
        else if (strncmp(tlv->leaf_id, "dst-mask", strlen("dst-mask")) == 0)
            dst_mask = tlv->value;
        else
            assert(0);
   } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch(cmdcode) {
        case ACL_CMD_CONFIG:
        switch (enable_or_disable) {
            case CONFIG_ENABLE:
                return access_list_config(node, access_list_name, action_name, proto, src_ip, src_mask, dst_ip, dst_mask);
            case CONFIG_DISABLE:
                return access_list_unconfig(node, access_list_name, action_name, proto, src_ip, src_mask, dst_ip, dst_mask);
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
                init_param(&action, LEAF, 0, 0, acl_action_validation_cbk, STRING, "action", "permit/deny");
                libcli_register_param(&access_list_name, &action);
                libcli_register_display_callback(&action, acl_display_supported_protocols);
                {
                    /* access-list <name> <action> <proto>*/
                    static param_t proto;
                    init_param(&proto, LEAF, 0, acl_config_handler, acl_proto_validation_cbk, STRING, "protocol", "specify protocol");
                    libcli_register_param(&action, &proto);
                    set_param_cmd_code(&proto, ACL_CMD_CONFIG);
                    {
                        /* access-list <name> <action> <proto> <host>...*/
                        static param_t host;
                        init_param(&host, CMD, "host", 0, 0, STRING, 0, "specify host IP Address");
                        libcli_register_param(&proto, &host);
                        {
                            /* access-list <name> <action> <proto> <host> <src-ip-addr>*/
                            /* host src ip */
                            static param_t src_ip;
                            init_param(&src_ip, LEAF, 0, acl_config_handler, 0, IPV4, "src-ip", "specify Host Src IPV4 Address");
                            libcli_register_param(&host, &src_ip);
                            set_param_cmd_code(&src_ip, ACL_CMD_CONFIG);
                            {
                                /* access-list <name> <action> <proto> <host> <src-ip-addr> <dst ip address> ....*/
                                /* Dst ip */
                                static param_t dst_ip;
                                init_param(&dst_ip, LEAF, 0, 0, 0, IPV4, "dst-ip", "specify Dst IPV4 Address");
                                libcli_register_param(&src_ip, &dst_ip);
                                {
                                    /* access-list <name> <action> <proto> <host> <src-ip-addr> <dst ip address> <mask address>*/
                                    /* Dst Mask */
                                    static param_t dst_mask;
                                    init_param(&dst_mask, LEAF, 0, acl_config_handler, 0, IPV4, "dst-mask", "specify Dst IPV4 Mask");
                                    libcli_register_param(&dst_ip, &dst_mask);
                                    set_param_cmd_code(&dst_mask, ACL_CMD_CONFIG);
                                }
                            }
                            {
                                /* access-list <name> <action> <proto> <host> <src-ip-addr> host...*/
                                /* Dst host */
                                static param_t host;
                                init_param(&host, CMD, "host", 0, 0, STRING, 0, "specify Dst host IP Address");
                                libcli_register_param(&src_ip, &host);
                                {
                                    /* access-list <name> <action> <proto> <host> <src-ip-addr> host <dst-addr>.*/
                                    static param_t dst_ip;
                                    init_param(&dst_ip, LEAF, 0, acl_config_handler, 0, IPV4, "dst-ip", "specify Host Dst IPV4 Address");
                                    libcli_register_param(&host, &dst_ip);
                                    set_param_cmd_code(&dst_ip, ACL_CMD_CONFIG);
                                }
                            }
                        }
                    }
                    {
                        /* access-list <name> <action> <proto> <src-ip-addr>*/
                        /* Src ip */
                        static param_t src_ip;
                        init_param(&src_ip, LEAF, 0, 0, 0, IPV4, "src-ip", "specify Src IPV4 Address");
                        libcli_register_param(&proto, &src_ip);
                        {
                            /* access-list <name> <action> <proto> <src-ip-addr> <src-mask-addr>*/
                            /* Src Mask */
                            static param_t src_mask;
                            init_param(&src_mask, LEAF, 0, acl_config_handler, 0, IPV4, "src-mask", "specify Src IPV4 Mask");
                            libcli_register_param(&src_ip, &src_mask);
                            set_param_cmd_code(&src_mask, ACL_CMD_CONFIG);
                            {
                                /* access-list <name> <action> <proto> <src-ip-addr> <src-mask-addr> host...*/
                                /* Dst host */
                                static param_t host;
                                init_param(&host, CMD, "host", 0, 0, STRING, 0, "specify Dst host IP Address");
                                libcli_register_param(&src_mask, &host);
                                {
                                    /* access-list <name> <action> <proto> <src-ip-addr> <src-mask-addr> host <dst-ip-addr>*/
                                    static param_t dst_ip;
                                    init_param(&dst_ip, LEAF, 0, acl_config_handler, 0, IPV4, "dst-ip", "specify Host Dst IPV4 Address");
                                    libcli_register_param(&host, &dst_ip);
                                    set_param_cmd_code(&dst_ip, ACL_CMD_CONFIG);
                                }
                            }
                            {
                                /* access-list <name> <action> <proto> <src-ip-addr> <src-mask-addr> <dst-ip-addr> ...*/
                                /* Dst ip */
                                static param_t dst_ip;
                                init_param(&dst_ip, LEAF, 0, 0, 0, IPV4, "dst-ip", "specify Dst IPV4 Address");
                                libcli_register_param(&src_mask, &dst_ip);
                                {
                                    /* access-list <name> <action> <proto> <src-ip-addr> <src-mask-addr> <dst-ip-addr> <dst-mask>*/
                                    /* Dst Mask */
                                    static param_t dst_mask;
                                    init_param(&dst_mask, LEAF, 0, acl_config_handler, 0, IPV4, "dst-mask", "specify Dst IPV4 Mask");
                                    libcli_register_param(&dst_ip, &dst_mask);
                                    set_param_cmd_code(&dst_mask, ACL_CMD_CONFIG);
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
                init_param(&dirn, LEAF, 0, 0, 0, STRING, "dirn", "Access List Direction");
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

    access_list_t *acc_lst = (access_list_t *)data;
    acl_entry_t *acl_entry = (acl_entry_t *)node->data;

    if (!acl_entry) return;
    
    printf (" access-list %s %s %s %s ",
        acc_lst->name,
        acl_entry->action == ACL_PERMIT ? "permit" : "deny" , 
        proto_name_str( acl_entry->proto),
        tcp_ip_covert_ip_n_to_p(acl_entry->saddr.ip4.prefix, 0));
    printf ("%s ", tcp_ip_covert_ip_n_to_p(acl_entry->saddr.ip4.mask, 0));
    printf ("%s ", tcp_ip_covert_ip_n_to_p(acl_entry->daddr.ip4.prefix , 0));
    printf ("%s ", tcp_ip_covert_ip_n_to_p(acl_entry->daddr.ip4.mask, 0));
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
