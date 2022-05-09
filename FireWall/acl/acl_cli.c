#include "../../CommandParser/libcli.h"
#include "../CommandParser/cmdtlv.h"
#include "../../graph.h"
#include "acldb.h"
#include "../mtrie/mtrie.h"
#include "../../utils.h"

extern graph_t *topo;

#define ACL_CMD_CONFIG  1
#define ACL_CMD_SHOW 2

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
access_list_config(node_t *node, 
                    char *access_list_name,
                    char *action_name,
                    char *proto,
                    char *src_ip,
                    char *src_mask,
                    char *dst_ip,
                    char *dst_mask) {

    acl_entry_t *acl_entry = (acl_entry_t *)calloc(1, sizeof(acl_entry_t));

    /* Action */
    if (strncmp(action_name, "permit", 6) == 0 ) {
        acl_entry->action = ACL_PERMIT;
    }
    else if (strncmp(action_name, "deny", 4) == 0 ) {
        acl_entry->action = ACL_DENY;
    }
    else {
        goto ACL_INSTALLATION_FAILED;
    }

    /* Protocol */
    acl_entry->proto = acl_string_to_proto(proto);
    if (acl_entry->proto == ACL_PROTO_NONE) goto ACL_INSTALLATION_FAILED;

    /* Src ip */
    if (src_ip == NULL) {
        acl_entry->saddr.ip4.prefix = 0;
    }
    else {
        acl_entry->saddr.ip4.prefix =  tcp_ip_covert_ip_p_to_n(src_ip);
    }
   
    /* Src mask */
    if (src_mask == NULL) {
        acl_entry->saddr.ip4.mask = ~0;
    }
    else {
        acl_entry->saddr.ip4.mask =  tcp_ip_covert_ip_p_to_n(src_mask);
    }

    /* Dst ip */
    if (dst_ip == NULL) {
        acl_entry->daddr.ip4.prefix = 0;
    }
    else {
        acl_entry->daddr.ip4.prefix =  tcp_ip_covert_ip_p_to_n(dst_ip);
    }

    /* Dst Mask */
    if (dst_mask == NULL) {
        acl_entry->daddr.ip4.mask = ~0;
    }
    else {
        acl_entry->daddr.ip4.mask =  tcp_ip_covert_ip_p_to_n(dst_mask);
    }

    bitmap_init(&acl_entry->prefix, ACL_PREFIX_LEN);
    bitmap_init(&acl_entry->mask, ACL_PREFIX_LEN);

    if (acl_process_user_config(
            node, access_list_name, acl_entry) == 0) {
        return 0;
    }

    ACL_INSTALLATION_FAILED:
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

    return 0;
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
                break;
            case CONFIG_DISABLE:
                return access_list_unconfig(node, access_list_name, action_name, proto, src_ip, src_mask, dst_ip, dst_mask);
        }
        break;
        default: ;
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
            init_param(&access_list_name, LEAF, 0, 0, 0, STRING, "access-list-name", "Access Policy Name");
            libcli_register_param(&access_list, &access_list_name);
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
}

static void
acl_entry_show_one_acl_entry(acl_entry_t *acl_entry) {

    printf ("  %s  %d  %s  ",
        acl_entry->action == ACL_PERMIT ? "permit" : "deny" , 
        acl_entry->proto, 
        tcp_ip_covert_ip_n_to_p(acl_entry->saddr.ip4.prefix, 0));
    printf ("%s  ", tcp_ip_covert_ip_n_to_p(acl_entry->saddr.ip4.mask, 0));
    printf ("%s  ", tcp_ip_covert_ip_n_to_p(acl_entry->daddr.ip4.prefix , 0));
    printf ("%s  ", tcp_ip_covert_ip_n_to_p(acl_entry->daddr.ip4.mask, 0));
    printf(" (hits %lu)\n", acl_entry->hit_count);
}

static void
access_list_show_all(node_t *node) {

    glthread_t *curr, *curr1;
    acl_entry_t *acl_entry;
    access_list_t *acc_lst;

    ITERATE_GLTHREAD_BEGIN(&node->access_lists_db, curr) {

        acc_lst = glthread_to_access_list(curr);
        printf ("Access-list : %s ref_count = %d\n" , acc_lst->name, acc_lst->ref_count);
        
        ITERATE_GLTHREAD_BEGIN(&acc_lst->head, curr1) {

                acl_entry = glthread_to_acl_entry(curr1);
                acl_entry_show_one_acl_entry(acl_entry);

        } ITERATE_GLTHREAD_END(&acc_lst->head, curr1);
        
        /* For debugging enable the below two lines */
        //printf ("\nAccess-List Mtrie : #Nodes = %d\n\n", acc_lst->mtrie->N);
        //mtrie_post_order_traverse(acc_lst->mtrie, mtrie_print_node);

        printf ("********\n");
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
