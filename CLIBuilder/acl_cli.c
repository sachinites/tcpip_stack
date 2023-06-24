#include "libcli.h"

#define ACL_PROTO_MAX 256
#define ACL_MAX_PORTNO 65535
#define ACL_CMD_CONFIG  1
#define ACL_CMD_SHOW 2


static int
acl_action_LEAF_VALIDATION_cbk(Stack_t *tlv_stack, unsigned char *value) {

    if (strncmp(value, "permit", 6) == 0 || 
            strncmp(value, "deny", 4) == 0) {

        return LEAF_VALIDATION_SUCCESS;
    }
    return LEAF_VALIDATION_FAILED;
}

static int
acl_proto_LEAF_VALIDATION_cbk(Stack_t *tlv_stack, unsigned char *value) {

    return LEAF_VALIDATION_SUCCESS;
}

static int
acl_port_no_LEAF_VALIDATION (Stack_t *stack, unsigned char *value) {

    int64_t val_num = atoi((const char *)value);
    if (val_num >= 0 && val_num <= ACL_PROTO_MAX)
        return LEAF_VALIDATION_SUCCESS;
    cprintf ("%s is Invalid. Valid Value Range : [0 %d]\n", value, ACL_PROTO_MAX);
    return LEAF_VALIDATION_FAILED;
}

static int
acl_config_handler(int cmdcode,
                   Stack_t *tlv_stack,
                   op_mode enable_or_disable)
{

    char ip[16];
    uint32_t seq_no = ~0;
    char *proto = NULL;
    char *src_ip = NULL;
    char *dst_ip = NULL;
    tlv_struct_t *tlv = NULL;
    char *host_src_ip = NULL;
    char *host_dst_ip = NULL;
    char *action_name = NULL;
    char *subnet_src_ip = NULL;
    char *subnet_dst_ip = NULL;
    char *subnet_dst_mask = NULL;
    char *subnet_src_mask = NULL;
    char *access_list_name = NULL;

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

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv)
    {

        if (parser_match_leaf_id(tlv->leaf_id, "access-list-name"))
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
        else if (parser_match_leaf_id(tlv->leaf_id, "src-port-no-eq"))
        {
            src_port_no_eq = atoi((const char *)tlv->value);
            if (!(src_port_no_eq > 0 && src_port_no_eq < ACL_MAX_PORTNO))
            {
                cprintf("Error : Invalid Src lt value. Supported (0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id(tlv->leaf_id, "src-port-no-lt"))
        {
            src_port_no_lt = atoi((const char *)tlv->value);
            if (src_port_no_lt <= 0 || src_port_no_lt > ACL_MAX_PORTNO)
            {
                cprintf("Error : Invalid Src lt value. Supported (0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id(tlv->leaf_id, "src-port-no-gt"))
        {
            src_port_no_gt = atoi((const char *)tlv->value);
            if (src_port_no_gt < 0 || src_port_no_gt >= ACL_MAX_PORTNO)
            {
                cprintf("Error : Invalid Src gt value. Supported [0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id(tlv->leaf_id, "src-port-no1"))
        {
            src_port_no1 = atoi((const char *)tlv->value);
            if (!(src_port_no1 >= 0 && src_port_no1 <= ACL_MAX_PORTNO))
            {
                cprintf("Error : Invalid Src Port Range value. Supported [0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id(tlv->leaf_id, "src-port-no2"))
        {
            src_port_no2 = atoi((const char *)tlv->value);
            if (!(src_port_no2 >= 0 && src_port_no2 <= ACL_MAX_PORTNO))
            {
                cprintf("Error : Invalid Src Port Range value. Supported [0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id(tlv->leaf_id, "dst-port-no-eq"))
        {
            dst_port_no_eq = atoi((const char *)tlv->value);
            if (!(dst_port_no_eq > 0 && dst_port_no_eq < ACL_MAX_PORTNO))
            {
                cprintf("Error : Invalid Dst lt value. Supported (0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id(tlv->leaf_id, "dst-port-no-lt"))
        {
            dst_port_no_lt = atoi((const char *)tlv->value);
            if (dst_port_no_lt <= 0 || dst_port_no_lt > ACL_MAX_PORTNO)
            {
                cprintf("Error : Invalid Dst lt value. Supported (0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id(tlv->leaf_id, "dst-port-no-gt"))
        {
            dst_port_no_gt = atoi((const char *)tlv->value);
            if (dst_port_no_gt < 0 || dst_port_no_gt >= ACL_MAX_PORTNO)
            {
                cprintf("Error : Invalid Dst gt value. Supported [0, %d)\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id(tlv->leaf_id, "dst-port-no1"))
        {
            dst_port_no1 = atoi((const char *)tlv->value);
            if (!(dst_port_no1 >= 0 && dst_port_no1 <= ACL_MAX_PORTNO))
            {
                cprintf("Error : Invalid Dst Port Range value. Supported [0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
        else if (parser_match_leaf_id(tlv->leaf_id, "dst-port-no2"))
        {
            dst_port_no2 = atoi((const char *)tlv->value);
            if (!(dst_port_no2 >= 0 && dst_port_no2 <= ACL_MAX_PORTNO))
            {
                cprintf("Error : Invalid Dst Port Range value. Supported [0, %d]\n", ACL_MAX_PORTNO);
                return -1;
            }
        }
    }
    TLV_LOOP_END;

    /* Sanity Checks */
    if (src_port_no_eq ||
        src_port_no_lt ||
        src_port_no_gt ||
        src_port_no1 ||
        src_port_no2 ||
        dst_port_no_eq ||
        dst_port_no_lt ||
        dst_port_no_gt ||
        dst_port_no1 ||
        dst_port_no2)
    {

        if ((src_port_no1 > src_port_no2) || (dst_port_no1 > dst_port_no2))
        {

            cprintf("Error : Port Number Ranges specified is incorrect\n");
            return -1;
        }

        /* Handling port numbers */
        if (src_port_no_eq)
        {

            src_port_no1 = src_port_no2 = src_port_no_eq;
        }
        else if (src_port_no_lt)
        {

            src_port_no1 = 0;
            src_port_no2 = src_port_no_lt;
        }
        else if (src_port_no_gt)
        {

            src_port_no1 = src_port_no_gt;
            src_port_no2 = ACL_MAX_PORTNO;
        }

        if (dst_port_no_eq)
        {

            dst_port_no1 = dst_port_no2 = dst_port_no_eq;
        }
        else if (dst_port_no_lt)
        {

            dst_port_no1 = 0;
            dst_port_no2 = dst_port_no_lt;
        }
        else if (dst_port_no_gt)
        {

            dst_port_no1 = dst_port_no_gt;
            dst_port_no2 = ACL_MAX_PORTNO;
        }

        switch (cmdcode)
        {
        case ACL_CMD_CONFIG:
            switch (enable_or_disable)
            {
            case CONFIG_ENABLE:

                cprintf("Access list : config enable\n");
                break;

            case CONFIG_DISABLE:

                cprintf("Access list : config disable\n");
                break;
            }
            break;
        default:;
        }
        return 0;
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
                init_param(&action, LEAF, 0, 0, acl_action_LEAF_VALIDATION_cbk, STRING, "permit|deny", "permit/deny");
                libcli_register_param(&seq_no, &action);
                {
                     /* access-list <name> <action> <proto>*/
                    static param_t proto;
                    init_param(&proto, LEAF, 0, acl_config_handler, acl_proto_LEAF_VALIDATION_cbk, STRING, "protocol", "specify protocol");
                    libcli_register_param(&action, &proto);
                    libcli_set_param_cmd_code(&proto, ACL_CMD_CONFIG);

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
                                      init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_LEAF_VALIDATION, INT, "src-port-no-eq", "specify Src Port Number");
                                      libcli_register_param(&eq, &src_port_no);
                                      libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
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
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_LEAF_VALIDATION, INT, "src-port-no-gt", "specify Src Port Number");
                                    libcli_register_param(&gt, &src_port_no);
                                    libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
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
                                    init_param(&src_port_no1, LEAF, 0, NULL, acl_port_no_LEAF_VALIDATION, INT, "src-port-no1", "specify Src Port Number Lower Bound");
                                    libcli_register_param(&range, &src_port_no1);
                                    {
                                        /* access-list <name> <action> <proto> host <src-ip> range <src-port-no1> <src-port-no2>*/
                                        static param_t src_port_no2;
                                        init_param(&src_port_no2, LEAF, 0, acl_config_handler, acl_port_no_LEAF_VALIDATION, INT, "src-port-no2", "specify Src Port Number Upper Bound");
                                        libcli_register_param(&src_port_no1, &src_port_no2);
                                        libcli_set_param_cmd_code(&src_port_no2, ACL_CMD_CONFIG);
                                    }
                                }
                            }
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
                               {
                                 /* access-list <name> <action> <proto> <src-ip> <src-mask> eq ...*/
                                 static param_t eq;
                                 init_param(&eq, CMD, "eq", 0, 0, INVALID, 0, "eq equal");
                                  libcli_register_param(&src_mask, &eq);
                                  {
                                      /* access-list <name> <action> <proto> <src-ip> <src-mask> eq <src-port-no>*/
                                      static param_t src_port_no;
                                      init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_LEAF_VALIDATION, INT, "src-port-no-eq", "specify Src Port Number");
                                      libcli_register_param(&eq, &src_port_no);
                                      libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
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
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_LEAF_VALIDATION, INT, "src-port-no-lt", "specify Src Port Number");
                                    libcli_register_param(&lt, &src_port_no);
                                    libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG );
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
                                    init_param(&src_port_no, LEAF, 0, acl_config_handler, acl_port_no_LEAF_VALIDATION, INT, "src-port-no-gt", "specify Src Port Number");
                                    libcli_register_param(&gt, &src_port_no);
                                    libcli_set_param_cmd_code(&src_port_no, ACL_CMD_CONFIG);
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
                                    init_param(&src_port_no1, LEAF, 0, NULL, acl_port_no_LEAF_VALIDATION, INT, "src-port-no1", "specify Src Port Number Lower Bound");
                                    libcli_register_param(&range, &src_port_no1);
                                    {
                                        /* access-list <name> <action> <proto> host <src-ip> range <src-port-no1> <src-port-no2>*/
                                        static param_t src_port_no2;
                                        init_param(&src_port_no2, LEAF, 0, acl_config_handler, acl_port_no_LEAF_VALIDATION, INT, "src-port-no2", "specify Src Port Number Upper Bound");
                                        libcli_register_param(&src_port_no1, &src_port_no2);
                                        libcli_set_param_cmd_code(&src_port_no2, ACL_CMD_CONFIG);
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
}


static int
acl_show_handler(int cmdcode,
                 Stack_t *tlv_stack,
                 op_mode enable_or_disable) {

    tlv_struct_t *tlv = NULL;
    unsigned char * node_name = NULL;
   
    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv)
    {
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
    }
    TLV_LOOP_END;

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
