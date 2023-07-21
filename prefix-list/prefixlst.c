#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../graph.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "prefixlst.h"
#include "../utils.h"
#include "../CLIBuilder/libcli.h"
#include "../cmdcodes.h"

extern graph_t *topo;
extern void prefix_list_notify_clients(node_t *node, prefix_list_t *prefix_lst) ;

prefix_list_t *
prefix_lst_lookup_by_name (pfxlst_db *pfxlstdb, unsigned char *pfxlst_name) {

    glthread_t *curr;
    prefix_list_t *prefix_lst;

    ITERATE_GLTHREAD_BEGIN(pfxlstdb, curr) {

        prefix_lst = glue_to_pfx_lst(curr);
        
        if (string_compare(prefix_lst->name, pfxlst_name, PFX_LST_NAME_LEN) == 0) {
            return prefix_lst;
        }

    } ITERATE_GLTHREAD_END(pfxlstdb, curr);
    
    return NULL;
}

static pfx_lst_node_t *
prefix_lst_node_lookup (prefix_list_t *prefix_lst, pfx_lst_node_t *pfx_lst_node_template) {

    glthread_t *curr;
    pfx_lst_node_t *pfx_lst_node;

   ITERATE_GLTHREAD_BEGIN(&prefix_lst->pfx_lst_head, curr) {

        pfx_lst_node = glue_to_pfx_lst_node(curr);

        if (pfx_lst_node->pfx == pfx_lst_node_template->pfx &&
             pfx_lst_node->pfx_len == pfx_lst_node_template->pfx_len &&
             pfx_lst_node->lb == pfx_lst_node_template->lb &&
             pfx_lst_node->ub == pfx_lst_node_template->ub) {

             return pfx_lst_node;
        }
   } ITERATE_GLTHREAD_END(&prefix_lst->pfx_lst_head, curr);

    return NULL;
}

static int
prefix_lst_node_comp_fn (void *arg1, void *arg2) {

    pfx_lst_node_t *new_node = (pfx_lst_node_t *)arg1;
    pfx_lst_node_t *existing_node = (pfx_lst_node_t *)arg2;

    if (new_node->seq_no == existing_node->seq_no) return 0;

    return  new_node->seq_no - existing_node->seq_no;
}

bool
prefix_list_add_rule (prefix_list_t *prefix_lst,
                                   uint32_t seq_no,
                                   pfx_lst_result_t res,
                                   uint32_t prefix,
                                   uint8_t len,
                                   int8_t lb,
                                   int8_t ub) {

    pfx_lst_node_t *pfx_lst_node;
    pfx_lst_node_t *pfx_lst_node_existing;

    pfx_lst_node = (pfx_lst_node_t *)XCALLOC(0, 1, pfx_lst_node_t);
    pfx_lst_node->pfx = prefix;
    pfx_lst_node->pfx_len = len;

    pfx_lst_node->lb = (lb == -1) ? len : lb;
    pfx_lst_node->ub = (ub == -1) ? len : ub;

    pfx_lst_node_existing = prefix_lst_node_lookup (prefix_lst, pfx_lst_node);

    if (pfx_lst_node_existing) {
        XFREE(pfx_lst_node);
        pfx_lst_node = NULL;
        cprintf ("Error : This Prefix list rule already exists\n");
        return false;
    }

    pfx_lst_node->seq_no = !seq_no ? (prefix_lst->seq_no += PFX_LST_SEQ_NO_LAPS) : seq_no;
    pfx_lst_node->res = res;

    glthread_priority_insert (&prefix_lst->pfx_lst_head,
                                            &pfx_lst_node->glue,
                                            prefix_lst_node_comp_fn,
                                            (int)&((pfx_lst_node_t *)0)->glue);

    return true;
}

bool
prefix_list_del_rule (prefix_list_t *prefix_lst,
                                  uint32_t seq_no) {

    glthread_t *curr;
    pfx_lst_node_t *pfx_lst_node;

     ITERATE_GLTHREAD_BEGIN(&prefix_lst->pfx_lst_head, curr) {

        pfx_lst_node = glue_to_pfx_lst_node(curr);
        if (pfx_lst_node->seq_no == seq_no) {
            remove_glthread(&pfx_lst_node->glue);
           XFREE(pfx_lst_node);
            return true;
        }
     } ITERATE_GLTHREAD_END(&prefix_lst->pfx_lst_head, curr);

    return false;
}

static void
print_pfx_lst_node ( prefix_list_t *prefix_lst, pfx_lst_node_t *pfx_lst_node) {

    unsigned char out_buff[16];

    cprintf ("prefix-list %s %s %u %s/%d ge %d le %d (hit-count = %lu)\n",  
        prefix_lst->name,
        pfx_lst_node->res == PFX_LST_DENY ? "deny" : "permit",
        pfx_lst_node->seq_no,
        tcp_ip_covert_ip_n_to_p(pfx_lst_node->pfx,  out_buff),
        pfx_lst_node->pfx_len,
        pfx_lst_node->lb,
        pfx_lst_node->ub,
        pfx_lst_node->hit_count);
}


void
prefix_list_show (prefix_list_t *prefix_lst) {

    glthread_t *curr;
    pfx_lst_node_t *pfx_lst_node;

    ITERATE_GLTHREAD_BEGIN(&prefix_lst->pfx_lst_head, curr) {

        pfx_lst_node = glue_to_pfx_lst_node(curr);
        print_pfx_lst_node (prefix_lst, pfx_lst_node);

     } ITERATE_GLTHREAD_END(&prefix_lst->pfx_lst_head, curr);
}

pfx_lst_result_t
prefix_list_evaluate_against_pfx_lst_node (uint32_t prefix,
                                                                      uint8_t len,
                                                                      pfx_lst_node_t *pfx_lst_node) {

    bool rc = false;
    uint32_t subnet_mask = ~0;
    uint32_t input_binary_prefix = 0;
    uint32_t pfxlst_node_binary_prefix = 0;

    if (len < pfx_lst_node->lb) return PFX_LST_SKIP;

    if (pfx_lst_node->ub > -1 && 
        (len > pfx_lst_node->ub)) return PFX_LST_SKIP;
    
     /*Compute Mask in binary format as well*/
    if (pfx_lst_node->pfx_len) {
        subnet_mask = subnet_mask << (32 - pfx_lst_node->pfx_len);
    }
    else {
        subnet_mask = 0;
    }

    /*Perform logical AND to apply mask on IP address*/
    input_binary_prefix = prefix & subnet_mask;
    pfxlst_node_binary_prefix = pfx_lst_node->pfx & subnet_mask;

    rc = (input_binary_prefix == pfxlst_node_binary_prefix);

    if (!rc) {
        return PFX_LST_SKIP;
    }

    pfx_lst_node->hit_count++;
    return pfx_lst_node->res;
}

pfx_lst_result_t
prefix_list_evaluate (uint32_t prefix, uint8_t len, prefix_list_t *prefix_lst) {

    glthread_t *curr;
    pfx_lst_node_t *pfx_lst_node;
    pfx_lst_result_t res;

    ITERATE_GLTHREAD_BEGIN(&prefix_lst->pfx_lst_head, curr) {

        pfx_lst_node = glue_to_pfx_lst_node(curr);

        res = prefix_list_evaluate_against_pfx_lst_node (prefix, len, pfx_lst_node);

        switch (res) {
            case PFX_LST_SKIP:
                continue;
            case PFX_LST_DENY:
            case PFX_LST_PERMIT:
                return res;
            case PFX_LST_UNKNOWN:
                assert(0);
        }

     } ITERATE_GLTHREAD_END(&prefix_lst->pfx_lst_head, curr);    

    return PFX_LST_SKIP;
}

static int
prefix_lst_config_handler (int cmdcode,
                                           Stack_t *tlv_stack,
                                           op_mode enable_or_disable){

    bool new_pfx_lst;
    uint32_t seq_no = 0;
    tlv_struct_t *tlv = NULL;
    char *pfx_lst_name = NULL;
    char *res_str = NULL;

    c_string node_name = NULL;
    uint8_t lb = -1, ub = -1, len = 0;

    char *nw_prefix = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value; 
        else if(parser_match_leaf_id(tlv->leaf_id, "pfxlst-name"))
            pfx_lst_name = tlv->value; 
        else if(parser_match_leaf_id(tlv->leaf_id, "permit|deny"))
            res_str = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "seq-no"))
            seq_no = atoi((const char *)tlv->value);
        else if(parser_match_leaf_id(tlv->leaf_id, "nw-ip"))
            nw_prefix = tlv->value;
        else if(parser_match_leaf_id(tlv->leaf_id, "nw-mask"))
            len = atoi((const char *)tlv->value); 
        else if(parser_match_leaf_id(tlv->leaf_id, "ge-n"))
            lb = atoi((const char *)tlv->value);                
        else if(parser_match_leaf_id(tlv->leaf_id, "le-n"))
            ub = atoi((const char *)tlv->value);               
    } TLV_LOOP_END;

    new_pfx_lst = false;

    node_t *node = node_get_node_by_name(topo, node_name);

    prefix_list_t *prefix_lst = prefix_lst_lookup_by_name (&node->prefix_lst_db, pfx_lst_name);

    /* Handle negation CLI Begin */
    if (enable_or_disable == CONFIG_DISABLE) {

        if (!prefix_lst) return -1;

        if (seq_no) {
            if (prefix_list_del_rule(prefix_lst, seq_no)) {
                prefix_list_notify_clients(node, prefix_lst);
                if (IS_GLTHREAD_LIST_EMPTY(&prefix_lst->pfx_lst_head)) {
                    if (!prefix_list_is_in_use(prefix_lst))
                    {
                        remove_glthread(&prefix_lst->glue);
                        prefix_list_dereference(prefix_lst);
                        cprintf("Delete Successful.\n");
                    }
                }
                return 0;
            }
        } else {

            if (!prefix_list_is_in_use(prefix_lst)) {
                remove_glthread(&prefix_lst->glue);
                prefix_list_dereference(prefix_lst);
                cprintf ("Delete Successful.\n");
            }
            else {
                cprintf ("Error : Prefix List in Use, cannot delete\n");
            }
        }
        return 0;
    }
    /* Handle negation CLI Done */

    if (res_str == NULL) {
        cprintf ("Error : Incomplete Prefix List\n");
        return -1;
    }

    pfx_lst_result_t res = (strcmp (res_str, "permit") == 0) ? PFX_LST_PERMIT : PFX_LST_DENY;


    if (!prefix_lst) {

        prefix_lst = (prefix_list_t *)XCALLOC(0, 1, prefix_list_t);
        string_copy ((char *)prefix_lst->name, pfx_lst_name, PFX_LST_NAME_LEN);
        new_pfx_lst = true;
    }

    if (!prefix_list_add_rule (prefix_lst,
                                             seq_no,
                                             res, 
                                             nw_prefix ? tcp_ip_covert_ip_p_to_n(nw_prefix) : 0,
                                             len, lb, ub)) {
        
        cprintf ("Error : Rule Could not be configured\n");

        if (new_pfx_lst) {
            XFREE(prefix_lst);
        }

        return -1;
    }

    if (new_pfx_lst) {
        glthread_add_last (&node->prefix_lst_db, &prefix_lst->glue);
        prefix_list_reference(prefix_lst);
    }
    else {
        prefix_list_notify_clients(node, prefix_lst);
    }

    return 0;
}

static int
prefix_lst_validate_input_result_value(Stack_t *tlv_stack, char *value) {

    if (strcmp(value, "permit") == 0 || 
            strcmp(value, "deny") == 0) {

        return LEAF_VALIDATION_SUCCESS;
    }

    cprintf ("Mention either : permit Or deny. Case sensitive\n");
    return LEAF_VALIDATION_FAILED;
}


/* Prefix List CLI */
/* config node <node-name> prefix-list <name> <seq-no> <permit | deny> <network> <mask> [le <N>] [ge <N>] */
void prefix_list_cli_config_tree(param_t *param)
{
    {
        static param_t prefix_lst;
        init_param(&prefix_lst, CMD, "prefix-list", NULL, NULL, INVALID, NULL, "prefix-list");
        libcli_register_param(param, &prefix_lst);
        {
            static param_t prefix_lst_name;
            init_param(&prefix_lst_name, LEAF, NULL, NULL, NULL, STRING, "pfxlst-name", "prefix-list Name");
            libcli_register_param(&prefix_lst, &prefix_lst_name);
            {
                static param_t res;
                init_param(&res, LEAF, NULL, NULL, prefix_lst_validate_input_result_value, STRING, "permit|deny", "prefix-list result [permit | deny]");
                libcli_register_param(&prefix_lst_name, &res);
                {
                    static param_t seq_no;
                    init_param(&seq_no, LEAF, NULL, prefix_lst_config_handler, NULL, INT, "seq-no", "prefix-list Sequence No");
                    libcli_register_param(&res, &seq_no);
                    libcli_set_param_cmd_code(&seq_no, CMDCODE_CONFIG_PREFIX_LST);
                    {
                        static param_t nw_ip;
                        init_param(&nw_ip, LEAF, 0, 0, 0, IPV4, "nw-ip", "specify Network IPV4 Address");
                        libcli_register_param(&seq_no, &nw_ip);
                        {
                            static param_t nw_mask;
                            init_param(&nw_mask, LEAF, NULL, prefix_lst_config_handler, NULL, INT, "nw-mask", "specify IPV4 Mask");
                            libcli_register_param(&nw_ip, &nw_mask);
                            libcli_set_param_cmd_code(&nw_mask, CMDCODE_CONFIG_PREFIX_LST);
                            {
                                static param_t ge;
                                init_param(&ge, CMD, "ge", 0, 0, INVALID, 0, "specify greater than equal ");
                                libcli_register_param(&nw_mask, &ge);
                                {
                                    static param_t gen;
                                    init_param(&gen, LEAF, NULL, prefix_lst_config_handler, NULL, INT, "ge-n", "greater than equal Number");
                                    libcli_register_param(&ge, &gen);
                                    libcli_set_param_cmd_code(&gen, CMDCODE_CONFIG_PREFIX_LST);
                                    {
                                        static param_t le;
                                        init_param(&le, CMD, "le", 0, 0, INVALID, 0, "specify less than equal ");
                                        libcli_register_param(&gen, &le);
                                        {
                                            static param_t len;
                                            init_param(&len, LEAF, NULL, prefix_lst_config_handler, NULL, INT, "le-n", "less than equal Number");
                                            libcli_register_param(&le, &len);
                                            libcli_set_param_cmd_code(&len, CMDCODE_CONFIG_PREFIX_LST);
                                        }
                                    }
                                }
                            }
                            {
                                static param_t le;
                                init_param(&le, CMD, "le", 0, 0, INVALID, 0, "specify less than equal ");
                                libcli_register_param(&nw_mask, &le);
                                {
                                    static param_t len;
                                    init_param(&len, LEAF, NULL, prefix_lst_config_handler, NULL, INT, "le-n", "less than equal Number");
                                    libcli_register_param(&le, &len);
                                    libcli_set_param_cmd_code(&len, CMDCODE_CONFIG_PREFIX_LST);
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
prefix_lst_show_handler (int cmdcode,
                                          Stack_t *tlv_stack,
                                           op_mode enable_or_disable){

    c_string node_name = NULL;
    char *pfx_lst_name = NULL;
    node_t *node;
    tlv_struct_t *tlv = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv){

        if(parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value; 
        else if(parser_match_leaf_id(tlv->leaf_id, "pfxlst-name"))
            pfx_lst_name = tlv->value; 
    } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch (cmdcode) {
        case CMDCODE_SHOW_PREFIX_LST_ALL:
            {
                glthread_t *curr;
                prefix_list_t *prefix_lst;
                ITERATE_GLTHREAD_BEGIN(&node->prefix_lst_db, curr) {

                    prefix_lst = glue_to_pfx_lst(curr);
                    prefix_list_show(prefix_lst);

                }  ITERATE_GLTHREAD_END(&node->prefix_lst_db, curr);
            }
        break;
        case CMDCODE_SHOW_PREFIX_LST_ONE:
        {
             prefix_list_t *prefix_lst = prefix_lst_lookup_by_name(&node->prefix_lst_db, pfx_lst_name);
             if (!prefix_lst) {
                return -1;
             }
             prefix_list_show(prefix_lst);
        }
        break;
        default:
        break;
    }

    return 0;
}

void prefix_list_cli_show_tree(param_t *param) {

    {
        static param_t prefix_lst;
        init_param(&prefix_lst, CMD, "prefix-list",prefix_lst_show_handler, NULL, INVALID, NULL, "prefix-list");
        libcli_register_param(param, &prefix_lst);
        libcli_set_param_cmd_code(&prefix_lst, CMDCODE_SHOW_PREFIX_LST_ALL);
        {
            static param_t prefix_lst_name;
            init_param(&prefix_lst_name, LEAF, NULL, prefix_lst_show_handler, NULL, STRING, "pfxlst-name", "prefix-list Name");
            libcli_register_param(&prefix_lst, &prefix_lst_name);
            libcli_set_param_cmd_code(&prefix_lst_name, CMDCODE_SHOW_PREFIX_LST_ONE);
        }
    }
}

/* Prefix-list change notification */
typedef void (*prefix_list_change_cbk)(node_t *, prefix_list_t *);
extern void isis_prefix_list_change(node_t *node, prefix_list_t *pfx_lst);
static prefix_list_change_cbk notif_arr[] = { 
                                                                        isis_prefix_list_change,
                                                                        /*add_mode_callbacks_here,*/
                                                                        0,
                                                                        };

void
prefix_list_notify_clients(node_t *node, prefix_list_t *prefix_lst) {

    int i = 0 ;
    while (notif_arr[i]) {
        notif_arr[i](node, prefix_lst);
        i++;
    }
}

void
prefix_list_mem_init () {

    MM_REG_STRUCT(0, prefix_list_t);
    MM_REG_STRUCT(0, pfx_lst_result_t);
    MM_REG_STRUCT(0, pfx_lst_node_t);
}
