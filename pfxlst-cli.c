#include "cmdcodes.h"
#include "router_init.h"
#include "libs/prefix-list/prefixlst.h"
#include "CLIBuilder/libcli.h"
#include "CLIBuilder/cmdtlv.h"

extern graph_t *topo;

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
                prefix_list_update_notify_clients(node, prefix_lst);
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

        prefix_lst = (prefix_list_t *)XCALLOC2(0, 1, prefix_list_t);
        string_copy ((char *)prefix_lst->name, pfx_lst_name, PFX_LST_NAME_LEN);
        new_pfx_lst = true;
    }

    /* Reject up-front so the user gets a specific message; prefix_list_add_rule
       enforces the same invariant defensively. */
    if (seq_no && prefix_list_lookup_by_seq_no(prefix_lst, seq_no)) {

        cprintf("Error : Rule with sequence number %u already exists\n", seq_no);

        if (new_pfx_lst) {
            XFREE(prefix_lst);
        }

        return -1;
    }

    if (!prefix_list_add_rule (prefix_lst,
                                             seq_no,
                                             res, 
                                             nw_prefix ? tcp_ip_convert_ip_p_to_n(nw_prefix) : 0,
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
        prefix_list_update_notify_clients(node, prefix_lst);
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
                    libcli_disable_batch_processing(&seq_no);
                    {
                        static param_t nw_ip;
                        init_param(&nw_ip, LEAF, 0, 0, 0, IPV4, "nw-ip", "specify Network IPV4 Address");
                        libcli_register_param(&seq_no, &nw_ip);
                        {
                            static param_t nw_mask;
                            init_param(&nw_mask, LEAF, NULL, prefix_lst_config_handler, NULL, INT, "nw-mask", "specify IPV4 Mask");
                            libcli_register_param(&nw_ip, &nw_mask);
                            libcli_set_param_cmd_code(&nw_mask, CMDCODE_CONFIG_PREFIX_LST);
                            libcli_disable_batch_processing(&nw_mask);
                            {
                                static param_t ge;
                                init_param(&ge, CMD, "ge", 0, 0, INVALID, 0, "specify greater than equal ");
                                libcli_register_param(&nw_mask, &ge);
                                {
                                    static param_t gen;
                                    init_param(&gen, LEAF, NULL, prefix_lst_config_handler, NULL, INT, "ge-n", "greater than equal Number");
                                    libcli_register_param(&ge, &gen);
                                    libcli_set_param_cmd_code(&gen, CMDCODE_CONFIG_PREFIX_LST);
                                    libcli_disable_batch_processing(&gen);
                                    {
                                        static param_t le;
                                        init_param(&le, CMD, "le", 0, 0, INVALID, 0, "specify less than equal ");
                                        libcli_register_param(&gen, &le);
                                        {
                                            static param_t len;
                                            init_param(&len, LEAF, NULL, prefix_lst_config_handler, NULL, INT, "le-n", "less than equal Number");
                                            libcli_register_param(&le, &len);
                                            libcli_set_param_cmd_code(&len, CMDCODE_CONFIG_PREFIX_LST);
                                            libcli_disable_batch_processing(&len);
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
                                    libcli_disable_batch_processing(&len);
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

    printw("\n\r");
    
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

/* Prefix-list change subscription registry.

   The set of clients interested in prefix-list updates lives on the
   owning node (node->prefix_lst_clients) instead of in a global table.
   Each entry binds a callback to a (vrf_id, instance_no) tuple supplied
   by the caller at registration time; the registry is otherwise opaque
   to the protocol identity. */

struct prefix_lst_client_ {

    prefix_list_change_cbk cbk;
    vrf_t   *vrf;
    uint32_t instance_no;
};

static bool
prefix_lst_client_matches(const prefix_lst_client_t *c,
                          prefix_list_change_cbk cbk,
                          vrf_t *vrf,
                          uint32_t instance_no)
{
    return c
        && c->cbk == cbk
        && c->vrf == vrf
        && c->instance_no == instance_no;
}

void
prefix_list_register_client(node_t *node,
                            prefix_list_change_cbk cbk,
                            vrf_t *vrf,
                            uint32_t instance_no)
{
    if (!node || !cbk) return;

    /* Idempotent: silently ignore a duplicate registration so a caller
       can re-register without book-keeping. */
    for (prefix_lst_client_t *c : node->prefix_lst_clients) {
        if (prefix_lst_client_matches(c, cbk, vrf, instance_no))
            return;
    }

    prefix_lst_client_t *client =
        (prefix_lst_client_t *)XCALLOC(0, 1, prefix_lst_client_t);
    client->cbk         = cbk;
    client->vrf         = vrf;
    client->instance_no = instance_no;

    node->prefix_lst_clients.push_back(client);
}

void
prefix_list_unregister_client(node_t *node,
                              prefix_list_change_cbk cbk,
                              vrf_t *vrf,
                              uint32_t instance_no)
{
    if (!node || !cbk) return;

    auto &clients = node->prefix_lst_clients;
    for (auto it = clients.begin(); it != clients.end(); ++it) {

        prefix_lst_client_t *c = *it;
        if (!prefix_lst_client_matches(c, cbk, vrf, instance_no))
            continue;

        clients.erase(it);
        XFREE(c);
        return;
    }
}

void
prefix_list_update_notify_clients(node_t *node, prefix_list_t *prefix_lst)
{
    /* Snapshot the registry so a callback that mutates the registry
       (re-register / unregister) cannot invalidate our iterator. */
    std::vector<prefix_lst_client_t *> snapshot = node->prefix_lst_clients;

    for (prefix_lst_client_t *c : snapshot) {
        if (!c || !c->cbk) continue;

        c->cbk(node, c->vrf, c->instance_no, prefix_lst);
    }
}