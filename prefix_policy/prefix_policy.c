#include <memory.h>
#include <stdlib.h>
#include "prefix_policy.h"
#include "../CommandParser/libcli.h"
#include "../CommandParser/cmdtlv.h"
#include "../cmdcodes.h"
#include "../graph.h"

extern graph_t *topo;

static int
policy_compare_fn (const avltree_node_t *_c1_new, 
                                 const avltree_node_t *_c2_existing){

    policy_t *policy_new = avltree_container_of(_c1_new, policy_t , glue);
    policy_t *policy_existing = avltree_container_of(_c2_existing, policy_t , glue);

    return strncmp(policy_new->name, policy_existing->name, POLICY_NAME_LEN);
}

static int
policy_prefix_tree_compare_fn (
                                const avltree_node_t *_c1_new, 
                                 const avltree_node_t *_c2_existing){

    policy_prefix_t *pprefix_new =  avltree_container_of(_c1_new, policy_prefix_t , glue);
    policy_prefix_t *pprefix_old =  avltree_container_of(_c2_existing, policy_prefix_t , glue);

    if (pprefix_new->metric < pprefix_old->metric) {
        return -1;
    }
    
    if (pprefix_new->metric > pprefix_old->metric) {
        return 1;
    }

    if (pprefix_new->mask < pprefix_old->mask) {
        return -1;
    }

    if (pprefix_new->mask > pprefix_old->mask) {
        return 1;
    }

    if (pprefix_new->protocol < pprefix_old->protocol) {
        return -1;
    }

    if (pprefix_new->protocol > pprefix_old->protocol) {
        return 1;
    }

    return 0;
}

void
policy_init (policy_db_t *policy_db) {

    avltree_init(policy_db, policy_compare_fn);
}

policy_t *
policy_get(policy_db_t *policy_db, unsigned char *policy_name) {

    policy_t * policy = policy_lookup(policy_db, policy_name);
    if (policy) return policy;
    policy = (policy_t *)calloc (1, sizeof(policy_t));
    strncpy(policy->name, policy_name, POLICY_NAME_LEN);
    avltree_init(&policy->prefix_tree, policy_prefix_tree_compare_fn);
    policy->ref_count = 1;
    avltree_insert(&policy->glue, policy_db);
    return policy;
}

static void
policy_flush_prefix_tree(policy_t *policy) {

    avltree_node_t *avl_node;
    policy_prefix_t *pprefix;

    if (avltree_is_empty(&policy->prefix_tree)) return;

    ITERATE_AVL_TREE_BEGIN (&policy->prefix_tree, avl_node) {

        avltree_remove(avl_node, &policy->prefix_tree);
        pprefix = avltree_container_of(avl_node, policy_prefix_t, glue);
        free(pprefix);

    }ITERATE_AVL_TREE_END;
}

void
policy_dereference (policy_db_t *policy_db, policy_t *policy) {

    policy->ref_count--;
    if (policy->ref_count > 0) return;
    avltree_remove(&policy->glue, policy_db);
    policy_flush_prefix_tree(policy);
    free(policy);
}

void
policy_reference (policy_t *policy) {

    policy->ref_count++;
}

policy_prefix_t *
policy_add_prefix (policy_t *policy, uint32_t prefix, uint8_t mask, uint8_t proto) {


    policy_prefix_t *pprefix =  policy_lookup_prefix(policy, prefix, mask, proto);
    
    if (pprefix) return NULL;

    pprefix = (policy_prefix_t *)calloc (1, sizeof(policy_prefix_t));
    pprefix->prefix = prefix;
    pprefix->mask = mask;
    pprefix->protocol = proto;

    avltree_insert(&pprefix->glue, &policy->prefix_tree);
    return pprefix;
}

void
policy_prefix_set_action_matric (policy_prefix_t *pprefix, uint32_t metric) {

    pprefix->metric_set = true;
    pprefix->metric = metric;
}

void
policy_prefix_unset_action_matric (policy_prefix_t *pprefix, uint32_t metric) {

    pprefix->metric_set = false;
    pprefix->metric = 0;
}

bool
policy_evaluate (policy_t *policy, uint32_t prefix, uint8_t mask, uint8_t proto, 
    policy_prefix_action_template_t *act_template) {

     policy_prefix_t *pprefix =  policy_lookup_prefix(policy, prefix, mask, proto);
     
     if (!pprefix) return false;

    if (pprefix->metric_set) {

        act_template->metric_set = true;
        act_template->metric = pprefix->metric;
    }

    return true;
}

void
policy_delete_prefix (policy_t *policy, uint32_t prefix, uint8_t mask, uint8_t proto) {

    policy_prefix_t *pprefix =  policy_lookup_prefix(policy, prefix, mask, proto);

    if (!pprefix) return;

    avltree_remove(&pprefix->glue, &policy->prefix_tree);
    free(pprefix);
}

policy_t *
policy_lookup(policy_db_t *policy_db, unsigned char *policy_name) {

    policy_t policy_template;

    strncpy(policy_template.name, policy_name, POLICY_NAME_LEN);
    avltree_node_t *avl_node = avltree_lookup(&policy_template.glue, policy_db);
    if (!avl_node) return NULL;
    return avltree_container_of(avl_node, policy_t, glue);
}

 policy_prefix_t *
 policy_lookup_prefix (policy_t *policy, uint32_t prefix, uint8_t mask, uint8_t proto) {

     policy_prefix_t pprefix_template;

     pprefix_template.prefix = prefix;
     pprefix_template.mask = mask;
     pprefix_template.protocol = proto;

     avltree_node_t *avl_node = avltree_lookup(&pprefix_template.glue, &policy->prefix_tree);
     if (!avl_node) return NULL;
    return avltree_container_of(avl_node, policy_prefix_t, glue);
 }

static int
policy_config_handler(
                    param_t *param, 
                    ser_buff_t *tlv_buf,
                    op_mode enable_or_disable){

    node_t *node;
    int cmdcode = -1;
    uint8_t mask;
    char *node_name;
    char *policy_name;
    char *prefix_ip = NULL;
    tlv_struct_t *tlv = NULL;
    policy_t *policy;

     cmdcode = EXTRACT_CMD_CODE(tlv_buf);

      TLV_LOOP_BEGIN(tlv_buf, tlv){

        if  (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) ==0)
            node_name = tlv->value;
        else if (strncmp(tlv->leaf_id, "policy-name", strlen("policy-name")) ==0)
            policy_name =  tlv->value;
        else if (strncmp(tlv->leaf_id, "prefix-ip", strlen("prefix-ip")) ==0)
            prefix_ip = tlv->value;
        else if (strncmp(tlv->leaf_id, "mask", strlen("mask")) ==0)
            mask = atoi(tlv->value);
        else
            assert(0);
   } TLV_LOOP_END;

    node = node_get_node_by_name(topo, node_name);

    switch(cmdcode){
        case CMDCODE_IMPORT_POLICY_CREATE_DELETE:
            switch(enable_or_disable){
                case CONFIG_ENABLE:
                    policy_get(&node->import_policy_db, policy_name);
                break;
                case CONFIG_DISABLE:
                    policy = policy_get(&node->import_policy_db, policy_name);
                    if (!policy) {
                        printf ("Error : Policy do not exist\n");
                        return -1;
                    }
                    if (policy->ref_count > 1) {
                        printf ("Error : Policy In Use, Cannot Delete\n");
                        return -1;
                    }
                    policy_dereference(&node->import_policy_db, policy);
                break;
                default : ;
            }
            break;
        case CMDCODE_IMPORT_POLICY_PREFIX:
            policy = policy_get(&node->import_policy_db, policy_name);
            {
                uint32_t prefix = tcp_ip_covert_ip_p_to_n(prefix_ip);
                policy_add_prefix(policy, prefix, mask, 0);
            }
            break;
        default: ;
    }

    return 0;
}

 /* CLIs */


 /* config node <node-name> [no] import-policy <policy-name> prefix <prefix> <mask> then metric <metric value>*/

/* config node <node-name> .. .*/
 param_t *
 policy_config_cli_tree () {

     static param_t import_policy;
     init_param(&import_policy, CMD, "import-policy", 0, 0, INVALID, 0, "import-policy");
    {
         /* config node <node-name> [no] import-policy <policy-name> */
        static param_t policy_name;
        init_param(&policy_name, LEAF, 0, policy_config_handler, 0, STRING, "policy-name", "Policy Name");
        libcli_register_param(&import_policy, &policy_name);
        set_param_cmd_code(&policy_name, CMDCODE_IMPORT_POLICY_CREATE_DELETE);
        {
            /* config node <node-name> [no] import-policy <policy-name> prefix <prefix> <mask>*/
             static param_t prefix;
             init_param(&prefix, CMD, "prefix", 0, 0, INVALID, 0, "Prefix");
             libcli_register_param(&policy_name, &prefix);
            {
                static param_t prefix_ip;
                init_param(&prefix_ip, LEAF, 0, 0, 0, IPV4, "prefix-ip", "Prefix IP Address");
                libcli_register_param(&prefix, &prefix_ip);
                {
                    static param_t mask;
                    init_param(&mask, LEAF, 0, policy_config_handler, 0, INT, "mask", "Mask [0-32]");
                    libcli_register_param(&prefix_ip, &mask);
                    set_param_cmd_code(&mask, CMDCODE_IMPORT_POLICY_PREFIX);
                }
            }
        }
    }

     return &import_policy;
 } 