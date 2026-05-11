/*
redistribute connected|static|bgp|ospf|isis [prefix-list <pfx-lst-name>] [metric <n>]
  All keywords after the source protocol are optional.
*/

#include <stdlib.h>
#include <string.h>

#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"
#include "../router_init.h"
#include "../libs/LinuxMemoryManager/uapi_mm.h"
#include "../libs/prefix-list/prefixlst.h"
#include "rtm_dist_mgr.h"
#include "rtm_enums.h"

extern graph_t *topo;
extern int cprintf(const char *format, ...);

/* Caution : Order is maintained as per enum : RTM_PROTO_T */
void (*RT_DIST_HANDLERS[])(node_t *, rt_advert_info_t *) = {

    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};

/* Per-file command codes for redistribution policy CLI */
#define CMDCODE_RTM_REDIST_CONNECTED  1
#define CMDCODE_RTM_REDIST_LOCAL      2
#define CMDCODE_RTM_REDIST_STATIC     3
#define CMDCODE_RTM_REDIST_BGP        4
#define CMDCODE_RTM_REDIST_OSPF       5
#define CMDCODE_RTM_REDIST_ISIS       6

redist_target_t *
rtm_protocol_rt_distribution_policy_config_cli_handler(
    RTM_PROTO_T proto,
    int cmdcode,
    Stack_t *tlv_stack,
    op_mode enable_or_disable,
    dist_mgr_t **dist_mgr_out);


static void 
dist_mgr_target_delink (dist_mgr_t *dist_mgr, redist_target_t *target) {

    redist_target_t *curr = dist_mgr->target_lst, *prev = NULL;

    while (curr) {

        if (curr == target) {

            if (prev) prev->next = curr->next;
            else dist_mgr->target_lst = curr->next;
            curr->next = NULL;
            return;
        }
        prev = curr;
        curr = curr->next;
    }
}

extern int
rtm_isis_rt_distribution_policy_config_cli_handler(
    int cmdcode,
    Stack_t *tlv_stack,
    op_mode enable_or_disable) {

    tlv_struct *tlv;
    char *node_name = NULL;
    dist_mgr_t *dist_mgr = NULL;

    redist_target_t *target = rtm_protocol_rt_distribution_policy_config_cli_handler(
                    RTM_PROTO_ISIS, 
                    cmdcode, 
                    tlv_stack, enable_or_disable, &dist_mgr);

    if (!target) return -1;

    /* Invoke redistribution callback for all routes currently 
        redistributed to this target */
    rtm_dist_mgr_refresh_dist_routes_to_target(dist_mgr, target);
    
    /* If target's rule list is empty, then Queue the target for deletion.
        Deletion of the target should be done asynchronously (deferred) 
        through Garbage collector because we need to send DELETE to this 
        target for all routes we have flashed to it */

    if (!target->rule_list) {
        dist_mgr_target_delink (dist_mgr, target);
        rtm_dis_mgr_gc (dist_mgr, target, DIST_MGR_GC_TYPE_TARGET);
    }

    return 0;
}

static void 
rtm_distribution_policy_common_subtree_cli(
            param_t *mount_point, 
            int cmdcode, 
            int (*cbk)(int, Stack_t*, op_mode) ) {

 {
            param_t *prefix_list = (param_t *)calloc (1, sizeof (param_t));
            init_param(prefix_list, CMD, "prefix-list", 0, 0, INVALID, 0,
                "Optional: apply prefix-list filter");
            libcli_register_param(mount_point, prefix_list);
            {
                param_t *pfx_lst_name = (param_t *)calloc (1, sizeof (param_t));
                init_param(pfx_lst_name, LEAF, 0, cbk, 
                    0, STRING, "pfx-lst-name", "Prefix-list name");
                libcli_register_param(prefix_list, pfx_lst_name);
                libcli_set_param_cmd_code(pfx_lst_name, cmdcode);
                libcli_disable_batch_processing(pfx_lst_name);
                {
                    param_t *metric = (param_t *)calloc (1, sizeof (param_t));
                    init_param(metric, CMD, "metric", 0, 0, INVALID, 0,
                        "Set redistributed metric (optional, default 0)");
                    libcli_register_param(pfx_lst_name, metric);
                    {
                        param_t *metric_val = (param_t *)calloc (1, sizeof (param_t));
                        init_param(metric_val, LEAF, 0,
                            cbk, 0, INT, "metric-val",
                            "Metric value");
                        libcli_register_param(metric, metric_val);
                        libcli_set_param_cmd_code(metric_val, cmdcode);
                        libcli_disable_batch_processing(metric_val);
                    }
                }
            }
        }
        {
            param_t *metric = (param_t *)calloc (1, sizeof (param_t));
            init_param(metric, CMD, "metric", 0, 0, INVALID, 0,
                       "Set redistributed metric (optional, default 0)");
            libcli_register_param(mount_point, metric);
            {
                param_t *metric_val = (param_t *)calloc (1, sizeof (param_t));
                        init_param(metric_val, LEAF, 0,
                           cbk, 0, INT, "metric-val",
                           "Metric value");
                libcli_register_param(metric, metric_val);
                libcli_set_param_cmd_code(metric_val, cmdcode);
                libcli_disable_batch_processing(metric_val);
            }
        }

}

void
rtm_build_distribution_policy_cli_tree(param_t *mount_point, 
            int (*cbk)(int, Stack_t*, op_mode), RTM_PROTO_T exempt_proto) {

    param_t *redistribute = (param_t *)calloc(1, sizeof (param_t));
    init_param(redistribute, CMD, "redistribute", 0, 0, INVALID, 0,
        "Route redistribution policy");
    libcli_register_param(mount_point, redistribute);

    if (exempt_proto != RTM_PROTO_CONNECTED)
    {
        param_t *connected = (param_t *)calloc(1, sizeof (param_t));
        init_param(connected, CMD, "connected", cbk, 0, INVALID, 0,
            "Redistribute connected routes");
        libcli_register_param(redistribute, connected);
        libcli_set_param_cmd_code(connected, CMDCODE_RTM_REDIST_CONNECTED);
        libcli_disable_batch_processing(connected);
        rtm_distribution_policy_common_subtree_cli (connected, CMDCODE_RTM_REDIST_CONNECTED, cbk);
    }

    if (exempt_proto != RTM_PROTO_CONNECTED)
    {
        param_t *local = (param_t *)calloc(1, sizeof (param_t));
        init_param(local, CMD, "local", cbk, 0, INVALID, 0,
            "Redistribute local routes");
        libcli_register_param(redistribute, local);
        libcli_set_param_cmd_code(local, CMDCODE_RTM_REDIST_LOCAL);
        libcli_disable_batch_processing(local);
        rtm_distribution_policy_common_subtree_cli (local, CMDCODE_RTM_REDIST_LOCAL, cbk);
    }    

    if (exempt_proto != RTM_PROTO_STATIC)
    {
        param_t *static_rt = (param_t *)calloc(1, sizeof (param_t));
        init_param(static_rt, CMD, "static", cbk, 0, INVALID, 0,
            "Redistribute static routes");
        libcli_register_param(redistribute, static_rt);
        libcli_set_param_cmd_code(static_rt, CMDCODE_RTM_REDIST_STATIC);
        libcli_disable_batch_processing(static_rt);
        rtm_distribution_policy_common_subtree_cli (static_rt, CMDCODE_RTM_REDIST_STATIC, cbk);
    }

    if (exempt_proto != RTM_PROTO_BGP)
    {
        param_t *bgp = (param_t *)calloc(1, sizeof (param_t));
        init_param(bgp, CMD, "bgp", cbk, 0, INVALID, 0,
            "Redistribute BGP routes");
        libcli_register_param(redistribute, bgp);
        libcli_set_param_cmd_code(bgp, CMDCODE_RTM_REDIST_BGP);
        libcli_disable_batch_processing(bgp);
        rtm_distribution_policy_common_subtree_cli (bgp, CMDCODE_RTM_REDIST_BGP, cbk);
    }

    if (exempt_proto != RTM_PROTO_OSPF)
    {
        param_t *ospf = (param_t *)calloc(1, sizeof (param_t));
        init_param(ospf, CMD, "ospf", cbk, 0, INVALID, 0,
            "Redistribute OSPF routes");
        libcli_register_param(redistribute, ospf);
        libcli_set_param_cmd_code(ospf, CMDCODE_RTM_REDIST_OSPF);
        libcli_disable_batch_processing(ospf); 
        rtm_distribution_policy_common_subtree_cli (ospf, CMDCODE_RTM_REDIST_OSPF, cbk);
    }

    if (exempt_proto != RTM_PROTO_ISIS)
    {
        param_t *isis = (param_t *)calloc(1, sizeof (param_t));
        init_param(isis, CMD, "isis", cbk, 0, INVALID, 0,
            "Redistribute ISIS routes");
        libcli_register_param(redistribute, isis);
        libcli_set_param_cmd_code(isis, CMDCODE_RTM_REDIST_ISIS);
        libcli_disable_batch_processing(isis); 
        rtm_distribution_policy_common_subtree_cli (isis, CMDCODE_RTM_REDIST_ISIS, cbk);
    }

}

static RTM_PROTO_T
rtm_redist_cmdcode_to_src_proto(int cmdcode)
{
    switch (cmdcode) {
    case CMDCODE_RTM_REDIST_CONNECTED:
        return RTM_PROTO_CONNECTED;
    case CMDCODE_RTM_REDIST_LOCAL:
        return RTM_PROTO_LOCAL;        
    case CMDCODE_RTM_REDIST_STATIC:
        return RTM_PROTO_STATIC;
    case CMDCODE_RTM_REDIST_BGP:
        return RTM_PROTO_BGP;
    case CMDCODE_RTM_REDIST_OSPF:
        return RTM_PROTO_OSPF;
    case CMDCODE_RTM_REDIST_ISIS:
        return RTM_PROTO_ISIS;
    default:
        return RTM_PROTO_MAX;
    }
}

static redist_target_t *
redist_target_find(
    dist_mgr_t *dm,
    RTM_PROTO_T dst_proto,
    uint32_t dst_inst,
    uint8_t dst_vrf)
{
    redist_target_t *t;

    for (t = dm->target_lst; t; t = t->next) {
        if (t->proto == dst_proto && t->instance_no == dst_inst
            && t->vrf == dst_vrf)
            return t;
    }
    return NULL;
}

static int
rt_advertised_node_tree_comp_fn(
    const avltree_node_t *node1,
    const avltree_node_t *node2)
{
    rt_advertised_node_t *rt1 = avltree_container_of (node1, rt_advertised_node_t, glue);
    rt_advertised_node_t *rt2 = avltree_container_of (node2, rt_advertised_node_t, glue);

    if ((uintptr_t)rt1->dist_rt < (uintptr_t)rt2->dist_rt) return 1;
    if ((uintptr_t)rt1->dist_rt > (uintptr_t)rt2->dist_rt) return -1;
    return 0;
}

static redist_target_t *
redist_target_get_or_create(
    dist_mgr_t *dm,
    RTM_PROTO_T dst_proto,
    uint32_t dst_inst,
    uint8_t dst_vrf)
{
    redist_target_t *t = redist_target_find(dm, dst_proto, dst_inst, dst_vrf);

    if (t) return t;

    t = (redist_target_t *)XCALLOC2(0, 1, redist_target_t);
    t->proto = dst_proto;
    t->instance_no = dst_inst;
    t->vrf = dst_vrf;
    init_Fglthread(&t->client_redis_queue);
    t->client_flash_job = NULL;
    avltree_init(&t->rt_advertised, rt_advertised_node_tree_comp_fn);
    t->rule_list = NULL;
    t->next = dm->target_lst;
    dm->target_lst = t;
    return t;
}

static void
dist_rule_list_append(redist_target_t *target, dist_rule_t *rule)
{
    dist_rule_t **pp = &target->rule_list;

    while (*pp)
        pp = &(*pp)->next;
    *pp = rule;
    rule->next = NULL;
}

static bool
dist_rule_list_remove(redist_target_t *target, dist_rule_t *rule)
{
    dist_rule_t **pp = &target->rule_list;

    while (*pp) {
        if (*pp == rule) {
            *pp = rule->next;
            return true;
        }
        pp = &(*pp)->next;
    }
    return false;
}

/* Find the rule on `target` whose every identity attribute matches `key`.
   Compares all dist_rule_t fields that define the rule (source identity,
   filter, action). The list-linkage `next` and the back-pointer
   `owning_target` are intentionally excluded from the match. */
static dist_rule_t *
dist_rule_find(redist_target_t *target, const dist_rule_t *key)
{
    dist_rule_t *r;

    for (r = target->rule_list; r; r = r->next) {

        /* Source identity */
        if (r->src_proto       != key->src_proto)       continue;
        if (r->src_sub_proto   != key->src_sub_proto)   continue;
        if (r->src_vrf_id      != key->src_vrf_id)      continue;
        if (r->src_instance_no != key->src_instance_no) continue;

        /* Filter */
        if (r->pfx_lst         != key->pfx_lst)         continue;

        /* Action */
        if (r->out_cost        != key->out_cost)        continue;
        if (r->out_tag         != key->out_tag)         continue;
        if (r->out_community   != key->out_community)   continue;

        return r;
    }
    return NULL;
}

/* Generic Route policy function handler for all protocols */
redist_target_t *
rtm_protocol_rt_distribution_policy_config_cli_handler(

    RTM_PROTO_T target_proto,
    int cmdcode,
    Stack_t *tlv_stack,
    op_mode enable_or_disable,
    dist_mgr_t **dist_mgr_out)
{
    tlv_struct_t *tlv;
    dist_rule_t *rule;
    c_string node_name = NULL;
    c_string vrf_name = NULL;
    c_string pfx_lst_name = NULL;
    const char *metric_str = NULL;

    TLV_LOOP_STACK_BEGIN(tlv_stack, tlv)
    {
        if (parser_match_leaf_id(tlv->leaf_id, "node-name"))
            node_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "vrf-name"))
            vrf_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "pfx-lst-name"))
            pfx_lst_name = tlv->value;
        else if (parser_match_leaf_id(tlv->leaf_id, "metric-val"))
            metric_str = (const char *)tlv->value;
    }
    TLV_LOOP_END;

    RTM_PROTO_T src_proto = rtm_redist_cmdcode_to_src_proto(cmdcode);

    if (src_proto >= RTM_PROTO_MAX) {
        cprintf("Error: unknown redistribute source for command\n");
        return NULL;
    }

    node_t *node = node_get_node_by_name(topo, node_name);
    vrf_t *vrf = vrf_get_by_name(node, (char *)vrf_name);

    *dist_mgr_out = node->dist_mgr;

    if (!vrf) {
        cprintf("Error: VRF not found\n");
        return NULL;
    }

    uint32_t metric_u = 0;

    if (metric_str && metric_str[0])
        metric_u = (uint32_t)strtoul(metric_str, NULL, 10);

    prefix_list_t *pfx_lst = NULL;

    if (pfx_lst_name) {
        pfx_lst = prefix_lst_lookup_by_name(
            &node->prefix_lst_db, (unsigned char *)pfx_lst_name);
        if (!pfx_lst) {
            cprintf("Error: prefix-list does not exist\n");
            return NULL;
        }
    }

    /* Build a single rule template that fully describes this CLI invocation.
       It is used for the existence/duplicate lookups below and, in the
       CONFIG_ENABLE path, as the prototype for the new rule allocation.
       Adding a new attribute to dist_rule_t will only require initializing
       it here. */
    dist_rule_t key;
    memset(&key, 0, sizeof(key));
    key.src_proto       = src_proto;
    key.src_sub_proto   = RTM_SUB_PROTO_NA;
    key.src_instance_no = 0;
    key.src_vrf_id      = vrf->vrf_id;
    key.pfx_lst         = pfx_lst;
    key.out_cost        = metric_u;
    key.out_tag         = 0;
    key.out_community   = 0;

    redist_target_t *target =
        redist_target_find(node->dist_mgr, target_proto, 0, vrf->vrf_id);

    if (enable_or_disable == CONFIG_DISABLE) {

        if (!target) {
            cprintf("Error: target protocol not found\n");
            return NULL;
        }

        rule = dist_rule_find(target, &key);

        if (!rule) {
            cprintf("Error: rule not found\n");
            return NULL;
        }

        dist_rule_list_remove(target, rule);

        if (rule->pfx_lst) prefix_list_dereference(rule->pfx_lst);

        XFREE(rule);
        return target;
    }

    /* CONFIG_ENABLE */

    if (target && dist_rule_find(target, &key)) {
        //cprintf("Error: same rule already exists\n");
        return NULL;
    }

    if (!target) {

        target = redist_target_get_or_create(
            node->dist_mgr, target_proto, 0, vrf->vrf_id);
    }

    /* Materialize the rule from the template. memcpy preserves every
       identity field that was matched above, so the lookup and the
       allocation can never drift apart. */
    rule = (dist_rule_t *)XCALLOC2(0, 1, dist_rule_t);
    memcpy(rule, &key, sizeof(*rule));
    rule->next = NULL;
    rule->owning_target = target;
    if (rule->pfx_lst) prefix_list_reference(rule->pfx_lst);
    dist_rule_list_append(target, rule);
    return rule->owning_target;
}

void 
rtm_unregister_rt_distribution_cbk (
    dist_mgr_t *dist_mgr,
    RTM_PROTO_T proto, 
    uint8_t vrf_id, uint32_t instance_no) {

    redist_target_t *target = 
        redist_target_find(dist_mgr, proto, instance_no, vrf_id);
    
    if (!target) return;
    dist_mgr_target_delink (dist_mgr, target);
    rtm_dis_mgr_gc (dist_mgr, target, DIST_MGR_GC_TYPE_TARGET);
}



