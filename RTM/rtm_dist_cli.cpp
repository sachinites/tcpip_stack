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

static void static_rt_dist_handler(node_t *node, rt_advert_info_t *rt_advert)
{
    (void)node;
    (void)rt_advert;
}
static void connected_rt_dist_handler(node_t *node, rt_advert_info_t *rt_advert)
{
    (void)node;
    (void)rt_advert;
}
static void local_rt_dist_handler(node_t *node, rt_advert_info_t *rt_advert)
{
    (void)node;
    (void)rt_advert;
}
static void bgp_rt_dist_handler(node_t *node, rt_advert_info_t *rt_advert)
{
    (void)node;
    (void)rt_advert;
}
static void ldp_rt_dist_handler(node_t *node, rt_advert_info_t *rt_advert)
{
    (void)node;
    (void)rt_advert;
}
static void ospf_rt_dist_handler(node_t *node, rt_advert_info_t *rt_advert)
{
    (void)node;
    (void)rt_advert;
}
static void isis_rt_dist_handler(node_t *node, rt_advert_info_t *rt_advert)
{
    (void)node;
    (void)rt_advert;
}

void (*RT_DIST_HANDLERS[])(node_t *, rt_advert_info_t *) = {
    static_rt_dist_handler,
    connected_rt_dist_handler,
    local_rt_dist_handler,
    bgp_rt_dist_handler,
    isis_rt_dist_handler,
    ospf_rt_dist_handler,
    ldp_rt_dist_handler,
    NULL,
};

/* Per-file command codes for redistribution policy CLI */
#define CMDCODE_RTM_REDIST_CONNECTED  1
#define CMDCODE_RTM_REDIST_STATIC     2
#define CMDCODE_RTM_REDIST_BGP        3
#define CMDCODE_RTM_REDIST_OSPF       4
#define CMDCODE_RTM_REDIST_ISIS       5

void
rtm_protocol_rt_distribution_policy_config_cli_handler(
    RTM_PROTO_T proto,
    int cmdcode,
    Stack_t *tlv_stack,
    op_mode enable_or_disable);


extern int
rtm_isis_rt_distribution_policy_config_cli_handler(
    int cmdcode,
    Stack_t *tlv_stack,
    op_mode enable_or_disable) {

    rtm_protocol_rt_distribution_policy_config_cli_handler(
            RTM_PROTO_ISIS, cmdcode, tlv_stack, enable_or_disable);

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
        if (t->dst_proto == dst_proto && t->dst_instance_no == dst_inst
            && t->dst_vrf == dst_vrf)
            return t;
    }
    return NULL;
}

static uint32_t g_redist_next_target_handle = 1;

static redist_target_t *
redist_target_get_or_create(
    dist_mgr_t *dm,
    RTM_PROTO_T dst_proto,
    uint32_t dst_inst,
    uint8_t dst_vrf)
{
    redist_target_t *t = redist_target_find(dm, dst_proto, dst_inst, dst_vrf);

    if (t)
        return t;

    t = (redist_target_t *)XCALLOC2(0, 1, redist_target_t);
    t->dst_proto = dst_proto;
    t->dst_instance_no = dst_inst;
    t->dst_vrf = dst_vrf;
    t->target_handle = g_redist_next_target_handle++;
    if ((unsigned)dst_proto < (unsigned)RTM_PROTO_MAX)
        t->redis_cbk = RT_DIST_HANDLERS[dst_proto];
    init_Fglthread(&t->client_redis_queue);
    t->client_flash_job = NULL;
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

static dist_rule_t *
dist_rule_find(
    redist_target_t *target,
    RTM_PROTO_T src_proto,
    prefix_list_t *pfx_lst,
    uint32_t out_cost)
{
    dist_rule_t *r;

    for (r = target->rule_list; r; r = r->next) {
        if (r->src_proto == src_proto && r->src_sub_proto == RTM_SUB_PROTO_NA
            && r->src_instance_no == 0 && r->pfx_lst == pfx_lst
            && r->out_cost == out_cost)
            return r;
    }
    return NULL;
}

/* Generic Route policy function handler for all protocols */
void
rtm_protocol_rt_distribution_policy_config_cli_handler(
    RTM_PROTO_T proto,
    int cmdcode,
    Stack_t *tlv_stack,
    op_mode enable_or_disable)
{
    tlv_struct_t *tlv;
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
        else if (parser_match_leaf_id(tlv->leaf_id, "metric-val") ||
                 parser_match_leaf_id(tlv->leaf_id, "n"))
            metric_str = (const char *)tlv->value;
    }
    TLV_LOOP_END;

    if (!node_name)
        return;

    RTM_PROTO_T src_proto = rtm_redist_cmdcode_to_src_proto(cmdcode);

    if (src_proto >= RTM_PROTO_MAX) {
        cprintf("Error: unknown redistribute source for command\n");
        return;
    }

    node_t *node = node_get_node_by_name(topo, node_name);

    if (!node) {
        cprintf("Error: node not found\n");
        return;
    }

    if (!node->dist_mgr) {
        cprintf("Error: route distribution manager is not initialized\n");
        return;
    }

    vrf_t *vrf = vrf_get_by_name(node, (char *)vrf_name);

    if (!vrf) {
        cprintf("Error: VRF not found\n");
        return;
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
            return;
        }
    }

    if (enable_or_disable == CONFIG_DISABLE) {
        redist_target_t *target =
            redist_target_find(node->dist_mgr, proto, 0, vrf->vrf_id);

        if (!target) {
            cprintf("Error: target not found\n");
            return;
        }

        dist_rule_t *rule =
            dist_rule_find(target, src_proto, pfx_lst, metric_u);

        if (!rule)
            return;

        dist_rule_list_remove(target, rule);
        if (rule->pfx_lst)
            prefix_list_dereference(rule->pfx_lst);
        XFREE(rule);
        return;
    }

    /* CONFIG_ENABLE */
    redist_target_t *target = redist_target_get_or_create(
        node->dist_mgr, proto, 0, vrf->vrf_id);

    if (dist_rule_find(target, src_proto, pfx_lst, metric_u))
        return;

    dist_rule_t *rule = (dist_rule_t *)XCALLOC2(0, 1, dist_rule_t);

    rule->src_proto = src_proto;
    rule->src_sub_proto = RTM_SUB_PROTO_NA;
    rule->src_instance_no = 0;
    rule->out_cost = metric_u;
    rule->out_tag = 0;
    rule->out_community = 0;
    rule->pfx_lst = pfx_lst;

    if (pfx_lst)
        prefix_list_reference(pfx_lst);

    dist_rule_list_append(target, rule);
}




