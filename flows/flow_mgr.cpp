/*
 * flow_mgr.cpp — Global and per-interface flow databases (rte_hash + AVL indexes).
 *
 * Mutations run on dp_ev_dis (single writer).  Deleted flow objects are queued on
 * gc_thread and freed by a periodic job (1 minute).
 */

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "../../libs/EventDispatcher/event_dispatcher.h"
#include "../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../../libs/Tree/libtree.h"
#include "../../libs/gluethread/glthread.h"
#include "../../libs/libtimer/WheelTimer.h"
#include "../Interface/dp_intf.h"
#include "../Interface/intf_cons.h"
#include "../dp_const.h"
#include "../dp_ctx.h"
#include "flow_mgr.h"

extern int cprintf(const char *format, ...);

#define DP_FLOW_HASH_ENTRIES        8192
#define DP_FLOW_GC_INTERVAL_MS      (60 * 1000)

#define ASSERT_ON_DP_EV_DIS(dp_ctx)                                         \
    assert((dp_ctx)->dp_ev_dis.thread &&                                    \
           pthread_equal(pthread_self(), *(dp_ctx)->dp_ev_dis.thread))

typedef struct dp_flow_entry_ {

    dp_flow_t flow;

    avltree_node_t ifindex_glue;
    avltree_node_t nexthop_mac_glue;
    avltree_node_t nh_glue;

} dp_flow_entry_t;

static uint32_t dp_flow_hash_seq;

static int
flow_key_cmp(const flow_key_t *k1, const flow_key_t *k2)
{
    int rc = memcmp(k1, k2, sizeof(flow_key_t));

    if (rc < 0)
        return -1;
    if (rc > 0)
        return 1;
    return 0;
}

static int
flow_nexthop_mac_cmp(const uint8_t *m1, const uint8_t *m2)
{
    int rc = memcmp(m1, m2, 6);

    if (rc < 0)
        return -1;
    if (rc > 0)
        return 1;
    return 0;
}

static int
flow_ifindex_avl_cmp(const avltree_node_t *node1, const avltree_node_t *node2)
{
    dp_flow_entry_t *e1 = avltree_container_of(node1, dp_flow_entry_t, ifindex_glue);
    dp_flow_entry_t *e2 = avltree_container_of(node2, dp_flow_entry_t, ifindex_glue);

    if (e1->flow.flow_key.ifindex < e2->flow.flow_key.ifindex)
        return -1;
    if (e1->flow.flow_key.ifindex > e2->flow.flow_key.ifindex)
        return 1;

    return flow_key_cmp(&e1->flow.flow_key, &e2->flow.flow_key);
}

static int
flow_nexthop_mac_avl_cmp(const avltree_node_t *node1, const avltree_node_t *node2)
{
    dp_flow_entry_t *e1 = avltree_container_of(node1, dp_flow_entry_t, nexthop_mac_glue);
    dp_flow_entry_t *e2 = avltree_container_of(node2, dp_flow_entry_t, nexthop_mac_glue);
    int rc;

    rc = flow_nexthop_mac_cmp(e1->flow.fdata.nexthop_mac, e2->flow.fdata.nexthop_mac);
    if (rc)
        return rc;

    return flow_key_cmp(&e1->flow.flow_key, &e2->flow.flow_key);
}

static int
flow_nh_avl_cmp(const avltree_node_t *node1, const avltree_node_t *node2)
{
    dp_flow_entry_t *e1 = avltree_container_of(node1, dp_flow_entry_t, nh_glue);
    dp_flow_entry_t *e2 = avltree_container_of(node2, dp_flow_entry_t, nh_glue);

    if (e1->flow.fdata.nh.cnhidx < e2->flow.fdata.nh.cnhidx)
        return -1;
    if (e1->flow.fdata.nh.cnhidx > e2->flow.fdata.nh.cnhidx)
        return 1;

    return flow_key_cmp(&e1->flow.flow_key, &e2->flow.flow_key);
}

static void
dp_flow_hash_create(struct rte_hash **hash_out,
                    const char *ctx_name,
                    const char *suffix)
{
    char hash_name[RTE_HASH_NAMESIZE];
    uint32_t seq = __atomic_fetch_add(&dp_flow_hash_seq, 1, __ATOMIC_RELAXED);
    struct rte_hash_parameters params = {};

    snprintf(hash_name, sizeof(hash_name), "flow_%.10s_%.10s_%u",
             ctx_name ? ctx_name : "dp", suffix ? suffix : "g", seq);

    params.name               = hash_name;
    params.entries            = DP_FLOW_HASH_ENTRIES;
    params.key_len            = sizeof(flow_key_t);
    params.hash_func          = rte_jhash;
    params.hash_func_init_val = 0;
    params.socket_id          = 0;
    params.extra_flag         = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;

    *hash_out = rte_hash_create(&params);
    if (!*hash_out) {
        cprintf("Error: flow rte_hash_create(%s) failed: %s\n",
                hash_name, rte_strerror(rte_errno));
    }
}

static bool
lflow_db_ensure(dp_intf_t *intf, const char *ctx_name)
{
    char suffix[32];

    if (!intf)
        return false;

    if (intf->lflow_db && intf->lflow_db->hash)
        return true;

    if (!intf->lflow_db)
        intf->lflow_db = (lflow_db_t *)XCALLOC2(0, 1, lflow_db_t);

    snprintf(suffix, sizeof(suffix), "if%u", intf->port_id);
    dp_flow_hash_create(&intf->lflow_db->hash, ctx_name, suffix);

    return intf->lflow_db->hash != NULL;
}

static dp_flow_entry_t *
dp_flow_entry_lookup_gflow(flow_mgr_t *flow_mgr, const flow_key_t *flow_key)
{
    void *data = NULL;

    if (!flow_mgr || !flow_mgr->gflow_db || !flow_mgr->gflow_db->hash)
        return NULL;

    if (rte_hash_lookup_data(flow_mgr->gflow_db->hash, flow_key, &data) < 0)
        return NULL;

    return (dp_flow_entry_t *)data;
}

static void
dp_flow_entry_remove_indexes(flow_mgr_t *flow_mgr, dp_flow_entry_t *entry)
{
    avltree_remove(&entry->ifindex_glue, &flow_mgr->gflow_db_keyed_by_ifindex);
    avltree_remove(&entry->nexthop_mac_glue, &flow_mgr->gflow_db_keyed_by_nexthop_mac);
    avltree_remove(&entry->nh_glue, &flow_mgr->gflow_db_keyed_by_nh);
}

static void
dp_flow_entry_insert_indexes(flow_mgr_t *flow_mgr, dp_flow_entry_t *entry)
{
    avltree_insert(&entry->ifindex_glue, &flow_mgr->gflow_db_keyed_by_ifindex);
    avltree_insert(&entry->nexthop_mac_glue, &flow_mgr->gflow_db_keyed_by_nexthop_mac);
    avltree_insert(&entry->nh_glue, &flow_mgr->gflow_db_keyed_by_nh);
}

static void
dp_flow_entry_queue_gc(flow_mgr_t *flow_mgr, dp_flow_entry_t *entry)
{
    glthread_data_node_t *node;

    node = (glthread_data_node_t *)XCALLOC2(0, 1, glthread_data_node_t);
    init_glthread(&node->glue);
    node->data = entry;
    glthread_add_last(&flow_mgr->gc_thread.glue, &node->glue);
}

static void
dp_flow_mgr_gc_drain(dp_ctx_t *dp_ctx)
{
    flow_mgr_t *flow_mgr = dp_ctx->flow_mgr;
    glthread_t *curr;

    if (!flow_mgr)
        return;

    while ((curr = dequeue_glthread_first(&flow_mgr->gc_thread.glue))) {
        glthread_data_node_t *node = glue_to_glthread_data_node(curr);
        dp_flow_entry_t *entry = (dp_flow_entry_t *)node->data;

        XFREE(node);
        XFREE(entry);
    }
}

static void
dp_flow_mgr_gc_cbk(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size)
{
    (void)arg_size;

    if (!ev_dis)
        return;

    dp_ctx_t *dp_ctx = (dp_ctx_t *)arg;
    if (!dp_ctx)
        dp_ctx = (dp_ctx_t *)ev_dis->app_data;

    dp_flow_mgr_gc_drain(dp_ctx);
}

void
dp_flow_mgr_init(dp_ctx_t *dp_ctx)
{
    flow_mgr_t *flow_mgr;

    assert(dp_ctx);
    assert(!dp_ctx->flow_mgr);

    flow_mgr = (flow_mgr_t *)XCALLOC2(0, 1, flow_mgr_t);

    flow_mgr->gflow_db = (gflow_db_t *)XCALLOC2(0, 1, gflow_db_t);
    dp_flow_hash_create(&flow_mgr->gflow_db->hash, dp_ctx->ctx_name, "g");

    avltree_init(&flow_mgr->gflow_db_keyed_by_ifindex, flow_ifindex_avl_cmp);
    avltree_init(&flow_mgr->gflow_db_keyed_by_nexthop_mac, flow_nexthop_mac_avl_cmp);
    avltree_init(&flow_mgr->gflow_db_keyed_by_nh, flow_nh_avl_cmp);

    init_glthread(&flow_mgr->gc_thread.glue);

    dp_ctx->flow_mgr = flow_mgr;

    if (dp_ctx->dp_wt) {
        flow_mgr->gc_wheel_job = timer_register_app_event(
            DP_TIMER(dp_ctx),
            dp_flow_mgr_gc_cbk,
            (void *)dp_ctx,
            sizeof(*dp_ctx),
            DP_FLOW_GC_INTERVAL_MS,
            1);
    }
}

bool
dp_flow_mgr_create_flow(dp_ctx_t *dp_ctx,
                        flow_key_t flow_key,
                        flow_data_t *fdata)
{
    flow_mgr_t *flow_mgr;
    dp_intf_t *intf;
    dp_flow_entry_t *entry;
    int rc;

    if (!dp_ctx || !fdata)
        return false;

    flow_mgr = dp_ctx->flow_mgr;
    if (!flow_mgr || !flow_mgr->gflow_db || !flow_mgr->gflow_db->hash)
        return false;

    ASSERT_ON_DP_EV_DIS(dp_ctx);

    if (flow_key.ifindex >= DP_MAX_INTF)
        return false;

    intf = dp_ctx->intf_table[flow_key.ifindex];
    if (!intf)
        return false;

    if (!lflow_db_ensure(intf, dp_ctx->ctx_name))
        return false;

    if (dp_flow_entry_lookup_gflow(flow_mgr, &flow_key))
        return false;

    entry = (dp_flow_entry_t *)XCALLOC2(0, 1, dp_flow_entry_t);
    if (!entry)
        return false;

    entry->flow.flow_key = flow_key;
    memcpy(&entry->flow.fdata, fdata, sizeof(flow_data_t));

    avltree_node_init(&entry->ifindex_glue);
    avltree_node_init(&entry->nexthop_mac_glue);
    avltree_node_init(&entry->nh_glue);

    rc = rte_hash_add_key_data(flow_mgr->gflow_db->hash,
                               &entry->flow.flow_key, entry);
    if (rc < 0) {
        XFREE(entry);
        return false;
    }

    rc = rte_hash_add_key_data(intf->lflow_db->hash,
                               &entry->flow.flow_key, entry);
    if (rc < 0) {
        rte_hash_del_key(flow_mgr->gflow_db->hash, &entry->flow.flow_key);
        XFREE(entry);
        return false;
    }

    dp_flow_entry_insert_indexes(flow_mgr, entry);
    return true;
}

bool
dp_flow_mgr_delete_flow(dp_ctx_t *dp_ctx,
                        uint32_t ifindex,
                        flow_key_t flow_key)
{
    flow_mgr_t *flow_mgr;
    dp_intf_t *intf;
    dp_flow_entry_t *entry;

    if (!dp_ctx)
        return false;

    flow_mgr = dp_ctx->flow_mgr;
    if (!flow_mgr || !flow_mgr->gflow_db || !flow_mgr->gflow_db->hash)
        return false;

    ASSERT_ON_DP_EV_DIS(dp_ctx);

    if (ifindex >= DP_MAX_INTF)
        return false;

    flow_key.ifindex = ifindex;

    entry = dp_flow_entry_lookup_gflow(flow_mgr, &flow_key);
    if (!entry)
        return false;

    intf = dp_ctx->intf_table[ifindex];
    if (intf && intf->lflow_db && intf->lflow_db->hash)
        rte_hash_del_key(intf->lflow_db->hash, &flow_key);

    rte_hash_del_key(flow_mgr->gflow_db->hash, &flow_key);
    dp_flow_entry_remove_indexes(flow_mgr, entry);
    dp_flow_entry_queue_gc(flow_mgr, entry);
    return true;
}
