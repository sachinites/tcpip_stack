#include <assert.h>

#include "../libs/Tracer/tracer.h"
#include "../libs/LinuxMemoryManager/uapi_mm.h"

#include "../router_init.h"
#include "../libs/prefix-list/prefixlst.h"
#include "../net.h"
#include "rtm_dist_mgr.h"
#include "rtm_presentation.h"
#include "rtm_priv_api.h"
#include "rtm_nh.h"
#include "rtm_proto.h"

/*

================================================================================
 RTM Distribution Manager (dist_mgr) — reading guide for new programmers
================================================================================

WHAT THIS MODULE DOES
---------------------
The Route Table Manager (RTM) tells the distribution manager whenever a route
that is eligible for redistribution changes (add / delete).  This file
implements that manager: it remembers every *redistributed* route instance,
matches it against per-protocol *redistribution rules*, and enqueues work so
each *target* protocol (IS-IS, OSPF, …) receives RTM_CLIENT_RT_ADD or
RTM_CLIENT_RT_DEL callbacks with a filled-in rt_advert_info_t.

It is **not** the main RIB/FIB; it is the cross-protocol “who should see this
external route” layer sitting on top of RTM presentation events.

HOW TO READ THIS FILE (order)
-----------------------------
1. rtm_dist_mgr_init              — allocates dist_mgr_t, empty trees/queues.
2. rtm_distribution_manager_update — entry for RTM add/delete; builds indexes.
3. dist_mgr_schedule_route_advertise + dist_mgr_redistrbution_job_cbk — batches
   work onto the node’s main event thread (see Threading below).
4. rtm_dist_mgr_distribute_route_to_target_clients — policy loop: permit/deny,
   advertise or withdraw per target.
5. rtm_dist_mgr_refresh_dist_routes_to_target — re-evaluate all routes when
   rules on one target change.
6. rtm_dist_mgr_client_request_route_replay — target asks to re-sync state.
7. rtm_dis_mgr_gc + dist_mgr_gc_job_cbk — deferred teardown of targets (after
   client queues are drained).

THREADING / ASYNC MODEL
-----------------------
Most work is **not** done inline in rtm_distribution_manager_update.  Routes
pending distribution are linked on dist_mgr->redis_queue; a single one-shot
task (redis_task) drains the whole queue on the node’s EV dispatcher.  Likewise,
target-specific rt_advert_info_t objects queue on redist_target_t::client_redis_queue
and are delivered by client_flash_job.  GC uses the same pattern on gc_queue
with TASK_PRIORITY_GARBAGE_COLLECTOR.

Assume: callbacks run on the **same** logical control-plane thread as other RTM
jobs for that node unless you know a caller violates that; design still uses
queues to avoid deep recursion and to batch work.

DATA STRUCTURES (mental model)
------------------------------
- nhidx_tree: one rt_redist_route_t per (indirect NH idx, direct NH idx) pair,
  encoded in Cnhidx via fib_set_nh_idx().  Lookup/delete by presentation event
  uses this tree first.
- route_tree_by_prefix: avl_prefix_node_t per prefix; each holds an Fglthread
  list of all redist routes for that prefix (different NH / source).
- route_tree[afi][proto]: avl_vrf_node_t per (vrf_id, instance_no); each holds
  an Fglthread list of routes sourced under that vrf/instance for that AFI/proto.
  (Useful for iteration / policy refresh, not for nhidx lookup.)

- redist_target_t: a registered consumer (proto + vrf + instance) with an
  ordered rule list and rt_advertised AVL of routes currently advertised to it.

REFERENCE COUNTING (rt_redist_route_t::ref_count)
------------------------------------------------
A route’s refcount drops to zero only when nothing holds it: prefix list,
vrf/proto list, redis queue glue, target advertisement nodes, etc.  On add,
rt_redist_route_reference is called when linking into each structure and again
when enqueueing for distribution; matching rt_redist_route_dereference calls
remove those references.  When refcount hits zero, nh_proto is released,
bitmaps freed, and the rt_redist_route_t is destroyed.

ADVERTISEMENT TRACKING
----------------------
client_advert_tracker (bitmaps over proto / vrf / instance) records which
targets have been told about this route so we can withdraw precisely and avoid
duplicate adds.  rtm_redist_target_record_rt_advertisement updates both the
target’s rt_advertised tree and those bitmaps.

POLICY
------
Rules on each target are evaluated in list order.  First matching rule that
passes source + prefix-list wins for add; if no rule permits and the route was
previously advertised, we send withdraw.  IPv4-only limitation: prefix-list
filters deny non-IPv4 when a filter is configured (see rtm_dist_mgr_rule_filter_permits).

================================================================================
 (Original design overview — retained for additional detail)
================================================================================

The RTM (Route Table Manager) Distribution Manager is responsible for tracking,
managing, and advertising redistributed routing information within the system.
Its primary role is to manage lifecycle events of redistributed (redist) routes
and ensure those routes are properly propagated to relevant protocol clients
according to the system’s redistribution policies.

Key Concepts and Data Structures:
---------------------------------

1. **dist_mgr_t**:
   The distribution manager root object, maintaining trees of redistributed
   routes and mappings from next-hop indices and route prefixes. Also tracks
   registered redistribution targets (protocol clients interested in route
   updates) and GC (garbage collection) tasks.

2. **rt_redist_route_t**:
   Represents a redistributed route instance, encapsulating route prefix,
   next-hop, client advertisement tracking bitmaps, reference counts, and glue
   nodes for AVL trees.

3. **redist_target_t**:
   Represents a redistribution target client/protocol – e.g., OSPF, IS-IS –
   that is interested in receiving route advertisements. Each target has its
   own advertisement list for bookkeeping.

4. **AVL Trees**:
   Central to fast route/path lookups and management.
   - **nhidx_tree**: Indexed by combined next-hop index, enables efficient
     management by next-hop.
   - **route_tree_by_prefix**: Indexed by route prefixes for per-prefix
     operations.

5. **Advertisement Bitmaps**:
   Each redist route maintains client-specific bitmaps (per-protocol, per-vrf,
   per-instance) to efficiently track which clients have been advertised each
   route.

6. **Reference Counting**:
   `rt_redist_route_t` employs refcounting to ensure safe reuse and teardown
   during add/delete and GC operations.

Core Flow:
----------

1. **Route Reception & Installation**:
   RTM receives a route presentation event (e.g., from a protocol or RIB).
   Insertion into AVL trees (`nhidx_tree`, `route_tree_by_prefix`) occurs, new
   route records are initialized, and protocol waitlists/queues are set up as
   needed.

2. **Distribute to Target Clients**:
   Once a route is installed/updated, the manager determines which
   redistribution targets are eligible/interested and advertises the route
   accordingly, updating their advertisement bitmaps and reference counts.

3. **Client Advertisement/Withdrawal**:
   When a target client is deleted or the route is withdrawn, the relevant bit
   is cleared in the advertisement tracker, and reference counts are updated.
   The system ensures all bookkeeping is cleaned up, and if no references
   remain, triggers route teardown.

4. **Garbage Collection**:
   Uses an asynchronous GC queue and callback (dist_mgr_gc_job_cbk) to reliably
   tear down route/target resources after draining protocol queues, ensuring
   late resources are reclaimed without dangling pointers or premature frees.

5. **Reference-safe Teardown**:
   At each removal (route or target), AVL tree nodes are safely removed, and all
   data structures are reference-checked and zeroed out before memory is freed.

Design Considerations:
---------------------

- **Efficiency:** AVL trees and bitmaps for O(log n) route/target management.
- **Concurrency Safety:** Asynchronous GC helps avoid freeing while clients
  still hold queued callbacks.
- **Extensibility:** Per-target and per-client bitmaps simplify new protocols
  or VRF instances.
- **Tracing:** `tracer` calls visualize redistribution flow (DREDIS / DREDIS_DET).

Summary:
--------

The RTM DIST MGR distributes and withdraws routes between routing protocols and
client stacks using explicit state, indexes, and asynchronous queues for safe
teardown.

*/


#define DIST_MGR_PREEMPT_THRESHOLD 1000 

typedef struct prefix_lst_ prefix_list_t;
typedef struct node_ node_t;

/* Mention Application CBKs here*/
extern void isis_rtm_route_notif (vrf_t *vrf, rt_advert_info_t  *rt_advert);

/* Pack indirect + direct next-hop indices into one 64-bit key (Cnhidx) used as
 * the AVL sort key for nhidx_tree.  Presentation events always supply both. */
extern inline void 
fib_set_nh_idx(
    uint64_t *p, 
    uint32_t inhidx, 
    uint32_t nhidx);

extern void 
dist_mgr_prefix_lst_change_cbk(node_t *node,
                               vrf_t *vrf,
                               uint32_t instance_no,
                               prefix_list_t *prefix_lst);

static void 
dist_mgr_schedule_route_advertise(dist_mgr_t *dist_mgr, rt_redist_route_t *dist_route);

static void 
rtm_dist_mgr_distribute_route_to_target_clients 
    (dist_mgr_t *dist_mgr, rt_redist_route_t *dist_rt);

/* ------------------------------------------------------------------------- */
/* AVL comparators — return >0 if node1 goes "before" node2 in tree order     */
/* (library convention used here: 1 / -1 / 0).                                */
/* ------------------------------------------------------------------------- */

static int
nhidx_tree_comp_fn(
    const avltree_node_t *node1,
    const avltree_node_t *node2)
{
    rt_redist_route_t *rt1 = avltree_container_of(
            node1, rt_redist_route_t, nhidx_glue);

    rt_redist_route_t *rt2 = avltree_container_of(
            node2, rt_redist_route_t, nhidx_glue);    

    if (rt1->Cnhidx < rt2->Cnhidx) return 1;
    if (rt1->Cnhidx > rt2->Cnhidx) return -1;
    return 0;
}

static int
prefix_tree_comp_fn(
    const avltree_node_t *node1,
    const avltree_node_t *node2)
{
    avl_prefix_node_t *pfx1 = avltree_container_of(
            node1, avl_prefix_node_t, glue);

    avl_prefix_node_t *pfx2 = avltree_container_of(
            node2, avl_prefix_node_t, glue);  

    return (cmn_prefix_compare (&pfx1->prefix, &pfx2->prefix));
}

static int
vrf_instance_tree_comp_fn(
    const avltree_node_t *node1,
    const avltree_node_t *node2)
{

    avl_vrf_node_t *vrf1 = avltree_container_of(
        node1, avl_vrf_node_t, glue);

    avl_vrf_node_t *vrf2 = avltree_container_of(
        node2, avl_vrf_node_t, glue);

    if (vrf1->vrf_no < vrf2->vrf_no)
        return 1;
    if (vrf1->vrf_no > vrf2->vrf_no)
        return -1;

    if (vrf1->instance_no < vrf2->instance_no)
        return 1;
    if (vrf1->instance_no > vrf2->instance_no)
        return -1;

    return 0;
}

/* ------------------------------------------------------------------------- */
/* Initialization — one dist_mgr per node; route_tree is [AFI][source proto] */
/* ------------------------------------------------------------------------- */

void 
rtm_dist_mgr_init (node_t *node) {

    uint32_t i;

    dist_mgr_t *dist_mgr = (dist_mgr_t *)XCALLOC2(0, 1, dist_mgr_t);
    dist_mgr->node = node;
    dist_mgr->gc_task = NULL;
    dist_mgr->redis_task = NULL;

    dist_mgr->target_lst = NULL;

    avltree_init(&dist_mgr->nhidx_tree, nhidx_tree_comp_fn);
    avltree_init(&dist_mgr->route_tree_by_prefix, prefix_tree_comp_fn);

    for (i = 0; i < (uint32_t)RTM_PROTO_MAX; i++) {

        avltree_init(&dist_mgr->route_tree[AF_IPV4][i],  vrf_instance_tree_comp_fn);
        avltree_init(&dist_mgr->route_tree[AF_IPV6][i],  vrf_instance_tree_comp_fn);
        avltree_init(&dist_mgr->route_tree[AF_LABEL][i], vrf_instance_tree_comp_fn);
        avltree_init(&dist_mgr->route_tree[AF_MAC][i],   vrf_instance_tree_comp_fn);
    }

    init_Fglthread(&dist_mgr->redis_queue);
    init_Fglthread(&dist_mgr->gc_queue);
    init_Fglthread(&dist_mgr->pfxlst_book_keep);
    
    for (i = 0; i < RTM_PROTO_MAX; i++) dist_mgr->target_cbks[i] = NULL;
    dist_mgr->target_cbks[RTM_PROTO_ISIS] = isis_rtm_route_notif;


    node->dist_mgr = dist_mgr;

    prefix_list_register_client (node, dist_mgr_prefix_lst_change_cbk, 
        0,   // prefix list is VRF independent Concept
        0);  // No instance 
}

/* ------------------------------------------------------------------------- */
/* rt_redist_route_t reference counting                                       */
/* ------------------------------------------------------------------------- */

static void 
rt_redist_route_reference (rt_redist_route_t *redis_rt) {

    redis_rt->ref_count++;
}

static void 
rtm_dist_mgr_check_and_delete (rt_redist_route_t *redis_rt) {

    /* Last step of teardown; extend here if invariants must hold before free. */
    XFREE(redis_rt);
}

static uint32_t
rt_redist_route_dereference (dist_mgr_t *dist_mgr, rt_redist_route_t *redis_rt) {

    redis_rt->ref_count--;
    
    if (redis_rt->ref_count) return redis_rt->ref_count;

    rtm_t *rtm = rtm_get_route_target_rtm(
                vrf_get_by_id (dist_mgr->node, redis_rt->nh_proto->vrf_id),
                redis_rt->prefix.afi,
                redis_rt->nh_proto->proto,
                redis_rt->nh_proto->sub_proto);

    rtm_nh_proto_dereference(rtm, redis_rt->nh_proto);
    redis_rt->nh_proto = NULL;

    bitmap_free_internal (&redis_rt->client_advert_tracker.proto_bitmap);
    bitmap_free_internal (&redis_rt->client_advert_tracker.vrf_id);
    bitmap_free_internal (&redis_rt->client_advert_tracker.instance_no);
    
    rtm_dist_mgr_check_and_delete (redis_rt);    

    return 0;
}   

/* Record or clear that `dist_rt` is advertised to `target`: maintains
 * target->rt_advertised AVL and the per-route bitmaps.  add=true bumps
 * dist_rt refcount; add=false may drop it to zero and destroy the route. */

void 
rtm_redist_target_record_rt_advertisement 
    (dist_mgr_t *dist_mgr, 
    redist_target_t *target, 
    rt_redist_route_t *dist_rt, bool add) {

    rt_advertised_node_t *node;

    if (add) {    
        node = (rt_advertised_node_t *)XCALLOC2(0, 1, rt_advertised_node_t);
        avltree_node_init (&node->glue);
        node->dist_rt = dist_rt;
        rt_redist_route_reference(dist_rt);
        assert(!avltree_insert(&node->glue, &target->rt_advertised));
        bitmap_set_bit_at (&dist_rt->client_advert_tracker.proto_bitmap, target->proto);
        bitmap_set_bit_at (&dist_rt->client_advert_tracker.vrf_id, target->vrf->vrf_id);
        bitmap_set_bit_at (&dist_rt->client_advert_tracker.instance_no, target->instance_no);
        return;
    }

    rt_advertised_node_t tmplate;
    avltree_node_init (&tmplate.glue);
    tmplate.dist_rt = dist_rt;

    avltree_node_t *avl_node = avltree_lookup (&tmplate.glue, &target->rt_advertised);
    assert (avl_node);

    node = avltree_container_of(avl_node, rt_advertised_node_t, glue);
    assert(avltree_remove (&node->glue, &target->rt_advertised));
    assert(node->dist_rt == dist_rt);

    node->dist_rt = NULL;
    bitmap_unset_bit_at (&dist_rt->client_advert_tracker.proto_bitmap, target->proto);
    bitmap_unset_bit_at (&dist_rt->client_advert_tracker.vrf_id, target->vrf->vrf_id);
    bitmap_unset_bit_at (&dist_rt->client_advert_tracker.instance_no, target->instance_no);
    rt_redist_route_dereference(dist_mgr, dist_rt);
}

/* ------------------------------------------------------------------------- */
/* RTM presentation hook — build/update indexes, then schedule distribution     */
/*                                                                               */
/* ADD: insert nhidx + prefix + vrf/instance lists (each link holds a ref).     */
/* DELETE: remove from all lists (deref each), mark is_deleted, then schedule   */
/*         one more distribute pass so targets get withdrawals.                 */
/* The extra rt_redist_route_reference on DELETE keeps the object alive until   */
/* unlink + schedule complete.                                                  */
/* ------------------------------------------------------------------------- */

void 
rtm_distribution_manager_update (dist_mgr_t *dist_mgr,
                                 rtm_presentation_data_t *presentation_data) {

    uint64_t Cnhidx;
    char rt_str[48];
    char nh_str[128];
    avltree_node_t *avl_node;
    rt_redist_route_t rt_tmplate;
    
    tracer (dist_mgr->node->cptr, DREDIS_DET,
        "REDIS-MGR : Route %s, NH %s(%u), Operation %s\n",
        rtm_format_prefix(&presentation_data->route, rt_str, sizeof(rt_str)),
        presentation_data->operation == RTM_PPT_OP_ADD ? \
        rtm_nh_one_liner_trace(presentation_data->nh, nh_str, sizeof(nh_str)) : "deleted",
        presentation_data->nh_idx,
        presentation_data->operation == RTM_PPT_OP_ADD ? "Add" : 
        presentation_data->operation == RTM_PPT_OP_UPDATE ? "Update" : "Delete");

    switch (presentation_data->operation) {

        case RTM_PPT_OP_ADD:
        {
            rt_redist_route_t *redis_rt = (rt_redist_route_t *)XCALLOC2(0, 1, rt_redist_route_t);

            fib_set_nh_idx(&Cnhidx, 
                presentation_data->inh_idx, 
                presentation_data->nh_idx);

            redis_rt->Cnhidx = Cnhidx;
            avltree_node_init (&redis_rt->nhidx_glue);

            memcpy(&redis_rt->prefix, &presentation_data->route, sizeof (redis_rt->prefix));
            init_glthread (&redis_rt->rt_pfx_lst_glue);
            init_glthread (&redis_rt->rt_src_lst_glue);

            redis_rt->nh_proto = presentation_data->inh ? \
                                 presentation_data->inh->rtm_nh_proto : presentation_data->nh->rtm_nh_proto;
            rtm_nh_proto_reference(redis_rt->nh_proto);

            redis_rt->route_vrf = presentation_data->vrf;

            init_glthread (&redis_rt->redis_glue);
            redis_rt->is_deleted = false;
            redis_rt->ref_count = 0;

            bitmap_init(&redis_rt->client_advert_tracker.proto_bitmap, bitmap_next_32_divisible_integer((uint16_t)RTM_PROTO_MAX));
            bitmap_init(&redis_rt->client_advert_tracker.vrf_id, bitmap_next_32_divisible_integer((uint16_t)MAX_VRF_PER_NODE));
            bitmap_init(&redis_rt->client_advert_tracker.instance_no, bitmap_next_32_divisible_integer(32));
            
            avl_node = avltree_insert (&redis_rt->nhidx_glue, &dist_mgr->nhidx_tree);

            /* Duplicate Cnhidx would mean two redist entries for same NH keys. */
            assert(!avl_node);
            rt_redist_route_reference(redis_rt);

            avl_prefix_node_t pfx_node_tmplate;
            memcpy(&pfx_node_tmplate.prefix, 
                &presentation_data->route, sizeof (pfx_node_tmplate.prefix));
            avltree_node_init (&pfx_node_tmplate.glue);

            avl_node = avltree_lookup (&pfx_node_tmplate.glue, &dist_mgr->route_tree_by_prefix);
          
            avl_prefix_node_t *pfx_node = NULL;

            if (!avl_node) {

                pfx_node = (avl_prefix_node_t *)XCALLOC2(0, 1, avl_prefix_node_t);
                memcpy(&pfx_node->prefix, &presentation_data->route, sizeof (pfx_node->prefix));
                avltree_node_init (&pfx_node->glue);
                init_Fglthread(&pfx_node->rt_pfx_lst);                
                assert(!avltree_insert (&pfx_node->glue, &dist_mgr->route_tree_by_prefix));
            }
            else {

                pfx_node = avltree_container_of (avl_node, avl_prefix_node_t, glue);
            }

            /* Fglthread list under prefix: all redist routes for this prefix. */
            Fglthread_add_next (&pfx_node->rt_pfx_lst, &pfx_node->rt_pfx_lst.head, &redis_rt->rt_pfx_lst_glue);
            rt_redist_route_reference(redis_rt);

            avl_vrf_node_t avl_vrf_node_tmplate;
            avl_vrf_node_tmplate.vrf_no = presentation_data->vrf;
            avl_vrf_node_tmplate.instance_no = redis_rt->nh_proto->instance_no;
            avltree_node_init (&avl_vrf_node_tmplate.glue);

            avl_node = avltree_lookup (&avl_vrf_node_tmplate.glue, 
                        &dist_mgr->route_tree[presentation_data->route.afi]
                                             [redis_rt->nh_proto->proto]);

            
            avl_vrf_node_t *avl_vrf_node = NULL;

            if (!avl_node) {

                avl_vrf_node = (avl_vrf_node_t *)XCALLOC2(0, 1, avl_vrf_node_t);
                avl_vrf_node->vrf_no = avl_vrf_node_tmplate.vrf_no;
                avl_vrf_node->instance_no = avl_vrf_node_tmplate.instance_no;
                avltree_node_init (&avl_vrf_node->glue);
                init_Fglthread(&avl_vrf_node->rt_src_lst); 
                assert(!avltree_insert (&avl_vrf_node->glue, 
                    &dist_mgr->route_tree[presentation_data->route.afi]
                                         [redis_rt->nh_proto->proto]));
            }
            else {

                avl_vrf_node = avltree_container_of (avl_node, avl_vrf_node_t, glue);
            }

            /* Same route keyed by vrf/instance under its source protocol tree. */
            Fglthread_add_next (&avl_vrf_node->rt_src_lst, &avl_vrf_node->rt_src_lst.head, &redis_rt->rt_src_lst_glue);
            rt_redist_route_reference(redis_rt);

            dist_mgr_schedule_route_advertise (dist_mgr, redis_rt);
        }
        break;
        case RTM_PPT_OP_DELETE:
        {

            fib_set_nh_idx(&Cnhidx,
                presentation_data->inh_idx,
                presentation_data->nh_idx);

            rt_tmplate.Cnhidx = Cnhidx;
            avltree_node_init(&rt_tmplate.nhidx_glue);

            avl_node = avltree_lookup(&rt_tmplate.nhidx_glue, &dist_mgr->nhidx_tree);
            if (!avl_node) break;

            rt_redist_route_t *redis_rt = avltree_container_of(
                    avl_node, rt_redist_route_t, nhidx_glue);
            
            /* Hold one ref while we unlink from every list and enqueue withdraw. */
            rt_redist_route_reference(redis_rt);

            avltree_remove(&redis_rt->nhidx_glue, &dist_mgr->nhidx_tree);
            rt_redist_route_dereference(dist_mgr, redis_rt);

            /* Remove from prefix-keyed tree; prune the prefix node when empty */
            avl_prefix_node_t pfx_node_tmplate;
            memcpy(&pfx_node_tmplate.prefix, &redis_rt->prefix, sizeof(pfx_node_tmplate.prefix));
            avltree_node_init(&pfx_node_tmplate.glue);

            avl_node = avltree_lookup(&pfx_node_tmplate.glue, &dist_mgr->route_tree_by_prefix);
            assert(avl_node);
            avl_prefix_node_t *pfx_node = avltree_container_of(avl_node, avl_prefix_node_t, glue);
            remove_Fglthread(&pfx_node->rt_pfx_lst, &redis_rt->rt_pfx_lst_glue);
            rt_redist_route_dereference(dist_mgr, redis_rt);

            if (Fglthread_list_is_empty(&pfx_node->rt_pfx_lst)) {
                avltree_remove(&pfx_node->glue, &dist_mgr->route_tree_by_prefix);
                XFREE(pfx_node);
            }

            /* Remove from vrf/proto-keyed tree; prune the vrf node when empty */
            avl_vrf_node_t avl_vrf_node_tmplate;
            avl_vrf_node_tmplate.vrf_no     = presentation_data->vrf;
            avl_vrf_node_tmplate.instance_no = redis_rt->nh_proto->instance_no;
            avltree_node_init(&avl_vrf_node_tmplate.glue);

            avl_node = avltree_lookup(&avl_vrf_node_tmplate.glue,
                        &dist_mgr->route_tree[presentation_data->route.afi]
                                             [redis_rt->nh_proto->proto]);
            assert(avl_node);
            avl_vrf_node_t *avl_vrf_node = avltree_container_of(avl_node, avl_vrf_node_t, glue);
            remove_Fglthread(&avl_vrf_node->rt_src_lst, &redis_rt->rt_src_lst_glue);
            rt_redist_route_dereference(dist_mgr, redis_rt);

            if (Fglthread_list_is_empty(&avl_vrf_node->rt_src_lst)) {
                avltree_remove(&avl_vrf_node->glue,
                    &dist_mgr->route_tree[presentation_data->route.afi]
                                         [redis_rt->nh_proto->proto]);
                XFREE(avl_vrf_node);
            }

            /* Stale for policy adds; distribute path only sends withdraws. */
            redis_rt->is_deleted = true;
            dist_mgr_schedule_route_advertise(dist_mgr, redis_rt);

            /* Drop the delete-path safety reference. */
            rt_redist_route_dereference(dist_mgr, redis_rt);
        }
        break;
        case RTM_PPT_OP_UPDATE:
            assert(0);
    }
}

/* ------------------------------------------------------------------------- */
/* Main redistribution queue (dist_mgr->redis_queue)                         */
/*                                                                               */
/* Multiple routes may be linked before the one-shot redis_task runs. Each      */
/* enqueue takes a ref; the job drops it after rtm_dist_mgr_distribute_route_* . */
/* If redis_glue is already on the queue, schedule_route_advertise is a no-op   */
/* (coalescing duplicate schedule for the same route).                          */
/* ------------------------------------------------------------------------- */

static void 
dist_mgr_redistrbution_job_cbk(
        event_dispatcher_t *ev_dis, 
        void *arg, uint32_t arg_size) {

    glthread_t *curr;
    uint32_t count = 0;
    dist_mgr_t *dist_mgr = (dist_mgr_t *)arg;
    rt_redist_route_t *dist_rt = NULL;
    
    dist_mgr->redis_task = NULL;

    while ((curr = dequeue_glthread_first(&dist_mgr->redis_queue.head))) {
        
        dist_rt = rt_redist_route_redis_glue_to_rt(curr);
        rtm_dist_mgr_distribute_route_to_target_clients (dist_mgr, dist_rt);
        rt_redist_route_dereference(dist_mgr, dist_rt);

        count++;

        if (count % DIST_MGR_PREEMPT_THRESHOLD == 0) {
            /* Yield to avoid starving other jobs if the queue is very long. */
            dist_mgr->redis_task = task_create_new_job (EV(dist_mgr->node), 
                                        (void *)dist_mgr, 
                                        dist_mgr_redistrbution_job_cbk,
                                        TASK_ONE_SHOT, 
                                        TASK_PRIORITY_COMPUTE);
            return;
        }
    }
}

void 
dist_mgr_schedule_route_advertise(dist_mgr_t *dist_mgr, rt_redist_route_t *dist_rt) {

    /* Already queued — wait for pending job to process this route. */
    if (!IS_GLTHREAD_LIST_EMPTY(&dist_rt->redis_glue)) return;

    Fglthread_add_last (&dist_mgr->redis_queue, &dist_rt->redis_glue);
    rt_redist_route_reference(dist_rt);

    /* Only one outstanding redis_task; it will drain the whole queue. */
    if (dist_mgr->redis_task) return;

    dist_mgr->redis_task = task_create_new_job (EV(dist_mgr->node), 
                                    (void *)dist_mgr, 
                                    dist_mgr_redistrbution_job_cbk,
                                    TASK_ONE_SHOT, 
                                    TASK_PRIORITY_COMPUTE);
}

/* ------------------------------------------------------------------------- */
/* Policy: rule matching and per-target client delivery                       */
/* ------------------------------------------------------------------------- */

static bool
rtm_dist_mgr_rule_source_matches (dist_rule_t *rule, 
                                   rtm_nh_proto_t *nh_proto,
                                   uint8_t route_vrf) {

    if (rule->src_proto != nh_proto->proto) return false;

    /* RTM_SUB_PROTO_NA on the rule acts as a wildcard for sub-protocol */
    if (rule->src_sub_proto != RTM_SUB_PROTO_NA &&
        rule->src_sub_proto != nh_proto->sub_proto) return false;

    if ((uint32_t)rule->src_instance_no != nh_proto->instance_no) return false;

    if (rule->src_vrf_id != route_vrf) return false;
    
    return true;
}

/* Returns PERMIT, DENY, or SKIP (no match).
   PERMIT  – prefix-list matched and permitted, or no filter is configured.
   DENY    – prefix-list matched and explicitly denied; callers must stop
             processing further rules for this route.
   SKIP    – prefix-list had no matching entry; caller may try the next rule. */
static pfx_lst_result_t
rtm_dist_mgr_rule_filter_eval (dist_rule_t *rule, cmn_prefix_t *prefix) {

    /* No filter configured => permit by default */
    if (!rule->pfx_lst) return PFX_LST_PERMIT;

    /* prefix-list library currently supports IPv4 only.
       For non-IPv4 routes with a configured filter, deny to be safe. */
    if (prefix->afi != AF_IPV4) return PFX_LST_DENY;

    return prefix_list_evaluate (prefix->u.v4_addr,
                                 prefix->prefix_len,
                                 rule->pfx_lst);
}

/* First rule on this target that permits redistribution of dist_rt (VRF + policy). */
bool
rtm_dist_mgr_target_first_permitting_rule(
    redist_target_t *target,
    rt_redist_route_t *dist_rt,
    dist_rule_t **rule_out)
{
    dist_rule_t *rule;

    if (rule_out)
        *rule_out = NULL;

    if (dist_rt->is_deleted)
        return false;

    for (rule = target->rule_list; rule; rule = rule->next) {

        if (!rtm_dist_mgr_rule_source_matches(rule, dist_rt->nh_proto, dist_rt->route_vrf))
            continue;

        switch (rtm_dist_mgr_rule_filter_eval(rule, &dist_rt->prefix)) {
            case PFX_LST_PERMIT:
                if (rule_out) *rule_out = rule;
                return true;
            case PFX_LST_DENY:
                /* Explicit deny is terminal; no further rule can override. */
                return false;
            case PFX_LST_SKIP:
            default:
                continue;
        }
    }
    return false;
}

static inline void
rtm_dist_mgr_advert_fill_from_route(
    rt_advert_info_t *advert_info,
    rt_redist_route_t *dist_rt)
{
    memset(advert_info, 0, sizeof(*advert_info));
    memcpy(&advert_info->route, &dist_rt->prefix, sizeof(advert_info->route));
    advert_info->src_proto = dist_rt->nh_proto->proto;
    advert_info->src_vrf_id = dist_rt->route_vrf;
    advert_info->Cnhidx = dist_rt->Cnhidx;
}

/* Drains target->client_redis_queue; each advert_info is malloc’d, freed here. */
static void 
target_redis_cbk (
        event_dispatcher_t *ev_dis, 
        void *arg, uint32_t arg_size) {

    glthread_t *curr;
    uint32_t count = 0 ;
    redist_target_t *target = (redist_target_t *)arg;
    rt_advert_info_t *advert_info;

    target->client_flash_job = NULL;
    node_t *node = (node_t *)ev_dis->app_data;
    dist_mgr_t *dist_mgr = node->dist_mgr;

    while ((curr = dequeue_glthread_first(&target->client_redis_queue.head))) {

        advert_info = redis_glue_to_rt_advert_info(curr);

        if ((dist_mgr->target_cbks)[target->proto]) {
            (*dist_mgr->target_cbks[target->proto])(target->vrf, advert_info);
        }
        XFREE(advert_info);

        count++;

        if (count % DIST_MGR_PREEMPT_THRESHOLD == 0) {
            /* Yield to avoid starving other jobs if the queue is very long. */
            target->client_flash_job = task_create_new_job (EV(node), 
                                        (void *)target, 
                                        target_redis_cbk,
                                        TASK_ONE_SHOT, 
                                        TASK_PRIORITY_COMPUTE);
            return;
        }
    }
}

static inline void
rtm_dist_mgr_schedule_rt_advert_info_to_target (
                dist_mgr_t *dist_mgr, 
                redist_target_t *target, 
                rt_advert_info_t *advert_info) {

    Fglthread_add_last (&target->client_redis_queue,
                        &advert_info->redis_glue);

    if (target->client_flash_job) return;

    target->client_flash_job = task_create_new_job (EV(dist_mgr->node), 
                                    (void *)target, 
                                    target_redis_cbk,
                                    TASK_ONE_SHOT, 
                                    TASK_PRIORITY_COMPUTE);
}

/* Walk every registered target: apply rules, enqueue RTM_CLIENT_RT_ADD/DEL to
 * the target’s client queue, and sync rtm_redist_target_record_rt_advertisement. */

void rtm_dist_mgr_distribute_route_to_target_clients(
            dist_mgr_t *dist_mgr, 
            rt_redist_route_t *dist_rt)
{
    char rt_str[48];
    dist_rule_t *rule;
    redist_target_t *target;
    rt_advert_info_t advert_tmplate;
    rt_advert_info_t *advert_info;

    /* Build route-derived advertisement template once; per-rule action fields
       are applied on cloned objects before queuing to targets. */
    rtm_dist_mgr_advert_fill_from_route(&advert_tmplate, dist_rt);

    /* This route has been deleted , withdraw it from all targets */
    if (dist_rt->is_deleted)
    {
        /* Withdraw from every target that still has this route in rt_advertised. */
        for (target = dist_mgr->target_lst; target; target = target->next)
        {
            if (redist_route_is_advertised_to_client(dist_rt, target))
            {
                advert_info = (rt_advert_info_t *)XCALLOC2(0, 1, rt_advert_info_t);
                memcpy(advert_info, &advert_tmplate, sizeof(*advert_info));
                init_glthread(&advert_info->redis_glue);
                advert_info->code = RTM_CLIENT_RT_DEL;

                tracer(dist_mgr->node->cptr, DREDIS_DET,
                       "REDIS-MGR : Withdraw %s from target proto %s instance %u vrf %u\n",
                       rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                       rtm_proto_to_string(target->proto),
                       target->instance_no,
                       target->vrf->vrf_id);

                rtm_dist_mgr_schedule_rt_advert_info_to_target(dist_mgr, target, advert_info);
                rtm_redist_target_record_rt_advertisement (dist_mgr, target, dist_rt, false);
            }
        }

        return;
    }

    /* 1. For all Target clients TC */
    for (target = dist_mgr->target_lst; target; target = target->next)
    {
        if (rtm_dist_mgr_target_first_permitting_rule(target, dist_rt, &rule))
        {
            /* Skip if this route already advertised */
            if (redist_route_is_advertised_to_client(dist_rt, target)) {

                tracer(dist_mgr->node->cptr, DREDIS_DET,
                       "REDIS-MGR : Route %s already advertised to target proto %s instance %u vrf %u, skip re-advertisement\n",
                       rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                       rtm_proto_to_string(target->proto),
                       target->instance_no,
                       target->vrf->vrf_id);
            }
            else
            {
                /* Clone base advertisement, apply rule action and queue by pointer */
                advert_info = (rt_advert_info_t *)XCALLOC2(0, 1, rt_advert_info_t);
                memcpy(advert_info, &advert_tmplate, sizeof(*advert_info));
                advert_info->out_cost = rule->out_cost;
                advert_info->out_tag = rule->out_tag;
                advert_info->out_community = rule->out_community;
                advert_info->code = RTM_CLIENT_RT_ADD;
                init_glthread(&advert_info->redis_glue);

                tracer(dist_mgr->node->cptr, DREDIS_DET,
                       "REDIS-MGR : Advertise %s to target proto %s instance %u vrf %u\n",
                       rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                       rtm_proto_to_string(target->proto),
                       target->instance_no,
                       target->vrf->vrf_id);

                rtm_dist_mgr_schedule_rt_advert_info_to_target(dist_mgr, target, advert_info);
                rtm_redist_target_record_rt_advertisement(dist_mgr, target, dist_rt, true);
            }
        }
        else if (redist_route_is_advertised_to_client(dist_rt, target))
        {
            /* No rule permits this route; withdraw if previously advertised. */
            advert_info = (rt_advert_info_t *)XCALLOC2(0, 1, rt_advert_info_t);
            memcpy(advert_info, &advert_tmplate, sizeof(*advert_info));
            init_glthread(&advert_info->redis_glue);
            advert_info->code = RTM_CLIENT_RT_DEL;

            tracer(dist_mgr->node->cptr, DREDIS_DET,
                   "REDIS-MGR : Withdraw %s from target proto %s instance %u vrf %u\n",
                   rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                   rtm_proto_to_string(target->proto),
                   target->instance_no,
                   target->vrf->vrf_id);

            rtm_dist_mgr_schedule_rt_advert_info_to_target(dist_mgr, target, advert_info);
            rtm_redist_target_record_rt_advertisement(dist_mgr, target, dist_rt, false);
        }

    } /* for each target */
}

/* Called when a target’s rule list changes: recompute add vs withdraw for every
 * redist route still indexed by nhidx_tree (full scan). */
void
rtm_dist_mgr_broadcast_dist_routes_to_target(
                        dist_mgr_t *dist_mgr,
                        redist_target_t *target)
{
    avltree_node_t *avl_node;
    rt_redist_route_t *dist_rt;
    dist_rule_t *rule;
    rt_advert_info_t advert_tmplate;
    rt_advert_info_t *advert_info;
    char rt_str[48];
    bool should_advert;
    bool is_advertised;

    ITERATE_AVL_TREE_BEGIN(&dist_mgr->nhidx_tree, avl_node)
    {
        dist_rt = avltree_container_of(avl_node, rt_redist_route_t, nhidx_glue);
        should_advert =
            rtm_dist_mgr_target_first_permitting_rule(target, dist_rt, &rule);
        is_advertised = redist_route_is_advertised_to_client(dist_rt, target);

        if (is_advertised && !should_advert) {

            rtm_dist_mgr_advert_fill_from_route(&advert_tmplate, dist_rt);
            advert_info = (rt_advert_info_t *)XCALLOC2(0, 1, rt_advert_info_t);
            memcpy(advert_info, &advert_tmplate, sizeof(*advert_info));
            init_glthread(&advert_info->redis_glue);
            advert_info->code = RTM_CLIENT_RT_DEL;

            tracer(dist_mgr->node->cptr, DREDIS_DET,
                   "REDIS-MGR : Policy flash withdraw %s from target proto %s instance %u vrf %u\n",
                   rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                   rtm_proto_to_string(target->proto),
                   target->instance_no,
                   target->vrf->vrf_id);

            rtm_dist_mgr_schedule_rt_advert_info_to_target(dist_mgr, target, advert_info);
            rtm_redist_target_record_rt_advertisement (dist_mgr, target, dist_rt, false);
        }
        else if (!is_advertised && should_advert) {

            rtm_dist_mgr_advert_fill_from_route(&advert_tmplate, dist_rt);
            advert_info = (rt_advert_info_t *)XCALLOC2(0, 1, rt_advert_info_t);
            memcpy(advert_info, &advert_tmplate, sizeof(*advert_info));
            advert_info->out_cost = rule->out_cost;
            advert_info->out_tag = rule->out_tag;
            advert_info->out_community = rule->out_community;
            advert_info->code = RTM_CLIENT_RT_ADD;
            init_glthread(&advert_info->redis_glue);

            tracer(dist_mgr->node->cptr, DREDIS_DET,
                   "REDIS-MGR : Policy flash advertise %s to target proto %s instance %u vrf %u\n",
                   rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                   rtm_proto_to_string(target->proto),
                   target->instance_no,
                   target->vrf->vrf_id);

            rtm_dist_mgr_schedule_rt_advert_info_to_target(dist_mgr, target, advert_info);
            rtm_redist_target_record_rt_advertisement (dist_mgr, target, dist_rt, true);
        }
    }
    ITERATE_AVL_TREE_END;
}

/* Target (e.g. IS-IS) restarted or missed updates: replay from what we believe
 * is currently advertised in target->rt_advertised.  Note: successful replay
 * of ADD does not call rtm_redist_target_record_rt_advertisement (see inline
 * comment in ADD branch) — state is already consistent in the AVL. */
void 
rtm_dist_mgr_client_request_route_replay (
        dist_mgr_t *dist_mgr, 
        RTM_PROTO_T proto, 
        uint32_t instance_no, uint8_t vrf_id) {

    redist_target_t *target;
    avltree_node_t *avl_node;
    rt_advertised_node_t *adv_node;
    rt_redist_route_t *dist_rt;
    dist_rule_t *rule;
    rt_advert_info_t advert_tmplate;
    rt_advert_info_t *advert_info;
    char rt_str[48];
    bool should_advert;

    tracer (dist_mgr->node->cptr, DREDIS,
           "REDIS-MGR : Client request route replay for proto %s instance %u vrf %u\n",
           rtm_proto_to_string(proto),
           instance_no, vrf_id);

    for (target = dist_mgr->target_lst; target; target = target->next) {
        if (target->proto == proto && target->instance_no == instance_no
            && target->vrf->vrf_id == vrf_id)
            break;
    }

    if (!target) {

        tracer (dist_mgr->node->cptr, DREDIS | DERR,
           "REDIS-MGR : Error : No matching target found for proto %s instance %u vrf %u, cannot replay routes\n",
           rtm_proto_to_string(proto),
           instance_no, vrf_id);
        return;
    }

    ITERATE_AVL_TREE_BEGIN(&target->rt_advertised, avl_node)
    {
        adv_node = avltree_container_of(avl_node, rt_advertised_node_t, glue);
        dist_rt = adv_node->dist_rt;

        should_advert =
            rtm_dist_mgr_target_first_permitting_rule(target, dist_rt, &rule);

        if (!should_advert) {

            rtm_dist_mgr_advert_fill_from_route(&advert_tmplate, dist_rt);
            advert_info = (rt_advert_info_t *)XCALLOC2(0, 1, rt_advert_info_t);
            memcpy(advert_info, &advert_tmplate, sizeof(*advert_info));
            init_glthread(&advert_info->redis_glue);
            advert_info->code = RTM_CLIENT_RT_DEL;

            tracer(dist_mgr->node->cptr, DREDIS_DET,
                   "REDIS-MGR : Replay withdraw %s from target proto %s instance %u vrf %u\n",
                   rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                   rtm_proto_to_string(target->proto),
                   target->instance_no,
                   target->vrf->vrf_id);

            rtm_dist_mgr_schedule_rt_advert_info_to_target(dist_mgr, target, advert_info);
            rtm_redist_target_record_rt_advertisement (dist_mgr, target, dist_rt, false);
        }
        else {

            rtm_dist_mgr_advert_fill_from_route(&advert_tmplate, dist_rt);
            advert_info = (rt_advert_info_t *)XCALLOC2(0, 1, rt_advert_info_t);
            memcpy(advert_info, &advert_tmplate, sizeof(*advert_info));
            advert_info->out_cost = rule->out_cost;
            advert_info->out_tag = rule->out_tag;
            advert_info->out_community = rule->out_community;
            advert_info->code = RTM_CLIENT_RT_ADD;
            init_glthread(&advert_info->redis_glue);

            tracer(dist_mgr->node->cptr, DREDIS_DET,
                   "REDIS-MGR : Replay flash advertise %s to target proto %s instance %u vrf %u\n",
                   rtm_format_prefix(&dist_rt->prefix, rt_str, sizeof(rt_str)),
                   rtm_proto_to_string(target->proto),
                   target->instance_no,
                   target->vrf->vrf_id);

            rtm_dist_mgr_schedule_rt_advert_info_to_target(dist_mgr, target, advert_info);
            /* Intentionally no record_rt_advertisement(true): adv_node already
             * links dist_rt in rt_advertised; replay only refreshes the client. */
        }
    }
    ITERATE_AVL_TREE_END;
}

/* ------------------------------------------------------------------------- */
/* Deferred GC — destroy targets after client queues are empty                  */
/* ------------------------------------------------------------------------- */

typedef struct dist_mgr_gc_container_ {

    DIST_MGR_GC_TYPE_T type;
    void *object;
    glthread_t glue;

} dist_mgr_gc_container_t;
GLTHREAD_TO_STRUCT(dist_mgr_gc_container_object, dist_mgr_gc_container_t, glue);


static void 
dist_mgr_target_check_and_delete (redist_target_t *target) {

    assert (!target->rule_list);
    assert (Fglthread_list_is_empty (&target->client_redis_queue));
    assert (!target->client_flash_job);
    assert (!target->next);
    assert (avltree_is_empty (&target->rt_advertised));
    XFREE  (target);
}

static void 
rtm_dist_mgr_target_release_all_resources (dist_mgr_t *dist_mgr, redist_target_t *target) {

    /* Free the Rule list. Each rule may hold a reference on its filter
       prefix-list which must be released before the rule itself is freed. */
    dist_rule_t *rule;

    while ((rule = target->rule_list)) {

        target->rule_list = rule->next;
        rule->next = NULL;
        if (rule->pfx_lst) prefix_list_dereference(rule->pfx_lst);
        XFREE(rule);
    }

    /* Release the routes advertised to this target i.e. target->rt_advertised.
       At GC time the client has already drained client_redis_queue, so we just
       tear down the bookkeeping: drop the per-target advertisement bit on each
       dist_rt, dereference the dist_rt, and free the avl entry. */
    avltree_node_t *avl_node;
    rt_advertised_node_t *adv_node;
    rt_redist_route_t *dist_rt;

    ITERATE_AVL_TREE_BEGIN(&target->rt_advertised, avl_node)
    {
        adv_node = avltree_container_of(avl_node, rt_advertised_node_t, glue);
        dist_rt = adv_node->dist_rt;

        avltree_remove(&adv_node->glue, &target->rt_advertised);
        adv_node->dist_rt = NULL;
        XFREE(adv_node);

        bitmap_unset_bit_at (&dist_rt->client_advert_tracker.proto_bitmap, target->proto);
        bitmap_unset_bit_at (&dist_rt->client_advert_tracker.vrf_id, target->vrf->vrf_id);
        bitmap_unset_bit_at (&dist_rt->client_advert_tracker.instance_no, target->instance_no);
        rt_redist_route_dereference(dist_mgr, dist_rt);

    } ITERATE_AVL_TREE_END;
}

/* Processes gc_queue; for DIST_MGR_GC_TYPE_TARGET tears down rules, advertised
 * routes, and frees the redist_target_t. */
static void 
dist_mgr_gc_job_cbk(
        event_dispatcher_t *ev_dis, 
        void *arg, uint32_t arg_size) {

    glthread_t *curr;
    dist_mgr_t *dist_mgr = (dist_mgr_t *)arg;
    dist_mgr_gc_container_t *container = NULL;

    dist_mgr->gc_task = NULL;

    while ((curr = dequeue_glthread_first(&dist_mgr->gc_queue.head))) {

        container = dist_mgr_gc_container_object(curr);
        
        switch (container->type) {

            case DIST_MGR_GC_TYPE_TARGET:
                rtm_dist_mgr_target_release_all_resources (dist_mgr, (redist_target_t *)container->object);
                dist_mgr_target_check_and_delete((redist_target_t *)container->object);
                break;
            default: ;
                break;
        }
        XFREE(container);
    }
}

/* Enqueue object for asynchronous free; coalesces to one gc_task like redis. */
void 
rtm_dis_mgr_gc (dist_mgr_t *dist_mgr, void *object, DIST_MGR_GC_TYPE_T type) {

    dist_mgr_gc_container_t *container = 
        (dist_mgr_gc_container_t *)XCALLOC2(0, 1, dist_mgr_gc_container_t);

    container->type = type;
    container->object = object;
    init_glthread(&container->glue);
    Fglthread_add_last (&dist_mgr->gc_queue, &container->glue);

    if (dist_mgr->gc_task) return;

    dist_mgr->gc_task = task_create_new_job (EV(dist_mgr->node), 
                                    (void *)dist_mgr, 
                                    dist_mgr_gc_job_cbk,
                                    TASK_ONE_SHOT, 
                                    TASK_PRIORITY_GARBAGE_COLLECTOR);

}