#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include "../libs/LinuxMemoryManager/uapi_mm.h"
#include "../libs/Tree/libtree.h"
#include "../libs/Tracer/tracer.h"
#include "../libs/common/cmn_prefix.h"
#include "rtm.h"
#include "rtm_nhtracker.h"
#include "rtm_presentation.h"
#include "rtm_nh.h"
#include "rtm_route.h"
#include "rtm_proto.h"
#include "rtm_show.h"
#include "../tcp_ip_trace.h"
#include "../router_init.h"

extern int cprintf(const char *format, ...);

static int
rtm_tracker_client_db_reg_id_compare (
        const avltree_node_t *node1,
        const avltree_node_t *node2);

static int
rtm_tracked_prefix_compare (
        const avltree_node_t *node1,
        const avltree_node_t *node2);

/* Exact key ordering for the client-id AVL (no wildcard semantics). */
static int
rtm_tracker_client_id_compare (
        const rtm_tracker_client_id_t *id1,
        const rtm_tracker_client_id_t *id2) {

    if (id1->proto != id2->proto) {
        return (id1->proto < id2->proto) ? -1 : 1;
    }

    if (id1->sub_proto != id2->sub_proto) {
        return (id1->sub_proto < id2->sub_proto) ? -1 : 1;
    }

    if (id1->vrf_id != id2->vrf_id) {
        return (id1->vrf_id < id2->vrf_id) ? -1 : 1;
    }

    if (id1->instance_no != id2->instance_no) {
        return (id1->instance_no < id2->instance_no) ? -1 : 1;
    }

    return 0;
}

/*
 * Match helper: sub_proto value 0 is a wildcard on either side.
 * proto / vrf_id / instance_no always compare exactly.
 */
static bool
rtm_tracker_client_id_matches (
        const rtm_tracker_client_id_t *registered,
        const rtm_tracker_client_id_t *event) {

    if (!registered || !event)
        return false;

    if (registered->proto != event->proto)
        return false;

    if (registered->vrf_id != event->vrf_id)
        return false;

    if (registered->instance_no != event->instance_no)
        return false;

    if (registered->sub_proto != 0 && event->sub_proto != 0 &&
        registered->sub_proto != event->sub_proto)
        return false;

    return true;
}

static void
rtm_tracker_client_id_from_nh_proto (
        rtm_tracker_client_id_t *client_id,
        rtm_nh_proto_t *nh_proto) {

    memset(client_id, 0, sizeof(*client_id));
    if (!nh_proto)
        return;

    client_id->proto = nh_proto->proto;
    client_id->sub_proto = nh_proto->sub_proto;
    client_id->vrf_id = nh_proto->vrf_id;
    client_id->instance_no = (uint16_t)nh_proto->instance_no;
}

static int
rtm_tracker_client_db_reg_id_compare (
        const avltree_node_t *node1,
        const avltree_node_t *node2) {

    rtm_tracker_client_db_t *db1 =
        avltree_container_of(node1, rtm_tracker_client_db_t, avlnode_glue_reg_id);
    rtm_tracker_client_db_t *db2 =
        avltree_container_of(node2, rtm_tracker_client_db_t, avlnode_glue_reg_id);

    if (db1->reg_id < db2->reg_id)
        return -1;
    if (db1->reg_id > db2->reg_id)
        return 1;
    return 0;
}

int
rtm_tracker_client_db_compare (
        const avltree_node_t *node1,
        const avltree_node_t *node2) {

    rtm_tracker_client_db_t *db1 =
        avltree_container_of(node1, rtm_tracker_client_db_t, avlnode_glue_client_id);
    rtm_tracker_client_db_t *db2 =
        avltree_container_of(node2, rtm_tracker_client_db_t, avlnode_glue_client_id);

    return rtm_tracker_client_id_compare(&db1->client_id, &db2->client_id);
}

static int
rtm_tracked_prefix_compare (
        const avltree_node_t *node1,
        const avltree_node_t *node2) {

    rtm_tracked_prefix_t *pfx1 =
        avltree_container_of(node1, rtm_tracked_prefix_t, glue);
    rtm_tracked_prefix_t *pfx2 =
        avltree_container_of(node2, rtm_tracked_prefix_t, glue);

    return cmn_prefix_compare(&pfx1->tracked_prefix, &pfx2->tracked_prefix);
}

static rtm_tracked_prefix_t *
rtm_tracker_lookup_tracked_prefix (
        rtm_tracker_client_db_t *client_db,
        cmn_prefix_t *prefix) {

    rtm_tracked_prefix_t template_pfx;
    avltree_node_t *node;

    if (!client_db || !prefix)
        return NULL;

    memset(&template_pfx, 0, sizeof(template_pfx));
    template_pfx.tracked_prefix = *prefix;
    avltree_node_init(&template_pfx.glue);

    node = avltree_lookup(&template_pfx.glue, &client_db->tracked_prefix_tree);
    if (!node)
        return NULL;

    return avltree_container_of(node, rtm_tracked_prefix_t, glue);
}

static void
rtm_tracker_free_tracked_prefix_tree (rtm_tracker_client_db_t *client_db) {

    avltree_node_t *node;

    if (!client_db)
        return;

    while ((node = avltree_first(&client_db->tracked_prefix_tree)) != NULL) {

        rtm_tracked_prefix_t *tracked =
            avltree_container_of(node, rtm_tracked_prefix_t, glue);

        avltree_remove(node, &client_db->tracked_prefix_tree);
        XFREE(tracked);
    }
}

void
rtm_tracker_init (rtm_tracker_t **rtm_tracker) {

    rtm_tracker_t *tracker;

    if (!rtm_tracker)
        return;

    if (*rtm_tracker)
        return;

    tracker = (rtm_tracker_t *)XCALLOC2(0, 1, rtm_tracker_t);
    avltree_init(&tracker->client_db_by_client_id, rtm_tracker_client_db_compare);
    avltree_init(&tracker->client_db_by_reg_id, rtm_tracker_client_db_reg_id_compare);
    *rtm_tracker = tracker;
}

static void
rtm_tracker_free_client_db (
        rtm_tracker_t *tracker,
        rtm_tracker_client_db_t *client_db) {

    if (!tracker || !client_db)
        return;

    rtm_tracker_free_tracked_prefix_tree(client_db);

    if (avltree_node_is_inuse(&tracker->client_db_by_client_id,
                              &client_db->avlnode_glue_client_id)) {
        avltree_remove(&client_db->avlnode_glue_client_id,
                       &tracker->client_db_by_client_id);
    }

    if (avltree_node_is_inuse(&tracker->client_db_by_reg_id,
                              &client_db->avlnode_glue_reg_id)) {
        avltree_remove(&client_db->avlnode_glue_reg_id,
                       &tracker->client_db_by_reg_id);
    }

    XFREE(client_db);
}

void
rtm_tracker_deinit (rtm_tracker_t **rtm_tracker) {

    rtm_tracker_t *tracker;
    avltree_node_t *node;

    if (!rtm_tracker || !*rtm_tracker)
        return;

    tracker = *rtm_tracker;

    while ((node = avltree_first(&tracker->client_db_by_client_id)) != NULL) {

        rtm_tracker_client_db_t *client_db =
            avltree_container_of(node, rtm_tracker_client_db_t, avlnode_glue_client_id);
        rtm_tracker_free_client_db(tracker, client_db);
    }

    assert(avltree_is_empty(&tracker->client_db_by_client_id));
    assert(avltree_is_empty(&tracker->client_db_by_reg_id));

    XFREE(tracker);
    *rtm_tracker = NULL;
}

static uintptr_t
rtm_tracker_client_db_registration_id (rtm_tracker_client_db_t *client_db) {

    return (uintptr_t)client_db;
}

static rtm_tracker_client_db_t *
rtm_tracker_lookup_client_db_by_registration_id (
        rtm_tracker_t *tracker,
        uintptr_t registration_id) {

    rtm_tracker_client_db_t template_db;
    avltree_node_t *node;

    if (!tracker || !registration_id)
        return NULL;

    memset(&template_db, 0, sizeof(template_db));
    template_db.reg_id = registration_id;
    avltree_node_init(&template_db.avlnode_glue_reg_id);

    node = avltree_lookup(&template_db.avlnode_glue_reg_id, &tracker->client_db_by_reg_id);
    if (!node)
        return NULL;

    return avltree_container_of(node, rtm_tracker_client_db_t, avlnode_glue_reg_id);
}

static rtm_tracker_client_db_t *
rtm_tracker_lookup_client_db_by_id (
        rtm_tracker_t *tracker,
        rtm_tracker_client_id_t *client_id) {

    rtm_tracker_client_db_t template_db;
    avltree_node_t *node;

    if (!tracker || !client_id)
        return NULL;

    memset(&template_db, 0, sizeof(template_db));
    template_db.client_id = *client_id;
    avltree_node_init(&template_db.avlnode_glue_client_id);

    node = avltree_lookup(&template_db.avlnode_glue_client_id, &tracker->client_db_by_client_id);
    if (!node)
        return NULL;

    return avltree_container_of(node, rtm_tracker_client_db_t, avlnode_glue_client_id);
}

uintptr_t
rtm_tracker_register_client (
        rtm_t *rtm,
        rtm_tracker_client_id_t *client_id,
        rtm_tracker_client_callback_t callback) {

    rtm_tracker_t *tracker;
    rtm_tracker_client_db_t *client_db;

    if (!rtm || !client_id || !callback)
        return 0;

    tracker = rtm->nh_tracker;
    if (!tracker)
        return 0;

    client_db = rtm_tracker_lookup_client_db_by_id(tracker, client_id);
    if (client_db) {
        client_db->callback = callback;
        return client_db->reg_id;
    }

    client_db = (rtm_tracker_client_db_t *)XCALLOC2(0, 1, rtm_tracker_client_db_t);
    client_db->client_id = *client_id;
    client_db->callback = callback;
    client_db->reg_id = rtm_tracker_client_db_registration_id(client_db);
    avltree_init(&client_db->tracked_prefix_tree, rtm_tracked_prefix_compare);
    avltree_node_init(&client_db->avlnode_glue_client_id);
    avltree_node_init(&client_db->avlnode_glue_reg_id);
    avltree_insert(&client_db->avlnode_glue_client_id, &tracker->client_db_by_client_id);
    avltree_insert(&client_db->avlnode_glue_reg_id, &tracker->client_db_by_reg_id);

    return client_db->reg_id;
}


void
rtm_tracker_unregister_client (rtm_t *rtm, uintptr_t registration_id) {

    rtm_tracker_t *tracker;
    rtm_tracker_client_db_t *client_db;

    if (!rtm || !registration_id)
        return;

    tracker = rtm->nh_tracker;
    if (!tracker)
        return;

    client_db = rtm_tracker_lookup_client_db_by_registration_id(tracker, registration_id);
    if (!client_db)
        return;

    rtm_tracker_free_client_db(tracker, client_db);
}

void
rtm_track (
        rtm_t *rtm,
        cmn_prefix_t *prefix_to_track,
        uintptr_t registration_id) {

    rtm_tracker_t *tracker;
    rtm_tracker_client_db_t *client_db;
    rtm_tracked_prefix_t *tracked;

    if (!rtm || !prefix_to_track || !registration_id)
        return;

    tracker = rtm->nh_tracker;
    if (!tracker)
        return;

    client_db = rtm_tracker_lookup_client_db_by_registration_id(tracker, registration_id);
    if (!client_db)
        return;

    if (rtm_tracker_lookup_tracked_prefix(client_db, prefix_to_track))
        return;

    tracked = (rtm_tracked_prefix_t *)XCALLOC2(0, 1, rtm_tracked_prefix_t);
    tracked->tracked_prefix = *prefix_to_track;
    avltree_node_init(&tracked->glue);
    avltree_insert(&tracked->glue, &client_db->tracked_prefix_tree);
}

void
rtm_untrack (
        rtm_t *rtm,
        cmn_prefix_t *prefix_to_track,
        uintptr_t registration_id) {

    rtm_tracker_t *tracker;
    rtm_tracker_client_db_t *client_db;
    rtm_tracked_prefix_t *tracked;

    if (!rtm || !prefix_to_track || !registration_id)
        return;

    tracker = rtm->nh_tracker;
    if (!tracker)
        return;

    client_db = rtm_tracker_lookup_client_db_by_registration_id(tracker, registration_id);
    if (!client_db)
        return;

    tracked = rtm_tracker_lookup_tracked_prefix(client_db, prefix_to_track);
    if (!tracked)
        return;

    avltree_remove(&tracked->glue, &client_db->tracked_prefix_tree);
    XFREE(tracked);
}

void
show_rtm_tracker_client_db (rtm_tracker_client_db_t *client_db) {

    avltree_node_t *node;
    char client_id_str[160];
    char vrf_str[16];
    char prefix_str[48];

    if (!client_db)
        return;

    snprintf(vrf_str, sizeof(vrf_str), "%u",
             (unsigned)client_db->client_id.vrf_id);
    rtm_format_redist_target_client_id(
        client_db->client_id.proto,
        vrf_str,
        client_db->client_id.instance_no,
        client_id_str,
        sizeof(client_id_str));

    cprintf(
        "  Tracker client : %s sub_proto %s reg_id 0x%lx  adds %u dels %u\n",
        client_id_str,
        rtm_sub_proto_to_string(client_db->client_id.sub_proto),
        (unsigned long)client_db->reg_id,
        client_db->add_count,
        client_db->delete_count);

    if (avltree_is_empty(&client_db->tracked_prefix_tree)) {
        cprintf("    Tracked prefixes: (none)\n");
        return;
    }

    ITERATE_AVL_TREE_BEGIN(&client_db->tracked_prefix_tree, node) {

        rtm_tracked_prefix_t *tracked =
            avltree_container_of(node, rtm_tracked_prefix_t, glue);

        cmn_prefix_to_string(&tracked->tracked_prefix, &prefix_str);
        cprintf("    Tracked prefix: %s\n", prefix_str);

    } ITERATE_AVL_TREE_END;
}

static void
rtm_tracker_notify_client_inh_update (
        rtm_tracker_client_db_t *client_db,
        rtm_presentation_data_t *presentation_data) {

    rtm_tracker_client_data_t client_data;

    if (!client_db || !client_db->callback || !presentation_data ||
        !presentation_data->inh)
        return;

    /* Notify only if this INH is one the client asked to track. */
    if (!rtm_tracker_lookup_tracked_prefix(client_db,
                                           &presentation_data->inh->prefix))
        return;

    memset(&client_data, 0, sizeof(client_data));
    client_data.tracked_prefix = presentation_data->inh->prefix;
    client_data.route = presentation_data->route;
    client_data.dnhidx = presentation_data->nh ? presentation_data->nh->idx : 0;
    client_data.add = (presentation_data->operation == RTM_PPT_OP_ADD);

    client_db->callback(&presentation_data->inh->prefix,
                        &client_db->client_id,
                        &client_data);

    if (client_data.add)
        client_db->add_count++;
    else
        client_db->delete_count++;
}

static void 
rtm_tracker_inh_update_to_client(rtm_t *rtm, 
                                 rtm_presentation_data_t *presentation_data) {

    char client_id_str[160];
    char vrf_str[16];
    char prefix_str[48];
    char nh_str[48];
    char inh_str[48];
    rtm_tracker_t *tracker;
    rtm_tracker_client_id_t client_id;
    rtm_tracker_client_db_t *client_db;

    if (!rtm || !presentation_data || !presentation_data->rtm_nh_proto)
        return;

    tracker = rtm->nh_tracker;

    rtm_tracker_client_id_from_nh_proto(&client_id, presentation_data->rtm_nh_proto);

    client_db = rtm_tracker_lookup_client_db_by_id(tracker, &client_id);
    if (client_db) {
        rtm_tracker_notify_client_inh_update(client_db,
                                             presentation_data);
        return;
    }

    snprintf(vrf_str, sizeof(vrf_str), "%u",
             (unsigned)client_id.vrf_id);
             
    rtm_format_redist_target_client_id(
        client_id.proto,
        vrf_str,
        client_id.instance_no,
        client_id_str,
        sizeof(client_id_str));

    tracer(
        rtm->node->cptr, DRTM_DET,
        "RTM[%s] : No client [%s sub_proto %s] found for NH Tracker : "
        "Route %s, Nexthop %s, Indirect NH %s, "
        "operation %s, nh_idx %u, inh_idx %u\n",
        rtm->name,
        client_id_str,
        rtm_sub_proto_to_string(client_id.sub_proto),
        rtm_format_prefix(&presentation_data->route, prefix_str, sizeof(prefix_str)),
        presentation_data->nh
            ? rtm_format_nexthop(&presentation_data->nh->prefix, nh_str, sizeof(nh_str))
            : "None",
        presentation_data->inh
            ? rtm_format_nexthop(&presentation_data->inh->prefix, inh_str, sizeof(inh_str))
            : "None",
        presentation_data->operation == RTM_PPT_OP_ADD ? "Add" :
            (presentation_data->operation == RTM_PPT_OP_DELETE ? "Delete" : "Unknown"),
        presentation_data->nh ? presentation_data->nh->idx : 0,
        presentation_data->inh ? presentation_data->inh->idx : 0
    );
}

void
rtm_publish_to_nhtracker (rtm_t *rtm, rtm_presentation_data_t *presentation_data) {

    char prefix_str[48];
    char nh_str[48];
    char inh_str[48];

    if (!rtm || !presentation_data)
        return;

    tracer(
        rtm->node->cptr, DRTM,
        "RTM[%s] : Publishing to NH Tracker : Route %s, Nexthop %s, Indirect NH %s, "
        "operation %s, nh_idx %u, inh_idx %u\n",
        rtm->name,
        rtm_format_prefix(&presentation_data->route, prefix_str, sizeof(prefix_str)),
        presentation_data->nh
            ? rtm_format_nexthop(&presentation_data->nh->prefix, nh_str, sizeof(nh_str))
            : "None",
        presentation_data->inh
            ? rtm_format_nexthop(&presentation_data->inh->prefix, inh_str, sizeof(inh_str))
            : "None",
        presentation_data->operation == RTM_PPT_OP_ADD ? "Add" :
            (presentation_data->operation == RTM_PPT_OP_DELETE ? "Delete" : "Unknown"),
        presentation_data->nh ? presentation_data->nh->idx : 0,
        presentation_data->inh ? presentation_data->inh->idx : 0
    );

    /* If this is INH, then inform the regstered client about the new nexthop add/del */
    if (presentation_data->inh) {
        rtm_tracker_inh_update_to_client(rtm, presentation_data);
    }
}

void 
rtm_tracker_request_nh_tracker_db_replay (
        rtm_t *rtm, uintptr_t registration_id) {

    rtm_nh *inh;
    rtm_nh *dnh;
    rtm_tracker_t *tracker;
    glthread_t *nh_lst;
    glthread_t *curr;
    glthread_t *dnh_glue;
    glthread_data_node_t *data_node;
    avltree_node_t *node;
    rtm_tracked_prefix_t *tracked;
    rtm_tracker_client_db_t *client_db;
    rtm_tracker_client_data_t client_data;
    rtm_tracker_client_id_t client_id;

    if (!rtm || !registration_id)
        return;

    tracker = rtm->nh_tracker;
    if (!tracker)
        return;

    client_db = rtm_tracker_lookup_client_db_by_registration_id(tracker, registration_id);
    if (!client_db || !client_db->callback)
        return;

    client_id = client_db->client_id;

    ITERATE_AVL_TREE_BEGIN(&client_db->tracked_prefix_tree, node) {

        tracked =
            avltree_container_of(node, rtm_tracked_prefix_t, glue);

        nh_lst = &rtm->nhs_by_src[client_db->client_id.proto];

        ITERATE_GLTHREAD_BEGIN(nh_lst, curr) {

            inh = src_glue_to_rtm_nh(curr);
            if (!inh->is_indirect)
                continue;
            if (!inh->is_active)
                continue;
            if (!rtm_nh_is_resolved(inh))
                continue;
            if (!inh->rtm_nh_proto)
                continue;
            {
                rtm_tracker_client_id_t client_id;

                rtm_tracker_client_id_from_nh_proto(&client_id, inh->rtm_nh_proto);
                if (!rtm_tracker_client_id_matches(&client_id, &client_id))
                    continue;
            }
            if (cmn_prefix_compare(&inh->prefix, &tracked->tracked_prefix) != 0)
                continue;
            if (!inh->resolved_via_route)
                continue;

            ITERATE_GLTHREAD_BEGIN(&inh->direct_nh_list.head, dnh_glue) {

                data_node = glue_to_glthread_data_node(dnh_glue);
                dnh = (rtm_nh *)data_node->data;
                memset(&client_data, 0, sizeof(client_data));
                client_data.tracked_prefix = inh->prefix;
                client_data.route = inh->resolved_via_route->prefix;
                client_data.dnhidx = dnh->idx;
                client_data.add = true;
                client_db->callback(&inh->prefix, &client_id, &client_data);
                client_db->add_count++;

            } ITERATE_GLTHREAD_END(&inh->direct_nh_list.head, dnh_glue);

        } ITERATE_GLTHREAD_END(nh_lst, curr);

    } ITERATE_AVL_TREE_END;
}