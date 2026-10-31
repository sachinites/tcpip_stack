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
rtm_tracker_client_id_compare (
        const rtm_tracker_client_id_t *id1,
        const rtm_tracker_client_id_t *id2) {

    if (id1->proto != id2->proto) {
        return (id1->proto < id2->proto) ? -1 : 1;
    }

    if (id1->vrf_id != id2->vrf_id) {
        return (id1->vrf_id < id2->vrf_id) ? -1 : 1;
    }

    if (id1->instance_no != id2->instance_no) {
        return (id1->instance_no < id2->instance_no) ? -1 : 1;
    }

    return 0;
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
    avltree_node_init(&client_db->avlnode_glue_client_id);
    avltree_node_init(&client_db->avlnode_glue_reg_id);
    avltree_insert(&client_db->avlnode_glue_client_id, &tracker->client_db_by_client_id);
    avltree_insert(&client_db->avlnode_glue_reg_id, &tracker->client_db_by_reg_id);

    return client_db->reg_id;
}

uintptr_t
rtm_tracker_reg_id_from_nh_proto (rtm_t *rtm, rtm_nh_proto_t *nh_proto) {

    rtm_tracker_t *tracker;
    rtm_tracker_client_id_t client_id;
    rtm_tracker_client_db_t *client_db;

    if (!rtm || !nh_proto)
        return 0;

    tracker = rtm->nh_tracker;
    if (!tracker)
        return 0;

    client_id.proto = nh_proto->proto;
    client_id.vrf_id = nh_proto->vrf_id;
    client_id.instance_no = (uint16_t)nh_proto->instance_no;

    client_db = rtm_tracker_lookup_client_db_by_id(tracker, &client_id);
    if (!client_db)
        return 0;

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

    if (!rtm || !prefix_to_track || !registration_id)
        return;

    tracker = rtm->nh_tracker;
    if (!tracker)
        return;

    (void)rtm_tracker_lookup_client_db_by_registration_id(tracker, registration_id);
}

void
rtm_untrack (
        rtm_t *rtm,
        cmn_prefix_t *prefix_to_track,
        uintptr_t registration_id) {

    rtm_tracker_t *tracker;

    if (!rtm || !prefix_to_track || !registration_id)
        return;

    tracker = rtm->nh_tracker;
    if (!tracker)
        return;

    (void)rtm_tracker_lookup_client_db_by_registration_id(tracker, registration_id);
}

void
show_rtm_tracker_client_db (rtm_tracker_client_db_t *client_db) {

    char client_id_str[160];
    char vrf_str[16];

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
        "  Tracker client : %s reg_id 0x%lx\n",
        client_id_str,
        (unsigned long)client_db->reg_id);
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
}
