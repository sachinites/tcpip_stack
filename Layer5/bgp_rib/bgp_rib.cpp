#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>

/* Hashtable is compiled with g++ into libs/libstd.a (C++ linkage). */
#include "../../libs/c-hashtable/hashtable.h"
#include "../../libs/c-hashtable/hashtable_itr.h"

#include "../../libs/Tree/libtree.h"
#include "../../libs/common/cmn_prefix.h"
#include "../../tcpconst.h"

#include "../../RTM/rtm_nhtracker.h"
#include "../../vrf/vrf.h"

#include "../bgp_rtr.h"

#include "bgp_rib.h"
#include "bgp_nlri_key.h"
#include "bgp_nlri_wire.h"

#define BGP_RIB_HT_MIN_SIZE  128

typedef struct bgp_rib_route_entry_ {
    bgp_nlri_key_t   *key;
    bgp_rib_attrs_t  *attrs;
    cmn_prefix_t      nh_prefix;
    bool              nh_indexed;
    avltree_node_t    nlri_glue;
} bgp_rib_route_entry_t;

typedef struct bgp_rib_nh_bucket_ {
    cmn_prefix_t     nexthop;
    avltree_t        routes;
    avltree_node_t   glue;
} bgp_rib_nh_bucket_t;

typedef struct bgp_rib_ {
    uint8_t                 afi;
    uint8_t                 safi;
    hashtable_t            *routes;
    avltree_t               routes_by_nh;
    bgp_rib_export_route_cb export_route;
    void                    *bgp_instance;
    uintptr_t               nh_tracker_reg_id;
} bgp_rib_t;

/*
 * Same AFI/SAFI -> RTM mapping as bgp_global_rib_nhtracker_rtm():
 *   IPv4 unicast  -> def_vrf->inet0
 *   VPNv4         -> def_vrf->inet0
 *   L2VPN EVPN    -> def_vrf->inet0
 */
static rtm_t *
bgp_rib_nh_tracker_rtm(const bgp_rib_t *rib)
{
    bgp_inst_t *bgp;
    def_vrf_t *def_vrf;

    if (!rib || !rib->bgp_instance) {
        return NULL;
    }

    bgp = (bgp_inst_t *)rib->bgp_instance;
    if (!bgp->node) {
        return NULL;
    }

    def_vrf = (def_vrf_t *)NODE_DEF_VRF(bgp->node);
    if (!def_vrf) {
        return NULL;
    }

    if (rib->afi == AFI_IPV4 && rib->safi == SAFI_UNICAST) {
        return def_vrf->vrf.inet0;
    }
    if (rib->afi == AFI_IPV4 && rib->safi == SAFI_MPLS_VPN) {
        return def_vrf->vrf.inet0;
    }
    if (rib->afi == AFI_L2VPN && rib->safi == SAFI_MPLS_EVPN) {
        return def_vrf->vrf.inet0;
    }

    return NULL;
}

static void
bgp_rtm_track_inh_prefix(bgp_rib_t *rib, const cmn_prefix_t *nexthop)
{
    rtm_t *rtm;

    if (!rib || !nexthop || !rib->nh_tracker_reg_id) {
        return;
    }

    rtm = bgp_rib_nh_tracker_rtm(rib);
    if (!rtm) {
        return;
    }

    rtm_track(rtm, (cmn_prefix_t *)nexthop, rib->nh_tracker_reg_id);
}

static void
bgp_rib_nh_bucket_rtm_untrack(bgp_rib_t *rib, const cmn_prefix_t *nexthop)
{
    rtm_t *rtm;

    if (!rib || !nexthop || !rib->nh_tracker_reg_id) {
        return;
    }

    rtm = bgp_rib_nh_tracker_rtm(rib);
    if (!rtm) {
        return;
    }

    rtm_untrack(rtm, (cmn_prefix_t *)nexthop, rib->nh_tracker_reg_id);
}

static bgp_rib_attrs_t *
bgp_rib_attrs_dup(const bgp_rib_attrs_t *attrs)
{
    bgp_rib_attrs_t *copy;

    if (!attrs) {
        return NULL;
    }

    copy = (bgp_rib_attrs_t *)calloc(1, sizeof(*copy));
    if (!copy) {
        return NULL;
    }

    memcpy(copy, attrs, sizeof(*copy));
    return copy;
}

static bgp_rib_route_entry_t *
bgp_rib_route_entry_alloc(bgp_nlri_key_t *key,
                          bgp_rib_attrs_t *attrs)
{
    bgp_rib_route_entry_t *entry;

    if (!key || !attrs) {
        return NULL;
    }

    entry = (bgp_rib_route_entry_t *)calloc(1, sizeof(*entry));
    if (!entry) {
        return NULL;
    }

    entry->key = key;
    entry->attrs = attrs;
    return entry;
}

static void
bgp_rib_route_entry_free(bgp_rib_route_entry_t *entry)
{
    if (!entry) {
        return;
    }

    bgp_nlri_key_free(entry->key);
    free(entry->attrs);
    free(entry);
}

static int
bgp_rib_nh_bucket_compare(const avltree_node_t *node1,
                          const avltree_node_t *node2)
{
    bgp_rib_nh_bucket_t *b1 =
        avltree_container_of(node1, bgp_rib_nh_bucket_t, glue);
    bgp_rib_nh_bucket_t *b2 =
        avltree_container_of(node2, bgp_rib_nh_bucket_t, glue);

    return cmn_prefix_compare(&b1->nexthop, &b2->nexthop);
}

static int
bgp_rib_route_entry_nlri_compare(const avltree_node_t *node1,
                                 const avltree_node_t *node2)
{
    bgp_rib_route_entry_t *e1 =
        avltree_container_of(node1, bgp_rib_route_entry_t, nlri_glue);
    bgp_rib_route_entry_t *e2 =
        avltree_container_of(node2, bgp_rib_route_entry_t, nlri_glue);

    return bgp_nlri_key_cmp(e1->key, e2->key);
}

static bool
bgp_rib_attrs_to_nh_prefix(const bgp_rib_attrs_t *attrs,
                           cmn_prefix_t *nh_prefix)
{
    char nh_cidr[72];

    if (!attrs || !nh_prefix || attrs->nexthop[0] == '\0') {
        return false;
    }

    memset(nh_prefix, 0, sizeof(*nh_prefix));

    if (strchr(attrs->nexthop, '/')) {
        strncpy(nh_cidr, attrs->nexthop, sizeof(nh_cidr) - 1);
        nh_cidr[sizeof(nh_cidr) - 1] = '\0';
    } else {
        snprintf(nh_cidr, sizeof(nh_cidr), "%s/32", attrs->nexthop);
    }

    return cmn_parse_prefix_string(nh_cidr, nh_prefix);
}

static bgp_rib_nh_bucket_t *
bgp_rib_lookup_create_nh_bucket(bgp_rib_t *rib,
                         const cmn_prefix_t *nh_prefix,
                         bool create)
{
    bgp_rib_nh_bucket_t template_bucket;
    bgp_rib_nh_bucket_t *bucket;
    avltree_node_t *node;

    if (!rib || !nh_prefix) {
        return NULL;
    }

    memset(&template_bucket, 0, sizeof(template_bucket));
    template_bucket.nexthop = *nh_prefix;
    avltree_node_init(&template_bucket.glue);

    node = avltree_lookup(&template_bucket.glue, &rib->routes_by_nh);
    if (node) {
        return avltree_container_of(node, bgp_rib_nh_bucket_t, glue);
    }

    if (!create) {
        return NULL;
    }

    bucket = (bgp_rib_nh_bucket_t *)calloc(1, sizeof(*bucket));
    if (!bucket) {
        return NULL;
    }

    bucket->nexthop = *nh_prefix;
    avltree_init(&bucket->routes, bgp_rib_route_entry_nlri_compare);
    avltree_node_init(&bucket->glue);
    avltree_insert(&bucket->glue, &rib->routes_by_nh);
    bgp_rtm_track_inh_prefix(rib, &bucket->nexthop);
    return bucket;
}

static void
bgp_rib_nh_index_remove(bgp_rib_t *rib, bgp_rib_route_entry_t *entry)
{
    bgp_rib_nh_bucket_t *bucket;

    if (!rib || !entry || !entry->nh_indexed) {
        return;
    }

    bucket = bgp_rib_lookup_create_nh_bucket(rib, &entry->nh_prefix, false);
    if (!bucket) {
        entry->nh_indexed = false;
        return;
    }

    avltree_remove(&entry->nlri_glue, &bucket->routes);

    entry->nh_indexed = false;

    if (avltree_is_empty(&bucket->routes)) {
        bgp_rib_nh_bucket_rtm_untrack(rib, &bucket->nexthop);
        avltree_remove(&bucket->glue, &rib->routes_by_nh);
        free(bucket);
    }
}

static bgp_rib_err_t
bgp_rib_nh_index_insert(bgp_rib_t *rib, bgp_rib_route_entry_t *entry)
{
    bgp_rib_nh_bucket_t *bucket;
    cmn_prefix_t nh_prefix;

    if (!rib || !entry) {
        return BGP_RIB_ERR_NULL;
    }

    if (!bgp_rib_attrs_to_nh_prefix(entry->attrs, &nh_prefix)) {
        return BGP_RIB_OK;
    }

    bucket = bgp_rib_lookup_create_nh_bucket(rib, &nh_prefix, true);
    if (!bucket) {
        return BGP_RIB_ERR_NOMEM;
    }

    entry->nh_prefix = nh_prefix;
    avltree_node_init(&entry->nlri_glue);
    avltree_insert(&entry->nlri_glue, &bucket->routes);
    entry->nh_indexed = true;
    return BGP_RIB_OK;
}

static bgp_rib_route_entry_t *
bgp_rib_entry_lookup(bgp_rib_t *rib, const bgp_nlri_key_t *key)
{
    if (!rib || !key) {
        return NULL;
    }

    return (bgp_rib_route_entry_t *)hashtable_search(rib->routes, (void *)key);
}

bgp_rib_t *
bgp_rib_create(uint8_t afi, uint8_t safi)
{
    bgp_rib_t *rib;

    rib = (bgp_rib_t *)calloc(1, sizeof(*rib));
    if (!rib) {
        return NULL;
    }

    rib->afi = afi;
    rib->safi = safi;
    rib->routes = create_hashtable(BGP_RIB_HT_MIN_SIZE,
                                   bgp_nlri_key_hash_fn,
                                   bgp_nlri_key_equal_fn);
    if (!rib->routes) {
        free(rib);
        return NULL;
    }

    avltree_init(&rib->routes_by_nh, bgp_rib_nh_bucket_compare);
    return rib;
}

static void
bgp_rib_clear_routes(bgp_rib_t *rib)
{
    struct hashtable_itr *itr;
    bgp_nlri_key_t key_copy;

    if (!rib || !rib->routes) {
        return;
    }

    while (hashtable_count(rib->routes) > 0) {
        const bgp_nlri_key_t *key;

        itr = hashtable_iterator(rib->routes);
        if (!itr) {
            break;
        }

        key = (const bgp_nlri_key_t *)hashtable_iterator_key(itr);
        if (!key) {
            free(itr);
            break;
        }

        key_copy = *key;
        free(itr);
        bgp_rib_route_delete(rib, &key_copy);
    }
}

void
bgp_rib_nh_tracker_unregister(bgp_rib_t *rib)
{
    rtm_t *rtm;

    if (!rib || !rib->nh_tracker_reg_id) {
        return;
    }

    rtm = bgp_rib_nh_tracker_rtm(rib);
    if (rtm) {
        rtm_tracker_unregister_client(rtm, rib->nh_tracker_reg_id);
    }

    rib->nh_tracker_reg_id = 0;
}

uintptr_t
bgp_rib_nh_tracker_reg_id(const bgp_rib_t *rib)
{
    return rib ? rib->nh_tracker_reg_id : 0;
}

void
bgp_rib_destroy(bgp_rib_t *rib)
{
    if (!rib) {
        return;
    }

    bgp_rib_clear_routes(rib);
    bgp_rib_nh_tracker_unregister(rib);

    if (rib->routes) {
        hashtable_destroy(rib->routes, 0);
        rib->routes = NULL;
    }

    assert(avltree_is_empty(&rib->routes_by_nh));
    free(rib);
}

uint8_t
bgp_rib_get_afi(const bgp_rib_t *rib)
{
    return rib ? rib->afi : 0;
}

uint8_t
bgp_rib_get_safi(const bgp_rib_t *rib)
{
    return rib ? rib->safi : 0;
}

void
bgp_rib_set_export_route(bgp_rib_t *rib,
                         void *bgp_instance,
                         bgp_rib_export_route_cb export_route)
{
    if (!rib) {
        return;
    }

    rib->bgp_instance = bgp_instance;
    rib->export_route = export_route;
}

void
bgp_rib_set_nh_tracker(bgp_rib_t *rib,
                       uintptr_t nh_tracker_reg_id)
{
    avltree_node_t *node;

    if (!rib) {
        return;
    }

    rib->nh_tracker_reg_id = nh_tracker_reg_id;

    if (!rib->nh_tracker_reg_id) {
        return;
    }

    ITERATE_AVL_TREE_BEGIN(&rib->routes_by_nh, node) {

        bgp_rib_nh_bucket_t *bucket =
            avltree_container_of(node, bgp_rib_nh_bucket_t, glue);

        bgp_rtm_track_inh_prefix(rib, &bucket->nexthop);
        
    } ITERATE_AVL_TREE_END;
}

bgp_rib_err_t
bgp_rib_route_add(bgp_rib_t *rib,
                  const bgp_nlri_key_t *key,
                  const bgp_rib_attrs_t *attrs)
{
    bgp_rib_route_entry_t *entry;
    bgp_rib_attrs_t *stored_attrs;
    bgp_nlri_key_t *stored_key;
    bgp_rib_err_t rc;

    if (!rib || !key || key->wire_len == 0 || !attrs) {
        return BGP_RIB_ERR_NULL;
    }

    entry = bgp_rib_entry_lookup(rib, key);
    if (entry) {
        bgp_rib_nh_index_remove(rib, entry);
        memcpy(entry->attrs, attrs, sizeof(*entry->attrs));
        rc = bgp_rib_nh_index_insert(rib, entry);
        if (rc != BGP_RIB_OK) {
            return rc;
        }

        if (rib->export_route) {
            rib->export_route(rib->bgp_instance, rib->afi, rib->safi,
                              entry->key, entry->attrs, true, 0);
        }
        return BGP_RIB_OK;
    }

    stored_key = bgp_nlri_key_dup(key);
    if (!stored_key) {
        return BGP_RIB_ERR_NOMEM;
    }

    stored_attrs = bgp_rib_attrs_dup(attrs);
    if (!stored_attrs) {
        bgp_nlri_key_free(stored_key);
        return BGP_RIB_ERR_NOMEM;
    }

    entry = bgp_rib_route_entry_alloc(stored_key, stored_attrs);
    if (!entry) {
        bgp_nlri_key_free(stored_key);
        free(stored_attrs);
        return BGP_RIB_ERR_NOMEM;
    }

    if (!hashtable_insert(rib->routes, stored_key, entry)) {
        bgp_rib_route_entry_free(entry);
        return BGP_RIB_ERR_NOMEM;
    }

    rc = bgp_rib_nh_index_insert(rib, entry);
    if (rc != BGP_RIB_OK) {
        hashtable_remove(rib->routes, stored_key);
        bgp_rib_route_entry_free(entry);
        return rc;
    }

    if (rib->export_route) {
        rib->export_route(rib->bgp_instance, rib->afi, rib->safi,
                          stored_key, stored_attrs, true, 0);
    }

    return BGP_RIB_OK;
}

bgp_rib_err_t
bgp_rib_route_delete(bgp_rib_t *rib,
                     const bgp_nlri_key_t *key)
{
    bgp_rib_route_entry_t *entry;

    if (!rib || !key || key->wire_len == 0) {
        return BGP_RIB_ERR_NULL;
    }

    entry = (bgp_rib_route_entry_t *)hashtable_remove(rib->routes, (void *)key);
    if (!entry) {
        return BGP_RIB_ERR_NOT_FOUND;
    }

    if (rib->export_route) {
        rib->export_route(rib->bgp_instance, rib->afi, rib->safi,
                          entry->key, entry->attrs, false, 0);
    }

    bgp_rib_nh_index_remove(rib, entry);
    bgp_rib_route_entry_free(entry);
    return BGP_RIB_OK;
}

const bgp_rib_attrs_t *
bgp_rib_route_lookup(const bgp_rib_t *rib,
                     const bgp_nlri_key_t *key)
{
    bgp_rib_route_entry_t *entry;

    if (!rib || !key || key->wire_len == 0) {
        return NULL;
    }

    entry = bgp_rib_entry_lookup((bgp_rib_t *)rib, key);
    if (!entry) {
        return NULL;
    }

    return entry->attrs;
}

unsigned int
bgp_rib_route_count_by_nh(const bgp_rib_t *rib,
                          const cmn_prefix_t *nh_prefix)
{
    bgp_rib_nh_bucket_t *bucket;
    avltree_node_t *node;
    unsigned int count = 0;

    if (!rib || !nh_prefix) {
        return 0;
    }

    bucket = bgp_rib_lookup_create_nh_bucket((bgp_rib_t *)rib, nh_prefix, false);
    if (!bucket) {
        return 0;
    }

    ITERATE_AVL_TREE_BEGIN(&bucket->routes, node) {
        (void)node;
        count++;
    }     ITERATE_AVL_TREE_END;

    return count;
}

typedef struct bgp_rib_export_all_ctx_ {
    bgp_rib_t *rib;
    uint16_t   target_vrf_id;
    uint8_t    export_route_type;
} bgp_rib_export_all_ctx_t;

static int
bgp_rib_export_all_walk_cb(const bgp_nlri_key_t *key,
                           const bgp_rib_attrs_t *attrs,
                           void *userdata)
{
    bgp_rib_export_all_ctx_t *ctx = (bgp_rib_export_all_ctx_t *)userdata;
    bgp_rib_t *rib = ctx->rib;

    if (!rib->export_route) {
        return 0;
    }

    if (rib->safi == SAFI_MPLS_EVPN && ctx->export_route_type != 0) {
        if (!key || key->wire_len == 0 ||
            key->wire[0] != ctx->export_route_type) {
            return 0;
        }
    }

    rib->export_route(rib->bgp_instance, rib->afi, rib->safi,
                      (bgp_nlri_key_t *)key,
                      (bgp_rib_attrs_t *)attrs,
                      true,
                      ctx->target_vrf_id);
    return 0;
}

void
bgp_rib_export_all(bgp_rib_t *rib,
                   uint16_t target_vrf_id,
                   uint8_t export_route_type)
{
    bgp_rib_export_all_ctx_t ctx;

    if (!rib || !rib->export_route) {
        return;
    }

    ctx.rib = rib;
    ctx.target_vrf_id = target_vrf_id;
    ctx.export_route_type = export_route_type;
    bgp_rib_route_walk(rib, bgp_rib_export_all_walk_cb, &ctx);
}

void
bgp_rib_route_walk_by_nh(bgp_rib_t *rib,
                         const cmn_prefix_t *nh_prefix,
                         bgp_rib_walk_cb cb,
                         void *userdata)
{
    bgp_rib_nh_bucket_t *bucket;
    avltree_node_t *node;

    if (!rib || !nh_prefix || !cb) {
        return;
    }

    bucket = bgp_rib_lookup_create_nh_bucket(rib, nh_prefix, false);
    if (!bucket) {
        return;
    }

    ITERATE_AVL_TREE_BEGIN(&bucket->routes, node) {
        bgp_rib_route_entry_t *entry =
            avltree_container_of(node, bgp_rib_route_entry_t, nlri_glue);

        if (cb(entry->key, entry->attrs, userdata) != 0) {
            break;
        }
    } ITERATE_AVL_TREE_END;
}

void
bgp_rib_nh_walk(bgp_rib_t *rib,
                bgp_rib_nh_walk_cb cb,
                void *userdata)
{
    avltree_node_t *node;

    if (!rib || !cb) {
        return;
    }

    ITERATE_AVL_TREE_BEGIN(&rib->routes_by_nh, node) {
        bgp_rib_nh_bucket_t *bucket =
            avltree_container_of(node, bgp_rib_nh_bucket_t, glue);
        unsigned int route_count = 0;
        avltree_node_t *inner;

        ITERATE_AVL_TREE_BEGIN(&bucket->routes, inner) {
            (void)inner;
            route_count++;
        } ITERATE_AVL_TREE_END;

        if (cb(&bucket->nexthop, route_count, userdata) != 0) {
            break;
        }
    } ITERATE_AVL_TREE_END;
}

void
bgp_rib_route_walk(bgp_rib_t *rib,
                   bgp_rib_walk_cb cb,
                   void *userdata)
{
    struct hashtable_itr *itr;

    if (!rib || !cb || !rib->routes) {
        return;
    }

    if (hashtable_count(rib->routes) == 0) {
        return;
    }

    itr = hashtable_iterator(rib->routes);
    if (!itr) {
        return;
    }

    do {
        bgp_rib_route_entry_t *entry;

        entry = (bgp_rib_route_entry_t *)hashtable_iterator_value(itr);
        if (!entry || !entry->key || !entry->attrs) {
            break;
        }

        if (cb(entry->key, entry->attrs, userdata) != 0) {
            break;
        }

    } while (hashtable_iterator_advance(itr));

    free(itr);
}

unsigned int
bgp_rib_route_count(const bgp_rib_t *rib)
{
    if (!rib || !rib->routes) {
        return 0;
    }

    return hashtable_count(rib->routes);
}

void
bgp_rib_print_routes(bgp_rib_t *rib, FILE *fp)
{
    struct hashtable_itr *itr;

    if (!rib || !fp || !rib->routes) {
        return;
    }

    if (hashtable_count(rib->routes) == 0) {
        return;
    }

    itr = hashtable_iterator(rib->routes);
    if (!itr) {
        return;
    }

    do {
        bgp_rib_route_entry_t *entry =
            (bgp_rib_route_entry_t *)hashtable_iterator_value(itr);

        if (!entry || !entry->key || !entry->attrs) {
            break;
        }

        bgp_nlri_wire_print_route(rib->afi, rib->safi,
                                  entry->key, entry->attrs, fp);
    } while (hashtable_iterator_advance(itr));

    free(itr);
}
