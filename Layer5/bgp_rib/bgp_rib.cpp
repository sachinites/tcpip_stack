#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* Hashtable is compiled with g++ into libs/libstd.a (C++ linkage). */
#include "../../libs/c-hashtable/hashtable.h"
#include "../../libs/c-hashtable/hashtable_itr.h"

#include "bgp_rib.h"
#include "bgp_nlri_key.h"
#include "bgp_nlri_wire.h"

#define BGP_RIB_HT_MIN_SIZE  128

typedef struct bgp_rib_ {
    uint8_t                 afi;
    uint8_t                 safi;
    hashtable_t            *routes;
    bgp_rib_export_route_cb export_route;
    void                    *bgp_instance;
} bgp_rib_t;

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

    return rib;
}

void
bgp_rib_destroy(bgp_rib_t *rib)
{
    if (rib->routes) {
        hashtable_destroy(rib->routes, 1);
        rib->routes = NULL;
    }

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

bgp_rib_err_t
bgp_rib_route_add(bgp_rib_t *rib,
                  const bgp_nlri_key_t *key,
                  const bgp_rib_attrs_t *attrs)
{
    bgp_rib_attrs_t *stored_attrs;
    bgp_nlri_key_t *stored_key;
    bgp_rib_attrs_t *existing;

    if (!rib || !key || key->wire_len == 0 || !attrs) {
        return BGP_RIB_ERR_NULL;
    }

    existing = (bgp_rib_attrs_t *)hashtable_search(
            rib->routes, (void *)key);

    if (existing) {
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

    if (!hashtable_insert(rib->routes, stored_key, stored_attrs)) {
        bgp_nlri_key_free(stored_key);
        free(stored_attrs);
        return BGP_RIB_ERR_NOMEM;
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
    bgp_rib_attrs_t *attrs;

    if (!rib || !key || key->wire_len == 0) {
        return BGP_RIB_ERR_NULL;
    }

    attrs = (bgp_rib_attrs_t *)hashtable_remove(
            rib->routes, (void *)key);
    if (!attrs) {
        return BGP_RIB_ERR_NOT_FOUND;
    }

    if (rib->export_route) {
        rib->export_route(rib->bgp_instance, rib->afi, rib->safi,
                          (bgp_nlri_key_t *)key, attrs, false, 0);
    }

    free(attrs);
    return BGP_RIB_OK;
}

const bgp_rib_attrs_t *
bgp_rib_route_lookup(const bgp_rib_t *rib,
                     const bgp_nlri_key_t *key)
{
    const bgp_rib_attrs_t *attrs;
    bgp_rib_t *mutable_rib;

    if (!rib || !key || key->wire_len == 0) {
        return NULL;
    }

    /* Lock required; caller must treat returned pointer as ephemeral. */
    mutable_rib = (bgp_rib_t *)rib;
    attrs = (const bgp_rib_attrs_t *)hashtable_search(
            rib->routes, (void *)key);
    return attrs;
}

typedef struct bgp_rib_export_all_ctx_ {
    bgp_rib_t *rib;
    uint16_t   target_vrf_id;
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

    rib->export_route(rib->bgp_instance, rib->afi, rib->safi,
                      (bgp_nlri_key_t *)key,
                      (bgp_rib_attrs_t *)attrs,
                      true,
                      ctx->target_vrf_id);
    return 0;
}

void
bgp_rib_export_all(bgp_rib_t *rib,
                   uint16_t target_vrf_id)
{
    bgp_rib_export_all_ctx_t ctx;

    if (!rib || !rib->export_route) {
        return;
    }

    ctx.rib = rib;
    ctx.target_vrf_id = target_vrf_id;
    bgp_rib_route_walk(rib, bgp_rib_export_all_walk_cb, &ctx);
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

    /*
     * hashtable_iterator() leaves e==NULL when the table is empty.
     * Calling hashtable_iterator_key() in that state segfaults.
     */
    if (hashtable_count(rib->routes) == 0) {
        return;
    }

    itr = hashtable_iterator(rib->routes);
    if (!itr) {
        return;
    }

    do {
        const bgp_nlri_key_t *key;
        const bgp_rib_attrs_t *attrs;

        key = (const bgp_nlri_key_t *)hashtable_iterator_key(itr);
        attrs = (const bgp_rib_attrs_t *)hashtable_iterator_value(itr);
        if (!key || !attrs) {
            break;
        }

        if (cb(key, attrs, userdata) != 0) {
            break;
        }
    } while (hashtable_iterator_advance(itr));

    free(itr);
}

unsigned int
bgp_rib_route_count(const bgp_rib_t *rib)
{
    unsigned int count;
    bgp_rib_t *mutable_rib;

    if (!rib || !rib->routes) {
        return 0;
    }

    mutable_rib = (bgp_rib_t *)rib;
    count = hashtable_count(rib->routes);
    return count;
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
        const bgp_nlri_key_t *key =
            (const bgp_nlri_key_t *)hashtable_iterator_key(itr);
        const bgp_rib_attrs_t *attrs =
            (const bgp_rib_attrs_t *)hashtable_iterator_value(itr);

        if (!key || !attrs) {
            break;
        }

        bgp_nlri_wire_print_route(rib->afi, rib->safi, key, attrs, fp);
    } while (hashtable_iterator_advance(itr));

    free(itr);
}
