#include <stdlib.h>
#include <string.h>

extern "C" {
#include "../../libs/c-hashtable/hashtable.h"
#include "../../libs/c-hashtable/hashtable_itr.h"
}

#include "bgp_rib.h"
#include "bgp_nlri_key.h"
#include "bgp_nlri_wire.h"

#define BGP_RIB_HT_MIN_SIZE  128

typedef struct bgp_rib_ {
    uint8_t      afi;
    uint8_t      safi;
    hashtable_t *routes;
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
    if (!rib) {
        return;
    }

    if (rib->routes) {
        hashtable_destroy(rib->routes, 1);
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
        memcpy(existing, attrs, sizeof(*existing));
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

    free(attrs);
    return BGP_RIB_OK;
}

const bgp_rib_attrs_t *
bgp_rib_route_lookup(const bgp_rib_t *rib,
                     const bgp_nlri_key_t *key)
{
    if (!rib || !key || key->wire_len == 0) {
        return NULL;
    }

    return (const bgp_rib_attrs_t *)hashtable_search(
            rib->routes, (void *)key);
}

void
bgp_rib_route_walk(bgp_rib_t *rib,
                   bgp_rib_walk_cb cb,
                   void *userdata)
{
    struct hashtable_itr *itr;

    if (!rib || !cb) {
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

        if (cb(key, attrs, userdata) != 0) {
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

    if (!rib || !fp) {
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

        bgp_nlri_wire_print_route(rib->afi, rib->safi, key, attrs, fp);
    } while (hashtable_iterator_advance(itr));

    free(itr);
}
