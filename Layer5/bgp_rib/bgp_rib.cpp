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
    uint8_t      afi;
    uint8_t      safi;
    hashtable_t *routes;
    pthread_mutex_t lock;
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
    pthread_mutex_init(&rib->lock, NULL);
    rib->routes = create_hashtable(BGP_RIB_HT_MIN_SIZE,
                                   bgp_nlri_key_hash_fn,
                                   bgp_nlri_key_equal_fn);
    if (!rib->routes) {
        pthread_mutex_destroy(&rib->lock);
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

    pthread_mutex_lock(&rib->lock);
    if (rib->routes) {
        hashtable_destroy(rib->routes, 1);
        rib->routes = NULL;
    }
    pthread_mutex_unlock(&rib->lock);
    pthread_mutex_destroy(&rib->lock);

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

    pthread_mutex_lock(&rib->lock);

    existing = (bgp_rib_attrs_t *)hashtable_search(
            rib->routes, (void *)key);
    if (existing) {
        memcpy(existing, attrs, sizeof(*existing));
        pthread_mutex_unlock(&rib->lock);
        return BGP_RIB_OK;
    }

    stored_key = bgp_nlri_key_dup(key);
    if (!stored_key) {
        pthread_mutex_unlock(&rib->lock);
        return BGP_RIB_ERR_NOMEM;
    }

    stored_attrs = bgp_rib_attrs_dup(attrs);
    if (!stored_attrs) {
        bgp_nlri_key_free(stored_key);
        pthread_mutex_unlock(&rib->lock);
        return BGP_RIB_ERR_NOMEM;
    }

    if (!hashtable_insert(rib->routes, stored_key, stored_attrs)) {
        bgp_nlri_key_free(stored_key);
        free(stored_attrs);
        pthread_mutex_unlock(&rib->lock);
        return BGP_RIB_ERR_NOMEM;
    }

    pthread_mutex_unlock(&rib->lock);
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

    pthread_mutex_lock(&rib->lock);

    attrs = (bgp_rib_attrs_t *)hashtable_remove(
            rib->routes, (void *)key);
    if (!attrs) {
        pthread_mutex_unlock(&rib->lock);
        return BGP_RIB_ERR_NOT_FOUND;
    }

    free(attrs);
    pthread_mutex_unlock(&rib->lock);
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
    pthread_mutex_lock(&mutable_rib->lock);
    attrs = (const bgp_rib_attrs_t *)hashtable_search(
            rib->routes, (void *)key);
    pthread_mutex_unlock(&mutable_rib->lock);
    return attrs;
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

    pthread_mutex_lock(&rib->lock);

    /*
     * hashtable_iterator() leaves e==NULL when the table is empty.
     * Calling hashtable_iterator_key() in that state segfaults.
     */
    if (hashtable_count(rib->routes) == 0) {
        pthread_mutex_unlock(&rib->lock);
        return;
    }

    itr = hashtable_iterator(rib->routes);
    if (!itr) {
        pthread_mutex_unlock(&rib->lock);
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
    pthread_mutex_unlock(&rib->lock);
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
    pthread_mutex_lock(&mutable_rib->lock);
    count = hashtable_count(rib->routes);
    pthread_mutex_unlock(&mutable_rib->lock);
    return count;
}

void
bgp_rib_print_routes(bgp_rib_t *rib, FILE *fp)
{
    struct hashtable_itr *itr;

    if (!rib || !fp || !rib->routes) {
        return;
    }

    pthread_mutex_lock(&rib->lock);

    if (hashtable_count(rib->routes) == 0) {
        pthread_mutex_unlock(&rib->lock);
        return;
    }

    itr = hashtable_iterator(rib->routes);
    if (!itr) {
        pthread_mutex_unlock(&rib->lock);
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
    pthread_mutex_unlock(&rib->lock);
}
