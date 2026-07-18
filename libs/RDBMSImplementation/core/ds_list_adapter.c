/*
 * Reference storage engine: a sorted singly linked list behind the generic
 * rdbms_ds_ops_t vtable. It honours the same external contract as the B+tree
 * adapter (unique keys, key/value ownership, ordered scan) so it is a drop-in
 * replacement, proving the storage layer is pluggable.
 *
 * Key ownership matches the B+tree: the engine takes over the key->key buffer
 * on a successful insert and frees it (via libc free) on remove/destroy;
 * values are freed via the configured free_fn.
 */

#include <stdlib.h>
#include "rdbms_ds.h"

typedef struct list_node_ {

    BPluskey_t key;
    void *value;
    struct list_node_ *next;

} list_node_t;

typedef struct list_engine_ {

    list_node_t *head;
    ds_key_cmp_fn cmp_fn;
    ds_value_free_fn free_fn;
    key_mdata_t *key_mdata;
    int key_mdata_size;

} list_engine_t;

static void *
list_create (const rdbms_ds_config_t *cfg) {

    list_engine_t *e = (list_engine_t *) calloc (1, sizeof (list_engine_t));
    if (!e) return NULL;

    e->head = NULL;
    e->cmp_fn = cfg->cmp_fn;
    e->free_fn = cfg->free_fn ? cfg->free_fn : free;
    e->key_mdata = cfg->key_mdata;
    e->key_mdata_size = cfg->key_mdata_size;
    return e;
}

static void
list_destroy (void *impl) {

    list_engine_t *e = (list_engine_t *) impl;
    list_node_t *n, *nx;

    if (!e) return;

    for (n = e->head; n; n = nx) {
        nx = n->next;
        free (n->key.key);
        if (e->free_fn) e->free_fn (n->value);
        free (n);
    }
    free (e);
}

/*
 * Keep the list sorted ascending by the comparison contract (cmp > 0 means the
 * first key is smaller). Reject duplicate keys just like the B+tree.
 */
static bool
list_insert (void *impl, BPluskey_t *key, void *value) {

    list_engine_t *e = (list_engine_t *) impl;
    list_node_t **pp = &e->head;
    list_node_t *n;

    while (*pp) {

        int c = e->cmp_fn (&(*pp)->key, key, e->key_mdata, e->key_mdata_size);

        if (c == 0) return false;             /* duplicate key */
        if (c > 0) { pp = &(*pp)->next; continue; }  /* (*pp) < key -> advance */
        break;                                /* (*pp) > key -> insert here */
    }

    n = (list_node_t *) calloc (1, sizeof (list_node_t));
    if (!n) return false;

    n->key = *key;    /* take ownership of key->key buffer */
    n->value = value;
    n->next = *pp;
    *pp = n;
    return true;
}

static void *
list_query (void *impl, BPluskey_t *key) {

    list_engine_t *e = (list_engine_t *) impl;
    list_node_t *n;

    for (n = e->head; n; n = n->next) {

        int c = e->cmp_fn (&n->key, key, e->key_mdata, e->key_mdata_size);
        if (c == 0) return n->value;
        if (c < 0) break;    /* passed the slot (n > key) in a sorted list */
    }
    return NULL;
}

static bool
list_remove (void *impl, BPluskey_t *key) {

    list_engine_t *e = (list_engine_t *) impl;
    list_node_t **pp = &e->head;

    while (*pp) {

        int c = e->cmp_fn (&(*pp)->key, key, e->key_mdata, e->key_mdata_size);

        if (c == 0) {
            list_node_t *n = *pp;
            *pp = n->next;
            free (n->key.key);
            if (e->free_fn) e->free_fn (n->value);
            free (n);
            return true;
        }
        if (c < 0) break;    /* passed the slot */
        pp = &(*pp)->next;
    }
    return false;
}

static void
list_cursor_reset (void *impl, rdbms_ds_cursor_t *cur) {

    (void) impl;
    cur->node = NULL;
    cur->index = 0;
}

/*
 * Cursor contract: {node == NULL, index == 0} means "before first". After the
 * first fetch, cur->node stashes the NEXT node to return and index marks the
 * scan as started (so a NULL node then means "exhausted").
 *
 * On exhaustion the cursor is reset back to {NULL, 0} so the next call restarts
 * the scan. This mirrors BPlusTree_get_next_record and is what the nested-loop
 * join relies on when it re-scans an inner table.
 */
static void *
list_cursor_next (void *impl, rdbms_ds_cursor_t *cur, BPluskey_t **key_out) {

    list_engine_t *e = (list_engine_t *) impl;
    list_node_t *cn;

    if (cur->node == NULL && cur->index == 0) {
        cn = e->head;                       /* not started -> first */
    } else {
        cn = (list_node_t *) cur->node;     /* next to return (may be NULL) */
    }

    if (!cn) {
        cur->node = NULL;                   /* reset so a re-scan restarts */
        cur->index = 0;
        if (key_out) *key_out = NULL;
        return NULL;
    }

    cur->node = cn->next;
    cur->index = 1;
    if (key_out) *key_out = &cn->key;
    return cn->value;
}

static const rdbms_ds_ops_t list_ops = {

    "list",
    list_create,
    list_destroy,
    list_insert,
    list_query,
    list_remove,
    list_cursor_reset,
    list_cursor_next
};

const rdbms_ds_ops_t *
rdbms_ds_list_ops (void) {

    return &list_ops;
}
