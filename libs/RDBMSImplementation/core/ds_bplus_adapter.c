/*
 * Default storage engine: adapts the B+tree behind the generic rdbms_ds_ops_t
 * vtable. Behaviour is identical to calling the BPlusTree_* API directly.
 */

#include <stdlib.h>
#include "../BPlusTreeLib/BPlusTree.h"
#include "rdbms_ds.h"

static void *
bplus_create (const rdbms_ds_config_t *cfg) {

    BPlusTree_t *t = (BPlusTree_t *) calloc (1, sizeof (BPlusTree_t));
    if (!t) return NULL;

    BPlusTree_init (t,
                    cfg->cmp_fn,
                    NULL,
                    NULL,
                    cfg->max_children,
                    cfg->free_fn,
                    cfg->key_mdata,
                    cfg->key_mdata_size);
    return t;
}

static void
bplus_destroy (void *impl) {

    BPlusTree_t *t = (BPlusTree_t *) impl;
    if (!t) return;
    if (t->Root) BPlusTree_Destroy (t);
    free (t);
}

static bool
bplus_insert (void *impl, BPluskey_t *key, void *value) {

    return BPlusTree_Insert ((BPlusTree_t *) impl, key, value);
}

static void *
bplus_query (void *impl, BPluskey_t *key) {

    return BPlusTree_Query_Key ((BPlusTree_t *) impl, key);
}

static bool
bplus_remove (void *impl, BPluskey_t *key) {

    return BPlusTree_Delete ((BPlusTree_t *) impl, key);
}

static void
bplus_cursor_reset (void *impl, rdbms_ds_cursor_t *cur) {

    (void) impl;
    cur->node = NULL;
    cur->index = 0;
}

static void *
bplus_cursor_next (void *impl, rdbms_ds_cursor_t *cur, BPluskey_t **key_out) {

    BPlusTreeNode *node = (BPlusTreeNode *) cur->node;
    void *rec = BPlusTree_get_next_record ((BPlusTree_t *) impl,
                                           &node, &cur->index, key_out);
    cur->node = node;
    return rec;
}

static const rdbms_ds_ops_t bplus_ops = {

    "bplustree",
    bplus_create,
    bplus_destroy,
    bplus_insert,
    bplus_query,
    bplus_remove,
    bplus_cursor_reset,
    bplus_cursor_next
};

const rdbms_ds_ops_t *
rdbms_ds_bplus_ops (void) {

    return &bplus_ops;
}
