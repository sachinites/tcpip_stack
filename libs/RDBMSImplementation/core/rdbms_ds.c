/*
 * Generic storage-engine registry and handle dispatch.
 *
 * Concrete engines (see ds_bplus_adapter.c, ds_list_adapter.c) register their
 * rdbms_ds_ops_t here. rdbms_ds_create() picks an engine by name (or the
 * current default) and wraps its instance in an rdbms_ds_t handle.
 */

#include <stdlib.h>
#include <string.h>
#include "rdbms_ds.h"

#define RDBMS_DS_MAX_ENGINES 16

static const rdbms_ds_ops_t *g_engines[RDBMS_DS_MAX_ENGINES];
static int g_engine_count = 0;
static const rdbms_ds_ops_t *g_default_engine = NULL;

/* Provided by the built-in adapters. */
extern const rdbms_ds_ops_t *rdbms_ds_bplus_ops (void);
extern const rdbms_ds_ops_t *rdbms_ds_list_ops (void);

const rdbms_ds_ops_t *
rdbms_ds_lookup (const char *name) {

    int i;

    if (!name) return NULL;

    for (i = 0; i < g_engine_count; i++) {
        if (strcmp (g_engines[i]->name, name) == 0) {
            return g_engines[i];
        }
    }
    return NULL;
}

int
rdbms_ds_register (const rdbms_ds_ops_t *ops) {

    if (!ops || !ops->name) return -1;
    if (rdbms_ds_lookup (ops->name)) return 0;   /* already registered */
    if (g_engine_count >= RDBMS_DS_MAX_ENGINES) return -1;

    g_engines[g_engine_count++] = ops;
    return 0;
}

void
rdbms_ds_set_default (const char *name) {

    const rdbms_ds_ops_t *ops = rdbms_ds_lookup (name);
    if (ops) g_default_engine = ops;
}

void
rdbms_ds_register_builtins (void) {

    rdbms_ds_register (rdbms_ds_bplus_ops ());
    rdbms_ds_register (rdbms_ds_list_ops ());

    if (!g_default_engine) {
        g_default_engine = rdbms_ds_lookup ("bplustree");
    }
}

rdbms_ds_t *
rdbms_ds_create (const char *engine, const rdbms_ds_config_t *cfg) {

    const rdbms_ds_ops_t *ops;
    rdbms_ds_t *ds;

    ops = engine ? rdbms_ds_lookup (engine) : g_default_engine;
    if (!ops) return NULL;

    ds = (rdbms_ds_t *) calloc (1, sizeof (rdbms_ds_t));
    if (!ds) return NULL;

    ds->ops = ops;
    ds->impl = ops->create (cfg);

    if (!ds->impl) {
        free (ds);
        return NULL;
    }
    return ds;
}

void
rdbms_ds_destroy (rdbms_ds_t *ds) {

    if (!ds) return;
    if (ds->ops && ds->ops->destroy) ds->ops->destroy (ds->impl);
    free (ds);
}

bool
rdbms_ds_insert (rdbms_ds_t *ds, BPluskey_t *key, void *value) {

    return ds->ops->insert (ds->impl, key, value);
}

void *
rdbms_ds_query (rdbms_ds_t *ds, BPluskey_t *key) {

    return ds->ops->query (ds->impl, key);
}

bool
rdbms_ds_remove (rdbms_ds_t *ds, BPluskey_t *key) {

    return ds->ops->remove (ds->impl, key);
}

void
rdbms_ds_cursor_reset (rdbms_ds_t *ds, rdbms_ds_cursor_t *cur) {

    if (ds->ops->cursor_reset) {
        ds->ops->cursor_reset (ds->impl, cur);
    } else {
        cur->node = NULL;
        cur->index = 0;
    }
}

void *
rdbms_ds_cursor_next (rdbms_ds_t *ds, rdbms_ds_cursor_t *cur, BPluskey_t **key_out) {

    return ds->ops->cursor_next (ds->impl, cur, key_out);
}
