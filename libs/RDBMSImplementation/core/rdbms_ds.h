#ifndef __RDBMS_DS__
#define __RDBMS_DS__

/*
 * Generic storage-engine interface for the RDBMS.
 *
 * A concrete storage structure (B+tree, linked list, ...) implements the
 * rdbms_ds_ops_t vtable and registers itself. The SQL engine talks only to
 * rdbms_ds_t handles, so the underlying structure is pluggable.
 *
 * The shared key / compare types below used to live in BPlusTree.h; they are
 * relocated here so engines do not have to depend on the B+tree headers.
 * BPlusTree.h now includes this file for these definitions.
 */

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One field of a (possibly composite) key: data type id + byte width. */
typedef struct key_mdata_ {

    int dtype;
    int size;

} key_mdata_t;

/* Opaque key: a byte buffer plus its length. */
typedef struct BPluskey {

    uint16_t key_size;
    void *key;

} BPluskey_t;

/* Comparison contract (inherited from the B+tree): returns > 0 when the first
 * key is LESS than the second, < 0 when GREATER, and 0 when equal. */
typedef int  (*ds_key_cmp_fn) (BPluskey_t *, BPluskey_t *, key_mdata_t *, int);
typedef void (*ds_value_free_fn) (void *);

/* Configuration handed to an engine at creation time. */
typedef struct rdbms_ds_config_ {

    ds_key_cmp_fn    cmp_fn;         /* required */
    ds_value_free_fn free_fn;        /* value deallocator (NULL => libc free) */
    key_mdata_t     *key_mdata;      /* composite key layout */
    int              key_mdata_size;
    uint16_t         max_children;   /* engine hint (B+tree fanout); ignored otherwise */

} rdbms_ds_config_t;

/*
 * Opaque sequential-scan cursor. A zeroed cursor ({node = NULL, index = 0})
 * means "before the first record". Every engine must honour this contract so
 * the RDBMS_DS_ITERATE macro and the join scan work uniformly.
 */
typedef struct rdbms_ds_cursor_ {

    void *node;
    int   index;

} rdbms_ds_cursor_t;

/* The vtable a concrete engine must provide. */
typedef struct rdbms_ds_ops_ {

    const char *name;
    void  *(*create)       (const rdbms_ds_config_t *cfg);              /* -> impl handle */
    void   (*destroy)      (void *impl);
    bool   (*insert)       (void *impl, BPluskey_t *key, void *value);  /* false on dup */
    void  *(*query)        (void *impl, BPluskey_t *key);               /* value or NULL */
    bool   (*remove)       (void *impl, BPluskey_t *key);               /* false if absent */
    void   (*cursor_reset) (void *impl, rdbms_ds_cursor_t *cur);
    void  *(*cursor_next)  (void *impl, rdbms_ds_cursor_t *cur, BPluskey_t **key_out);

} rdbms_ds_ops_t;

/* A storage handle: the engine ops plus the concrete instance. */
typedef struct rdbms_ds_ {

    const rdbms_ds_ops_t *ops;
    void *impl;

} rdbms_ds_t;

/* ---- Engine registry ---- */

int  rdbms_ds_register (const rdbms_ds_ops_t *ops);   /* keyed by ops->name */
void rdbms_ds_set_default (const char *name);         /* e.g. "bplustree" */
const rdbms_ds_ops_t *rdbms_ds_lookup (const char *name);
void rdbms_ds_register_builtins (void);               /* registers bplustree + list */

/* ---- Handle lifecycle + operations ---- */

rdbms_ds_t *rdbms_ds_create  (const char *engine /* NULL => default */,
                              const rdbms_ds_config_t *cfg);
void        rdbms_ds_destroy (rdbms_ds_t *ds);
bool        rdbms_ds_insert  (rdbms_ds_t *ds, BPluskey_t *key, void *value);
void       *rdbms_ds_query   (rdbms_ds_t *ds, BPluskey_t *key);
bool        rdbms_ds_remove  (rdbms_ds_t *ds, BPluskey_t *key);
void        rdbms_ds_cursor_reset (rdbms_ds_t *ds, rdbms_ds_cursor_t *cur);
void       *rdbms_ds_cursor_next  (rdbms_ds_t *ds, rdbms_ds_cursor_t *cur,
                                   BPluskey_t **key_out);

/* Drop-in replacement for BPTREE_ITERATE_ALL_RECORDS_BEGIN/END. */
#define RDBMS_DS_ITERATE_BEGIN(ds, key_ptr, rec_ptr)                        \
    {                                                                       \
        rdbms_ds_cursor_t _c;                                               \
        _c.node = NULL;                                                     \
        _c.index = 0;                                                       \
        while (((rec_ptr) = rdbms_ds_cursor_next ((ds), &_c, &(key_ptr)))) {

#define RDBMS_DS_ITERATE_END                                                \
        }                                                                   \
    }

#ifdef __cplusplus
}
#endif

#endif
