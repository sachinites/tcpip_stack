/*
 * =====================================================================================
 *
 *       Filename:  label_mgr.cpp
 *
 *    Description:  MPLS Label Manager - Implementation
 *
 *        Pool tracking : 5 x BitOp bitmap_t chunks of 20000 bits each,
 *                         together covering labels [1 .. 100000].
 *        Registry      : AVL tree (libs/Tree) keyed by start label, for
 *                         O(log n) lookup/removal on release.
 *        Per-client    : array of gluethread (libs/gluethread) list heads,
 *                         indexed by label_mgr_client_type_t; each record
 *                         also stores a uint32_t client instance id so that
 *                         (type, id) uniquely identifies the owner.
 *
 *        Version:  1.0
 *       Compiler:  gcc/g++
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>

#include "label_mgr.h"
#include "../libs/BitOp/bitmap.h"
#include "../libs/gluethread/glthread.h"
#include "../libs/Tree/libtree.h"

#include "../CLIBuilder/libcli.h"
#include "../CLIBuilder/cmdtlv.h"

/* ========================================================================
 * Internal Constants
 * ======================================================================== */

/* bitmap_t::tsize / index fields are only 16 bits wide (max 65535), so the
 * 100000-label pool is sharded into equal chunks that each fit in one
 * bitmap_t. 100000 / 5 = 20000, and 20000 % 32 == 0 (bitmap_init requires
 * size % 32 == 0), so the split is exact with no wasted bits. */
#define LABEL_MGR_NUM_CHUNKS   5u
#define LABEL_MGR_CHUNK_SIZE   (LABEL_MGR_POOL_SIZE / LABEL_MGR_NUM_CHUNKS)

/* Largest multiple of 32 that still fits bitmap_t's 16-bit tsize (<= 65535).
 * Used to size the private sub-allocator bitmap owned by each label block
 * (label_mgr_block_t), whose capacity is caller-chosen and not necessarily
 * a nice divisor of LABEL_MGR_POOL_SIZE the way the global pool's chunks are. */
#define LABEL_BLOCK_MAX_CHUNK_BITS 65504u

/* ========================================================================
 * Internal Structures
 * ======================================================================== */

typedef struct label_record_ {
    uint32_t            start_label;   /* first label of this allocation      */
    uint32_t            count;         /* 1 = single label, N = range          */
    label_mgr_client_t  client;        /* owning client (type + id)            */
    glthread_t          client_glue;   /* linked into label_mgr_t::clients[]   */
    avltree_node_t      avl_glue;      /* linked into label_mgr_t::records_by_start */
} label_record_t;

GLTHREAD_TO_STRUCT2(client_glue_to_record, label_record_t, client_glue);

struct label_mgr_ {
    bitmap_t            chunks[LABEL_MGR_NUM_CHUNKS];
    avltree_t           records_by_start;
    glthread_t          clients[LABEL_CLIENT_MAX];
    uint32_t            allocated_labels;
    uint32_t            num_records;
};

/*
 * A label block is an opaque handle wrapping one global label_record_t
 * (the reservation of [base_label, base_label + capacity - 1] from the
 * global pool) plus a *private* chunked bitmap that tracks which labels
 * within that range are currently handed out. label_mgr_block_alloc_label()/
 * label_mgr_block_release_label() only ever touch this private bitmap -
 * they never revisit the global pool.
 */
struct label_mgr_block_ {
    label_mgr_t         *mgr;
    label_record_t      *record;       /* backing global reservation           */
    label_mgr_client_t   client;       /* owning client (type + id)            */
    uint32_t              base_label;
    uint32_t              capacity;     /* size of the reserved range           */
    uint32_t              allocated;    /* labels currently handed out          */
    uint32_t              num_chunks;
    bitmap_t             *chunks;       /* heap array of size num_chunks         */
};

/* ========================================================================
 * Internal Helpers - pool index <-> chunk mapping
 * ======================================================================== */

static inline bool
label_mgr_client_is_valid(label_mgr_client_t client)
{
    return client.type > LABEL_CLIENT_NONE && client.type < LABEL_CLIENT_MAX;
}

static inline bool
label_mgr_label_in_range(uint32_t label)
{
    return label >= LABEL_MGR_POOL_MIN && label <= LABEL_MGR_POOL_MAX;
}

/* 0-based offset of `label` within the whole pool */
static inline uint32_t
label_to_pool_index(uint32_t label)
{
    return label - LABEL_MGR_POOL_MIN;
}

static inline uint32_t
pool_index_to_label(uint32_t index)
{
    return index + LABEL_MGR_POOL_MIN;
}

static inline void
pool_index_to_chunk(uint32_t index, uint32_t *chunk_idx, uint16_t *offset)
{
    *chunk_idx = index / LABEL_MGR_CHUNK_SIZE;
    *offset    = (uint16_t)(index % LABEL_MGR_CHUNK_SIZE);
}

static inline bool
pool_bit_test(label_mgr_t *lm, uint32_t index)
{
    uint32_t chunk_idx;
    uint16_t offset;
    pool_index_to_chunk(index, &chunk_idx, &offset);
    return bitmap_at(&lm->chunks[chunk_idx], offset);
}

static inline void
pool_bit_set(label_mgr_t *lm, uint32_t index)
{
    uint32_t chunk_idx;
    uint16_t offset;
    pool_index_to_chunk(index, &chunk_idx, &offset);
    bitmap_set_bit_at(&lm->chunks[chunk_idx], offset);
}

static inline void
pool_bit_clear(label_mgr_t *lm, uint32_t index)
{
    uint32_t chunk_idx;
    uint16_t offset;
    pool_index_to_chunk(index, &chunk_idx, &offset);
    bitmap_unset_bit_at(&lm->chunks[chunk_idx], offset);
}

/* Are the `count` labels starting at pool-index `index` all currently free ? */
static bool
pool_range_is_free(label_mgr_t *lm, uint32_t index, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        if (pool_bit_test(lm, index + i)) {
            return false;
        }
    }
    return true;
}

static void
pool_range_set(label_mgr_t *lm, uint32_t index, uint32_t count, bool used)
{
    for (uint32_t i = 0; i < count; i++) {
        if (used) {
            pool_bit_set(lm, index + i);
        } else {
            pool_bit_clear(lm, index + i);
        }
    }
}

/* First free label anywhere in the pool. Returns false if the pool is full. */
static bool
pool_find_first_free_label(label_mgr_t *lm, uint32_t *index_out)
{
    for (uint32_t c = 0; c < LABEL_MGR_NUM_CHUNKS; c++) {
        uint16_t bit = bitmap_get_unset_bit(&lm->chunks[c]);
        if (bit != UINT16_MAX) {
            *index_out = c * LABEL_MGR_CHUNK_SIZE + bit;
            return true;
        }
    }
    return false;
}

/* First-fit contiguous run of `count` free labels, scanning the whole pool
 * as one logical bit-space (transparently spanning chunk boundaries). */
static bool
pool_find_first_free_run(label_mgr_t *lm, uint32_t count, uint32_t *start_index_out)
{
    uint32_t run_start = 0;
    uint32_t run_len = 0;

    for (uint32_t index = 0; index < LABEL_MGR_POOL_SIZE; index++) {
        if (!pool_bit_test(lm, index)) {
            if (run_len == 0) {
                run_start = index;
            }
            run_len++;
            if (run_len == count) {
                *start_index_out = run_start;
                return true;
            }
        } else {
            run_len = 0;
        }
    }
    return false;
}

/* ========================================================================
 * Internal Helpers - allocation record registry
 * ======================================================================== */

static int
label_mgr_record_compare(const avltree_node_t *node1, const avltree_node_t *node2)
{
    const label_record_t *r1 = avltree_container_of(node1, label_record_t, avl_glue);
    const label_record_t *r2 = avltree_container_of(node2, label_record_t, avl_glue);

    if (r1->start_label < r2->start_label) return -1;
    if (r1->start_label > r2->start_label) return 1;
    return 0;
}

static label_record_t *
label_mgr_find_record(label_mgr_t *lm, uint32_t start_label)
{
    label_record_t key;
    memset(&key, 0, sizeof(key));
    key.start_label = start_label;

    avltree_node_t *found = avltree_lookup(&key.avl_glue, &lm->records_by_start);
    if (!found) {
        return NULL;
    }
    return avltree_container_of(found, label_record_t, avl_glue);
}

/* Creates and registers a record, returning the record itself (or NULL on
 * OOM) so callers that need it (e.g. label blocks) don't have to pay for a
 * second AVL lookup right after creating it. */
static label_record_t *
label_mgr_create_record_ex(label_mgr_t *lm,
                            label_mgr_client_t client,
                            uint32_t start_label,
                            uint32_t count)
{
    label_record_t *rec = (label_record_t *)calloc(1, sizeof(label_record_t));
    if (!rec) {
        return NULL;
    }

    rec->start_label = start_label;
    rec->count       = count;
    rec->client      = client;

    avltree_node_init(&rec->avl_glue);
    init_glthread(&rec->client_glue);

    avltree_insert(&rec->avl_glue, &lm->records_by_start);
    glthread_add_last(&lm->clients[client.type], &rec->client_glue);

    pool_range_set(lm, label_to_pool_index(start_label), count, true);

    lm->allocated_labels += count;
    lm->num_records++;

    return rec;
}

static label_mgr_rc_t
label_mgr_create_record(label_mgr_t *lm,
                         label_mgr_client_t client,
                         uint32_t start_label,
                         uint32_t count)
{
    return label_mgr_create_record_ex(lm, client, start_label, count) ?
           LABEL_MGR_OK : LABEL_MGR_ERR_MEMORY;
}

static void
label_mgr_destroy_record(label_mgr_t *lm, label_record_t *rec)
{
    pool_range_set(lm, label_to_pool_index(rec->start_label), rec->count, false);

    avltree_remove(&rec->avl_glue, &lm->records_by_start);
    remove_glthread(&rec->client_glue);

    lm->allocated_labels -= rec->count;
    lm->num_records--;

    free(rec);
}

/* ========================================================================
 * Internal Helpers - label block private sub-allocator
 *
 * Same chunked-bitmap idea as the global pool, but generalized to an
 * arbitrary capacity: chunks are LABEL_BLOCK_MAX_CHUNK_BITS wide (already
 * a multiple of 32) except possibly the last one, which is padded up to
 * the next multiple of 32 with its extra bits permanently pre-marked
 * "used" so they can never be handed out.
 * ======================================================================== */

static inline uint32_t
round_up_32(uint32_t v)
{
    return ((v + 31u) / 32u) * 32u;
}

static inline void
block_index_to_chunk(uint32_t index, uint32_t *chunk_idx, uint16_t *offset)
{
    *chunk_idx = index / LABEL_BLOCK_MAX_CHUNK_BITS;
    *offset    = (uint16_t)(index % LABEL_BLOCK_MAX_CHUNK_BITS);
}

static inline bool
block_bit_test(label_mgr_block_t *block, uint32_t index)
{
    uint32_t chunk_idx;
    uint16_t offset;
    block_index_to_chunk(index, &chunk_idx, &offset);
    return bitmap_at(&block->chunks[chunk_idx], offset);
}

static inline void
block_bit_set(label_mgr_block_t *block, uint32_t index)
{
    uint32_t chunk_idx;
    uint16_t offset;
    block_index_to_chunk(index, &chunk_idx, &offset);
    bitmap_set_bit_at(&block->chunks[chunk_idx], offset);
}

static inline void
block_bit_clear(label_mgr_block_t *block, uint32_t index)
{
    uint32_t chunk_idx;
    uint16_t offset;
    block_index_to_chunk(index, &chunk_idx, &offset);
    bitmap_unset_bit_at(&block->chunks[chunk_idx], offset);
}

/* First free index (0-based, relative to the block's own range). */
static bool
block_find_first_free(label_mgr_block_t *block, uint32_t *index_out)
{
    for (uint32_t c = 0; c < block->num_chunks; c++) {
        uint16_t bit = bitmap_get_unset_bit(&block->chunks[c]);
        if (bit == UINT16_MAX) {
            continue;
        }
        uint32_t idx = c * LABEL_BLOCK_MAX_CHUNK_BITS + bit;
        if (idx >= block->capacity) {
            /* Defensive only - padding bits are pre-marked used at init
             * time so bitmap_get_unset_bit should never surface one. */
            continue;
        }
        *index_out = idx;
        return true;
    }
    return false;
}

static void
label_mgr_block_free_internal(label_mgr_block_t *block)
{
    for (uint32_t c = 0; c < block->num_chunks; c++) {
        bitmap_free_internal(&block->chunks[c]);
    }
    free(block->chunks);
    free(block);
}

/* Wraps a freshly-created global reservation [start_label, start_label+count)
 * with a private per-block sub-allocator bitmap and returns the handle. */
static label_mgr_rc_t
label_mgr_block_create(label_mgr_t *lm,
                        label_mgr_client_t client,
                        uint32_t start_label,
                        uint32_t count,
                        label_mgr_block_t **block_out)
{
    label_record_t *rec = label_mgr_create_record_ex(lm, client, start_label, count);
    if (!rec) {
        return LABEL_MGR_ERR_MEMORY;
    }

    label_mgr_block_t *block = (label_mgr_block_t *)calloc(1, sizeof(label_mgr_block_t));
    if (!block) {
        label_mgr_destroy_record(lm, rec);
        return LABEL_MGR_ERR_MEMORY;
    }

    uint32_t num_chunks = (count + LABEL_BLOCK_MAX_CHUNK_BITS - 1u) / LABEL_BLOCK_MAX_CHUNK_BITS;
    if (num_chunks == 0) {
        num_chunks = 1;
    }

    bitmap_t *chunks = (bitmap_t *)calloc(num_chunks, sizeof(bitmap_t));
    if (!chunks) {
        free(block);
        label_mgr_destroy_record(lm, rec);
        return LABEL_MGR_ERR_MEMORY;
    }

    uint32_t remaining = count;
    for (uint32_t c = 0; c < num_chunks; c++) {
        uint32_t chunk_capacity = remaining < LABEL_BLOCK_MAX_CHUNK_BITS ?
                                   remaining : LABEL_BLOCK_MAX_CHUNK_BITS;
        uint16_t bitmap_size = (uint16_t)round_up_32(chunk_capacity);

        bitmap_init(&chunks[c], bitmap_size);
        for (uint16_t p = (uint16_t)chunk_capacity; p < bitmap_size; p++) {
            bitmap_set_bit_at(&chunks[c], p);
        }
        remaining -= chunk_capacity;
    }

    block->mgr        = lm;
    block->record     = rec;
    block->client     = client;
    block->base_label = start_label;
    block->capacity   = count;
    block->allocated  = 0;
    block->num_chunks = num_chunks;
    block->chunks     = chunks;

    *block_out = block;
    return LABEL_MGR_OK;
}

/* ========================================================================
 * Lifecycle
 * ======================================================================== */

label_mgr_t *
label_mgr_init(void)
{
    label_mgr_t *lm = (label_mgr_t *)calloc(1, sizeof(label_mgr_t));
    if (!lm) {
        return NULL;
    }

    for (uint32_t c = 0; c < LABEL_MGR_NUM_CHUNKS; c++) {
        bitmap_init(&lm->chunks[c], LABEL_MGR_CHUNK_SIZE);
    }

    avltree_init(&lm->records_by_start, label_mgr_record_compare);

    for (int i = 0; i < LABEL_CLIENT_MAX; i++) {
        init_glthread(&lm->clients[i]);
    }

    lm->allocated_labels = 0;
    lm->num_records = 0;

    return lm;
}

void
label_mgr_destroy(label_mgr_t *lm)
{
    if (!lm) {
        return;
    }

    for (int i = 0; i < LABEL_CLIENT_MAX; i++) {
        glthread_t *curr;
        ITERATE_GLTHREAD_BEGIN(&lm->clients[i], curr) {
            label_record_t *rec = client_glue_to_record(curr);
            avltree_remove(&rec->avl_glue, &lm->records_by_start);
            remove_glthread(&rec->client_glue);
            free(rec);
        } ITERATE_GLTHREAD_END(&lm->clients[i], curr);
    }

    for (uint32_t c = 0; c < LABEL_MGR_NUM_CHUNKS; c++) {
        bitmap_free_internal(&lm->chunks[c]);
    }

    free(lm);
}

/* ========================================================================
 * Single Label Allocation / Reservation / Release
 * ======================================================================== */

label_mgr_rc_t
label_mgr_alloc_label(label_mgr_t *lm,
                       label_mgr_client_t client,
                       uint32_t *label_out)
{
    if (!lm || !label_out || !label_mgr_client_is_valid(client)) {
        return LABEL_MGR_ERR_INVALID_PARAM;
    }

    uint32_t index;
    if (!pool_find_first_free_label(lm, &index)) {
        return LABEL_MGR_ERR_NO_LABELS_AVAILABLE;
    }

    uint32_t label = pool_index_to_label(index);
    label_mgr_rc_t rc = label_mgr_create_record(lm, client, label, 1);
    if (rc == LABEL_MGR_OK) {
        *label_out = label;
    }
    return rc;
}

label_mgr_rc_t
label_mgr_reserve_label(label_mgr_t *lm,
                         label_mgr_client_t client,
                         uint32_t label)
{
    if (!lm || !label_mgr_client_is_valid(client)) {
        return LABEL_MGR_ERR_INVALID_PARAM;
    }
    if (!label_mgr_label_in_range(label)) {
        return LABEL_MGR_ERR_OUT_OF_RANGE;
    }

    uint32_t index = label_to_pool_index(label);
    if (pool_bit_test(lm, index)) {
        return LABEL_MGR_ERR_LABEL_IN_USE;
    }

    return label_mgr_create_record(lm, client, label, 1);
}

label_mgr_rc_t
label_mgr_release_label(label_mgr_t *lm,
                         label_mgr_client_t client,
                         uint32_t label)
{
    if (!lm || !label_mgr_client_is_valid(client)) {
        return LABEL_MGR_ERR_INVALID_PARAM;
    }
    if (!label_mgr_label_in_range(label)) {
        return LABEL_MGR_ERR_OUT_OF_RANGE;
    }

    label_record_t *rec = label_mgr_find_record(lm, label);
    if (!rec || rec->count != 1) {
        return LABEL_MGR_ERR_NOT_FOUND;
    }
    if (!label_mgr_client_equal(rec->client, client)) {
        return LABEL_MGR_ERR_WRONG_OWNER;
    }

    label_mgr_destroy_record(lm, rec);
    return LABEL_MGR_OK;
}

/* ========================================================================
 * Label Range Allocation / Reservation / Release
 * ======================================================================== */

label_mgr_rc_t
label_mgr_alloc_range(label_mgr_t *lm,
                       label_mgr_client_t client,
                       uint32_t count,
                       uint32_t *start_label_out)
{
    if (!lm || !start_label_out || count == 0 || !label_mgr_client_is_valid(client)) {
        return LABEL_MGR_ERR_INVALID_PARAM;
    }
    if (count > LABEL_MGR_POOL_SIZE) {
        return LABEL_MGR_ERR_OUT_OF_RANGE;
    }

    uint32_t start_index;
    if (!pool_find_first_free_run(lm, count, &start_index)) {
        return LABEL_MGR_ERR_NO_LABELS_AVAILABLE;
    }

    uint32_t start_label = pool_index_to_label(start_index);
    label_mgr_rc_t rc = label_mgr_create_record(lm, client, start_label, count);
    if (rc == LABEL_MGR_OK) {
        *start_label_out = start_label;
    }
    return rc;
}

label_mgr_rc_t
label_mgr_reserve_range(label_mgr_t *lm,
                         label_mgr_client_t client,
                         uint32_t start_label,
                         uint32_t count)
{
    if (!lm || count == 0 || !label_mgr_client_is_valid(client)) {
        return LABEL_MGR_ERR_INVALID_PARAM;
    }
    if (!label_mgr_label_in_range(start_label) ||
        start_label + (uint64_t)count - 1 > LABEL_MGR_POOL_MAX) {
        return LABEL_MGR_ERR_OUT_OF_RANGE;
    }

    uint32_t start_index = label_to_pool_index(start_label);
    if (!pool_range_is_free(lm, start_index, count)) {
        return LABEL_MGR_ERR_RANGE_NOT_FREE;
    }

    return label_mgr_create_record(lm, client, start_label, count);
}

label_mgr_rc_t
label_mgr_release_range(label_mgr_t *lm,
                         label_mgr_client_t client,
                         uint32_t start_label)
{
    if (!lm || !label_mgr_client_is_valid(client)) {
        return LABEL_MGR_ERR_INVALID_PARAM;
    }
    if (!label_mgr_label_in_range(start_label)) {
        return LABEL_MGR_ERR_OUT_OF_RANGE;
    }

    label_record_t *rec = label_mgr_find_record(lm, start_label);
    if (!rec) {
        return LABEL_MGR_ERR_NOT_FOUND;
    }
    if (!label_mgr_client_equal(rec->client, client)) {
        return LABEL_MGR_ERR_WRONG_OWNER;
    }

    label_mgr_destroy_record(lm, rec);
    return LABEL_MGR_OK;
}

/* ========================================================================
 * Label Blocks - opaque handle to a reserved sub-pool
 * ======================================================================== */

label_mgr_rc_t
label_mgr_reserve_block(label_mgr_t *lm,
                         label_mgr_client_t client,
                         uint32_t count,
                         label_mgr_block_t **block_out)
{
    if (!lm || !block_out || count == 0 || !label_mgr_client_is_valid(client)) {
        return LABEL_MGR_ERR_INVALID_PARAM;
    }
    if (count > LABEL_MGR_POOL_SIZE) {
        return LABEL_MGR_ERR_OUT_OF_RANGE;
    }

    uint32_t start_index;
    if (!pool_find_first_free_run(lm, count, &start_index)) {
        return LABEL_MGR_ERR_NO_LABELS_AVAILABLE;
    }

    uint32_t start_label = pool_index_to_label(start_index);
    return label_mgr_block_create(lm, client, start_label, count, block_out);
}

label_mgr_rc_t
label_mgr_reserve_block_at(label_mgr_t *lm,
                            label_mgr_client_t client,
                            uint32_t start_label,
                            uint32_t count,
                            label_mgr_block_t **block_out)
{
    if (!lm || !block_out || count == 0 || !label_mgr_client_is_valid(client)) {
        return LABEL_MGR_ERR_INVALID_PARAM;
    }
    if (!label_mgr_label_in_range(start_label) ||
        start_label + (uint64_t)count - 1 > LABEL_MGR_POOL_MAX) {
        return LABEL_MGR_ERR_OUT_OF_RANGE;
    }

    uint32_t start_index = label_to_pool_index(start_label);
    if (!pool_range_is_free(lm, start_index, count)) {
        return LABEL_MGR_ERR_RANGE_NOT_FREE;
    }

    return label_mgr_block_create(lm, client, start_label, count, block_out);
}

label_mgr_rc_t
label_mgr_block_alloc_label(label_mgr_block_t *block, uint32_t *label_out)
{
    if (!block || !label_out) {
        return LABEL_MGR_ERR_INVALID_PARAM;
    }

    uint32_t index;
    if (!block_find_first_free(block, &index)) {
        return LABEL_MGR_ERR_NO_LABELS_AVAILABLE;
    }

    block_bit_set(block, index);
    block->allocated++;

    *label_out = block->base_label + index;
    return LABEL_MGR_OK;
}

label_mgr_rc_t
label_mgr_block_release_label(label_mgr_block_t *block, uint32_t label)
{
    if (!block) {
        return LABEL_MGR_ERR_INVALID_PARAM;
    }
    if (label < block->base_label || label >= block->base_label + block->capacity) {
        return LABEL_MGR_ERR_OUT_OF_RANGE;
    }

    uint32_t index = label - block->base_label;
    if (!block_bit_test(block, index)) {
        return LABEL_MGR_ERR_NOT_FOUND;
    }

    block_bit_clear(block, index);
    block->allocated--;

    return LABEL_MGR_OK;
}

label_mgr_rc_t
label_mgr_block_destroy(label_mgr_t *lm, label_mgr_block_t *block, bool force)
{
    if (!lm || !block) {
        return LABEL_MGR_ERR_INVALID_PARAM;
    }
    if (!force && block->allocated > 0) {
        return LABEL_MGR_ERR_BLOCK_NOT_EMPTY;
    }

    label_mgr_destroy_record(lm, block->record);
    label_mgr_block_free_internal(block);

    return LABEL_MGR_OK;
}

label_mgr_rc_t
label_mgr_block_get_stats(label_mgr_block_t *block, label_mgr_block_stats_t *stats_out)
{
    if (!block || !stats_out) {
        return LABEL_MGR_ERR_INVALID_PARAM;
    }

    stats_out->base_label = block->base_label;
    stats_out->capacity   = block->capacity;
    stats_out->allocated  = block->allocated;
    stats_out->free       = block->capacity - block->allocated;
    stats_out->client     = block->client;

    return LABEL_MGR_OK;
}

void
label_mgr_block_show(label_mgr_block_t *block)
{
    if (!block) {
        cprintf("Label Block : NULL handle\n");
        return;
    }

    char client_str[64];
    cprintf("Label Block [%u - %u] (client: %s)\n",
           block->base_label, block->base_label + block->capacity - 1,
           label_mgr_client_to_string(block->client, client_str, sizeof(client_str)));
    cprintf("  Capacity  : %u\n", block->capacity);
    cprintf("  Allocated : %u\n", block->allocated);
    cprintf("  Free      : %u\n", block->capacity - block->allocated);
}

/* ========================================================================
 * Display / Statistics
 * ======================================================================== */

void
label_mgr_show_client(label_mgr_t *lm, label_mgr_client_t client)
{
    if (!lm || !label_mgr_client_is_valid(client)) {
        cprintf("Label Manager : invalid client\n");
        return;
    }

    uint32_t num_labels = 0;
    uint32_t num_ranges = 0;
    uint32_t total_labels = 0;
    char client_str[64];

    cprintf("Client : %s\n",
           label_mgr_client_to_string(client, client_str, sizeof(client_str)));
    cprintf("  %-12s %-12s %-10s\n", "Start", "End", "Count");

    glthread_t *curr;
    ITERATE_GLTHREAD_BEGIN(&lm->clients[client.type], curr) {
        label_record_t *rec = client_glue_to_record(curr);

        if (!label_mgr_client_equal(rec->client, client)) {
            continue;
        }

        uint32_t end_label = rec->start_label + rec->count - 1;

        cprintf("  %-12u %-12u %-10u %s\n",
               rec->start_label, end_label, rec->count,
               rec->count == 1 ? "(label)" : "(range)");

        total_labels += rec->count;
        if (rec->count == 1) {
            num_labels++;
        } else {
            num_ranges++;
        }
    } ITERATE_GLTHREAD_END(&lm->clients[client.type], curr);

    cprintf("  ---------------------------------------------\n");
    cprintf("  Total : %u label(s), %u range(s), %u label(s) held\n",
           num_labels, num_ranges, total_labels);
}

void
label_mgr_show_all(label_mgr_t *lm)
{
    if (!lm) {
        cprintf("Label Manager : NULL handle\n");
        return;
    }

    label_mgr_stats_t stats;
    label_mgr_get_stats(lm, &stats);

    cprintf("=================================================\n");
    cprintf(" MPLS Label Manager - Pool Summary\n");
    cprintf("=================================================\n");
    cprintf("  Pool range      : [%u - %u]\n", LABEL_MGR_POOL_MIN, LABEL_MGR_POOL_MAX);
    cprintf("  Total labels    : %u\n", stats.total_labels);
    cprintf("  Allocated       : %u\n", stats.allocated_labels);
    cprintf("  Free            : %u\n", stats.free_labels);
    cprintf("  Allocation recs : %u\n", stats.num_records);
    cprintf("=================================================\n");
    cprintf("  %-16s %-12s %-12s %-10s\n", "Client", "Start", "End", "Count");

    for (int c = LABEL_CLIENT_NONE + 1; c < LABEL_CLIENT_MAX; c++) {
        glthread_t *curr;
        ITERATE_GLTHREAD_BEGIN(&lm->clients[c], curr) {
            label_record_t *rec = client_glue_to_record(curr);
            uint32_t end_label = rec->start_label + rec->count - 1;
            char client_str[64];

            cprintf("  %-16s %-12u %-12u %-10u %s\n",
                   label_mgr_client_to_string(rec->client, client_str, sizeof(client_str)),
                   rec->start_label, end_label, rec->count,
                   rec->count == 1 ? "(label)" : "(range)");
        } ITERATE_GLTHREAD_END(&lm->clients[c], curr);
    }
}

label_mgr_rc_t
label_mgr_get_stats(label_mgr_t *lm, label_mgr_stats_t *stats_out)
{
    if (!lm || !stats_out) {
        return LABEL_MGR_ERR_INVALID_PARAM;
    }

    stats_out->total_labels     = LABEL_MGR_POOL_SIZE;
    stats_out->allocated_labels = lm->allocated_labels;
    stats_out->free_labels      = LABEL_MGR_POOL_SIZE - lm->allocated_labels;
    stats_out->num_records      = lm->num_records;

    return LABEL_MGR_OK;
}

/* ========================================================================
 * Utility Functions
 * ======================================================================== */

const char *
label_mgr_client_type_to_string(label_mgr_client_type_t type)
{
    switch (type) {
        case LABEL_CLIENT_NONE:    return "none";
        case LABEL_CLIENT_STATIC:  return "static";
        case LABEL_CLIENT_LDP:     return "ldp";
        case LABEL_CLIENT_RSVP_TE: return "rsvp-te";
        case LABEL_CLIENT_BGP_LU:  return "bgp-lu";
        case LABEL_CLIENT_SR_MPLS: return "sr-mpls";
        case LABEL_CLIENT_L3VPN:   return "l3vpn";
        case LABEL_CLIENT_L2VPN:   return "l2vpn";
        case LABEL_CLIENT_ISIS:    return "isis";
        case LABEL_CLIENT_OSPF:    return "ospf";
        case LABEL_CLIENT_OAM:     return "oam";
        default:                   return "unknown";
    }
}

char *
label_mgr_client_to_string(label_mgr_client_t client, char *buf, size_t buflen)
{
    if (!buf || buflen == 0) {
        return buf;
    }

    snprintf(buf, buflen, "%s/%u",
             label_mgr_client_type_to_string(client.type), client.id);
    return buf;
}

const char *
label_mgr_rc_to_string(label_mgr_rc_t rc)
{
    switch (rc) {
        case LABEL_MGR_OK:                     return "OK";
        case LABEL_MGR_ERR_INVALID_PARAM:      return "Invalid parameter";
        case LABEL_MGR_ERR_OUT_OF_RANGE:       return "Label/range out of pool bounds";
        case LABEL_MGR_ERR_LABEL_IN_USE:       return "Label already in use";
        case LABEL_MGR_ERR_RANGE_NOT_FREE:     return "Range overlaps an existing allocation";
        case LABEL_MGR_ERR_NO_LABELS_AVAILABLE:return "No labels available";
        case LABEL_MGR_ERR_NOT_FOUND:          return "Allocation not found";
        case LABEL_MGR_ERR_WRONG_OWNER:        return "Allocation belongs to a different client";
        case LABEL_MGR_ERR_MEMORY:             return "Memory allocation failure";
        case LABEL_MGR_ERR_BLOCK_NOT_EMPTY:    return "Block still has outstanding label allocations";
        default:                               return "Unknown error";
    }
}
