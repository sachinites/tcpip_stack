/*
 * =====================================================================================
 *
 *       Filename:  label_mgr.h
 *
 *    Description:  MPLS Label Manager - Public API
 *
 *        The Label Manager owns a single, fixed pool of MPLS labels
 *        [LABEL_MGR_POOL_MIN .. LABEL_MGR_POOL_MAX] (1 - 100000) and hands
 *        them out to registered clients (protocols/applications), either：
 *
 *          - one label at a time                 (label)
 *          - a contiguous block of labels         (range)
 *
 *        either picked dynamically by the manager, or reserved by the
 *        caller at a specific value. The manager keeps track of exactly
 *        which client owns which label(s)/range(s) so that ownership can
 *        be displayed (label_mgr_show_*) and validated on release.
 *
 *        Pool layout:
 *        ┌──────────────────────────────────────────────────────────────┐
 *        │  Label space : [1 .............................. 100000]    │
 *        │  Tracked as  : 5 x BitOp bitmap_t chunks of 20000 bits each  │
 *        │                (bitmap_t's index/tsize are only 16-bit wide, │
 *        │                 so a single bitmap cannot span 100000 bits)  │
 *        └──────────────────────────────────────────────────────────────┘
 *
 *        Every allocation (single label or range) is recorded once as a
 *        label_record_t which is simultaneously linked into:
 *          - a global AVL tree, keyed by start label   (fast lookup/release)
 *          - a per-client glthread list                (fast show-per-client)
 *
 *        Label Blocks (opaque sub-pool handles):
 *        A client can also reserve a contiguous range up-front and get
 *        back an opaque label_mgr_block_t handle (label_mgr_reserve_block*).
 *        The handle owns its own private free/used bitmap scoped to just
 *        that range; label_mgr_block_alloc_label()/label_mgr_block_release_label()
 *        then hand out/reclaim individual labels *from within that range
 *        only* - they never touch the global pool. This is useful for a
 *        client that wants to manage its own local label space (e.g. one
 *        block per interface/tunnel) without repeatedly going through the
 *        global allocator. label_mgr_block_destroy() returns the whole
 *        range back to the global pool in one shot.
 *
 *        Version:  1.0
 *       Compiler:  gcc/g++
 *
 * =====================================================================================
 */

#ifndef __LABEL_MGR_H__
#define __LABEL_MGR_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Constants
 * ======================================================================== */

#define LABEL_MGR_POOL_MIN     1u
#define LABEL_MGR_POOL_MAX     100000u
#define LABEL_MGR_POOL_SIZE    (LABEL_MGR_POOL_MAX - LABEL_MGR_POOL_MIN + 1u)

/* ========================================================================
 * Type Definitions
 * ======================================================================== */

/*
 * @brief Client *type* (protocol/application class).
 *
 * Sequential (non-bitmask) on purpose: it indexes label_mgr_t::clients[],
 * mirroring the rtm->nhs_by_src[proto] idiom used elsewhere (RTM/rtm.cpp).
 * A full client identity is (type, id) - see label_mgr_client_t below.
 */
typedef enum label_mgr_client_type_ {
    LABEL_CLIENT_NONE    = 0,
    LABEL_CLIENT_STATIC,
    LABEL_CLIENT_LDP,
    LABEL_CLIENT_RSVP_TE,
    LABEL_CLIENT_BGP_LU,
    LABEL_CLIENT_SR_MPLS,
    LABEL_CLIENT_L3VPN,
    LABEL_CLIENT_L2VPN,
    LABEL_CLIENT_ISIS,
    LABEL_CLIENT_OSPF,
    LABEL_CLIENT_OAM,
    LABEL_CLIENT_MAX
} label_mgr_client_type_t;

/*
 * @brief Unique client identity: type enum + 32-bit instance id.
 *
 * Multiple instances of the same type (e.g. ISIS per VRF, L3VPN per
 * node context) are distinguished by `id`. Ownership checks on release
 * require both fields to match.
 */
typedef struct label_mgr_client_ {
    label_mgr_client_type_t type;
    uint32_t                id;
} label_mgr_client_t;

/* Convenience constructor for a (type, id) client identity. */
static inline label_mgr_client_t
label_mgr_make_client(label_mgr_client_type_t type, uint32_t id)
{
    label_mgr_client_t c;
    c.type = type;
    c.id   = id;
    return c;
}

static inline bool
label_mgr_client_equal(label_mgr_client_t a, label_mgr_client_t b)
{
    return a.type == b.type && a.id == b.id;
}

/*
 * @brief Return/error codes for all Label Manager operations.
 */
typedef enum label_mgr_rc_ {
    LABEL_MGR_OK = 0,
    LABEL_MGR_ERR_INVALID_PARAM,     /* bad argument (NULL handle, bad client, count == 0, ...) */
    LABEL_MGR_ERR_OUT_OF_RANGE,      /* label/range falls outside [POOL_MIN, POOL_MAX]          */
    LABEL_MGR_ERR_LABEL_IN_USE,      /* requested (reserve) label is already allocated          */
    LABEL_MGR_ERR_RANGE_NOT_FREE,    /* requested (reserve) range overlaps an existing allocation*/
    LABEL_MGR_ERR_NO_LABELS_AVAILABLE, /* dynamic alloc could not find a free label/run          */
    LABEL_MGR_ERR_NOT_FOUND,         /* release: no such allocation exists                       */
    LABEL_MGR_ERR_WRONG_OWNER,       /* release: allocation exists, but belongs to another client*/
    LABEL_MGR_ERR_MEMORY,            /* internal memory allocation failure                       */
    LABEL_MGR_ERR_BLOCK_NOT_EMPTY    /* block still has outstanding label allocations            */
} label_mgr_rc_t;

/*
 * @brief Pool-wide usage statistics.
 */
typedef struct label_mgr_stats_ {
    uint32_t total_labels;      /* LABEL_MGR_POOL_SIZE, always fixed        */
    uint32_t allocated_labels;  /* number of labels currently in use        */
    uint32_t free_labels;       /* total_labels - allocated_labels          */
    uint32_t num_records;       /* number of allocation records (single + range) */
} label_mgr_stats_t;

/* Opaque Label Manager handle */
typedef struct label_mgr_ label_mgr_t;

/* Opaque handle to a reserved label block (sub-pool) - see label_mgr_reserve_block() */
typedef struct label_mgr_block_ label_mgr_block_t;

/*
 * @brief Usage statistics for a single label block.
 */
typedef struct label_mgr_block_stats_ {
    uint32_t base_label;    /* first label of the block's reserved range */
    uint32_t capacity;      /* size of the reserved range (labels)       */
    uint32_t allocated;     /* labels currently allocated out of the block */
    uint32_t free;          /* capacity - allocated                      */
    label_mgr_client_t client; /* owning client (type + id)              */
} label_mgr_block_stats_t;

/* ========================================================================
 * Lifecycle
 * ======================================================================== */

/*
 * @brief Create and initialize a new Label Manager instance.
 *
 * The pool is always [LABEL_MGR_POOL_MIN, LABEL_MGR_POOL_MAX] (1-100000);
 * this range is fixed and not configurable by design.
 *
 * @return newly allocated label_mgr_t handle, or NULL on allocation failure
 */
label_mgr_t *
label_mgr_init(void);

/*
 * @brief Destroy a Label Manager instance and free all resources
 *        (including any outstanding allocation records).
 */
void
label_mgr_destroy(label_mgr_t *lm);

/* ========================================================================
 * Single Label Allocation / Reservation / Release
 * ======================================================================== */

/*
 * @brief Dynamically allocate the first available free label.
 *
 * @param lm         Label Manager handle
 * @param client     Owning client
 * @param label_out  [out] the allocated label value
 */
label_mgr_rc_t
label_mgr_alloc_label(label_mgr_t *lm,
                       label_mgr_client_t client,
                       uint32_t *label_out);

/*
 * @brief Reserve a specific label value requested by the caller.
 *
 * @param lm      Label Manager handle
 * @param client  Owning client
 * @param label   Specific label value to reserve
 */
label_mgr_rc_t
label_mgr_reserve_label(label_mgr_t *lm,
                         label_mgr_client_t client,
                         uint32_t label);

/*
 * @brief Release a previously allocated/reserved single label.
 *
 * Only matches an allocation that was made as a single label (i.e. not
 * part of a range) - use label_mgr_release_range() for ranges.
 *
 * @param lm      Label Manager handle
 * @param client  Client that must own this label
 * @param label   Label value to release
 */
label_mgr_rc_t
label_mgr_release_label(label_mgr_t *lm,
                         label_mgr_client_t client,
                         uint32_t label);

/* ========================================================================
 * Label Range Allocation / Reservation / Release
 * ======================================================================== */

/*
 * @brief Dynamically allocate the first available contiguous free block
 *        of `count` labels.
 *
 * @param lm              Label Manager handle
 * @param client          Owning client
 * @param count            Number of contiguous labels requested (>= 1)
 * @param start_label_out [out] first label of the allocated range
 */
label_mgr_rc_t
label_mgr_alloc_range(label_mgr_t *lm,
                       label_mgr_client_t client,
                       uint32_t count,
                       uint32_t *start_label_out);

/*
 * @brief Reserve a specific contiguous range [start_label, start_label + count - 1].
 *
 * @param lm           Label Manager handle
 * @param client       Owning client
 * @param start_label  First label of the requested range
 * @param count        Number of contiguous labels requested (>= 1)
 */
label_mgr_rc_t
label_mgr_reserve_range(label_mgr_t *lm,
                         label_mgr_client_t client,
                         uint32_t start_label,
                         uint32_t count);

/*
 * @brief Release a previously allocated/reserved range, identified by
 *        its start label. The range's size is recalled from the
 *        allocation record - the caller does not need to remember it.
 *
 * @param lm           Label Manager handle
 * @param client       Client that must own this range
 * @param start_label  First label of the range to release
 */
label_mgr_rc_t
label_mgr_release_range(label_mgr_t *lm,
                         label_mgr_client_t client,
                         uint32_t start_label);

/* ========================================================================
 * Label Blocks - opaque handle to a reserved sub-pool
 *
 * Reserve a contiguous range once (from the global pool) and receive an
 * opaque label_mgr_block_t handle. All subsequent label_mgr_block_*()
 * calls allocate/release labels *from within that reserved range only*;
 * they never touch the global pool directly.
 * ======================================================================== */

/*
 * @brief Reserve a contiguous range of `count` labels dynamically
 *        (first-fit over the global pool) and return an opaque handle
 *        to it.
 *
 * @param lm         Label Manager handle
 * @param client     Owning client
 * @param count      Number of labels to reserve for this block (>= 1)
 * @param block_out  [out] opaque handle to the newly reserved block
 */
label_mgr_rc_t
label_mgr_reserve_block(label_mgr_t *lm,
                         label_mgr_client_t client,
                         uint32_t count,
                         label_mgr_block_t **block_out);

/*
 * @brief Reserve a specific contiguous range [start_label, start_label + count - 1]
 *        and return an opaque handle to it.
 *
 * @param lm           Label Manager handle
 * @param client       Owning client
 * @param start_label  First label of the requested range
 * @param count        Number of labels to reserve for this block (>= 1)
 * @param block_out    [out] opaque handle to the newly reserved block
 */
label_mgr_rc_t
label_mgr_reserve_block_at(label_mgr_t *lm,
                            label_mgr_client_t client,
                            uint32_t start_label,
                            uint32_t count,
                            label_mgr_block_t **block_out);

/*
 * @brief Allocate a new label from within a previously reserved block.
 *
 * @param block      Block handle returned by label_mgr_reserve_block[_at]()
 * @param label_out  [out] the allocated label value
 */
label_mgr_rc_t
label_mgr_block_alloc_label(label_mgr_block_t *block, uint32_t *label_out);

/*
 * @brief Release a label previously allocated from a block, back into
 *        that same block (the label remains reserved at the global-pool
 *        level and can be handed out again by this block).
 *
 * @param block  Block handle
 * @param label  Label value to release; must lie within the block's range
 */
label_mgr_rc_t
label_mgr_block_release_label(label_mgr_block_t *block, uint32_t label);

/*
 * @brief Destroy a block handle and return its entire reserved range to
 *        the global pool.
 *
 * @param lm     Label Manager handle
 * @param block  Block handle to destroy (invalid to use afterwards)
 * @param force  If false, the call fails with LABEL_MGR_ERR_BLOCK_NOT_EMPTY
 *               when the block still has outstanding label allocations.
 *               If true, the block (and any labels still allocated from
 *               it) is unconditionally released back to the global pool.
 */
label_mgr_rc_t
label_mgr_block_destroy(label_mgr_t *lm, label_mgr_block_t *block, bool force);

/*
 * @brief Fetch usage statistics for a block.
 */
label_mgr_rc_t
label_mgr_block_get_stats(label_mgr_block_t *block, label_mgr_block_stats_t *stats_out);

/*
 * @brief Print a block's reserved range and current usage.
 */
void
label_mgr_block_show(label_mgr_block_t *block);

/* ========================================================================
 * Display / Statistics
 * ======================================================================== */

/*
 * @brief Print every label/range currently allocated to a given client
 *        identity (type + id).
 */
void
label_mgr_show_client(label_mgr_t *lm, label_mgr_client_t client);

/*
 * @brief Print the pool summary followed by every client's allocations.
 */
void
label_mgr_show_all(label_mgr_t *lm);

/*
 * @brief Fetch pool-wide usage statistics.
 */
label_mgr_rc_t
label_mgr_get_stats(label_mgr_t *lm, label_mgr_stats_t *stats_out);

/* ========================================================================
 * Utility Functions
 * ======================================================================== */

const char *
label_mgr_client_type_to_string(label_mgr_client_type_t type);

/* Format "type/id" into buf; returns buf. */
char *
label_mgr_client_to_string(label_mgr_client_t client, char *buf, size_t buflen);

const char *
label_mgr_rc_to_string(label_mgr_rc_t rc);

#ifdef __cplusplus
}
#endif

#endif /* __LABEL_MGR_H__ */
