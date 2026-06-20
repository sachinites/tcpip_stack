/*
 * =============================================================================
 * File: dp_table_gc.h
 * Description: Periodic GC scan for ARP and MAC table entries.
 * =============================================================================
 *
 * Replaces per-entry wheel-timer elements with a single periodic timer that
 * fires every DP_TABLE_SCAN_INTERVAL_SECS on dp_ev_dis.  On each fire it
 * walks all VRF ARP tables and the shared MAC table, deletes any entry whose
 * last_used timestamp is older than DP_TABLE_SCAN_INTERVAL_SECS (or that
 * has never been used by the data path), then reschedules itself.
 *
 * Concurrency:
 *   - The scan callback runs exclusively on dp_ev_dis (single-writer).
 *   - last_used is written by forwarding threads via relaxed atomic stores;
 *     the scan reads it with __atomic_load_n(__ATOMIC_RELAXED).
 * =============================================================================
 */

#ifndef __DP_TABLE_GC_H__
#define __DP_TABLE_GC_H__

typedef struct dp_ctx_ dp_ctx_t;

/* Idle window: entries unused for this many seconds are deleted. */
#define DP_TABLE_SCAN_INTERVAL_SECS  (30 * 60)   /* 30 minutes */

/* Max entries collected for deletion per table per scan pass.
 * Stack-allocated; keep modest to avoid large stack frames. */
#define DP_TABLE_GC_MAX_BATCH  512

/* Register the first scan timer on DP_TIMER(dp_ctx).  Call once after
 * the tables and wheel timer are initialised. */
void dp_table_gc_start(dp_ctx_t *dp_ctx);

/* Cancel the scan timer (call during dp_ctx teardown). */
void dp_table_gc_stop(dp_ctx_t *dp_ctx);

#endif /* __DP_TABLE_GC_H__ */
