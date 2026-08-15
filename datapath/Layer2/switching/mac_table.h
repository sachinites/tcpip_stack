#ifndef __MAC_TABLE_H__
#define __MAC_TABLE_H__

#include <stdint.h>
#include <assert.h>
#include <time.h>
#include "../../dp_const.h"
#include "../../../libs/libtimer/WheelTimer.h"
#include "../../../libs/common/cmn_struct.h"
#include "../../../utils.h"
#include "../../enums/l2_enums.h"

/*
 * MAC table design — rte_hash + single-writer dp_ev_dis model
 * ============================================================
 *  - mac_table_t wraps a DPDK rte_hash keyed by mac_table_key_t (8 bytes).
 *  - rte_hash is created with RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF so that
 *    DPDK packet-poll threads can call mac_table_lookup() lock-free while
 *    dp_ev_dis is the only writer (add / delete / timer expiry).
 *  - After deletion from the hash, entry memory is freed via a short GC
 *    timer callback on dp_ev_dis (DP_TABLE_GC_DELAY_MS) so that any
 *    reader that fetched the pointer just before deletion can finish safely.
 *  - All functions that mutate the table assert that they run on dp_ev_dis.
 */

/* Forward declarations */
typedef struct dp_intf_ dp_intf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct rte_mbuf pkt_mbuf_t;

/* rte_hash is forward-declared; callers need only mac_table.h, not rte_hash.h */
struct rte_hash;

#pragma pack(push, 8)

/* Composite key for the MAC rte_hash: (vlan_id, mac[6]) — exactly 8 bytes. */
typedef struct mac_table_key_ {
    uint16_t vlan_id;
    uint8_t  mac[6];
} mac_table_key_t;

/* Per-OIF entry stored in mac_table_entry_t::oif_list */
typedef struct mac_oif_entry_ {
    dp_intf_t *oif;
    glthread_t glue;
    uint32_t remote_dst_ip;
} mac_oif_entry_t;

GLTHREAD_TO_STRUCT(mac_oif_glue_to_entry, mac_oif_entry_t, glue);

typedef struct mac_table_entry_ {
    glthread_t oif_list;                /* list of mac_oif_entry_t */
    mac_addr_t mac;
    uint16_t flags;
    uint16_t vlan_id;
    char padding[4];
    /* last_used: wall-clock seconds written by forwarding threads via
     * mac_table_entry_touch().  Read by the GC scan on dp_ev_dis.
     * Dynamic entries are stamped at creation and refreshed on both source
     * (learning) and destination (forwarding) activity, so aging starts from
     * the moment the MAC was learned.  Static entries keep 0 (GC-exempt,
     * displayed as "never"). */
    time_t last_used;
} mac_table_entry_t;

typedef struct mac_table_ {
    struct rte_hash *hash;    /* keyed by mac_table_key_t; single-writer dp_ev_dis */
    uint32_t entry_count;
} mac_table_t;

#pragma pack(pop)

/* -------------------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------------- */
void init_mac_table(mac_table_t **mac_table, const char *ctx_name,
                    const char *suffix);
void destroy_mac_table(dp_ctx_t *dp_ctx, mac_table_t *mac_table);

/* -------------------------------------------------------------------------
 * Read path — lock-free, callable from any thread (DPDK workers included)
 * ---------------------------------------------------------------------- */
mac_table_entry_t *mac_table_lookup(mac_table_t *mac_table,
                                    uint16_t vlan, uint8_t *mac);

/* Called by the forwarding data path on each frame forwarded through this
 * entry.  Replaces the expensive per-frame cancel+reinit timer pair with a
 * relaxed atomic store.  On x86-64 __ATOMIC_RELAXED compiles to a plain
 * MOV — no fence, no lock. */
static inline void
mac_table_entry_touch(mac_table_entry_t *entry) {
    __atomic_store_n(&entry->last_used, time(NULL), __ATOMIC_RELAXED);
}

/* -------------------------------------------------------------------------
 * Write path — must be called from dp_ev_dis thread ONLY
 * ---------------------------------------------------------------------- */
void mac_table_entry_add(dp_ctx_t *dp_ctx, mac_table_t *mac_table,
                         uint8_t *mac_addr, uint16_t vlan_id,
                         dp_intf_t *oif, uint16_t flags,
                         uint32_t remote_dst_ip);

void mac_table_entry_delete(dp_ctx_t *dp_ctx, mac_table_t *mac_table,
                            uint8_t *mac_addr, uint16_t vlan_id,
                            dp_intf_t *intf, uint32_t remote_dst_ip);

void mac_table_entry_delete2(dp_ctx_t *dp_ctx, mac_table_t *mac_table,
                             uint16_t vlan_id, uint8_t *mac_addr);

/* GC delete — called from the periodic table GC scan on dp_ev_dis. */
void mac_table_gc_delete_entry(dp_ctx_t *dp_ctx, mac_table_t *mac_table,
                               mac_table_entry_t *entry);

/* Delete every non-static (dynamic) entry.  Flood / other static entries
 * are left in place.  Must run on dp_ev_dis. */
void mac_table_delete_all_dynamic(dp_ctx_t *dp_ctx, mac_table_t *mac_table);

/* -------------------------------------------------------------------------
 * Show — safe to call from dp_ev_dis; uses rte_hash_iterate
 * ---------------------------------------------------------------------- */
void show_mac_table(mac_table_t *mac_table, uint16_t vlan_id);

/* -------------------------------------------------------------------------
 * L2 switch entry point
 * ---------------------------------------------------------------------- */
void l2_switch_recv_frame(dp_ctx_t *dp_ctx,
                          uint16_t vlan_id,
                          dp_intf_t *interface,
                          struct rte_mbuf *mbuf);

/* -------------------------------------------------------------------------
 * OIF list helpers (called only from dp_ev_dis write path)
 * ---------------------------------------------------------------------- */
mac_oif_entry_t *mac_oif_entry_create(dp_intf_t *oif, uint32_t remote_dst_ip);
void mac_oif_entry_destroy(mac_oif_entry_t *oif_entry);
bool mac_table_entry_add_oif(mac_table_entry_t *mac_entry,
                             dp_intf_t *oif, uint32_t remote_dst_ip);
bool mac_table_entry_remove_oif(mac_table_entry_t *mac_entry,
                                uint32_t ifindex, uint32_t remote_dst_ip);
mac_oif_entry_t *mac_table_entry_find_oif(mac_table_entry_t *mac_entry,
                                          uint32_t ifindex,
                                          uint32_t remote_dst_ip);
bool mac_table_entry_has_oifs(mac_table_entry_t *mac_entry);
void mac_table_entry_clear_oifs(mac_table_entry_t *mac_entry);

#endif /* __MAC_TABLE_H__ */
