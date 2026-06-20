/*
 * =============================================================================
 * File: arp.h
 * Description: ARP table backed by DPDK rte_hash + single-writer dp_ev_dis.
 * =============================================================================
 *
 * Concurrency model:
 *   Writer : dp_ev_dis thread exclusively (add, delete, update, clear).
 *   Readers: any thread via arp_table_lookup() (rte_hash_lookup_data).
 *
 * Key:   arp_hash_key_t  { ip_addr (4B), _pad (4B) } = 8 bytes.
 * Value: arp_entry_t *   (pointer stored; rte_hash does NOT own the memory).
 *
 * Memory safety:
 *   After rte_hash_del_key() the entry is scheduled for deferred free via a
 *   DP_TABLE_GC_DELAY_MS wheel-timer callback on dp_ev_dis.  Readers that
 *   fetched the pointer before deletion have this window to finish.
 *
 * The pthread_rwlock and glthread list previously used for the ARP table
 * are removed.  Only arp_entry_t::arp_pending_list (a per-entry list of
 * packets waiting for ARP resolution) keeps using glthread.
 * =============================================================================
 */

#ifndef __ARP__HDR__
#define __ARP__HDR__

#include <time.h>
#include "../../../libs/common/cmn_struct.h"
#include "../../../libs/gluethread/glthread.h"
#include "../../../tcpconst.h"
#include "../../dp_const.h"

typedef struct rte_mbuf pkt_mbuf_t;
typedef struct arp_hdr_ arp_hdr_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct _wheel_timer_elem_t wheel_timer_elem_t;
struct rte_hash;   /* forward-declared; include <rte_hash.h> in .c files */

#include <stdint.h>

/* -------------------------------------------------------------------------
 * Hash key: 8 bytes (ip_addr + padding for rte_hash alignment requirement).
 * Note: multiple protocols for the same IP are stored in one entry;
 * proto is kept inside arp_entry_t and checked at delete time.
 * ---------------------------------------------------------------------- */
typedef struct arp_hash_key_ {
    uint32_t ip_addr;
    uint32_t _pad;
} arp_hash_key_t;

/* -------------------------------------------------------------------------
 * ARP table: one instance per VRF.
 * ---------------------------------------------------------------------- */
#pragma pack(push, 8)

typedef struct arp_table_ {
    struct rte_hash *hash;   /* keyed by arp_hash_key_t; single-writer dp_ev_dis */
} arp_table_t;

/* -------------------------------------------------------------------------
 * Per-entry pending-packet: a packet waiting for ARP resolution.
 * ---------------------------------------------------------------------- */
typedef struct arp_pending_entry_ arp_pending_entry_t;
typedef struct arp_entry_ arp_entry_t;
typedef void (*arp_processing_fn)(dp_ctx_t *,
                                  dp_intf_t *,
                                  arp_entry_t *,
                                  arp_pending_entry_t *);

struct arp_pending_entry_ {
    glthread_t arp_pending_entry_glue;
    arp_processing_fn cb;
    struct rte_mbuf *mbuf;
};

GLTHREAD_TO_STRUCT(arp_pending_entry_glue_to_arp_pending_entry,
    arp_pending_entry_t, arp_pending_entry_glue);

/* -------------------------------------------------------------------------
 * ARP entry.
 * arp_pending_list : glthread list of pending arp_pending_entry_t.
 * arp_table        : back-reference so GC callback can del the key.
 * last_used        : wall-clock seconds, written by forwarding threads
 *                    (relaxed atomic store), read by the GC scan on dp_ev_dis.
 *                    0 = never forwarded since entry was (re)inserted.
 * ---------------------------------------------------------------------- */
struct arp_entry_ {
    
    glthread_t arp_pending_list;
    mac_addr_t mac_addr;
    uint16_t proto;
    uint32_t ip_addr;      /* hash key */
    dp_intf_t *oif;
    bool is_sane;
    arp_table_t *arp_table; /* back-reference to owning table */
    time_t last_used;       /* updated by data-path on every forwarded pkt */
};

#pragma pack(pop)

GLTHREAD_TO_STRUCT(arp_pending_list_to_arp_entry, arp_entry_t, arp_pending_list);

#define IS_ARP_ENTRIES_EQUAL(e1, e2)                                   \
    ((e1)->ip_addr == (e2)->ip_addr &&                                  \
     mac_address_compare((e1)->mac_addr.mac, (e2)->mac_addr.mac) &&   \
     (e1)->oif == (e2)->oif &&                                         \
     (e1)->is_sane == (e2)->is_sane &&                                 \
     (e1)->is_sane == false &&                                         \
     (e1)->proto == (e2)->proto)

static inline bool
arp_entry_sane(arp_entry_t *arp_entry) {
    return arp_entry->is_sane;
}

/* Called by the forwarding data path on every packet that hits this entry.
 * Uses a relaxed atomic store so the compiler cannot cache or reorder the
 * write.  On x86-64 __ATOMIC_RELAXED compiles to a plain MOV — no fence. */
static inline void
arp_entry_touch(arp_entry_t *arp_entry) {
    __atomic_store_n(&arp_entry->last_used, time(NULL), __ATOMIC_RELAXED);
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------------- */
void init_arp_table(arp_table_t **arp_table, const char *ctx_name, const char *vrf_name);
void clear_arp_table(dp_ctx_t *dp_ctx, arp_table_t *arp_table);

/* -------------------------------------------------------------------------
 * Read path — lock-free, callable from any thread (DPDK workers included)
 * ---------------------------------------------------------------------- */
arp_entry_t *arp_table_lookup(arp_table_t *arp_table, uint32_t ip_addr);

/* -------------------------------------------------------------------------
 * Write path — must be called from dp_ev_dis thread ONLY
 * ---------------------------------------------------------------------- */
bool arp_table_entry_add(dp_ctx_t *dp_ctx,
                         dp_vrf_t *vrf,
                         arp_table_t *arp_table,
                         arp_entry_t *arp_entry,
                         glthread_t **arp_pending_list);

void arp_entry_delete(dp_ctx_t *dp_ctx, dp_vrf_t *vrf,
                      uint32_t ip_addr, uint16_t proto);

void arp_entry_delete_by_interface(dp_ctx_t *dp_ctx,
                                   arp_table_t *arp_table,
                                   dp_intf_t *intf);

void create_update_arp_sane_entry(dp_ctx_t *dp_ctx,
                                  dp_vrf_t *vrf,
                                  arp_table_t *arp_table,
                                  uint32_t ip_addr,
                                  struct rte_mbuf *mbuf);

void arp_table_update_from_arp_reply(dp_ctx_t *dp_ctx,
                                     dp_vrf_t *vrf,
                                     arp_table_t *arp_table,
                                     arp_hdr_t *arp_hdr,
                                     dp_intf_t *iif);

bool arp_entry_add(dp_ctx_t *dp_ctx,
                   dp_vrf_t *vrf,
                   unsigned char *ip_addr,
                   mac_addr_t mac,
                   dp_intf_t *oif,
                   uint16_t proto);

/* -------------------------------------------------------------------------
 * GC delete — called from the periodic table GC scan on dp_ev_dis.
 * Removes the entry from the hash, drains pending packets, and schedules
 * deferred memory free (DP_TABLE_GC_DELAY_MS grace period).
 * ---------------------------------------------------------------------- */
void arp_entry_schedule_delete(dp_ctx_t *dp_ctx, arp_entry_t *arp_entry);

/* -------------------------------------------------------------------------
 * Pending-entry management
 * ---------------------------------------------------------------------- */
void add_arp_pending_entry(dp_ctx_t *dp_ctx,
                           arp_entry_t *arp_entry,
                           arp_processing_fn cb,
                           struct rte_mbuf *mbuf);

/* -------------------------------------------------------------------------
 * ARP packet processing (posts jobs to dp_ev_dis from packet threads)
 * ---------------------------------------------------------------------- */
void send_arp_broadcast_request(dp_ctx_t *dp_ctx,
                                dp_vrf_t *vrf,
                                dp_intf_t *oif,
                                uint32_t ip_addr);

void process_arp_broadcast_request(dp_ctx_t *dp_ctx,
                                   dp_vrf_t *vrf,
                                   dp_intf_t *iif,
                                   ethernet_hdr_t *ethernet_hdr);

void process_arp_reply_msg(dp_ctx_t *dp_ctx,
                           dp_vrf_t *vrf,
                           dp_intf_t *iif,
                           ethernet_hdr_t *ethernet_hdr);

void l2_prepare_arp_reply_msg(ethernet_hdr_t *ethernet_hdr_reply,
                              mac_addr_t *dst_mac, uint32_t dst_ip,
                              mac_addr_t *src_mac, uint32_t src_ip);

/* -------------------------------------------------------------------------
 * Show (runs on dp_ev_dis via dp_uapi sync job)
 * ---------------------------------------------------------------------- */
void show_arp_table(arp_table_t *arp_table);

#endif /* __ARP__HDR__ */
