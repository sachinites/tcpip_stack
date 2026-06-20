/*
 * mac_table.cpp — MAC table backed by DPDK rte_hash
 *
 * Concurrency model (single-writer):
 *   Writer : dp_ev_dis thread exclusively.
 *   Readers: any thread via mac_table_lookup() (rte_hash_lookup_data).
 *
 * Memory safety after deletion:
 *   After rte_hash_del_key() the entry pointer is no longer reachable by new
 *   lookups, but a reader that fetched the pointer just before deletion may
 *   still be dereferencing it.  We schedule a GC timer (DP_TABLE_GC_DELAY_MS)
 *   on dp_ev_dis to free the memory; by then all in-flight readers are done.
 */

#include <memory.h>
#include <ncurses.h>
#include <pthread.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_errno.h>

#include "mac_table.h"
#include "../../../net.h"
#include "../../Interface/dp_intf.h"
#include "../../dp_ctx.h"
#include "../../Interface/dp_intf_store.h"
#include "../../../libs/EventDispatcher/event_dispatcher.h"
#include "../../../libs/Tracer/tracer.h"
#include "../../../libs/gluethread/glthread.h"
#include "../../dp_uapi.h"

extern int cprintf(const char *format, ...);

/* -------------------------------------------------------------------------
 * Write-thread assertion: all mutations must happen on dp_ev_dis.
 * ---------------------------------------------------------------------- */
#define ASSERT_ON_DP_EV_DIS(dp_ctx) \
    assert((dp_ctx)->dp_ev_dis.thread && \
           pthread_equal(pthread_self(), *(dp_ctx)->dp_ev_dis.thread))

/* -------------------------------------------------------------------------
 * GC callback: deferred free of a deleted entry.
 * Runs on dp_ev_dis (posted via wheel-timer) DP_TABLE_GC_DELAY_MS after
 * the entry was removed from the hash.
 * ---------------------------------------------------------------------- */
static void
mac_entry_gc_free_cbk(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size)
{
    mac_table_entry_t *entry = (mac_table_entry_t *)arg;
    mac_table_entry_clear_oifs(entry);
    XFREE(entry);
}

/* Schedule deferred free for an entry that has already been removed from hash. */
static void
mac_entry_schedule_gc(dp_ctx_t *dp_ctx, mac_table_entry_t *entry)
{
    timer_register_app_event(DP_TIMER(dp_ctx),
                             mac_entry_gc_free_cbk,
                             (void *)entry,
                             sizeof(*entry),
                             DP_TABLE_GC_DELAY_MS,
                             0);
}

/* -------------------------------------------------------------------------
 * Init / destroy
 * ---------------------------------------------------------------------- */

void
init_mac_table(mac_table_t **mac_table)
{
    *mac_table = (mac_table_t *)XCALLOC2(0, 1, mac_table_t);

    struct rte_hash_parameters params = {};
    params.name       = "mac_table";
    params.entries    = 8192;
    params.key_len    = sizeof(mac_table_key_t);
    params.hash_func  = rte_jhash;
    params.hash_func_init_val = 0;
    params.socket_id  = 0;   /* NUMA 0; table is node-global */
    /* RW_CONCURRENCY_LF: lock-free readers + single writer, no internal ring.
     * Unlike RW_CONCURRENCY, this does not allocate an rte_ring (which needs
     * hugepage memzones), so it works in non-hugepage / Linux mode too.
     * It implies NO_FREE_ON_DEL, which is fine: we manage entry lifetime
     * ourselves via the deferred-GC timer. */
    params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;

    (*mac_table)->hash = rte_hash_create(&params);
    if (!(*mac_table)->hash) {
        cprintf("Error: mac_table rte_hash_create failed: %s\n",
                rte_strerror(rte_errno));
    }
    (*mac_table)->entry_count = 0;
}

void
destroy_mac_table(dp_ctx_t *dp_ctx, mac_table_t *mac_table)
{
    if (!mac_table) return;
    if (!mac_table->hash) { XFREE(mac_table); return; }
    /* Free all remaining entries immediately (teardown context). */
    uint32_t next = 0;
    const void *key;
    void *data;
    while (rte_hash_iterate(mac_table->hash, &key, &data, &next) >= 0) {
        mac_table_entry_t *entry = (mac_table_entry_t *)data;
        mac_table_entry_cancel_expiry_timer(entry);
        mac_table_entry_clear_oifs(entry);
        XFREE(entry);
    }
    rte_hash_free(mac_table->hash);
    XFREE(mac_table);
}

/* -------------------------------------------------------------------------
 * Read path — lock-free, safe from any thread
 * ---------------------------------------------------------------------- */

mac_table_entry_t *
mac_table_lookup(mac_table_t *mac_table, uint16_t vlan, uint8_t *mac)
{
    if (!mac_table->hash) return NULL;
    mac_table_key_t key = { .vlan_id = vlan };
    memcpy(key.mac, mac, 6);
    void *data = NULL;
    rte_hash_lookup_data(mac_table->hash, &key, &data);
    return (mac_table_entry_t *)data;
}

/* -------------------------------------------------------------------------
 * Timer helpers (called on dp_ev_dis)
 * ---------------------------------------------------------------------- */

void
mac_table_entry_cancel_expiry_timer(mac_table_entry_t *mac_table_entry)
{
    if (mac_table_entry->exp_timer_wt_elem) {
        timer_de_register_app_event(mac_table_entry->exp_timer_wt_elem);
        mac_table_entry->exp_timer_wt_elem = NULL;
    }
}

static void
mac_table_entry_timer_expiry_cbk(event_dispatcher_t *ev_dis,
                                  void *arg, uint32_t arg_size)
{
    mac_table_entry_t *entry = (mac_table_entry_t *)arg;
    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;

    tracer(dp_ctx->dptr, DL2SW,
           "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x] Expired\n",
           entry->vlan_id,
           entry->mac.mac[0], entry->mac.mac[1],
           entry->mac.mac[2], entry->mac.mac[3],
           entry->mac.mac[4], entry->mac.mac[5]);

    entry->exp_timer_wt_elem = NULL;
    if (!dp_ctx->mac_table->hash) { mac_entry_gc_free_cbk(ev_dis, entry, 0); return; }

    mac_table_key_t key = { .vlan_id = entry->vlan_id };
    memcpy(key.mac, entry->mac.mac, 6);

    if (rte_hash_del_key(dp_ctx->mac_table->hash, &key) >= 0) {
        if (dp_ctx->mac_table->entry_count > 0)
            dp_ctx->mac_table->entry_count--;
        /* Readers that already hold this pointer get DP_TABLE_GC_DELAY_MS. */
        mac_entry_schedule_gc(dp_ctx, entry);
    }
    /* else: already explicitly deleted; GC already scheduled by that path. */
}

void
mac_table_entry_init_timer(dp_ctx_t *dp_ctx, mac_table_entry_t *mac_table_entry)
{
    assert(!mac_table_entry->exp_timer_wt_elem);
    mac_table_entry->exp_timer_wt_elem = timer_register_app_event(
        DP_TIMER(dp_ctx),
        mac_table_entry_timer_expiry_cbk,
        (void *)mac_table_entry,
        sizeof(mac_table_entry_t),
        MAC_ENTRY_EXP_TIME * 1000,
        0);
}

/* -------------------------------------------------------------------------
 * Write path — all callers must be on dp_ev_dis
 * ---------------------------------------------------------------------- */

void
mac_table_entry_add(dp_ctx_t *dp_ctx,
                    mac_table_t *mac_table,
                    uint8_t *mac_addr,
                    uint16_t vlan_id,
                    uint32_t ifindex,
                    uint16_t flags,
                    uint32_t remote_dst_ip)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);
    if (!mac_table->hash) return;

    dp_intf_t *oif = dp_ctx->intf_table[ifindex];
    if (!oif) {
        cprintf("Error: DP_CTX %s: Interface with ifindex %d not found\n",
                dp_ctx->ctx_name, ifindex);
        return;
    }

    mac_table_entry_t *existing = mac_table_lookup(mac_table, vlan_id, mac_addr);
    if (existing) {
        /* Entry already present: just add the new OIF if absent. */
        if (mac_table_entry_add_oif(existing, oif, remote_dst_ip)) {
            tracer(dp_ctx->dptr, DL2SW,
                   "MAC Table Entry [%d %02x:%02x:%02x:%02x:%02x:%02x]: OIF %s added\n",
                   vlan_id,
                   mac_addr[0], mac_addr[1], mac_addr[2],
                   mac_addr[3], mac_addr[4], mac_addr[5],
                   oif->if_name);
        }
        return;
    }

    /* New entry. */
    mac_table_entry_t *entry = (mac_table_entry_t *)XCALLOC2(0, 1, mac_table_entry_t);
    entry->vlan_id = vlan_id;
    memcpy(entry->mac.mac, mac_addr, sizeof(mac_addr_t));
    entry->flags = flags;
    init_glthread(&entry->oif_list);
    mac_table_entry_add_oif(entry, oif, remote_dst_ip);

    if (!(flags & MAC_STATIC))
        mac_table_entry_init_timer(dp_ctx, entry);

    mac_table_key_t key = { .vlan_id = vlan_id };
    memcpy(key.mac, mac_addr, 6);
    rte_hash_add_key_data(mac_table->hash, &key, entry);
    mac_table->entry_count++;

    tracer(dp_ctx->dptr, DL2SW,
           "MAC Table Entry [%d %02x:%02x:%02x:%02x:%02x:%02x %s] Added\n",
           vlan_id,
           mac_addr[0], mac_addr[1], mac_addr[2],
           mac_addr[3], mac_addr[4], mac_addr[5],
           oif->if_name);
}

/* Internal: remove entry from hash + cancel timer + schedule GC free. */
static void
mac_entry_remove(dp_ctx_t *dp_ctx,
                 mac_table_t *mac_table,
                 mac_table_entry_t *entry,
                 mac_table_key_t *key)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);
    if (!mac_table->hash) return;

    /* Cancel expiry timer so it does not race with our GC scheduling. */
    mac_table_entry_cancel_expiry_timer(entry);

    if (rte_hash_del_key(mac_table->hash, key) >= 0) {
        if (mac_table->entry_count > 0)
            mac_table->entry_count--;
        mac_entry_schedule_gc(dp_ctx, entry);
    }
}

void
mac_table_entry_delete(dp_ctx_t *dp_ctx,
                       mac_table_t *mac_table,
                       uint8_t *mac_addr,
                       uint16_t vlan_id,
                       uint32_t ifindex,
                       uint32_t remote_dst_ip)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);

    mac_table_entry_t *entry = mac_table_lookup(mac_table, vlan_id, mac_addr);
    if (!entry) return;

    mac_table_entry_remove_oif(entry, ifindex, remote_dst_ip);

    if (!mac_table_entry_has_oifs(entry)) {
        mac_table_key_t key = { .vlan_id = vlan_id };
        memcpy(key.mac, mac_addr, 6);

        tracer(dp_ctx->dptr, DL2SW,
               "MAC Table Entry [%d %02x:%02x:%02x:%02x:%02x:%02x] deleted\n",
               vlan_id,
               mac_addr[0], mac_addr[1], mac_addr[2],
               mac_addr[3], mac_addr[4], mac_addr[5]);

        mac_entry_remove(dp_ctx, mac_table, entry, &key);
    }
}

void
mac_table_entry_delete2(dp_ctx_t *dp_ctx, mac_table_t *mac_table,
                        uint16_t vlan_id, uint8_t *mac_addr)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);

    mac_table_entry_t *entry = mac_table_lookup(mac_table, vlan_id, mac_addr);
    if (!entry) return;

    mac_table_key_t key = { .vlan_id = vlan_id };
    memcpy(key.mac, mac_addr, 6);

    tracer(dp_ctx->dptr, DL2SW,
           "MAC Table Entry [%d %02x:%02x:%02x:%02x:%02x:%02x] deleted (delete2)\n",
           vlan_id,
           mac_addr[0], mac_addr[1], mac_addr[2],
           mac_addr[3], mac_addr[4], mac_addr[5]);

    mac_entry_remove(dp_ctx, mac_table, entry, &key);
}

/* -------------------------------------------------------------------------
 * Show — iterate rte_hash (safe on dp_ev_dis while writers are serialised)
 * ---------------------------------------------------------------------- */

static uint32_t
mac_table_entry_get_exp_time_left(mac_table_entry_t *entry)
{
    if (entry->exp_timer_wt_elem)
        return wt_get_remaining_time(entry->exp_timer_wt_elem);
    return 0;
}

static char *
mac_table_entry_append_oifs(mac_table_entry_t *entry,
                             char *buffer, uint16_t buff_size)
{
    uint16_t len = 0;
    glthread_t *curr;
    mac_oif_entry_t *oif_entry;

    memset(buffer, 0, buff_size);

    ITERATE_GLTHREAD_BEGIN(&entry->oif_list, curr) {
        oif_entry = mac_oif_glue_to_entry(curr);
        if (!oif_entry->oif) continue;

        len += snprintf(buffer + len, buff_size - len, "%s", oif_entry->oif->if_name);

        if (oif_entry->remote_dst_ip) {
            len += snprintf(buffer + len, buff_size - len, "(%d.%d.%d.%d)",
                            (oif_entry->remote_dst_ip >> 24) & 0xFF,
                            (oif_entry->remote_dst_ip >> 16) & 0xFF,
                            (oif_entry->remote_dst_ip >>  8) & 0xFF,
                            (oif_entry->remote_dst_ip)       & 0xFF);
        }
        len += snprintf(buffer + len, buff_size - len, " ");
    } ITERATE_GLTHREAD_END(&entry->oif_list, curr);

    return buffer;
}

void
show_mac_table(mac_table_t *mac_table, uint16_t vlan_id)
{
    if (!mac_table || !mac_table->hash) return;

    int count = 0;
    char buffer[1024];
    uint32_t next = 0;
    const void *key;
    void *data;

    printw("\n\r");
    cprintf("VLAN   MAC Address         Type         Exp-Time(ms)\n");
    cprintf("----  ------------        ------       --------------\n\n");

    while (rte_hash_iterate(mac_table->hash, &key, &data, &next) >= 0) {

        mac_table_entry_t *entry = (mac_table_entry_t *)data;
        if (vlan_id && vlan_id != entry->vlan_id) continue;

        count++;

        if (entry->vlan_id == DEFAULT_VLAN_ID) {
            cprintf("%-6s %02x:%02x:%02x:%02x:%02x:%02x  %-13s %-6d\n",
                    "--",
                    entry->mac.mac[0], entry->mac.mac[1],
                    entry->mac.mac[2], entry->mac.mac[3],
                    entry->mac.mac[4], entry->mac.mac[5],
                    mac_entry_flag(entry->flags),
                    mac_table_entry_get_exp_time_left(entry));
        } else {
            cprintf("%-6d %02x:%02x:%02x:%02x:%02x:%02x  %-13s %-6d\n",
                    entry->vlan_id,
                    entry->mac.mac[0], entry->mac.mac[1],
                    entry->mac.mac[2], entry->mac.mac[3],
                    entry->mac.mac[4], entry->mac.mac[5],
                    mac_entry_flag(entry->flags),
                    mac_table_entry_get_exp_time_left(entry));
        }

        mac_table_entry_append_oifs(entry, buffer, sizeof(buffer));
        cprintf("       Ports: %s\n\n", buffer);
    }

    if (!count) cprintf("(empty)\n");
}

/* -------------------------------------------------------------------------
 * OIF list management (called only from write path on dp_ev_dis)
 * ---------------------------------------------------------------------- */

mac_oif_entry_t *
mac_oif_entry_create(dp_intf_t *oif, uint32_t remote_dst_ip)
{
    mac_oif_entry_t *e = (mac_oif_entry_t *)XCALLOC2(0, 1, mac_oif_entry_t);
    e->oif = oif;
    e->remote_dst_ip = remote_dst_ip;
    init_glthread(&e->glue);
    return e;
}

void
mac_oif_entry_destroy(mac_oif_entry_t *oif_entry)
{
    if (oif_entry) {
        remove_glthread(&oif_entry->glue);
        XFREE(oif_entry);
    }
}

bool
mac_table_entry_add_oif(mac_table_entry_t *mac_entry,
                        dp_intf_t *oif, uint32_t remote_dst_ip)
{
    if (!mac_entry || !oif) return false;

    mac_oif_entry_t *existing =
        mac_table_entry_find_oif(mac_entry, oif->port_id, remote_dst_ip);
    if (existing) return false;

    mac_oif_entry_t *e = mac_oif_entry_create(oif, remote_dst_ip);
    glthread_add_next(&mac_entry->oif_list, &e->glue);
    return true;
}

bool
mac_table_entry_remove_oif(mac_table_entry_t *mac_entry,
                           uint32_t ifindex, uint32_t remote_dst_ip)
{
    if (!mac_entry) return false;

    mac_oif_entry_t *e =
        mac_table_entry_find_oif(mac_entry, ifindex, remote_dst_ip);
    if (e) {
        mac_oif_entry_destroy(e);
        return true;
    }
    return false;
}

mac_oif_entry_t *
mac_table_entry_find_oif(mac_table_entry_t *mac_entry,
                         uint32_t ifindex, uint32_t remote_dst_ip)
{
    if (!mac_entry) return NULL;

    glthread_t *curr;
    mac_oif_entry_t *e;

    ITERATE_GLTHREAD_BEGIN(&mac_entry->oif_list, curr) {
        e = mac_oif_glue_to_entry(curr);
        if (e->oif &&
            e->oif->port_id == ifindex &&
            e->remote_dst_ip == remote_dst_ip)
            return e;
    } ITERATE_GLTHREAD_END(&mac_entry->oif_list, curr);

    return NULL;
}

bool
mac_table_entry_has_oifs(mac_table_entry_t *mac_entry)
{
    if (!mac_entry) return false;
    return !IS_GLTHREAD_LIST_EMPTY(&mac_entry->oif_list);
}

void
mac_table_entry_clear_oifs(mac_table_entry_t *mac_entry)
{
    if (!mac_entry) return;

    glthread_t *curr;
    mac_oif_entry_t *e;

    ITERATE_GLTHREAD_BEGIN(&mac_entry->oif_list, curr) {
        e = mac_oif_glue_to_entry(curr);
        mac_oif_entry_destroy(e);
    } ITERATE_GLTHREAD_END(&mac_entry->oif_list, curr);
}
