/*
 * =============================================================================
 * File: dp_table_gc.c
 * Description: Periodic GC scan for ARP and MAC table entries.
 * =============================================================================
 */

#include <time.h>
#include <stdlib.h>

#include <rte_hash.h>

#include "../libs/libtimer/WheelTimer.h"
#include "../libs/EventDispatcher/event_dispatcher.h"
#include "../libs/Tracer/tracer.h"
#include "../tcp_ip_trace.h"

#include "dp_ctx.h"
#include "dp_table_gc.h"
#include "Layer2/arp/arp.h"
#include "Layer2/switching/mac_table.h"
#include "Vrfs/dp_vrf.h"
#include "Interface/intf_cons.h"

/* Forward declaration of the callback so start/stop can reference it. */
static void dp_table_gc_scan_cbk(event_dispatcher_t *ev_dis,
                                   void *arg, uint32_t arg_size);

/* -------------------------------------------------------------------------
 * ARP table scan
 * ---------------------------------------------------------------------- */

static void
dp_arp_table_gc_scan(dp_ctx_t *dp_ctx, arp_table_t *arp_table, time_t now)
{
    if (!arp_table || !arp_table->hash) return;

    uint32_t next = 0;
    const void *key;
    void *data;

    /* Collect expired entries first — safe to delete after iteration ends. */
    arp_entry_t *expired[DP_TABLE_GC_MAX_BATCH];
    int n = 0;

    while (n < DP_TABLE_GC_MAX_BATCH &&
           rte_hash_iterate(arp_table->hash, &key, &data, &next) >= 0) {
        arp_entry_t *entry = (arp_entry_t *)data;
        if (!entry) continue;
        time_t lu = __atomic_load_n(&entry->last_used, __ATOMIC_RELAXED);
        /* Delete if never forwarded (lu==0) OR idle >= scan interval. */
        if (lu == 0 || (now - lu) >= DP_TABLE_SCAN_INTERVAL_SECS)
            expired[n++] = entry;
    }

    for (int i = 0; i < n; i++) {
        char ip_str[IPV4_ADDR_LEN_STR];
        ip_ntop(expired[i]->ip_addr, ip_str);
        tracer(dp_ctx->dptr, DARP | DTIMER,
               "GC scan: ARP-entry %s idle >= %ds — deleting\n",
               ip_str, DP_TABLE_SCAN_INTERVAL_SECS);
        arp_entry_schedule_delete(dp_ctx, expired[i]);
    }
}

static void
dp_all_arp_tables_gc_scan(dp_ctx_t *dp_ctx, time_t now)
{
    int i;

    for (i = 0; i < DP_MAX_VRF; i++) {
        dp_vrf_t *vrf = dp_ctx->dp_vrf_table[i];
        if (vrf && vrf->arp_table)
            dp_arp_table_gc_scan(dp_ctx, vrf->arp_table, now);
    }
}

/* -------------------------------------------------------------------------
 * MAC table scan
 * ---------------------------------------------------------------------- */

static void
dp_mac_table_gc_scan(dp_ctx_t *dp_ctx, time_t now)
{
    mac_table_t *mac_table = dp_ctx->mac_table;
    if (!mac_table || !mac_table->hash) return;

    uint32_t next = 0;
    const void *key;
    void *data;

    mac_table_entry_t *expired[DP_TABLE_GC_MAX_BATCH];
    int n = 0;

    while (n < DP_TABLE_GC_MAX_BATCH &&
           rte_hash_iterate(mac_table->hash, &key, &data, &next) >= 0) {
        mac_table_entry_t *entry = (mac_table_entry_t *)data;
        if (!entry || (entry->flags & MAC_STATIC)) continue;
        time_t lu = __atomic_load_n(&entry->last_used, __ATOMIC_RELAXED);
        if (lu == 0 || (now - lu) >= DP_TABLE_SCAN_INTERVAL_SECS)
            expired[n++] = entry;
    }

    for (int i = 0; i < n; i++) {
        tracer(dp_ctx->dptr, DL2SW | DTIMER,
               "GC scan: MAC [%d %02x:%02x:%02x:%02x:%02x:%02x] idle >= %ds — deleting\n",
               expired[i]->vlan_id,
               expired[i]->mac.mac[0], expired[i]->mac.mac[1],
               expired[i]->mac.mac[2], expired[i]->mac.mac[3],
               expired[i]->mac.mac[4], expired[i]->mac.mac[5],
               DP_TABLE_SCAN_INTERVAL_SECS);
        mac_table_gc_delete_entry(dp_ctx, mac_table, expired[i]);
    }
}

/* -------------------------------------------------------------------------
 * Scan callback — runs on dp_ev_dis every DP_TABLE_SCAN_INTERVAL_SECS
 * ---------------------------------------------------------------------- */

static void
dp_table_gc_scan_cbk(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size)
{
    (void)arg;
    (void)arg_size;

    if (!ev_dis) return;

    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;
    if (!dp_ctx) return;
    time_t now = time(NULL);

    tracer(dp_ctx->dptr, DARP | DL2SW | DTIMER,
           "DP table GC scan: scanning ARP and MAC tables\n");

    dp_mac_table_gc_scan(dp_ctx, now);
    dp_all_arp_tables_gc_scan(dp_ctx, now);
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void
dp_table_gc_start(dp_ctx_t *dp_ctx)
{
    dp_ctx->table_scan_timer = timer_register_app_event(
        DP_TIMER(dp_ctx),
        dp_table_gc_scan_cbk,
        NULL, 0,
        (uint32_t)DP_TABLE_SCAN_INTERVAL_SECS * 1000,
        1);
}

void
dp_table_gc_stop(dp_ctx_t *dp_ctx)
{
    if (dp_ctx->table_scan_timer) {
        timer_de_register_app_event(dp_ctx->table_scan_timer);
        dp_ctx->table_scan_timer = NULL;
    }
}
