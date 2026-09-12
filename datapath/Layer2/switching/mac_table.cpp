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
#include <time.h>
#include <ncurses.h>
#include <pthread.h>
#include <arpa/inet.h>

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
#include "../MacNexthop/L2FwdObject.h"
#include "../../../dpcp_cmn.h"
#include "../../dp_const.h"

extern int cprintf(const char *format, ...);

static uint32_t mac_table_hash_seq;

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
    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;
    mac_table_entry_clear_oifs(dp_ctx, entry);
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
init_mac_table(mac_table_t **mac_table, const char *ctx_name,
               const char *suffix)
{
    *mac_table = (mac_table_t *)XCALLOC2(0, 1, mac_table_t);

    /* DPDK rte_hash names are process-global.  Global L2 MAC table uses
     * mac_<ctx>; per-BD tables use mac_<ctx>_<suffix> (e.g. bd10). */
    char hash_name[RTE_HASH_NAMESIZE];
    uint32_t seq = ++mac_table_hash_seq;

    if (suffix && suffix[0]) {
        snprintf(hash_name, sizeof(hash_name), "mac_%.10s_%.10s_%u",
                 ctx_name, suffix, seq);
    } else {
        snprintf(hash_name, sizeof(hash_name), "mac_%.20s_%u", ctx_name, seq);
    }

    struct rte_hash_parameters params = {};
    params.name       = hash_name;
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
        mac_table_entry_clear_oifs(dp_ctx, entry);
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
 * Per-entry MAC timers removed.  Expiry is handled by the single periodic
 * GC scan timer registered in dp_table_gc.c (DP_TABLE_SCAN_INTERVAL_SECS).
 * ---------------------------------------------------------------------- */

/* Forward declaration — defined in the write-path section below. */
static void mac_entry_remove(dp_ctx_t *dp_ctx, mac_table_t *mac_table,
                              mac_table_entry_t *entry, mac_table_key_t *key);
static bool mac_table_entry_grow_oifs(mac_table_entry_t *mac_entry);

/* GC delete — called from the periodic GC scan on dp_ev_dis.
 * Removes the entry from the hash and schedules deferred memory free. */
void
mac_table_gc_delete_entry(dp_ctx_t *dp_ctx, mac_table_t *mac_table,
                           mac_table_entry_t *entry)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);
    mac_table_key_t key = { .vlan_id = entry->vlan_id };
    memcpy(key.mac, entry->mac.mac, sizeof(key.mac));
    mac_entry_remove(dp_ctx, mac_table, entry, &key);
}

/* -------------------------------------------------------------------------
 * Write path — all callers must be on dp_ev_dis
 * ---------------------------------------------------------------------- */

void
mac_table_entry_add(dp_ctx_t *dp_ctx,
                    mac_table_t *mac_table,
                    uint8_t *mac_addr,
                    uint16_t vlan_id,
                    uint16_t flags,
                    mac_fwd_object_t *fwd_tmpl)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);

    if (!mac_table->hash || !fwd_tmpl) return;

    mac_table_entry_t *existing = mac_table_lookup(mac_table, vlan_id, mac_addr);

    if (existing) {
        if (mac_table_entry_attach_fwd(dp_ctx, existing, fwd_tmpl)) {
            tracer(dp_ctx->dptr, DL2SW,
                   "MAC Table Entry [%u %02x:%02x:%02x:%02x:%02x:%02x]: fwd obj added\n",
                   vlan_id,
                   mac_addr[0], mac_addr[1], mac_addr[2],
                   mac_addr[3], mac_addr[4], mac_addr[5]);
        }
        return;
    }

    mac_table_entry_t *entry = (mac_table_entry_t *)XCALLOC2(0, 1, mac_table_entry_t);
    entry->vlan_id = vlan_id;
    entry->last_used = (flags & MAC_STATIC) ? 0 : time(NULL);
    memcpy(entry->mac.mac, mac_addr, sizeof(mac_addr_t));
    entry->flags = flags;
    entry->oifs = NULL;
    entry->oif_count = 0;
    entry->oif_cap = 0;
    entry->nh_index = 0;
    mac_table_entry_attach_fwd(dp_ctx, entry, fwd_tmpl);

    mac_table_key_t key = { .vlan_id = vlan_id };
    memcpy(key.mac, mac_addr, 6);
    assert (!rte_hash_add_key_data(mac_table->hash, &key, entry));
    mac_table->entry_count++;

    tracer(dp_ctx->dptr, DL2SW,
           "MAC Table Entry [%u %02x:%02x:%02x:%02x:%02x:%02x] Added\n",
           vlan_id,
           mac_addr[0], mac_addr[1], mac_addr[2],
           mac_addr[3], mac_addr[4], mac_addr[5]);
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
                       mac_fwd_object_t *fwd_tmpl)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);

    mac_table_entry_t *entry = mac_table_lookup(mac_table, vlan_id, mac_addr);
    if (!entry || !fwd_tmpl) return;

    mac_fwd_object_t *fwd_obj =
        dp_ctx_lookup_mac_fwd_object(
            dp_ctx->l2_fwd_obj_tree[fwd_tmpl->fwd_type], fwd_tmpl);
    if (fwd_obj)
        mac_table_entry_detach_fwd(dp_ctx, entry, fwd_obj);

    if (!mac_table_entry_has_oifs(entry)) {
        mac_table_key_t key = { .vlan_id = vlan_id };
        memcpy(key.mac, mac_addr, 6);

        tracer(dp_ctx->dptr, DL2SW,
               "MAC Table Entry [%u %02x:%02x:%02x:%02x:%02x:%02x] deleted\n",
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

static mac_table_entry_t *
mac_table_entry_clone_static(const mac_table_entry_t *src)
{
    mac_table_entry_t *dst;
    uint16_t i;

    dst = (mac_table_entry_t *)XCALLOC2(0, 1, mac_table_entry_t);
    dst->vlan_id = src->vlan_id;
    dst->flags = src->flags;
    dst->last_used = src->last_used;
    dst->nh_index = 0;
    memcpy(dst->mac.mac, src->mac.mac, sizeof(dst->mac.mac));

    for (i = 0; i < src->oif_count; i++) {
        if (!src->oifs[i])
            continue;

        if (dst->oif_count >= dst->oif_cap &&
            !mac_table_entry_grow_oifs(dst)) {
            break;
        }

        mac_fwd_object_reference(src->oifs[i]);
        dst->oifs[dst->oif_count++] = src->oifs[i];
    }

    return dst;
}

static void
mac_table_gc_free_cbk(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size)
{
    mac_table_t *mac_table = (mac_table_t *)arg;
    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;

    destroy_mac_table(dp_ctx, mac_table);
}

void
mac_table_schedule_gc(dp_ctx_t *dp_ctx, mac_table_t *mac_table)
{
    if (!mac_table)
        return;

    timer_register_app_event(DP_TIMER(dp_ctx),
                             mac_table_gc_free_cbk,
                             (void *)mac_table,
                             sizeof(*mac_table),
                             DP_TABLE_GC_DELAY_MS,
                             0);
}

void
dp_bd_mac_notify_cp(dp_ctx_t *dp_ctx,
                    uint32_t bd_ifindex,
                    const uint8_t *mac_addr,
                    bool add)
{
    dp_intf_t *bd_intf;
    pkt_q_t *lmac_q;
    bd_lmac_data_t *lmac_data;

    if (!dp_ctx || !mac_addr || bd_ifindex >= DP_MAX_INTF)
        return;

    bd_intf = dp_ctx->intf_table[bd_ifindex];
    if (!bd_intf)
        return;

    lmac_q = bd_intf->lmac_queue;
    if (!lmac_q)
        return;

    lmac_data = (bd_lmac_data_t *)XCALLOC2(0, 1, bd_lmac_data_t);
    lmac_data->ac_ifindex = 0;
    lmac_data->ip_addr = 0;
    lmac_data->bd_ifindex = bd_ifindex;
    lmac_data->add = add;
    memcpy(lmac_data->mac.mac, mac_addr, sizeof(lmac_data->mac.mac));

    tracer (dp_ctx->dptr, DL2SW_DET,
            "MAC Table Entry [%s %02x:%02x:%02x:%02x:%02x:%02x] %s\n",
            bd_intf->if_name,
            mac_addr[0], mac_addr[1], mac_addr[2],
            mac_addr[3], mac_addr[4], mac_addr[5],
            add ? "added" : "deleted");

    dp_pkt_q_enqueue(dp_ctx, lmac_q, (char *)lmac_data, sizeof(*lmac_data));
}

mac_table_t *
mac_table_clear_retain_static(dp_ctx_t *dp_ctx,
                              mac_table_t *old_table,
                              uint32_t bd_ifindex,
                              const char *ctx_name,
                              const char *suffix)
{
    mac_table_t *new_table;
    uint32_t next = 0;
    const void *key;
    void *data;

    ASSERT_ON_DP_EV_DIS(dp_ctx);

    if (!old_table || !old_table->hash)
        return NULL;

    init_mac_table(&new_table, ctx_name, suffix);
    if (!new_table || !new_table->hash) {
        if (new_table)
            XFREE(new_table);
        return NULL;
    }

    while (rte_hash_iterate(old_table->hash, &key, &data, &next) >= 0) {
        mac_table_entry_t *src = (mac_table_entry_t *)data;
        mac_table_entry_t *dst;
        mac_table_key_t entry_key;

        if (!src)
            continue;

        if (!(src->flags & MAC_STATIC)) {
            /* Discard dynamic entry — notify CP of the unlearn. */
            dp_bd_mac_notify_cp(dp_ctx, bd_ifindex, src->mac.mac, false);
            continue;
        }

        dst = mac_table_entry_clone_static(src);
        entry_key.vlan_id = dst->vlan_id;
        memcpy(entry_key.mac, dst->mac.mac, sizeof(entry_key.mac));

        assert(rte_hash_add_key_data(new_table->hash, &entry_key, dst) >= 0);
        new_table->entry_count++;
    }

    return new_table;
}

void
mac_table_delete_all_dynamic(dp_ctx_t *dp_ctx, mac_table_t *mac_table)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);

    if (!mac_table || !mac_table->hash)
        return;

    /* Collect-then-delete so rte_hash_iterate is not invalidated mid-walk. */
    for (;;) {
        uint32_t next = 0;
        const void *key;
        void *data;
        mac_table_entry_t *batch[64];
        int n = 0;

        while (n < 64 &&
               rte_hash_iterate(mac_table->hash, &key, &data, &next) >= 0) {
            mac_table_entry_t *entry = (mac_table_entry_t *)data;
            if (entry && !(entry->flags & MAC_STATIC))
                batch[n++] = entry;
        }

        if (n == 0)
            break;

        for (int i = 0; i < n; i++)
            mac_table_gc_delete_entry(dp_ctx, mac_table, batch[i]);
    }
}

mac_fwd_object_t *
mac_table_get_forwarding_nh(mac_table_entry_t *entry)
{
    uint16_t i;
    uint16_t start_idx;
    mac_fwd_object_t *fwd_obj;

    if (!entry || !entry->oif_count)
        return NULL;

    if (mac_table_entry_is_broadcast(entry))
        return NULL;

    if (entry->oif_count == 1)
        return entry->oifs[0];

    start_idx = (uint16_t)((entry->nh_index + 1) % entry->oif_count);

    for (i = 0; i < entry->oif_count; i++) {
        uint16_t cur = (start_idx + i) % entry->oif_count;

        fwd_obj = entry->oifs[cur];
        if (!fwd_obj)
            continue;

        entry->nh_index = (uint8_t)cur;
        return fwd_obj;
    }

    return NULL;
}

/* -------------------------------------------------------------------------
 * Show — iterate rte_hash (safe on dp_ev_dis while writers are serialised)
 * ---------------------------------------------------------------------- */


static int
mac_table_fmt_one_oif(dp_ctx_t *dp_ctx, mac_fwd_object_t *fwd_obj,
                      char *buffer, uint16_t buff_size)
{
    int len = 0;

    if (!fwd_obj || buff_size == 0)
        return 0;

    switch (fwd_obj->fwd_type) {

        case L2_FWD_PORT:
        {
            dp_intf_t *oif = (fwd_obj->u.dp_intf < DP_MAX_INTF) ?
                dp_ctx->intf_table[fwd_obj->u.dp_intf] : NULL;
            if (oif)
                len = snprintf(buffer, buff_size, "%s", oif->if_name);
            else
                len = snprintf(buffer, buff_size, "if%u", fwd_obj->u.dp_intf);
            break;
        }

        case L2_FWD_RMAC:
        {
            if (!fwd_obj->u.rmac.rmacif ||
                !fwd_obj->u.rmac.rmacif->port_id ||
                (fwd_obj->u.rmac.rmacif->port_id > DP_MAX_INTF)) {
                break;
            }
            len = snprintf(buffer, buff_size, "%s",
                           fwd_obj->u.rmac.rmacif->if_name);
            break;
        }

        case L2_FWD_FLOODING:
            if (fwd_obj->u.l2_flood.vfif)
                len = snprintf(buffer, buff_size, "%s",
                               fwd_obj->u.l2_flood.vfif->if_name);
            break;

        case L2_FWD_VxLAN:
            len = snprintf(buffer, buff_size,
                           "nve(vni %u %d.%d.%d.%d)",
                           fwd_obj->u.vxlan.l2vni,
                           (fwd_obj->u.vxlan.vtep_ip >> 24) & 0xFF,
                           (fwd_obj->u.vxlan.vtep_ip >> 16) & 0xFF,
                           (fwd_obj->u.vxlan.vtep_ip >>  8) & 0xFF,
                           (fwd_obj->u.vxlan.vtep_ip)       & 0xFF);
            break;

        case L2_FWD_MPLS_TUNNEL:
        {
            mpls_lstack_t *st = fwd_obj->u.mpls_tunnel.lbl_stk;
            int off = 0;

            if (!st || st->curr_index < 0) {
                len = snprintf(buffer, buff_size,
                               "mpls(oif=%s nh=%u.%u.%u.%u)",
                               dp_ctx->intf_table[fwd_obj->u.mpls_tunnel.oif_ifindex] ?
                               dp_ctx->intf_table[fwd_obj->u.mpls_tunnel.oif_ifindex]->if_name : "-",
                               (fwd_obj->u.mpls_tunnel.nh_ip >> 24) & 0xFF,
                               (fwd_obj->u.mpls_tunnel.nh_ip >> 16) & 0xFF,
                               (fwd_obj->u.mpls_tunnel.nh_ip >> 8) & 0xFF,
                               fwd_obj->u.mpls_tunnel.nh_ip & 0xFF);
                break;
            }

            off += snprintf(buffer, buff_size,
                            "mpls(oif=%s nh=%u.%u.%u.%u labels=",
                            dp_ctx->intf_table[fwd_obj->u.mpls_tunnel.oif_ifindex] ?
                            dp_ctx->intf_table[fwd_obj->u.mpls_tunnel.oif_ifindex]->if_name : "-",
                            (fwd_obj->u.mpls_tunnel.nh_ip >> 24) & 0xFF,
                            (fwd_obj->u.mpls_tunnel.nh_ip >> 16) & 0xFF,
                            (fwd_obj->u.mpls_tunnel.nh_ip >> 8) & 0xFF,
                            fwd_obj->u.mpls_tunnel.nh_ip & 0xFF);

            for (int i = 0; i <= st->curr_index; i++) {
                off += snprintf(buffer + off, buff_size - off, "%s%u",
                                i ? "," : "",
                                mpls_label_get_value(st->labels[i].label_val));
                if (off >= buff_size)
                    break;
            }
            if (off < buff_size)
                off += snprintf(buffer + off, buff_size - off, ")");
            len = off;
            break;
        }
        case L2_FWD_SRv6_TUNNEL:
        {
            uint8_t seg_cnt = fwd_obj->u.srv6.seg_lst_cnt;
            int off = 0;
            const char *oif_name = "-";

            if (fwd_obj->u.srv6.oif_ifindex < DP_MAX_INTF &&
                dp_ctx->intf_table[fwd_obj->u.srv6.oif_ifindex])
                oif_name = dp_ctx->intf_table[fwd_obj->u.srv6.oif_ifindex]->if_name;

            off += snprintf(buffer, buff_size, "srv6(");

            if (fwd_obj->u.srv6.oif_ifindex) {
                off += snprintf(buffer + off, buff_size - off,
                                "oif=%s", oif_name);
            }

            if (fwd_obj->u.srv6.nh_ip) {
                off += snprintf(buffer + off, buff_size - off,
                                "%snh=%u.%u.%u.%u",
                                fwd_obj->u.srv6.oif_ifindex ? " " : "",
                                (fwd_obj->u.srv6.nh_ip >> 24) & 0xFF,
                                (fwd_obj->u.srv6.nh_ip >> 16) & 0xFF,
                                (fwd_obj->u.srv6.nh_ip >> 8) & 0xFF,
                                fwd_obj->u.srv6.nh_ip & 0xFF);
            }

            if (fwd_obj->u.srv6.seg_lst && seg_cnt) {
                off += snprintf(buffer + off, buff_size - off,
                                "%ssegs=",
                                (fwd_obj->u.srv6.oif_ifindex ||
                                 fwd_obj->u.srv6.nh_ip) ? " " : "");
                for (uint8_t i = 0; i < seg_cnt; i++) {
                    char sid[INET6_ADDRSTRLEN];

                    if (!inet_ntop(AF_INET6, (*fwd_obj->u.srv6.seg_lst)[i],
                                   sid, sizeof(sid)))
                        snprintf(sid, sizeof(sid), "?");

                    off += snprintf(buffer + off, buff_size - off, "%s%s",
                                    i ? "," : "", sid);
                    if (off >= buff_size)
                        break;
                }
            }

            if (off < buff_size)
                off += snprintf(buffer + off, buff_size - off, ")");
            len = off;
            break;
        }

        default:
            len = snprintf(buffer, buff_size, "fwd-%u",
                           (unsigned)fwd_obj->fwd_type);
            break;
    }

    return len;
}

static void
mac_table_entry_print_oifs(dp_ctx_t *dp_ctx, mac_table_entry_t *entry)
{
    char buffer[256];
    bool first = true;

    for (uint16_t i = 0; i < entry->oif_count; i++) {
        mac_fwd_object_t *fwd_obj = entry->oifs[i];
        if (!fwd_obj)
            continue;

        if (mac_table_fmt_one_oif(dp_ctx, fwd_obj, buffer, sizeof(buffer)) <= 0)
            continue;

        if (first) {
            cprintf("       Ports: %s  hits=%llu\n", buffer,
                    (unsigned long long)fwd_obj->hit_count);
            first = false;
        } else {
            cprintf("              %s  hits=%llu\n", buffer,
                    (unsigned long long)fwd_obj->hit_count);
        }
    }

    if (first)
        cprintf("       Ports:\n");
}

void
show_mac_table(dp_ctx_t *dp_ctx, mac_table_t *mac_table, uint16_t vlan_id)
{
    if (!mac_table || !mac_table->hash) return;

    int count = 0;
    uint32_t next = 0;
    const void *key;
    void *data;

    time_t now = time(NULL);
    printw("\n\r");
    cprintf("VLAN   MAC Address         Type         Idle-Time(sec)\n");
    cprintf("----  ------------        ------       --------------\n\n");

    while (rte_hash_iterate(mac_table->hash, &key, &data, &next) >= 0) {

        mac_table_entry_t *entry = (mac_table_entry_t *)data;
        if (vlan_id && vlan_id != entry->vlan_id) continue;

        count++;
        time_t lu = __atomic_load_n(&entry->last_used, __ATOMIC_RELAXED);
        char idle_str[16];
        if (lu == 0) snprintf(idle_str, sizeof(idle_str), "never");
        else         snprintf(idle_str, sizeof(idle_str), "%ld", (long)(now - lu));

        if (entry->vlan_id == DEFAULT_VLAN_ID) {
            cprintf("%-6s %02x:%02x:%02x:%02x:%02x:%02x  %-13s %-14s\n",
                    "--",
                    entry->mac.mac[0], entry->mac.mac[1],
                    entry->mac.mac[2], entry->mac.mac[3],
                    entry->mac.mac[4], entry->mac.mac[5],
                    mac_entry_flag(entry->flags),
                    idle_str);
        } else {
            cprintf("%-6d %02x:%02x:%02x:%02x:%02x:%02x  %-13s %-14s\n",
                    entry->vlan_id,
                    entry->mac.mac[0], entry->mac.mac[1],
                    entry->mac.mac[2], entry->mac.mac[3],
                    entry->mac.mac[4], entry->mac.mac[5],
                    mac_entry_flag(entry->flags),
                    idle_str);
        }

        mac_table_entry_print_oifs(dp_ctx, entry);
        cprintf("\n");
    }

    if (!count) cprintf("(empty)\n");
}

/* -------------------------------------------------------------------------
 * OIF list — interned mac_fwd_object_t pointers per MAC entry
 * ---------------------------------------------------------------------- */

static bool
mac_table_entry_grow_oifs(mac_table_entry_t *mac_entry)
{
    uint16_t new_cap = mac_entry->oif_cap ? mac_entry->oif_cap * 2 : 4;
    mac_fwd_object_t **oifs = (mac_fwd_object_t **)realloc(
        mac_entry->oifs, new_cap * sizeof(mac_fwd_object_t *));
    if (!oifs)
        return false;
    mac_entry->oifs = oifs;
    mac_entry->oif_cap = new_cap;
    return true;
}

bool
mac_table_entry_attach_fwd(dp_ctx_t *dp_ctx,
                           mac_table_entry_t *mac_entry,
                           mac_fwd_object_t *fwd_tmpl)
{
    mac_fwd_object_t *fwd_obj;
    mac_fwd_object_t *existing;

    if (!mac_entry || !fwd_tmpl || fwd_tmpl->fwd_type >= L2_FWD_MAX)
        return false;

    existing = dp_ctx_lookup_mac_fwd_object(
        dp_ctx->l2_fwd_obj_tree[fwd_tmpl->fwd_type], fwd_tmpl);
    if (existing && mac_table_entry_find_fwd(mac_entry, existing))
        return false;

    fwd_obj = dp_l2fwd_object_acquire(dp_ctx, fwd_tmpl);
    if (!fwd_obj)
        return false;

    if (mac_entry->oif_count >= mac_entry->oif_cap &&
        !mac_table_entry_grow_oifs(mac_entry)) {
        mac_fwd_object_dereference(dp_ctx, fwd_obj);
        return false;
    }

    mac_entry->oifs[mac_entry->oif_count++] = fwd_obj;
    return true;
}

bool
mac_table_entry_detach_fwd(dp_ctx_t *dp_ctx,
                           mac_table_entry_t *mac_entry,
                           mac_fwd_object_t *fwd_obj)
{
    uint16_t i;

    if (!mac_entry || !fwd_obj)
        return false;

    for (i = 0; i < mac_entry->oif_count; i++) {
        if (mac_entry->oifs[i] != fwd_obj)
            continue;

        mac_fwd_object_dereference(dp_ctx, fwd_obj);
        mac_entry->oifs[i] = mac_entry->oifs[mac_entry->oif_count - 1];
        mac_entry->oif_count--;
        if (mac_entry->nh_index >= mac_entry->oif_count)
            mac_entry->nh_index = 0;
        return true;
    }

    return false;
}

mac_fwd_object_t *
mac_table_entry_find_fwd(mac_table_entry_t *mac_entry,
                         mac_fwd_object_t *fwd_obj)
{
    uint16_t i;

    if (!mac_entry || !fwd_obj) return NULL;

    for (i = 0; i < mac_entry->oif_count; i++) {
        if (mac_entry->oifs[i] == fwd_obj)
            return fwd_obj;
    }

    return NULL;
}

bool
mac_table_entry_has_oifs(mac_table_entry_t *mac_entry)
{
    if (!mac_entry) return false;
    return mac_entry->oif_count > 0;
}

void
mac_table_entry_clear_oifs(dp_ctx_t *dp_ctx, mac_table_entry_t *mac_entry)
{
    if (!mac_entry) return;

    while (mac_entry->oif_count)
        mac_table_entry_detach_fwd(dp_ctx, mac_entry,
                                   mac_entry->oifs[mac_entry->oif_count - 1]);

    if (mac_entry->oifs) {
        XFREE(mac_entry->oifs);
        mac_entry->oifs = NULL;
        mac_entry->oif_cap = 0;
    }
}
