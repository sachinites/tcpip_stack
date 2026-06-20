/*
 * arp.c — ARP table backed by DPDK rte_hash + single-writer dp_ev_dis.
 *
 * All functions that mutate the table assert they run on dp_ev_dis.
 * Packet-path entry points (process_arp_reply_msg, process_arp_broadcast_request,
 * create_update_arp_sane_entry) post async jobs to dp_ev_dis so they are safe
 * to call from DPDK poll threads.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ncurses.h>
#include <pthread.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_errno.h>

#include "../../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../../../libs/common/l2_hdrs.h"
#include "arp.h"
#include "../l2fwd/ipv4-l2fwd.h"
#include "../../../tcp_ip_trace.h"
#include "../../../libs/libtimer/WheelTimer.h"
#include "../../../libs/pkt-block/pkt_mbuf.h"
#include "../../../utils.h"
#include "../../../libs/Tracer/tracer.h"
#include "../../../lmm_enums.h"
#include "../../Vrfs/dp_vrf.h"
#include "../../dp_ctx.h"
#include "../../Interface/dp_intf.h"
#include "../../dp_utils.h"
#include "../../dp_uapi.h"
#include "../../../CLIBuilder/cmdtlv.h"
#include "../../../CLIBuilder/libcli.h"
#include "../../../cmdcodes.h"

#define ARP_ENTRY_EXP_TIME  30      /* seconds */
#define ARP_HASH_ENTRIES    1024    /* max entries per VRF ARP table */

/* -------------------------------------------------------------------------
 * Write-thread assertion: all mutations must happen on dp_ev_dis.
 * ---------------------------------------------------------------------- */
#define ASSERT_ON_DP_EV_DIS(dp_ctx) \
    assert((dp_ctx)->dp_ev_dis.thread && \
           pthread_equal(pthread_self(), *(dp_ctx)->dp_ev_dis.thread))

/* -------------------------------------------------------------------------
 * Forward declarations
 * ---------------------------------------------------------------------- */
static bool
arp_table_entry_add_nolock(dp_ctx_t *dp_ctx,
                           dp_vrf_t *vrf,
                           arp_table_t *arp_table,
                           arp_entry_t *arp_entry,
                           glthread_t **arp_pending_list);

static void
arp_entry_schedule_delete(dp_ctx_t *dp_ctx, arp_entry_t *arp_entry);

/* -------------------------------------------------------------------------
 * Pending entry helpers
 * ---------------------------------------------------------------------- */

static void
delete_arp_pending_entry(arp_pending_entry_t *arp_pending_entry)
{
    remove_glthread(&arp_pending_entry->arp_pending_entry_glue);
    pkt_mbuf_dereference(arp_pending_entry->mbuf);
    XFREE(arp_pending_entry);
}

void
add_arp_pending_entry(dp_ctx_t *dp_ctx,
                      arp_entry_t *arp_entry,
                      arp_processing_fn cb,
                      struct rte_mbuf *mbuf)
{
    arp_pending_entry_t *pe =
        (arp_pending_entry_t *)XCALLOC2(0, 1, arp_pending_entry_t);
    init_glthread(&pe->arp_pending_entry_glue);
    pe->cb   = cb;
    pe->mbuf = mbuf;
    pkt_mbuf_ref_inc(mbuf);
    glthread_add_next(&arp_entry->arp_pending_list, &pe->arp_pending_entry_glue);

    char ip_str[IPV4_ADDR_LEN_STR];
    tcp_ip_covert_ip_n_to_p(arp_entry->ip_addr, ip_str);
    tracer(dp_ctx->dptr, DARP_DET, "ARP-entry %s: pending entry added\n", ip_str);
}

/* -------------------------------------------------------------------------
 * ARP broadcast request (send an ARP probe on the wire)
 * ---------------------------------------------------------------------- */
void
send_arp_broadcast_request(dp_ctx_t *dp_ctx,
                           dp_vrf_t *vrf,
                           dp_intf_t *oif,
                           uint32_t ip_addr)
{
    pkt_size_t pkt_size;
    uint16_t vlan_id = 0;
    char ip_str[16];

    tcp_ip_covert_ip_n_to_p(ip_addr, ip_str);

    if (oif && oif->if_type == DP_INTF_TYPE_VLAN)
        vlan_id = oif->vlan_id;

    struct rte_mbuf *mbuf = dp_pkt_mbuf_get_new(
        dp_ctx,
        (vlan_id ? sizeof(vlan_ethernet_hdr_t) : sizeof(ethernet_hdr_t))
        + sizeof(arp_hdr_t) + ETH_FCS_SIZE);

    ethernet_hdr_t *eth = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);

    if (vlan_id) {
        tag_pkt_with_vlan_id(mbuf, vlan_id);
        eth = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
    }

    if (!oif) {
        oif = dp_intf_get_matching_subnet_interface(dp_ctx, vrf, ip_addr);
        if (!oif) {
            tracer(dp_ctx->dptr, DARP | DERR,
                   "VRF:%s: No eligible subnet for ARP resolution for %s\n",
                   vrf->vrf_name, ip_str);
            pkt_mbuf_dereference(mbuf);
            return;
        }
        if (oif->ip_addr == ip_addr) {
            tracer(dp_ctx->dptr, DARP | DERR,
                   "VRF:%s: Attempt to resolve ARP for local IP %s\n",
                   vrf->vrf_name, ip_str);
            pkt_mbuf_dereference(mbuf);
            return;
        }
    }

    layer2_fill_with_broadcast_mac(eth->dst_mac.mac);
    memcpy(eth->src_mac.mac, oif->mac_add.mac, MAC_ADDR_SIZE);
    SET_COMMON_ETH_HDR_TYPE(eth, ETH_TYPE_ARP);

    arp_hdr_t *arp = (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth);
    arp->hw_type       = htons(0x1);
    arp->proto_type    = htons(ETH_TYPE_IPv4);
    arp->hw_addr_len   = MAC_ADDR_SIZE;
    arp->proto_addr_len = 4;
    arp->op_code       = htons(ARP_BROAD_REQ);
    memcpy(arp->src_mac.mac, oif->mac_add.mac, MAC_ADDR_SIZE);
    arp->src_ip = htonl(oif->ip_addr);
    memset(arp->dst_mac.mac, 0, MAC_ADDR_SIZE);
    arp->dst_ip = htonl(ip_addr);
    SET_COMMON_ETH_FCS(eth, sizeof(arp_hdr_t), 0);

    pkt_mbuf_update_new_hdr_type(mbuf, ETHERNET_HEADER);
    tracer(dp_ctx->dptr, DARP,
           "VRF:%s: Sending ARP Broadcast Request for %s out of %s\n",
           vrf->vrf_name, ip_str, oif->if_name);
    dp_send_pkt_out(dp_ctx, oif, mbuf);
    pkt_mbuf_dereference(mbuf);
}

/* -------------------------------------------------------------------------
 * ARP reply
 * ---------------------------------------------------------------------- */
void
l2_prepare_arp_reply_msg(ethernet_hdr_t *eth_reply,
                         mac_addr_t *dst_mac, uint32_t dst_ip,
                         mac_addr_t *src_mac, uint32_t src_ip)
{
    memcpy(eth_reply->dst_mac.mac, dst_mac->mac, sizeof(mac_addr_t));
    memcpy(eth_reply->src_mac.mac, src_mac->mac, sizeof(mac_addr_t));
    SET_COMMON_ETH_HDR_TYPE(eth_reply, ETH_TYPE_ARP);
    arp_hdr_t *arp = (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_reply);
    arp->hw_type        = htons(0x1);
    arp->proto_type     = htons(ETH_TYPE_IPv4);
    arp->hw_addr_len    = sizeof(mac_addr_t);
    arp->proto_addr_len = 4;
    arp->op_code        = htons(ARP_REPLY);
    memcpy(arp->src_mac.mac, src_mac->mac, MAC_ADDR_SIZE);
    arp->src_ip = htonl(src_ip);
    memcpy(arp->dst_mac.mac, dst_mac->mac, MAC_ADDR_SIZE);
    arp->dst_ip = htonl(dst_ip);
    SET_COMMON_ETH_FCS(eth_reply, sizeof(arp_hdr_t), 0);
}

static void
send_arp_reply_msg(dp_ctx_t *dp_ctx, ethernet_hdr_t *eth_in, dp_intf_t *oif)
{
    char ip_str[IPV4_ADDR_LEN_STR];
    arp_hdr_t *arp_in = (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_in);
    pkt_size_t total = sizeof(ethernet_hdr_t) + sizeof(arp_hdr_t) + ETH_FCS_SIZE;
    struct rte_mbuf *mbuf = dp_pkt_mbuf_get_new(dp_ctx, total);
    pkt_mbuf_update_new_hdr_type(mbuf, ETHERNET_HEADER);
    ethernet_hdr_t *eth_reply = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, 0);

    l2_prepare_arp_reply_msg(eth_reply,
        &arp_in->src_mac, htonl(arp_in->src_ip),
        &oif->mac_add, oif->ip_addr);

    arp_hdr_t *arp_reply = (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_reply);
    tracer(dp_ctx->dptr, DARP,
           "Sending ARP Reply [%s : %02x:%02x:%02x:%02x:%02x:%02x] out of %s\n",
           tcp_ip_covert_ip_n_to_p(htonl(arp_reply->dst_ip), (unsigned char *)ip_str),
           arp_reply->dst_mac.mac[0], arp_reply->dst_mac.mac[1],
           arp_reply->dst_mac.mac[2], arp_reply->dst_mac.mac[3],
           arp_reply->dst_mac.mac[4], arp_reply->dst_mac.mac[5],
           oif->if_name);

    dp_send_pkt_out(dp_ctx, oif, mbuf);
    pkt_mbuf_dereference(mbuf);
}

/* -------------------------------------------------------------------------
 * Packet-path entry points — post jobs to dp_ev_dis so they are safe
 * from DPDK poll threads.  The actual table mutations happen in the
 * dp_arp_table_process_msg handler on dp_ev_dis.
 * ---------------------------------------------------------------------- */

void
process_arp_reply_msg(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf, dp_intf_t *iif,
                      ethernet_hdr_t *ethernet_hdr)
{
    arp_hdr_t *arp = (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr);

    tracer(dp_ctx->dptr, DARP,
           "VRF:%s: Recvd ARP Reply on %s — posting ARP_UPDATE job\n",
           vrf->vrf_name, iif->if_name);

    dp_post_arp_update_from_pkt_job(dp_ctx, vrf, iif->port_id,
                                    htonl(arp->src_ip),
                                    arp->src_mac.mac);
}

void
process_arp_broadcast_request(dp_ctx_t *dp_ctx,
                               dp_vrf_t *vrf,
                               dp_intf_t *iif,
                               ethernet_hdr_t *ethernet_hdr)
{
    byte ip_str[IPV4_ADDR_LEN_STR];
    arp_hdr_t *arp = (arp_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr);

    tracer(dp_ctx->dptr, DARP,
           "VRF:%s: ARP-Broadcast Req from %02x:%02x:%02x:%02x:%02x:%02x "
           "for %s on %s\n",
           vrf->vrf_name,
           ethernet_hdr->src_mac.mac[0], ethernet_hdr->src_mac.mac[1],
           ethernet_hdr->src_mac.mac[2], ethernet_hdr->src_mac.mac[3],
           ethernet_hdr->src_mac.mac[4], ethernet_hdr->src_mac.mac[5],
           tcp_ip_covert_ip_n_to_p(htonl(arp->dst_ip), ip_str),
           iif->if_name);

    /* Send reply immediately if this request targets our interface IP.
     * This does not touch the ARP table, so it is safe from any thread. */
    if (htonl(arp->dst_ip) == iif->ip_addr)
        send_arp_reply_msg(dp_ctx, ethernet_hdr, iif);

    /* Update ARP table from sender's info — post to dp_ev_dis. */
    dp_post_arp_update_from_pkt_job(dp_ctx, vrf, iif->port_id,
                                    htonl(arp->src_ip),
                                    arp->src_mac.mac);
}

/* -------------------------------------------------------------------------
 * Thread identity helpers
 * ---------------------------------------------------------------------- */

/* Returns true if caller is the dp_ev_dis management thread. */
static inline bool
is_dp_ev_dis_thread(dp_ctx_t *dp_ctx)
{
    return dp_ctx->dp_ev_dis.thread &&
           pthread_equal(pthread_self(), *dp_ctx->dp_ev_dis.thread);
}

/* Returns true if caller is either dp_ev_dis or dp_purger_ev_dis.
 * Used for teardown paths that run on the purger thread. */
static inline bool
is_dp_management_thread(dp_ctx_t *dp_ctx)
{
    return is_dp_ev_dis_thread(dp_ctx) ||
           (dp_ctx->dp_purger_ev_dis.thread &&
            pthread_equal(pthread_self(), *dp_ctx->dp_purger_ev_dis.thread));
}

/* -------------------------------------------------------------------------
 * ARP table — lifecycle
 * ---------------------------------------------------------------------- */

void
init_arp_table(arp_table_t **arp_table)
{
    *arp_table = (arp_table_t *)XCALLOC2(0, 1, arp_table_t);

    static uint32_t arp_hash_instance = 0;
    char hash_name[32];
    snprintf(hash_name, sizeof(hash_name), "arp_table_%u", arp_hash_instance++);

    struct rte_hash_parameters params = {};
    params.name       = hash_name;
    params.entries    = ARP_HASH_ENTRIES;
    params.key_len    = sizeof(arp_hash_key_t);
    params.hash_func  = rte_jhash;
    params.hash_func_init_val = 0;
    params.socket_id  = 0;
    /* RW_CONCURRENCY_LF: lock-free readers + single writer, no internal ring.
     * Works without hugepages (unlike RW_CONCURRENCY which needs an rte_ring).
     * Implies NO_FREE_ON_DEL — we manage entry lifetime via deferred-GC. */
    params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;

    (*arp_table)->hash = rte_hash_create(&params);
    if (!(*arp_table)->hash) {
        cprintf("Error: arp_table rte_hash_create failed: %s\n",
                rte_strerror(rte_errno));
    }
}

/* GC callback: frees a deleted arp_entry_t after the safety window. */
static void
arp_entry_gc_free_cbk(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size)
{
    XFREE(arg);
}

/*
 * Internal: remove an entry from the hash, cancel its expiry timer,
 * drain pending packets, and schedule deferred free.
 * Caller MUST be on dp_ev_dis.
 */
static void
arp_entry_schedule_delete(dp_ctx_t *dp_ctx, arp_entry_t *arp_entry)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);

    arp_table_t *arp_table = arp_entry->arp_table;
    arp_hash_key_t key = { arp_entry->ip_addr, 0 };

    /* Cancel expiry timer to prevent a later timer callback racing with GC. */
    arp_entry_delete_expiration_timer(arp_entry);

    /* Remove from hash; readers may still hold the pointer until GC fires. */
    if (arp_table->hash)
        rte_hash_del_key(arp_table->hash, &key);

    /* Drop all pending packets that were waiting for this ARP resolution. */
    glthread_t *curr;
    arp_pending_entry_t *pe;
    ITERATE_GLTHREAD_BEGIN(&arp_entry->arp_pending_list, curr) {
        pe = arp_pending_entry_glue_to_arp_pending_entry(curr);
        delete_arp_pending_entry(pe);
    } ITERATE_GLTHREAD_END(&arp_entry->arp_pending_list, curr);

    /* Schedule deferred free. */
    timer_register_app_event(DP_TIMER(dp_ctx),
                             arp_entry_gc_free_cbk,
                             (void *)arp_entry,
                             sizeof(*arp_entry),
                             DP_TABLE_GC_DELAY_MS,
                             0);
}

void
clear_arp_table(dp_ctx_t *dp_ctx, arp_table_t *arp_table)
{
    /* clear_arp_table may run on dp_purger_ev_dis (VRF teardown). */
    assert(is_dp_management_thread(dp_ctx));

    if (!arp_table->hash) return;

    /* Collect all entries, cancel timers, drain pending lists. */
    uint32_t next = 0;
    const void *key;
    void *data;
    while (rte_hash_iterate(arp_table->hash, &key, &data, &next) >= 0) {
        arp_entry_t *entry = (arp_entry_t *)data;
        arp_entry_delete_expiration_timer(entry);

        glthread_t *curr;
        arp_pending_entry_t *pe;
        ITERATE_GLTHREAD_BEGIN(&entry->arp_pending_list, curr) {
            pe = arp_pending_entry_glue_to_arp_pending_entry(curr);
            delete_arp_pending_entry(pe);
        } ITERATE_GLTHREAD_END(&entry->arp_pending_list, curr);

        /* Schedule deferred free: readers get DP_TABLE_GC_DELAY_MS window. */
        timer_register_app_event(DP_TIMER(dp_ctx),
                                 arp_entry_gc_free_cbk,
                                 (void *)entry,
                                 sizeof(*entry),
                                 DP_TABLE_GC_DELAY_MS,
                                 0);
    }

    /* After reset, no new lookups will find any entry. */
    rte_hash_reset(arp_table->hash);
}

/* -------------------------------------------------------------------------
 * Read path — lock-free, callable from any thread
 * ---------------------------------------------------------------------- */

arp_entry_t *
arp_table_lookup(arp_table_t *arp_table, uint32_t ip_addr)
{
    if (!arp_table->hash) return NULL;
    arp_hash_key_t key = { ip_addr, 0 };
    void *data = NULL;
    rte_hash_lookup_data(arp_table->hash, &key, &data);
    return (arp_entry_t *)data;
}

/* -------------------------------------------------------------------------
 * Write path — table mutations (all MUST be called from dp_ev_dis)
 * ---------------------------------------------------------------------- */

void
arp_entry_delete(dp_ctx_t *dp_ctx, dp_vrf_t *vrf,
                 uint32_t ip_addr, uint16_t proto)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);

    arp_entry_t *entry = arp_table_lookup(vrf->arp_table, ip_addr);
    if (!entry || entry->proto != proto) return;

    char ip_str[IPV4_ADDR_LEN_STR];
    tcp_ip_covert_ip_n_to_p(ip_addr, ip_str);
    tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-entry %s deleted\n",
           vrf->vrf_name, ip_str);

    arp_entry_schedule_delete(dp_ctx, entry);
}

void
arp_entry_delete_by_interface(dp_ctx_t *dp_ctx,
                               arp_table_t *arp_table,
                               dp_intf_t *intf)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);
    if (!arp_table->hash) return;

    /* Collect entries matching this interface first (can't delete while iterating). */
    arp_entry_t *to_del[ARP_HASH_ENTRIES];
    int count = 0;
    uint32_t next = 0;
    const void *key;
    void *data;

    while (rte_hash_iterate(arp_table->hash, &key, &data, &next) >= 0) {
        arp_entry_t *entry = (arp_entry_t *)data;
        if (entry->oif == intf && count < ARP_HASH_ENTRIES)
            to_del[count++] = entry;
    }

    for (int i = 0; i < count; i++)
        arp_entry_schedule_delete(dp_ctx, to_del[i]);
}

static bool
arp_table_entry_add_nolock(dp_ctx_t *dp_ctx,
                           dp_vrf_t *vrf,
                           arp_table_t *arp_table,
                           arp_entry_t *arp_entry,
                           glthread_t **arp_pending_list)
{
    char ip_str[IPV4_ADDR_LEN_STR];
    tcp_ip_covert_ip_n_to_p(arp_entry->ip_addr, ip_str);
    tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-entry %s: add called\n",
           vrf->vrf_name, ip_str);

    if (arp_pending_list)
        assert(*arp_pending_list == NULL);

    if (!arp_table->hash) return false;

    arp_hash_key_t key = { arp_entry->ip_addr, 0 };
    arp_entry_t *old = arp_table_lookup(arp_table, arp_entry->ip_addr);

    /* Case 0: no existing entry → insert. */
    if (!old) {
        arp_entry->arp_table = arp_table;
        init_glthread(&arp_entry->arp_pending_list);
        rte_hash_add_key_data(arp_table->hash, &key, arp_entry);
        assert(arp_entry->exp_timer_wt_elem == NULL);
        if (arp_entry->proto == ETH_TYPE_ARP)
            arp_entry->exp_timer_wt_elem =
                arp_entry_create_expiration_timer(dp_ctx, arp_entry,
                                                  ARP_ENTRY_EXP_TIME);
        tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-entry %s added\n",
               vrf->vrf_name, ip_str);
        return true;
    }

    /* Case 1: identical full entry — nothing to do. */
    if (IS_ARP_ENTRIES_EQUAL(old, arp_entry)) {
        tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-entry %s already exists\n",
               vrf->vrf_name, ip_str);
        return false;
    }

    /* Case 2: replace existing full entry with new full entry. */
    if (!arp_entry_sane(old) &&
        (old->proto == arp_entry->proto ||
         (old->proto == ETH_TYPE_ARP && arp_entry->proto != ETH_TYPE_ARP))) {
        /* Replace pointer in hash atomically; GC old entry. */
        arp_entry->arp_table = arp_table;
        init_glthread(&arp_entry->arp_pending_list);
        rte_hash_add_key_data(arp_table->hash, &key, arp_entry);
        assert(arp_entry->exp_timer_wt_elem == NULL);
        if (arp_entry->proto == ETH_TYPE_ARP)
            arp_entry->exp_timer_wt_elem =
                arp_entry_create_expiration_timer(dp_ctx, arp_entry,
                                                  ARP_ENTRY_EXP_TIME);
        /* GC old (cancel its timer first). */
        arp_entry_delete_expiration_timer(old);
        timer_register_app_event(DP_TIMER(dp_ctx), arp_entry_gc_free_cbk,
                                 (void *)old, sizeof(*old), DP_TABLE_GC_DELAY_MS, 0);
        tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-entry %s replaced\n",
               vrf->vrf_name, ip_str);
        return true;
    }

    /* Case 3: both sane — merge new pending list into old, refresh timer. */
    if (arp_entry_sane(old) && arp_entry_sane(arp_entry)) {
        if (!IS_GLTHREAD_LIST_EMPTY(&arp_entry->arp_pending_list))
            glthread_add_next(&old->arp_pending_list,
                              arp_entry->arp_pending_list.right);
        if (arp_pending_list)
            *arp_pending_list = &old->arp_pending_list;
        arp_entry_refresh_expiration_timer(old);
        return false;
    }

    /* Case 4: existing is sane, new is full — update fields in-place.
     * Safe in non-DPDK mode (single-thread on dp_ev_dis).
     * In DPDK mode this is a benign race on bool is_sane / MAC bytes:
     * readers seeing stale is_sane=true will simply re-queue the packet. */
    if (arp_entry_sane(old) && !arp_entry_sane(arp_entry)) {
        memcpy(old->mac_addr.mac, arp_entry->mac_addr.mac, sizeof(mac_addr_t));
        old->oif   = arp_entry->oif;
        old->proto = arp_entry->proto;
        old->is_sane = false;   /* mark resolved */
        if (arp_pending_list)
            *arp_pending_list = &old->arp_pending_list;
        arp_entry_refresh_expiration_timer(old);
        tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP-entry %s resolved in-place\n",
               vrf->vrf_name, ip_str);
        return false;
    }

    tracer(dp_ctx->dptr, DARP | DERR,
           "VRF:%s: ARP-entry %s failed to add/update\n",
           vrf->vrf_name, ip_str);
    return false;
}

bool
arp_table_entry_add(dp_ctx_t *dp_ctx,
                    dp_vrf_t *vrf,
                    arp_table_t *arp_table,
                    arp_entry_t *arp_entry,
                    glthread_t **arp_pending_list)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);
    return arp_table_entry_add_nolock(dp_ctx, vrf, arp_table,
                                      arp_entry, arp_pending_list);
}

/* -------------------------------------------------------------------------
 * ARP table update from received ARP packet (reply / overheard request).
 * Runs on dp_ev_dis only (posted from packet threads).
 * ---------------------------------------------------------------------- */

static void
pending_arp_processing_callback_function(dp_ctx_t *dp_ctx,
                                         dp_intf_t *oif,
                                         arp_entry_t *arp_entry,
                                         arp_pending_entry_t *pe)
{
    pkt_size_t pkt_size;
    ethernet_hdr_t *eth = (ethernet_hdr_t *)pkt_mbuf_get_pkt(pe->mbuf, &pkt_size);
    memcpy(eth->dst_mac.mac, arp_entry->mac_addr.mac, MAC_ADDR_SIZE);
    memcpy(eth->src_mac.mac, oif->mac_add.mac, MAC_ADDR_SIZE);
    SET_COMMON_ETH_FCS(eth, pkt_size - GET_ETH_HDR_SIZE_EXCL_PAYLOAD(eth), 0);
    dp_send_pkt_out(dp_ctx, oif, pe->mbuf);
}

void
arp_table_update_from_arp_reply(dp_ctx_t *dp_ctx,
                                dp_vrf_t *vrf,
                                arp_table_t *arp_table,
                                arp_hdr_t *arp_hdr,
                                dp_intf_t *iif)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);

    uint32_t src_ip = htonl(arp_hdr->src_ip);
    char ip_str[IPV4_ADDR_LEN_STR];
    tcp_ip_covert_ip_n_to_p(src_ip, ip_str);
    tracer(dp_ctx->dptr, DARP, "VRF:%s: ARP update from %s\n",
           vrf->vrf_name, ip_str);

    arp_entry_t *new_entry = (arp_entry_t *)XCALLOC2(0, 1, arp_entry_t);
    new_entry->ip_addr = src_ip;
    memcpy(new_entry->mac_addr.mac, arp_hdr->src_mac.mac, MAC_ADDR_SIZE);
    new_entry->oif     = iif;
    new_entry->is_sane = false;
    new_entry->proto   = ETH_TYPE_ARP;

    glthread_t *arp_pending_list = NULL;
    bool rc = arp_table_entry_add_nolock(dp_ctx, vrf, arp_table,
                                         new_entry, &arp_pending_list);

    if (arp_pending_list) {
        glthread_t *curr;
        arp_pending_entry_t *pe;
        ITERATE_GLTHREAD_BEGIN(arp_pending_list, curr) {
            pe = arp_pending_entry_glue_to_arp_pending_entry(curr);
            remove_glthread(&pe->arp_pending_entry_glue);
            pe->cb(dp_ctx, iif, new_entry, pe);
            delete_arp_pending_entry(pe);
        } ITERATE_GLTHREAD_END(arp_pending_list, curr);

        assert(IS_GLTHREAD_LIST_EMPTY(arp_pending_list));
        (arp_pending_list_to_arp_entry(arp_pending_list))->is_sane = false;
    }

    if (rc == false)
        XFREE(new_entry);
}

/* -------------------------------------------------------------------------
 * create_update_arp_sane_entry — called from dp_ev_dis only
 * (ipv4-l2fwd posts a job when an ARP miss is detected on a DPDK thread)
 * ---------------------------------------------------------------------- */
void
create_update_arp_sane_entry(dp_ctx_t *dp_ctx,
                             dp_vrf_t *vrf,
                             arp_table_t *arp_table,
                             uint32_t ip_addr,
                             struct rte_mbuf *mbuf)
{
    ASSERT_ON_DP_EV_DIS(dp_ctx);

    arp_entry_t *entry = arp_table_lookup(arp_table, ip_addr);

    if (entry) {
        if (!arp_entry_sane(entry))
            assert(0); /* caller should have forwarded, not called us */

        /* Sane entry exists — append pending packet. */
        add_arp_pending_entry(dp_ctx, entry,
                              pending_arp_processing_callback_function, mbuf);
        arp_entry_refresh_expiration_timer(entry);
        pkt_mbuf_dereference(mbuf); /* release the extra ref taken by the caller */
        return;
    }

    char ip_str[IPV4_ADDR_LEN_STR];
    tcp_ip_covert_ip_n_to_p(ip_addr, ip_str);
    tracer(dp_ctx->dptr, DARP, "VRF:%s: creating ARP sane entry for %s\n",
           vrf->vrf_name, ip_str);

    entry = (arp_entry_t *)XCALLOC2(0, 1, arp_entry_t);
    entry->ip_addr  = ip_addr;
    entry->is_sane  = true;
    entry->proto    = ETH_TYPE_ARP;
    init_glthread(&entry->arp_pending_list);
    add_arp_pending_entry(dp_ctx, entry,
                          pending_arp_processing_callback_function, mbuf);
    pkt_mbuf_dereference(mbuf); /* release the extra ref taken by the caller */
    assert(arp_table_entry_add_nolock(dp_ctx, vrf, arp_table, entry, 0));
}

/* -------------------------------------------------------------------------
 * External add (from CLI / CP path — must be on dp_ev_dis)
 * ---------------------------------------------------------------------- */
bool
arp_entry_add(dp_ctx_t *dp_ctx,
              dp_vrf_t *vrf,
              unsigned char *ip_addr,
              mac_addr_t mac,
              dp_intf_t *oif,
              uint16_t proto)
{
    arp_entry_t *entry = (arp_entry_t *)XCALLOC2(0, 1, arp_entry_t);
    entry->ip_addr = tcp_ip_convert_ip_p_to_n((char *)ip_addr);
    memcpy(entry->mac_addr.mac, mac.mac, MAC_ADDR_SIZE);
    entry->proto = proto;
    entry->oif   = oif;
    init_glthread(&entry->arp_pending_list);
    if (!arp_table_entry_add(dp_ctx, vrf, vrf->arp_table, entry, 0)) {
        XFREE(entry);
        return false;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * Timer management
 * ---------------------------------------------------------------------- */

static void
arp_entry_timer_delete_cbk(event_dispatcher_t *ev_dis,
                            void *arg, uint32_t arg_size)
{
    if (!arg) return;
    arp_entry_t *entry = (arp_entry_t *)arg;
    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;
    char ip_str[IPV4_ADDR_LEN_STR];
    tcp_ip_covert_ip_n_to_p(entry->ip_addr, ip_str);
    tracer(dp_ctx->dptr, DARP | DTIMER, "ARP-entry %s expired\n", ip_str);
    entry->exp_timer_wt_elem = NULL;
    arp_entry_schedule_delete(dp_ctx, entry);
}

wheel_timer_elem_t *
arp_entry_create_expiration_timer(dp_ctx_t *dp_ctx,
                                   arp_entry_t *arp_entry,
                                   uint16_t exp_time)
{
    assert(arp_entry->exp_timer_wt_elem == NULL);

    arp_entry->exp_timer_wt_elem = timer_register_app_event(
        DP_TIMER(dp_ctx),
        arp_entry_timer_delete_cbk,
        (void *)arp_entry,
        sizeof(*arp_entry),
        ARP_ENTRY_EXP_TIME * 1000,
        0);

    char ip_str[IPV4_ADDR_LEN_STR];
    tcp_ip_covert_ip_n_to_p(arp_entry->ip_addr, ip_str);
    tracer(dp_ctx->dptr, DARP_DET | DTIMER,
           "ARP-entry %s: expiry timer created\n", ip_str);

    return arp_entry->exp_timer_wt_elem;
}

void
arp_entry_delete_expiration_timer(arp_entry_t *arp_entry)
{
    if (!arp_entry->exp_timer_wt_elem) return;
    timer_de_register_app_event(arp_entry->exp_timer_wt_elem);
    arp_entry->exp_timer_wt_elem = NULL;
}

void
arp_entry_refresh_expiration_timer(arp_entry_t *arp_entry)
{
    if (arp_entry->exp_timer_wt_elem)
        timer_reschedule(arp_entry->exp_timer_wt_elem,
                         ARP_ENTRY_EXP_TIME * 1000);
}

uint16_t
arp_entry_get_exp_time_left(arp_entry_t *arp_entry)
{
    if (arp_entry->exp_timer_wt_elem)
        return wt_get_remaining_time(arp_entry->exp_timer_wt_elem);
    return 0;
}

/* -------------------------------------------------------------------------
 * Show — iterate rte_hash (run on dp_ev_dis)
 * ---------------------------------------------------------------------- */
void
show_arp_table(arp_table_t *arp_table)
{
    if (!arp_table || !arp_table->hash) return;

    uint32_t next = 0;
    const void *key;
    void *data;
    int count = 0;

    printw("\n\r");
    while (rte_hash_iterate(arp_table->hash, &key, &data, &next) >= 0) {
        arp_entry_t *entry = (arp_entry_t *)data;
        count++;
        if (count == 1)
            cprintf("\t|========IP==========|========MAC========|=====OIF======|===Resolved==|=Exp-Time(msec)==|===Proto==|\n");
        else
            cprintf("\t|====================|===================|==============|=============|=================|==========|\n");

        char ip_str[IPV4_ADDR_LEN_STR];
        tcp_ip_covert_ip_n_to_p(entry->ip_addr, ip_str);
        cprintf("\t| %-18s | %02x:%02x:%02x:%02x:%02x:%02x |  %-12s|   %-6s    |  %-5d          |  %-6s  |\n",
                ip_str,
                entry->mac_addr.mac[0], entry->mac_addr.mac[1],
                entry->mac_addr.mac[2], entry->mac_addr.mac[3],
                entry->mac_addr.mac[4], entry->mac_addr.mac[5],
                entry->oif ? entry->oif->if_name : "null",
                arp_entry_sane(entry) ? "false" : "true",
                arp_entry_get_exp_time_left(entry),
                proto_id_str(entry->proto));
    }

    if (count)
        cprintf("\t|====================|===================|==============|=============|=================|==========|\n");
}
