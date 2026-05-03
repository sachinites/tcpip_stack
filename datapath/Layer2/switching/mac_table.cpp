
#include <memory.h>
#include <ncurses.h>
#include "mac_table.h"
#include "../../../net.h"
#include "../../Interface/dp_intf.h"
#include "../../dp_ctx.h"
#include "../../Interface/dp_intf_store.h"
#include "../../../libs/EventDispatcher/event_dispatcher.h"
#include "../../../libs/Tracer/tracer.h"
#include "../../../libs/gluethread/glthread.h"
#include "../../dp_uapi.h"
#include "../../../libs/c-hashtable/hashtable_itr.h"

/* -----------------------------------------------------------------------
 * Composite key: (vlan_id, mac[6])
 * The hashtable owns the key allocation; values are NOT freed by the HT.
 * ----------------------------------------------------------------------- */

unsigned int
mac_table_key_hash(void *key) {

    mac_table_key_t *k = (mac_table_key_t *)key;
    unsigned int h = (unsigned int)k->vlan_id;
    for (int i = 0; i < 6; i++) {
        h = h * 31 + k->mac[i];
    }
    return h;
}

int
mac_table_key_equal(void *key1, void *key2) {

    mac_table_key_t *k1 = (mac_table_key_t *)key1;
    mac_table_key_t *k2 = (mac_table_key_t *)key2;
    return (k1->vlan_id == k2->vlan_id) &&
           (memcmp(k1->mac, k2->mac, 6) == 0);
}

static mac_table_key_t *
mac_table_key_alloc(uint16_t vlan_id, uint8_t *mac) {

    mac_table_key_t *key = (mac_table_key_t *)XCALLOC2(0, 1, mac_table_key_t);
    key->vlan_id = vlan_id;
    memcpy(key->mac, mac, 6);
    return key;
}

/* -----------------------------------------------------------------------
 * Init
 * ----------------------------------------------------------------------- */

void
init_mac_table(mac_table_t **mac_table) {

    *mac_table = (mac_table_t *)XCALLOC2(0, 1, mac_table_t);
    (*mac_table)->mac_entries_ht = create_hashtable(
        64, mac_table_key_hash, mac_table_key_equal);
    (*mac_table)->entry_count = 0;
}

/* -----------------------------------------------------------------------
 * Lookup  O(1)
 * ----------------------------------------------------------------------- */

mac_table_entry_t *
mac_table_lookup(mac_table_t *mac_table, uint16_t vlan, uint8_t *mac) {

    mac_table_key_t key = { .vlan_id = vlan };
    memcpy(key.mac, mac, 6);
    return (mac_table_entry_t *)hashtable_search(mac_table->mac_entries_ht, &key);
}

/* -----------------------------------------------------------------------
 * Timer helpers
 * ----------------------------------------------------------------------- */

void
mac_table_entry_cancel_expiry_timer(mac_table_entry_t *mac_table_entry) {

    if (mac_table_entry->exp_timer_wt_elem) {
        timer_de_register_app_event(mac_table_entry->exp_timer_wt_elem);
        mac_table_entry->exp_timer_wt_elem = NULL;
    }
}

static void
mac_table_entry_timer_expiry_cbk(event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    mac_table_entry_t *mac_table_entry = (mac_table_entry_t *)arg;
    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;

    tracer(dp_ctx->dptr, DL2SW,
           "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x] Expired\n",
           mac_table_entry->vlan_id,
           mac_table_entry->mac.mac[0], mac_table_entry->mac.mac[1],
           mac_table_entry->mac.mac[2], mac_table_entry->mac.mac[3],
           mac_table_entry->mac.mac[4], mac_table_entry->mac.mac[5]);

    /* Remove from hashtable – key is freed by hashtable_remove */
    mac_table_key_t tmp_key = { .vlan_id = mac_table_entry->vlan_id };
    memcpy(tmp_key.mac, mac_table_entry->mac.mac, 6);
    hashtable_remove(dp_ctx->mac_table->mac_entries_ht, &tmp_key);
    if (dp_ctx->mac_table->entry_count > 0)
        dp_ctx->mac_table->entry_count--;

    mac_table_entry->exp_timer_wt_elem = NULL;
    mac_table_entry_clear_oifs(mac_table_entry);
    XFREE(mac_table_entry);
}

void
mac_table_entry_init_timer(dp_ctx_t *dp_ctx, mac_table_entry_t *mac_table_entry) {

    assert(!mac_table_entry->exp_timer_wt_elem);
    mac_table_entry->exp_timer_wt_elem = timer_register_app_event(
        DP_TIMER(dp_ctx),
        mac_table_entry_timer_expiry_cbk,
        (void *)mac_table_entry,
        sizeof(mac_table_entry_t),
        MAC_ENTRY_EXP_TIME * 1000, 0);
}

/* -----------------------------------------------------------------------
 * Clear (remove all dynamic entries)
 * ----------------------------------------------------------------------- */

void
clear_mac_table(node_t *node, mac_table_t *mac_table) {

    if (!mac_table || !mac_table->mac_entries_ht) return;
    if (hashtable_count(mac_table->mac_entries_ht) == 0) return;

    struct hashtable_itr *itr = hashtable_iterator(mac_table->mac_entries_ht);
    if (!itr) return;

    do {
        mac_table_entry_t *entry =
            (mac_table_entry_t *)hashtable_iterator_value(itr);

        if (entry->flags & MAC_STATIC) continue;

        mac_table_entry_cancel_expiry_timer(entry);
        mac_table_entry_clear_oifs(entry);
        XFREE(entry);
        mac_table->entry_count--;

        /* hashtable_iterator_remove advances the iterator and frees the key */
        if (!hashtable_iterator_remove(itr)) break;

    } while (1);

    XFREE(itr);
}

/* -----------------------------------------------------------------------
 * Delete by (vlan_id, mac, ifindex, remote_dst_ip)
 * ----------------------------------------------------------------------- */

void
mac_table_entry_delete(dp_ctx_t *dp_ctx,
                       mac_table_t *mac_table,
                       uint8_t *mac_addr,
                       uint16_t vlan_id,
                       uint32_t ifindex,
                       uint32_t remote_dst_ip) {

    mac_table_entry_t *mac_table_entry = mac_table_lookup(mac_table, vlan_id, mac_addr);
    if (!mac_table_entry) return;

    mac_table_entry_remove_oif(mac_table_entry, ifindex, remote_dst_ip);

    if (!mac_table_entry_has_oifs(mac_table_entry)) {

        mac_table_key_t tmp_key = { .vlan_id = vlan_id };
        memcpy(tmp_key.mac, mac_addr, 6);
        hashtable_remove(mac_table->mac_entries_ht, &tmp_key);
        mac_table->entry_count--;

        mac_table_entry_cancel_expiry_timer(mac_table_entry);

        tracer(dp_ctx->dptr, DL2SW,
               "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x] XFREEd\n",
               mac_table_entry->vlan_id,
               mac_table_entry->mac.mac[0], mac_table_entry->mac.mac[1],
               mac_table_entry->mac.mac[2], mac_table_entry->mac.mac[3],
               mac_table_entry->mac.mac[4], mac_table_entry->mac.mac[5]);

        mac_table_entry_clear_oifs(mac_table_entry);
        XFREE(mac_table_entry);
    }
}

/* -----------------------------------------------------------------------
 * Delete by (vlan_id, mac) – removes regardless of OIF count
 * ----------------------------------------------------------------------- */

void
mac_table_entry_delete2(dp_ctx_t *dp_ctx, mac_table_t *mac_table,
                        uint16_t vlan_id, uint8_t *mac_addr) {

    mac_table_entry_t *mac_table_entry = mac_table_lookup(mac_table, vlan_id, mac_addr);
    if (!mac_table_entry) return;

    mac_table_key_t tmp_key = { .vlan_id = vlan_id };
    memcpy(tmp_key.mac, mac_addr, 6);
    hashtable_remove(mac_table->mac_entries_ht, &tmp_key);
    mac_table->entry_count--;

    mac_table_entry_cancel_expiry_timer(mac_table_entry);

    tracer(dp_ctx->dptr, DL2SW,
           "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x] XFREEd\n",
           mac_table_entry->vlan_id,
           mac_table_entry->mac.mac[0], mac_table_entry->mac.mac[1],
           mac_table_entry->mac.mac[2], mac_table_entry->mac.mac[3],
           mac_table_entry->mac.mac[4], mac_table_entry->mac.mac[5]);

    mac_table_entry_clear_oifs(mac_table_entry);
    XFREE(mac_table_entry);
}

/* -----------------------------------------------------------------------
 * Add entry  O(1)
 * ----------------------------------------------------------------------- */

void
mac_table_entry_add(dp_ctx_t *dp_ctx,
                    mac_table_t *mac_table,
                    uint8_t *mac_addr,
                    uint16_t vlan_id,
                    uint32_t ifindex,
                    uint16_t flags,
                    uint32_t remote_dst_ip) {

    dp_intf_t *oif = dp_ctx->intf_table[ifindex];
    if (!oif) {
        cprintf("Error : DP_CTX %s : Interface with ifindex %d not found\n",
                dp_ctx->ctx_name, ifindex);
        return;
    }

    mac_table_entry_t *mac_table_entry = mac_table_lookup(mac_table, vlan_id, mac_addr);

    if (mac_table_entry) {
        if (mac_table_entry_add_oif(mac_table_entry, oif, remote_dst_ip)) {
            tracer(dp_ctx->dptr, DL2SW,
                   "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x] Interface %s added to existing entry\n",
                   vlan_id,
                   mac_addr[0], mac_addr[1], mac_addr[2],
                   mac_addr[3], mac_addr[4], mac_addr[5],
                   oif->if_name);
        }
        return;
    }

    /* Allocate new entry */
    mac_table_entry = (mac_table_entry_t *)XCALLOC2(0, 1, mac_table_entry_t);
    mac_table_entry->vlan_id = vlan_id;
    memcpy(mac_table_entry->mac.mac, mac_addr, sizeof(mac_addr_t));
    mac_table_entry->flags = flags;
    init_glthread(&mac_table_entry->oif_list);
    mac_table_entry_add_oif(mac_table_entry, oif, remote_dst_ip);

    if (!(flags & MAC_STATIC)) {
        mac_table_entry_init_timer(dp_ctx, mac_table_entry);
    }

    /* Insert into hashtable – key is heap-allocated, owned by hashtable */
    mac_table_key_t *key = mac_table_key_alloc(vlan_id, mac_addr);
    hashtable_insert(mac_table->mac_entries_ht, key, mac_table_entry);
    mac_table->entry_count++;

    tracer(dp_ctx->dptr, DL2SW,
           "MAC Table Entry : [%d %02x:%02x:%02x:%02x:%02x:%02x %s] Added\n",
           vlan_id,
           mac_addr[0], mac_addr[1], mac_addr[2],
           mac_addr[3], mac_addr[4], mac_addr[5],
           oif->if_name);
}

/* -----------------------------------------------------------------------
 * Show MAC table  (iterate hashtable)
 * ----------------------------------------------------------------------- */

static uint32_t
mac_table_entry_get_exp_time_left(mac_table_entry_t *mac_table_entry) {

    if (mac_table_entry->exp_timer_wt_elem) {
        return wt_get_remaining_time(mac_table_entry->exp_timer_wt_elem);
    }
    return 0;
}

static char *
mac_table_entry_append_oifs(mac_table_entry_t *mac_table_entry,
                             char *buffer, uint16_t buff_size) {

    uint16_t len = 0;
    glthread_t *curr;
    mac_oif_entry_t *oif_entry;

    memset(buffer, 0, buff_size);

    ITERATE_GLTHREAD_BEGIN(&mac_table_entry->oif_list, curr) {
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
    } ITERATE_GLTHREAD_END(&mac_table_entry->oif_list, curr);

    assert(len <= buff_size);
    return buffer;
}

void
show_mac_table(mac_table_t *mac_table, uint16_t vlan_id) {

    if (!mac_table || !mac_table->mac_entries_ht) return;

    int count = 0;
    char buffer[1024];

    printw("\n\r");
    cprintf("VLAN   MAC Address         Type         Exp-Time(ms)\n");
    cprintf("----  ------------        ------       --------------\n\n");

    if (hashtable_count(mac_table->mac_entries_ht) == 0) return;

    struct hashtable_itr *itr = hashtable_iterator(mac_table->mac_entries_ht);
    if (!itr) return;

    do {
        mac_table_entry_t *entry =
            (mac_table_entry_t *)hashtable_iterator_value(itr);

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

    } while (hashtable_iterator_advance(itr));

    XFREE(itr);
}

/* -----------------------------------------------------------------------
 * Dynamic OIF list management (unchanged logic)
 * ----------------------------------------------------------------------- */

mac_oif_entry_t *
mac_oif_entry_create(dp_intf_t *oif, uint32_t remote_dst_ip) {

    mac_oif_entry_t *oif_entry = (mac_oif_entry_t *)XCALLOC2(0, 1, mac_oif_entry_t);
    oif_entry->oif = oif;
    oif_entry->remote_dst_ip = remote_dst_ip;
    init_glthread(&oif_entry->glue);
    return oif_entry;
}

void
mac_oif_entry_destroy(mac_oif_entry_t *oif_entry) {

    if (oif_entry) {
        remove_glthread(&oif_entry->glue);
        XFREE(oif_entry);
    }
}

bool
mac_table_entry_add_oif(mac_table_entry_t *mac_entry, dp_intf_t *oif, uint32_t remote_dst_ip) {

    if (!mac_entry || !oif) return false;

    mac_oif_entry_t *existing = mac_table_entry_find_oif(mac_entry, oif->port_id, remote_dst_ip);
    if (existing) return false;

    mac_oif_entry_t *oif_entry = mac_oif_entry_create(oif, remote_dst_ip);
    glthread_add_next(&mac_entry->oif_list, &oif_entry->glue);
    return true;
}

bool
mac_table_entry_remove_oif(mac_table_entry_t *mac_entry, uint32_t ifindex, uint32_t remote_dst_ip) {

    if (!mac_entry) return false;

    mac_oif_entry_t *oif_entry = mac_table_entry_find_oif(mac_entry, ifindex, remote_dst_ip);
    if (oif_entry) {
        mac_oif_entry_destroy(oif_entry);
        return true;
    }
    return false;
}

mac_oif_entry_t *
mac_table_entry_find_oif(mac_table_entry_t *mac_entry, uint32_t ifindex, uint32_t remote_dst_ip) {

    if (!mac_entry) return NULL;

    glthread_t *curr;
    mac_oif_entry_t *oif_entry;

    ITERATE_GLTHREAD_BEGIN(&mac_entry->oif_list, curr) {
        oif_entry = mac_oif_glue_to_entry(curr);
        if (oif_entry->oif &&
            oif_entry->oif->port_id == ifindex &&
            oif_entry->remote_dst_ip == remote_dst_ip) {
            return oif_entry;
        }
    } ITERATE_GLTHREAD_END(&mac_entry->oif_list, curr);

    return NULL;
}

bool
mac_table_entry_has_oifs(mac_table_entry_t *mac_entry) {

    if (!mac_entry) return false;
    return !IS_GLTHREAD_LIST_EMPTY(&mac_entry->oif_list);
}

void
mac_table_entry_clear_oifs(mac_table_entry_t *mac_entry) {

    if (!mac_entry) return;

    glthread_t *curr;
    mac_oif_entry_t *oif_entry;

    ITERATE_GLTHREAD_BEGIN(&mac_entry->oif_list, curr) {
        oif_entry = mac_oif_glue_to_entry(curr);
        mac_oif_entry_destroy(oif_entry);
    } ITERATE_GLTHREAD_END(&mac_entry->oif_list, curr);
}
