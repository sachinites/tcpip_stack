/*
 * arp_sup_cache.cpp — ARP suppression cache (DPDK rte_hash).
 *
 * CRUD mirrors arp.c / mac_table.cpp:
 *   - RW_CONCURRENCY_LF for lock-free readers + single writer
 *   - values are heap entry pointers owned by this module
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_errno.h>

#include "arp_sup_cache.h"
#include "../../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../../../utils.h"
#include "../../../CLIBuilder/libcli.h"

#define ARP_SUP_HASH_ENTRIES  1024

void
arp_sup_cache_init(struct rte_hash **arp_sup_cache_db)
{
    static uint32_t seq;
    char hash_name[RTE_HASH_NAMESIZE];
    uint32_t id;

    assert(arp_sup_cache_db);

    id = __atomic_fetch_add(&seq, 1, __ATOMIC_RELAXED);
    snprintf(hash_name, sizeof(hash_name), "arp_sup_%u", id);

    struct rte_hash_parameters params = {};
    params.name               = hash_name;
    params.entries            = ARP_SUP_HASH_ENTRIES;
    params.key_len            = sizeof(arp_sup_hash_key_t);
    params.hash_func          = rte_jhash;
    params.hash_func_init_val = 0;
    params.socket_id          = 0;
    /* Lock-free readers + single writer; no hugepage rte_ring required. */
    params.extra_flag         = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;

    *arp_sup_cache_db = rte_hash_create(&params);
    if (!*arp_sup_cache_db) {
        cprintf("Error: arp_sup_cache rte_hash_create failed: %s\n",
                rte_strerror(rte_errno));
    }
}

bool
arp_sup_cache_entry_insert(struct rte_hash *arp_sup_cache_db,
                           uint32_t ip_addr,
                           mac_addr_t *mac_Addr)
{
    arp_sup_hash_key_t key = { ip_addr, 0 };
    void *data = NULL;
    dp_arp_sup_cache_entry_t *entry;
    int rc;

    if (!arp_sup_cache_db || !mac_Addr)
        return false;

    if (rte_hash_lookup_data(arp_sup_cache_db, &key, &data) >= 0) {
        entry = (dp_arp_sup_cache_entry_t *)data;
        memcpy(entry->mac_Addr.mac, mac_Addr->mac, MAC_ADDR_SIZE);
        return true;
    }

    entry = (dp_arp_sup_cache_entry_t *)XCALLOC2(0, 1, dp_arp_sup_cache_entry_t);
    if (!entry)
        return false;

    entry->ip_addr = ip_addr;
    memcpy(entry->mac_Addr.mac, mac_Addr->mac, MAC_ADDR_SIZE);

    rc = rte_hash_add_key_data(arp_sup_cache_db, &key, entry);
    if (rc < 0) {
        XFREE(entry);
        return false;
    }
    return true;
}

bool
arp_sup_cache_entry_delete(struct rte_hash *arp_sup_cache_db,
                           uint32_t ip_addr)
{
    arp_sup_hash_key_t key = { ip_addr, 0 };
    void *data = NULL;
    dp_arp_sup_cache_entry_t *entry;

    if (!arp_sup_cache_db)
        return false;

    if (rte_hash_lookup_data(arp_sup_cache_db, &key, &data) < 0)
        return false;

    entry = (dp_arp_sup_cache_entry_t *)data;
    if (rte_hash_del_key(arp_sup_cache_db, &key) < 0)
        return false;

    XFREE(entry);
    return true;
}

dp_arp_sup_cache_entry_t *
arp_sup_cache_entry_lookup(struct rte_hash *arp_sup_cache_db,
                           uint32_t ip_addr)
{
    arp_sup_hash_key_t key = { ip_addr, 0 };
    void *data = NULL;

    if (!arp_sup_cache_db)
        return NULL;

    if (rte_hash_lookup_data(arp_sup_cache_db, &key, &data) < 0)
        return NULL;

    return (dp_arp_sup_cache_entry_t *)data;
}

void
dp_arp_sup_cache_db_destroy(struct rte_hash *arp_sup_cache_db)
{
    uint32_t next = 0;
    const void *key;
    void *data;

    if (!arp_sup_cache_db)
        return;

    while (rte_hash_iterate(arp_sup_cache_db, &key, &data, &next) >= 0) {
        XFREE(data);
    }

    rte_hash_free(arp_sup_cache_db);
}


void
dp_arp_sup_cache_db_print(struct rte_hash *arp_sup_cache_db)
{
    uint32_t next = 0;
    const void *key;
    void *data;
    int count = 0;

    if (!arp_sup_cache_db)
        return;

    cprintf("%-16s  %-17s  %s\n", "IP Address", "MAC Address", "Supp Count");
    cprintf("%-16s  %-17s  %s\n",
            "----------------", "-----------------", "----------");

    while (rte_hash_iterate(arp_sup_cache_db, &key, &data, &next) >= 0) {
        dp_arp_sup_cache_entry_t *entry = (dp_arp_sup_cache_entry_t *)data;
        char ip_str[IPV4_ADDR_LEN_STR];
        char mac_str[18];

        ip_ntop(entry->ip_addr, (c_string)ip_str);
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 entry->mac_Addr.mac[0], entry->mac_Addr.mac[1],
                 entry->mac_Addr.mac[2], entry->mac_Addr.mac[3],
                 entry->mac_Addr.mac[4], entry->mac_Addr.mac[5]);
        cprintf("%-16s  %-17s  %u\n",
                ip_str, mac_str, entry->supp_count);
        count++;
    }

    if (!count)
        cprintf("(empty)\n");
    else
        cprintf("Total : %d\n", count);
}
