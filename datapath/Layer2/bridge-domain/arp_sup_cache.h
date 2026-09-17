/*
 * =============================================================================
 * File: arp_sup_cache.h
 * Description: EVPN ARP suppression cache backed by DPDK rte_hash.
 * =============================================================================
 *
 * Concurrency model (same as ARP/MAC tables):
 *   Writer : single writer (typically dp_ev_dis) for insert/delete/init.
 *   Readers: any thread via arp_sup_cache_entry_lookup() (rte_hash_lookup_data).
 *
 * Created with RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF (lock-free readers,
 * single writer; implies NO_FREE_ON_DEL — entry memory is owned by this module).
 *
 * Key:   arp_sup_hash_key_t { ip_addr (4B), _pad (4B) } = 8 bytes.
 * Value: dp_arp_sup_cache_entry_t * (pointer stored; rte_hash does NOT own it).
 * =============================================================================
 */

#ifndef __ARP_SUPPRESSION__
#define __ARP_SUPPRESSION__

#include <stdbool.h>
#include <stdint.h>

#include "../../../libs/common/cmn_struct.h"

struct rte_hash;   /* forward-declared; include <rte_hash.h> in .c/.cpp files */

#pragma pack(push, 8)

/* Hash key: 8 bytes (ip_addr + padding for rte_hash alignment). */
typedef struct arp_sup_hash_key_ {
    uint32_t ip_addr;
    uint32_t _pad;
} arp_sup_hash_key_t;

typedef struct arp_sup_cache_entry_ {
    uint32_t ip_addr;       /* Key */
    uint32_t supp_count;
    mac_addr_t mac_Addr;
    uint16_t _pad;
} dp_arp_sup_cache_entry_t;


#pragma pack(pop)

void
arp_sup_cache_init(struct rte_hash **arp_sup_cache_db);

bool
arp_sup_cache_entry_insert(struct rte_hash *arp_sup_cache_db,
                           uint32_t ip_addr,
                           mac_addr_t *mac_Addr);

bool
arp_sup_cache_entry_delete(struct rte_hash *arp_sup_cache_db,
                           uint32_t ip_addr);

/* Lock-free read. Returned pointer is valid until the entry is deleted. */
dp_arp_sup_cache_entry_t *
arp_sup_cache_entry_lookup(struct rte_hash *arp_sup_cache_db,
                           uint32_t ip_addr);


void 
dp_arp_sup_cache_db_destroy(struct rte_hash *arp_sup_cache_db);

void
dp_arp_sup_cache_db_print(struct rte_hash *arp_sup_cache_db);

#endif /* __ARP_SUPPRESSION__ */
