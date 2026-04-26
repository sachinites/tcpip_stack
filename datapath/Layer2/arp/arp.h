/*
 * =============================================================================
 * File: arp.h
 * Description: ARP table and ARP request/reply handling in the datapath.
 * =============================================================================
 *
 * Design:
 *   - arp_table_t: list of arp_entry_t (IP key, MAC, oif, proto, sane/pending).
 *   - send_arp_broadcast_request: send ARP request for an IP from an oif.
 *   - process_arp_broadcast_request / process_arp_reply_msg: handle received ARP.
 *   - arp_table_lookup, arp_entry_add, arp_entry_delete, create_update_arp_sane_entry:
 *     table management. Pending packets are queued and processed when ARP replies.
 * =============================================================================
 */

#ifndef __ARP__HDR__
#define __ARP__HDR__

#include <pthread.h>

#include "../../../libs/common/cmn_struct.h"
#include "../../../libs/gluethread/glthread.h"
#include "../../../tcpconst.h"

typedef struct pkt_block_ pkt_block_t;
typedef struct arp_hdr_ arp_hdr_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct _wheel_timer_elem_t wheel_timer_elem_t;

#include <stdint.h>

void
send_arp_broadcast_request(dp_ctx_t *dp_ctx,
                           dp_vrf_t *vrf,
                           dp_intf_t *oif, 
                           uint32_t ip_addr);

/*ARP Table APIs*/
#pragma pack(push, 8)
typedef struct arp_table_{

    glthread_t arp_entries;

    pthread_rwlock_t rwlock;

} arp_table_t;

typedef struct arp_pending_entry_ arp_pending_entry_t;
typedef struct arp_entry_ arp_entry_t;
typedef void (*arp_processing_fn)(dp_ctx_t *,
                                  dp_intf_t *,
                                  arp_entry_t *, 
                                  arp_pending_entry_t *);
struct arp_pending_entry_{

    glthread_t arp_pending_entry_glue;
    arp_processing_fn cb;
    pkt_block_t *pkt_block;
};

GLTHREAD_TO_STRUCT(arp_pending_entry_glue_to_arp_pending_entry, \
    arp_pending_entry_t, arp_pending_entry_glue);

struct arp_entry_{

    glthread_t arp_glue;
    glthread_t arp_pending_list;
    wheel_timer_elem_t *exp_timer_wt_elem;
    mac_addr_t mac_addr;
    uint16_t proto;
    uint32_t ip_addr;   /*key*/
    dp_intf_t *oif;
    bool is_sane;
	
};
#pragma pack(pop)
GLTHREAD_TO_STRUCT(arp_glue_to_arp_entry, arp_entry_t, arp_glue);
GLTHREAD_TO_STRUCT(arp_pending_list_to_arp_entry, arp_entry_t, arp_pending_list);

#define IS_ARP_ENTRIES_EQUAL(arp_entry_1, arp_entry_2)  \
    ((arp_entry_1->ip_addr == arp_entry_2->ip_addr) && \
        mac_address_compare(arp_entry_1->mac_addr.mac, arp_entry_2->mac_addr.mac) && \
        arp_entry_1->oif == arp_entry_2->oif && \
        arp_entry_1->is_sane == arp_entry_2->is_sane &&     \
        arp_entry_1->is_sane == false && \
        arp_entry_1->proto == arp_entry_2->proto)

void
init_arp_table(arp_table_t **arp_table);

static inline void
arp_table_rdlock(arp_table_t *arp_table) {
    pthread_rwlock_rdlock(&arp_table->rwlock);
}

static inline void
arp_table_wrlock(arp_table_t *arp_table) {
    pthread_rwlock_wrlock(&arp_table->rwlock);
}

static inline void
arp_table_unlock(arp_table_t *arp_table) {
    pthread_rwlock_unlock(&arp_table->rwlock);
}

arp_entry_t *
arp_table_lookup(arp_table_t *arp_table, uint32_t ip_addr);

void
clear_arp_table(arp_table_t *arp_table);

wheel_timer_elem_t *
arp_entry_create_expiration_timer(
		dp_ctx_t *dp_ctx,
		arp_entry_t *arp_entry,
		uint16_t exp_time);

void
arp_entry_delete_expiration_timer(
		arp_entry_t *arp_entry);

void
arp_entry_refresh_expiration_timer(
		arp_entry_t *arp_entry);

uint16_t
arp_entry_get_exp_time_left(arp_entry_t *arp_entry);

void
delete_arp_entry(arp_entry_t *arp_entry);

void
arp_entry_delete(dp_ctx_t *dp_ctx, dp_vrf_t *vrf, uint32_t ip_addr, uint16_t proto);

bool
arp_table_entry_add(dp_ctx_t *dp_ctx, 
                    dp_vrf_t *vrf,
					arp_table_t *arp_table,
					arp_entry_t *arp_entry,
                    glthread_t **arp_pending_list);
                   

void
show_arp_table(arp_table_t *arp_table);

void arp_table_update_from_arp_reply(dp_ctx_t *dp_ctx,
                                     dp_vrf_t *vrf,
                                     arp_table_t *arp_table,
                                     arp_hdr_t *arp_hdr,
                                     dp_intf_t *iif);


void
add_arp_pending_entry (dp_ctx_t *dp_ctx,
        arp_entry_t *arp_entry,
        arp_processing_fn cb,
        pkt_block_t *pkt_block);

void
create_update_arp_sane_entry(dp_ctx_t *dp_ctx,
                      dp_vrf_t *vrf,
					  arp_table_t *arp_table,
                      uint32_t ip_addr, 
					  pkt_block_t *pkt_block);

static bool 
arp_entry_sane(arp_entry_t *arp_entry){

    return arp_entry->is_sane;
}

void
process_arp_broadcast_request(dp_ctx_t *dp_ctx,
                              dp_vrf_t *vrf, dp_intf_t *iif, 
                              ethernet_hdr_t *ethernet_hdr);

void
process_arp_reply_msg(dp_ctx_t *dp_ctx,
                     dp_vrf_t *vrf, dp_intf_t *iif,
                     ethernet_hdr_t *ethernet_hdr);

/* ARP Table Public APIs to be exposed to applications */

bool
arp_entry_add(dp_ctx_t *dp_ctx,
                dp_vrf_t *vrf, unsigned char *ip_addr, mac_addr_t mac, dp_intf_t *oif, uint16_t proto);

void 
l2_prepare_arp_reply_msg(
                    ethernet_hdr_t *ethernet_hdr_reply, 
                    mac_addr_t *dst_mac, uint32_t dst_ip,
                    mac_addr_t *src_mac, uint32_t src_ip );
                    

void 
arp_entry_delete_by_interface  ( arp_table_t *arp_table, dp_intf_t *intf);

#endif
