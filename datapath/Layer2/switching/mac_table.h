#ifndef __MAC_TABLE_H__
#define __MAC_TABLE_H__

#include <stdint.h>
#include <assert.h>
#include "../../../libs/libtimer/WheelTimer.h"
#include "../../../libs/common/cmn_struct.h"
#include "../../../utils.h"
#include "../../enums/l2_enums.h"

typedef struct dp_intf_ dp_intf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct pkt_block_ pkt_block_t;

#pragma pack (push,8)

/* Structure to hold interface and remote IP pair */
typedef struct mac_oif_entry_ {
    dp_intf_t *oif;
    glthread_t glue;
    uint32_t remote_dst_ip;
}  mac_oif_entry_t;

GLTHREAD_TO_STRUCT(mac_oif_glue_to_entry, mac_oif_entry_t, glue);

typedef struct mac_table_entry_{

    glthread_t oif_list;  // Dynamic list of mac_oif_entry_t
    wheel_timer_elem_t *exp_timer_wt_elem;
    glthread_t mac_entry_glue;
    mac_addr_t mac;
    uint16_t flags;
    uint16_t vlan_id;
    char padding2[6];

} mac_table_entry_t;

GLTHREAD_TO_STRUCT(mac_entry_glue_to_mac_entry, mac_table_entry_t, mac_entry_glue);

typedef struct mac_table_{

    glthread_t mac_entries;
    
}  mac_table_t;

#pragma pack(pop)

#define IS_MAC_TABLE_ENTRY_EQUAL(mac_entry_1, mac_entry_2)   \
    (mac_address_compare  (mac_entry_1->mac.mac, mac_entry_2->mac.mac) && \
    (string_compare(mac_entry_1->mac.mac, mac_entry_2->mac.mac, sizeof(mac_addr_t)) == 0 && \
            mac_entry_1->vlan_id == mac_entry_2->vlan_id))

/* MAC Table Management Functions */
void init_mac_table(mac_table_t **mac_table);
mac_table_entry_t *mac_table_lookup(mac_table_t *mac_table, uint16_t vlan, uint8_t *mac);
void mac_table_entry_add (dp_ctx_t *dp_ctx, mac_table_t *mac_table,  
                          uint8_t *mac_addr,  uint16_t vlan_id, uint32_t ifindex, uint16_t flags, uint32_t remote_dst_ip) ;
void mac_table_entry_delete (dp_ctx_t *dp_ctx, mac_table_t *mac_table, 
                          uint8_t *mac_addr,  uint16_t vlan_id, uint32_t ifindex, uint32_t remote_dst_ip) ;
void
mac_table_entry_delete2 (dp_ctx_t *dp_ctx, mac_table_t *mac_table, uint16_t vlan_id, uint8_t *mac_addr);

void show_mac_table(mac_table_t *mac_table, uint16_t vlan_id);
void mac_table_entry_init_timer (dp_ctx_t *dp_ctx, mac_table_entry_t *mac_table_entry);
void mac_table_entry_cancel_expiry_timer (mac_table_entry_t *mac_table_entry) ;

/* Dynamic OIF list management functions */
mac_oif_entry_t *mac_oif_entry_create(dp_intf_t * oif, uint32_t remote_dst_ip);
void mac_oif_entry_destroy(mac_oif_entry_t *oif_entry);
bool mac_table_entry_add_oif(mac_table_entry_t *mac_entry, dp_intf_t * oif, uint32_t remote_dst_ip);
bool mac_table_entry_remove_oif(mac_table_entry_t *mac_entry, uint32_t ifindex, uint32_t remote_dst_ip);
mac_oif_entry_t *mac_table_entry_find_oif(mac_table_entry_t *mac_entry, uint32_t ifindex, uint32_t remote_dst_ip);
bool mac_table_entry_has_oifs(mac_table_entry_t *mac_entry);
void mac_table_entry_clear_oifs(mac_table_entry_t *mac_entry);

void l2_switch_recv_frame(dp_ctx_t *dp_ctx,
                           uint16_t vlan_id,
                           dp_intf_t *interface,
                           pkt_block_t *pkt_block);

#endif /* __MAC_TABLE_H__ */
