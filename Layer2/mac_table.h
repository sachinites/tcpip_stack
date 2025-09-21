#ifndef __MAC_TABLE_H__
#define __MAC_TABLE_H__

#include <stdint.h>
#include <assert.h>
#include "../Interface/InterfaceFwd.h"
#include "../libtimer/WheelTimer.h"
#include "../common/cmn_struct.h"
#include "../utils.h"

typedef struct node_ node_t;

/*L2 Switch Owns Mac Table*/
#define MAC_STATIC  0x1
#define MAC_DYNAMIC 0x2
#define MAC_CONTROL_PLANE   0x4

static inline const char * mac_entry_flag (uint16_t mac_entry_flag) {

    switch(mac_entry_flag) {
        case MAC_STATIC : return "static";
        case MAC_DYNAMIC : return "dynamic";
        case MAC_CONTROL_PLANE : return "control-plane";
        default: return "UNKNOWN";
    }
    return "nil";
}

#define MAC_MAC_OIF_CNT 4

typedef struct mac_table_entry_{

    InterfaceP oif[MAC_MAC_OIF_CNT];
    uint32_t remote_dst_ip[MAC_MAC_OIF_CNT];
    wheel_timer_elem_t *exp_timer_wt_elem;
    glthread_t mac_entry_glue;
    mac_addr_t mac;
    uint16_t flags;
    vlan_id_t vlan_id;
    char padding2[6];

    /* Add destructor */
    ~mac_table_entry_() {
        assert (!exp_timer_wt_elem);
    }

} __attribute__((aligned(8)))  mac_table_entry_t;

GLTHREAD_TO_STRUCT(mac_entry_glue_to_mac_entry, mac_table_entry_t, mac_entry_glue);

typedef struct mac_table_{

    glthread_t mac_entries;
    
}  __attribute__((aligned(8))) mac_table_t;

#define IS_MAC_TABLE_ENTRY_EQUAL(mac_entry_1, mac_entry_2)   \
    (mac_address_compare  (mac_entry_1->mac.mac, mac_entry_2->mac.mac) && \
    (string_compare(mac_entry_1->mac.mac, mac_entry_2->mac.mac, sizeof(mac_addr_t)) == 0 && \
            mac_entry_1->vlan_id == mac_entry_2->vlan_id))

/* MAC Table Management Functions */
void init_mac_table(mac_table_t **mac_table);
mac_table_entry_t *mac_table_lookup(mac_table_t *mac_table, vlan_id_t vlan, c_string mac);
void clear_mac_table(node_t *node, mac_table_t *mac_table);
void mac_table_entry_add (node_t *node, mac_table_t *mac_table,  
                          uint8_t *mac_addr,  uint16_t vlan_id, uint32_t ifindex, uint16_t flags, uint32_t remote_dst_ip) ;
void mac_table_entry_delete (node_t *node, mac_table_t *mac_table, 
                          uint8_t *mac_addr,  uint16_t vlan_id, uint32_t ifindex, uint32_t remote_dst_ip) ;
void
mac_table_entry_delete2 (node_t *node, mac_table_t *mac_table, vlan_id_t vlan_id, c_string mac);

void show_mac_table(mac_table_t *mac_table, vlan_id_t vlan_id);
void mac_table_entry_init_timer (node_t *node, mac_table_entry_t *mac_table_entry);
void mac_table_entry_cancel_expiry_timer (mac_table_entry_t *mac_table_entry) ;

#endif /* __MAC_TABLE_H__ */
