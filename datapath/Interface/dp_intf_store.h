#ifndef __DP_INTF_STORE__
#define __DP_INTF_STORE__

#include <stdint.h>
#include "intf_cons.h"

typedef  struct hashtable hashtable_t;
typedef struct dp_intf_ dp_intf_t;

void 
dp_init_intf_hashtable (hashtable_t **ht);

dp_intf_t *
dp_look_up_interface (hashtable_t *ht, uint32_t port_id);

void
dp_insert_interface (hashtable_t *ht, dp_intf_t *intf);

void
dp_delete_interface (hashtable_t *ht, uint32_t port_id) ;

dp_intf_t *
dp_create_interface (uint32_t port_id, uint32_t iftype, uint8_t (*mac_addr)[6], uint16_t vlan_id) ;

void 
dp_vlan_bind_port (dp_intf_t *vlan_intf, dp_intf_t *intf, DP_IntfL2Mode l2_mode);

void 
dp_vlan_unbind_port (dp_intf_t *vlan_intf, 
                     dp_intf_t *intf, 
                     DP_IntfL2Mode l2_mode, 
                     bool restore_intf_mode_to_none);


bool
dp_is_vlan_member (bitmap_t *vlan_bitmap, uint16_t vlan_id);

dp_intf_t *
dp_look_up_interface_by_vlan_id(hashtable_t *ht, uint16_t vlan_id);

void 
dp_check_and_free_interface (dp_intf_t *intf);

/* Vlan interface Hash table Mgmt */

void 
dp_init_vlan_intf_hashtable (hashtable_t **ht);

dp_intf_t *
dp_look_up_interface_by_vlan_id (hashtable_t *ht, uint16_t vlan_id);

void
dp_insert_vlan_interface (hashtable_t *ht, dp_intf_t *intf);

void
dp_remove_vlan_interface (hashtable_t *ht, uint16_t vlan_id) ;

#endif