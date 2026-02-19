#ifndef __DP_INTF_STORE__
#define __DP_INTF_STORE__

#include <stdint.h>
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
dp_create_interface (uint32_t port_id, uint32_t iftype, uint8_t (*mac_addr)[6]) ;

#endif 