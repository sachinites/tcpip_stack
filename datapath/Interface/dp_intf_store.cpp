#include "dp_intf.h"
#include "../../c-hashtable/hashtable.h"
#include "../../c-hashtable/hashtable_itr.h"
#include <stdlib.h>
#include <string.h>

/* Hash function for port_id (uint32_t) keys */
static unsigned int 
port_id_hash_function(void *key) {
    uint32_t *port_id = (uint32_t *)key;
    /* Simple hash for 32-bit port ID */
    return (*port_id) ^ ((*port_id) >> 16);
}

/* Equality function for port_id keys */
static int 
port_id_key_equal_function(void *key1, void *key2) {
    uint32_t *port_id1 = (uint32_t *)key1;
    uint32_t *port_id2 = (uint32_t *)key2;
    return (*port_id1 == *port_id2);
}

void 
dp_init_intf_hashtable (hashtable_t **ht) {
    /* Create hashtable with initial size of 16 entries */
    *ht = create_hashtable(16, port_id_hash_function, port_id_key_equal_function);
    
    if (!(*ht)) {
        /* Handle out of memory - could log error here */
        return;
    }
}

dp_intf_t *
dp_look_up_interface (hashtable_t *ht, uint32_t port_id) {
    if (!ht) {
        return NULL;
    }
    
    /* Search for the interface using port_id as key */
    return (dp_intf_t *)hashtable_search(ht, (void *)&port_id);
}

void
dp_insert_interface (hashtable_t *ht, dp_intf_t *intf) {
    
    /* Allocate a key for the hashtable (hashtable takes ownership of key) */
    uint32_t *key = (uint32_t *)malloc(sizeof(uint32_t));
    
    *key = intf->port_id;
    
    /* Insert the interface with port_id as key */
    if (!hashtable_insert(ht, (void *)key, (void *)intf)) {
        /* Insert failed - free the key we allocated */
        free(key);
    }
}

void
dp_delete_interface (hashtable_t *ht, uint32_t port_id) {
    
    /* Remove the interface from hashtable */
    dp_intf_t *intf = (dp_intf_t *)hashtable_remove(ht, (void *)&port_id);
    
    /* Free the interface structure if found */
    if (intf) {
        free(intf);
    }
}

dp_intf_t *
dp_create_interface (uint32_t port_id, uint32_t iftype, uint8_t (*mac_addr)[6]) {

    dp_intf_t *intf = (dp_intf_t *)calloc(1, sizeof(dp_intf_t));
    intf->port_id = port_id;
    intf->if_type = (DP_InterfaceType_t)iftype;
    intf->if_name[0] = '\0';
    intf->pkt_recv = 0;
    intf->pkt_sent = 0;
    intf->xmit_pkt_dropped = 0;
    intf->recvd_pkt_dropped = 0;
    intf->vrf = NULL;
    memset(intf->v6addr_link_local, 0, 16);
    memset(intf->v6addr, 0, 16);
    intf->v6mask = 0;
    intf->ip_addr = 0;
    intf->mask = 0;
    memcpy(&intf->mac_add, (void *)mac_addr, 6);
    intf->switchport = false;
    intf->vlan_intf = NULL;
    intf->vlan_id = 0;
    intf->vni_id = 0;
    intf->l2_mode = DP_LAN_MODE_NONE;
    intf->is_up = false;
    return intf;
}

