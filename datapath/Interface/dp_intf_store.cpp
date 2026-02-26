#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../../BitOp/bitmap.h"

#include "dp_intf.h"
#include "../../c-hashtable/hashtable.h"
#include "../../c-hashtable/hashtable_itr.h"


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
dp_check_and_free_interface (dp_intf_t *intf) {

    int i;

    assert(!intf->vrf);
    assert(!intf->vlan_intf);

    for (i = 0; i < MAX_VLAN_MEMBER_PORTS; i++) {
        assert(!intf->mports[i]);
    }

    assert(!intf->vlan_bitmap);
    assert(!intf->olay_tunnel_intf);

    free(intf);
}

void
dp_delete_interface (hashtable_t *ht, uint32_t port_id) {
    
    /* Remove the interface from hashtable */
    dp_intf_t *intf = (dp_intf_t *)hashtable_remove(ht, (void *)&port_id);
    assert(intf);
    dp_check_and_free_interface (intf);
}

dp_intf_t *
dp_create_interface (uint32_t port_id, uint32_t iftype, 
                     uint8_t (*mac_addr)[6], 
                     uint16_t vlan_id) {

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
    intf->vlan_id = vlan_id;
    intf->vni_id = 0;
    intf->l2_mode = DP_LAN_MODE_NONE;
    intf->is_up = false;
    return intf;
}


void 
dp_vlan_bind_port (dp_intf_t *vlan_intf, dp_intf_t *intf, DP_IntfL2Mode l2_mode) {

    dp_intf_t *mport;

    assert (intf->switchport);

    if (l2_mode == DP_LAN_ACCESS_MODE) {

        assert(!intf->vlan_intf);
        intf->vlan_intf = vlan_intf;
    }

    int i;

    for (i = 0; i < MAX_VLAN_MEMBER_PORTS; i++) {
        if (vlan_intf->mports[i] == intf) assert(0);
    }

    for (i = 0; i < MAX_VLAN_MEMBER_PORTS; i++) {
        if (vlan_intf->mports[i]) continue;
        break;
    }    

    assert (i != MAX_VLAN_MEMBER_PORTS);

    vlan_intf->mports[i] = intf;

    if (l2_mode == DP_LAN_TRUNK_MODE) {

        if (!intf->vlan_bitmap) {
            bitmap_init2(&intf->vlan_bitmap, DP_MAX_VLAN_SUPORT);
        }

        assert (!bitmap_at (intf->vlan_bitmap, vlan_intf->vlan_id));
        bitmap_set_bit_at(intf->vlan_bitmap, vlan_intf->vlan_id);
    }

    intf->l2_mode = l2_mode;
}

void 
dp_vlan_unbind_port (dp_intf_t *vlan_intf, 
                     dp_intf_t *intf, 
                     DP_IntfL2Mode l2_mode,
                     bool restore_intf_mode_to_none) {

    int i;

    assert (intf->switchport);

    /* In access mode, clear the vlan_intf pointer */
    if (l2_mode == DP_LAN_ACCESS_MODE) {
        
        assert(intf->vlan_intf == vlan_intf);
        intf->vlan_intf = NULL;
    }

    /* Find and remove the interface from vlan member ports */
    for (i = 0; i < MAX_VLAN_MEMBER_PORTS; i++) {
        if (vlan_intf->mports[i] == intf) {
            vlan_intf->mports[i] = NULL;
            break;
        }
    }

    /* Assert that we found and removed the interface */
    assert (i != MAX_VLAN_MEMBER_PORTS);

    /* In trunk mode, unset the vlan bit in bitmap */
    if (l2_mode == DP_LAN_TRUNK_MODE) {

        assert (intf->vlan_bitmap);
        assert (bitmap_at (intf->vlan_bitmap, vlan_intf->vlan_id));
        bitmap_unset_bit_at(intf->vlan_bitmap, vlan_intf->vlan_id);
    }

    if (!restore_intf_mode_to_none) return; 
    
    /* Reset L2 mode to none if no more VLANs are bound */
    if (l2_mode == DP_LAN_TRUNK_MODE) {

        /* Check if any VLAN bits are still set */
        bool has_vlans = false;
        for (i = 0; i < DP_MAX_VLAN_SUPORT; i++) {
            if (bitmap_at(intf->vlan_bitmap, i)) {
                has_vlans = true;
                break;
            }
        }
        if (!has_vlans) {
            intf->l2_mode = DP_LAN_MODE_NONE;
        }
    } else {
        /* In access mode, always reset to NONE when unbinding */
        intf->l2_mode = DP_LAN_MODE_NONE;
    }
}

bool
dp_is_vlan_member (bitmap_t *vlan_bitmap, uint16_t vlan_id) {

    /* VLAN IDs range from 0 to 4095 (12 bits) */
    if (!vlan_bitmap || vlan_id >= 4096) {
        return false;
    }
    
    /* Check if the vlan_id bit is set in the bitmap */
    return bitmap_at(vlan_bitmap, vlan_id);
}

dp_intf_t *
dp_look_up_interface_by_vlan_id(hashtable_t *ht, uint16_t vlan_id) {

    dp_intf_t *vlan_intf = NULL;

    return vlan_intf;
}