/*
 * =====================================================================================
 *
 *       Filename:  vni_mac_table.c
 *
 *    Description:  This file implements VNI-keyed MAC table management functionality.
 *                 Each VNI has its own separate MAC table for VXLAN forwarding.
 *
 *        Version:  1.0
 *        Created:  [Current Date]
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  AI Assistant
 *        Company:  TCP/IP Stack Implementation
 *        
 *        This file implements VNI-keyed MAC table management for VXLAN functionality.
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include "vxlan_dp.h"
#include "../../graph.h"
#include "../../gluethread/glthread.h"
#include "../../utils.h"
#include "../../Layer2/layer2.h"
#include "../../../lmm_enums.h"

void
init_vni_mac_table_db(vni_mac_table_db_t **vni_mac_table_db) {
    *vni_mac_table_db = (vni_mac_table_db_t *)XCALLOC2(0, 1, vni_mac_table_db_t);
    init_glthread(&((*vni_mac_table_db)->vni_mac_tables));
}

vni_mac_table_entry_t *
vni_mac_table_lookup(vni_mac_table_db_t *vni_mac_table_db, uint32_t vni_id) {
    
    if (!vni_mac_table_db) return NULL;
    
    glthread_t *curr;
    vni_mac_table_entry_t *entry;
    
    ITERATE_GLTHREAD_BEGIN(&vni_mac_table_db->vni_mac_tables, curr) {
        entry = vni_mac_table_glue_to_entry(curr);
        if (entry->vni_id == vni_id) {
            return entry;
        }
    } ITERATE_GLTHREAD_END(&vni_mac_table_db->vni_mac_tables, curr);
    
    return NULL;
}

mac_table_t *
get_vni_mac_table(node_t *node, uint32_t vni_id) {
    
    if (!node->node_nw_prop.vni_mac_table_db) {
        return NULL;
    }
    
    vni_mac_table_entry_t *entry = vni_mac_table_lookup(NODE_VNI_MAC_TABLE_DB(node), vni_id);
    return entry ? entry->mac_table : NULL;
}

bool
create_vni_mac_table(node_t *node, uint32_t vni_id) {
    
    if (!node->node_nw_prop.vni_mac_table_db) {
        init_vni_mac_table_db(&node->node_nw_prop.vni_mac_table_db);
    }
    
    vni_mac_table_db_t *vni_mac_table_db = NODE_VNI_MAC_TABLE_DB(node);
    
    /* Check if VNI MAC table already exists */
    vni_mac_table_entry_t *existing_entry = vni_mac_table_lookup(vni_mac_table_db, vni_id);
    if (existing_entry) {
        return true; /* Already exists */
    }
    
    /* Create new VNI MAC table entry */
    vni_mac_table_entry_t *entry = (vni_mac_table_entry_t *)XCALLOC2(0, 1, vni_mac_table_entry_t);
    entry->vni_id = vni_id;
    
    /* Initialize MAC table for this VNI */
    init_mac_table(&entry->mac_table);
    
    /* Add default MAC table entry: <vlan> <Router-MAC> <rmacif> */
    mac_table_entry_t *default_mac_entry = new mac_table_entry_t;
    default_mac_entry->vlan_id = vni_id; /* Use VNI as VLAN ID for VXLAN */
    
    /* Get router MAC address */
    mac_addr_t *rmac = NODE_RMAC(node);
    memcpy(default_mac_entry->mac.mac, rmac->mac, sizeof(mac_addr_t));
    
    /* Set RmacInterface as the output interface */
    default_mac_entry->oif[0] = NODE_RMAC_INTF(node);
    default_mac_entry->flags = MAC_STATIC; /* Static entry for router MAC */
    
    /* Initialize the glthread for this MAC entry */
    init_glthread(&default_mac_entry->mac_entry_glue);
    
    /* Add to MAC table */
    mac_table_entry_add(node, entry->mac_table, default_mac_entry);
    
    init_glthread(&entry->glue);
    glthread_add_next(&vni_mac_table_db->vni_mac_tables, &entry->glue);
    
    return true;
}

bool
delete_vni_mac_table(node_t *node, uint32_t vni_id) {
    
    vni_mac_table_db_t *vni_mac_table_db = NODE_VNI_MAC_TABLE_DB(node);
    
    if (!vni_mac_table_db) return false;
    
    vni_mac_table_entry_t *entry = vni_mac_table_lookup(vni_mac_table_db, vni_id);
    if (!entry) return false;
    
    /* Clear the MAC table */
    clear_mac_table(node, entry->mac_table);
    
    /* Remove from database */
    remove_glthread(&entry->glue);
    XFREE(entry);
    
    return true;
}

void
clear_vni_mac_table_db(vni_mac_table_db_t *vni_mac_table_db) {
    
    if (!vni_mac_table_db) return;
    
    glthread_t *curr;
    vni_mac_table_entry_t *entry;
    
    ITERATE_GLTHREAD_BEGIN(&vni_mac_table_db->vni_mac_tables, curr) {
        entry = vni_mac_table_glue_to_entry(curr);
        remove_glthread(curr);
        XFREE(entry);
    } ITERATE_GLTHREAD_END(&vni_mac_table_db->vni_mac_tables, curr);
}

void
dump_vni_mac_table(node_t *node, uint32_t vni_id) {
    
    mac_table_t *mac_table = get_vni_mac_table(node, vni_id);
    
    if (!mac_table) {
        cprintf("No MAC table found for VNI %u\n", vni_id);
        return;
    }
    
    cprintf("MAC Table for VNI %u:\n", vni_id);
    cprintf("MAC Table exists\n");
}
