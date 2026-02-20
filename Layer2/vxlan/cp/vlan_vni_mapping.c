/*
 * =====================================================================================
 *
 *       Filename:  vlan_vni_mapping.c
 *
 *    Description:  VLAN-VNI mapping management functions
 *
 *        Version:  1.0
 *        Created:  [Current Date]
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  AI Assistant
 *        Company:  TCP/IP Stack Implementation
 *        
 *        This file implements VLAN-VNI mapping functionality for the TCP/IP stack.
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include "vxlan.h"
#include "../dp/vlan_vni_ht.h"
#include "../../../router_init.h"
#include "../../../gluethread/glthread.h"
#include "../../../utils.h"
#include "../../../LinuxMemoryManager/uapi_mm.h"
#include "../../../lmm_enums.h"

void
init_vlan_vni_db(vxlan_vni_db_t **vlan_vni_db) {
    *vlan_vni_db = (vxlan_vni_db_t *)XCALLOC2(0, 1, vxlan_vni_db_t);
    init_glthread(&((*vlan_vni_db)->mappings));
}

vxlan_vni_mapping_t *
vlan_vni_lookup(vxlan_vni_db_t *vlan_vni_db, vlan_id_t vlan_id) {
    
    if (!vlan_vni_db) return NULL;
    
    glthread_t *curr;
    vxlan_vni_mapping_t *mapping;
    
    ITERATE_GLTHREAD_BEGIN(&vlan_vni_db->mappings, curr) {
        mapping = vxlan_vni_glue_to_mapping(curr);
        if (mapping->vlan_id == vlan_id) {
            return mapping;
        }
    } ITERATE_GLTHREAD_END(&vlan_vni_db->mappings, curr);
    
    return NULL;
}

vxlan_vni_mapping_t *
vlan_vni_lookup_by_vni(vxlan_vni_db_t *vlan_vni_db, uint32_t vni_id) {
    
    if (!vlan_vni_db) return NULL;
    
    glthread_t *curr;
    vxlan_vni_mapping_t *mapping;
    
    ITERATE_GLTHREAD_BEGIN(&vlan_vni_db->mappings, curr) {
        mapping = vxlan_vni_glue_to_mapping(curr);
        if (mapping->vni_id == vni_id) {
            return mapping;
        }
    } ITERATE_GLTHREAD_END(&vlan_vni_db->mappings, curr);
    
    return NULL;
}

bool
vlan_vni_add_mapping(node_t *node, vlan_id_t vlan_id, uint32_t vni_id) {
    
    if (!node->node_nw_prop.vlan_vni_db) {
        init_vlan_vni_db(&node->node_nw_prop.vlan_vni_db);
    }
    
    vxlan_vni_db_t *vlan_vni_db = NODE_VLAN_VNI_DB(node);
    
    /* Check if VLAN already has a mapping */
    vxlan_vni_mapping_t *existing_vlan = vlan_vni_lookup(vlan_vni_db, vlan_id);
    if (existing_vlan) {
        if (existing_vlan->vni_id == vni_id) {
            return true; /* Already configured with same VNI */
        }
        /* Check if the new VNI is already mapped to another VLAN */
        vxlan_vni_mapping_t *existing_vni = vlan_vni_lookup_by_vni(vlan_vni_db, vni_id);
        if (existing_vni && existing_vni->vlan_id != vlan_id) {
            printf("Error: VNI %u is already mapped to VLAN %u\n", vni_id, existing_vni->vlan_id);
            return false; /* VNI already mapped to different VLAN */
        }
        /* Update existing mapping */
        existing_vlan->vni_id = vni_id;
        /* Update hashtable atomically */
        vlan_vni_ht_add_mapping(node, vlan_id, vni_id);
        return true;
    }
    
    /* Check if VNI is already mapped to another VLAN */
    vxlan_vni_mapping_t *existing_vni = vlan_vni_lookup_by_vni(vlan_vni_db, vni_id);
    if (existing_vni) {
        printf("Error: VNI %u is already mapped to VLAN %u\n", vni_id, existing_vni->vlan_id);
        return false; /* VNI already mapped to different VLAN */
    }
    
    /* Create new mapping */
    vxlan_vni_mapping_t *mapping = (vxlan_vni_mapping_t *)XCALLOC2(0, 1, vxlan_vni_mapping_t);
    mapping->vlan_id = vlan_id;
    mapping->vni_id = vni_id;
    
    init_glthread(&mapping->glue);
    glthread_add_next(&vlan_vni_db->mappings, &mapping->glue);

    /* Add to hashtable atomically */
    //vlan_vni_ht_add_mapping(node, vlan_id, vni_id);
    
    return true;
}

bool
vlan_vni_remove_mapping(node_t *node, vlan_id_t vlan_id) {
    
    vxlan_vni_db_t *vlan_vni_db = NODE_VLAN_VNI_DB(node);
    if (!vlan_vni_db) return false;
    
    vxlan_vni_mapping_t *mapping = vlan_vni_lookup(vlan_vni_db, vlan_id);
    if (!mapping) return false;
    
    remove_glthread(&mapping->glue);
    XFREE(mapping);
    
    /* Remove from hashtable atomically */
    //vlan_vni_ht_remove_mapping(node, vlan_id);
    
    return true;
}

void
clear_vlan_vni_db(vxlan_vni_db_t *vlan_vni_db) {
    
    if (!vlan_vni_db) return;
    
    glthread_t *curr;
    vxlan_vni_mapping_t *mapping;
    
    ITERATE_GLTHREAD_BEGIN(&vlan_vni_db->mappings, curr) {
        mapping = vxlan_vni_glue_to_mapping(curr);
        remove_glthread(curr);
        XFREE(mapping);
    } ITERATE_GLTHREAD_END(&vlan_vni_db->mappings, curr);
}

uint32_t
vlan_to_vni_lookup(node_t *node, vlan_id_t vlan_id) {
    
    vxlan_vni_db_t *vlan_vni_db = NODE_VLAN_VNI_DB(node);
    if (!vlan_vni_db) return 0;
    
    vxlan_vni_mapping_t *mapping = vlan_vni_lookup(vlan_vni_db, vlan_id);
    return mapping ? mapping->vni_id : 0;
}

vlan_id_t
vni_to_vlan_lookup(node_t *node, uint32_t vni_id) {
    
    vxlan_vni_db_t *vlan_vni_db = NODE_VLAN_VNI_DB(node);
    if (!vlan_vni_db) return 0;
    if (!vni_id) return 0;
    
    glthread_t *curr;
    vxlan_vni_mapping_t *mapping;
    
    ITERATE_GLTHREAD_BEGIN(&vlan_vni_db->mappings, curr) {
        mapping = vxlan_vni_glue_to_mapping(curr);
        if (mapping->vni_id == vni_id) {
            return mapping->vlan_id;
        }
    } ITERATE_GLTHREAD_END(&vlan_vni_db->mappings, curr);
    
    return 0;
}
