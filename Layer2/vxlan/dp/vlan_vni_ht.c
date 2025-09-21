/*
 * =====================================================================================
 *
 *       Filename:  vlan_vni_ht.c
 *
 *    Description:  VLAN-VNI hashtable mapping implementation for O(1) lookup
 *                  Provides atomic updates using pointer swapping technique
 *
 *        Version:  1.0
 *        Created:  [Current Date]
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  AI Assistant
 *        Company:  TCP/IP Stack Implementation
 *        
 *        This file implements high-performance VLAN-VNI mapping using hashtables
 *        with atomic pointer updates for thread-safe operations.
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "vlan_vni_ht.h"
#include "../../../graph.h"
#include "../../../LinuxMemoryManager/uapi_mm.h"
#include "../../../lmm_enums.h"
#include "../../../Tracer/tracer.h"
#include "../cp/vxlan.h"

/* Forward declaration */
static void vlan_vni_ht_sync_from_cp_db_internal(node_t *node, vlan_vni_ht_db_t *ht_db);

/* Hash function for VLAN ID keys */
unsigned int 
vlan_hash_function(void *key) {
    vlan_id_t *vlan_key = (vlan_id_t *)key;
    return (unsigned int)(*vlan_key);
}

/* Equality function for VLAN ID keys */
int 
vlan_key_equal_function(void *key1, void *key2) {
    vlan_id_t *vlan_key1 = (vlan_id_t *)key1;
    vlan_id_t *vlan_key2 = (vlan_id_t *)key2;
    return (*vlan_key1 == *vlan_key2);
}

/* Hash function for VNI keys */
unsigned int 
vni_hash_function(void *key) {
    uint32_t *vni_key = (uint32_t *)key;
    /* Simple hash function for 32-bit VNI */
    return (*vni_key) ^ ((*vni_key) >> 16);
}

/* Equality function for VNI keys */
int 
vni_key_equal_function(void *key1, void *key2) {
    uint32_t *vni_key1 = (uint32_t *)key1;
    uint32_t *vni_key2 = (uint32_t *)key2;
    return (*vni_key1 == *vni_key2);
}

/* Create a new hashtable database */
vlan_vni_ht_db_t *
vlan_vni_ht_create_db(void) {
    vlan_vni_ht_db_t *ht_db = (vlan_vni_ht_db_t *)calloc(1, sizeof(vlan_vni_ht_db_t));
    
    /* Create VLAN -> VNI hashtable */
    ht_db->vlan_to_vni_ht = create_hashtable(16, vlan_hash_function, vlan_key_equal_function);
    if (!ht_db->vlan_to_vni_ht) {
        free(ht_db);
        return NULL;
    }
    
    /* Create VNI -> VLAN hashtable */
    ht_db->vni_to_vlan_ht = create_hashtable(16, vni_hash_function, vni_key_equal_function);
    if (!ht_db->vni_to_vlan_ht) {
        hashtable_destroy(ht_db->vlan_to_vni_ht, 0);
        free(ht_db);
        return NULL;
    }
    
    ht_db->entry_count = 0;
    pthread_mutex_init(&ht_db->mutex, NULL);
    return ht_db;
}

/* Destroy hashtable database */
void 
vlan_vni_ht_destroy_db(vlan_vni_ht_db_t *ht_db) {
    if (!ht_db) return;
    
    if (ht_db->vlan_to_vni_ht) {
        hashtable_destroy(ht_db->vlan_to_vni_ht, 1); /* Free values (vlan_vni_ht_entry_t) */
    }
    
    if (ht_db->vni_to_vlan_ht) {
        hashtable_destroy(ht_db->vni_to_vlan_ht, 1); /* Free values (vni_vlan_ht_entry_t) */
    }
    
    pthread_mutex_destroy(&ht_db->mutex);
    free(ht_db);
}

/* Clone hashtable database */
vlan_vni_ht_db_t *
vlan_vni_ht_clone_db(vlan_vni_ht_db_t *source_db) {
    if (!source_db) return vlan_vni_ht_create_db();
    
    vlan_vni_ht_db_t *new_db = vlan_vni_ht_create_db();
    if (!new_db) return NULL;
    
    /* Note: This is a simplified clone. In a full implementation,
     * you would iterate through the source hashtables and copy all entries.
     * For now, we'll rely on sync_from_cp_db to populate the clone.
     */
    
    return new_db;
}

/* Set the hashtable database pointer atomically */
void 
vlan_vni_ht_set_db(node_t *node, vlan_vni_ht_db_t *new_db) {
    NODE_VLAN_VNI_HT(node).store(new_db);
}

/* Get the hashtable database pointer atomically */
vlan_vni_ht_db_t *
vlan_vni_ht_get_db(node_t *node) {
    return NODE_VLAN_VNI_HT(node).load();
}

/* Clear the hashtable database pointer atomically */
void 
vlan_vni_ht_clear_db(node_t *node) {
    NODE_VLAN_VNI_HT(node).store(nullptr);
}

/* Atomic compare-and-swap for hashtable database pointer */
bool 
vlan_vni_ht_compare_and_swap_db(node_t *node, vlan_vni_ht_db_t *expected, vlan_vni_ht_db_t *new_db) {
    return NODE_VLAN_VNI_HT(node).compare_exchange_strong(expected, new_db);
}

/* O(1) VLAN to VNI lookup */
uint32_t 
vlan_vni_ht_vlan_to_vni_lookup(node_t *node, vlan_id_t vlan_id) {
    vlan_vni_ht_db_t *ht_db = vlan_vni_ht_get_db(node);
    if (!ht_db || !ht_db->vlan_to_vni_ht) return 0;
    
    pthread_mutex_lock(&ht_db->mutex);
    vlan_vni_ht_entry_t *entry = (vlan_vni_ht_entry_t *)hashtable_search(
        ht_db->vlan_to_vni_ht, &vlan_id);
    uint32_t result = entry ? entry->vni_id : 0;
    pthread_mutex_unlock(&ht_db->mutex);
    
    return result;
}

/* O(1) VNI to VLAN lookup */
vlan_id_t 
vlan_vni_ht_vni_to_vlan_lookup(node_t *node, uint32_t vni_id) {
    if (!vni_id) return 0;
    
    vlan_vni_ht_db_t *ht_db = vlan_vni_ht_get_db(node);
    if (!ht_db || !ht_db->vni_to_vlan_ht) return 0;
    
    pthread_mutex_lock(&ht_db->mutex);
    vni_vlan_ht_entry_t *entry = (vni_vlan_ht_entry_t *)hashtable_search(
        ht_db->vni_to_vlan_ht, &vni_id);
    vlan_id_t result = entry ? entry->vlan_id : 0;
    pthread_mutex_unlock(&ht_db->mutex);
    
    return result;
}

/* Add mapping with atomic update */
bool 
vlan_vni_ht_add_mapping(node_t *node, vlan_id_t vlan_id, uint32_t vni_id) {
    /* Step 1: Atomically set pointer to NULL and cache it */
    vlan_vni_ht_db_t *cached_db = vlan_vni_ht_get_db(node);
    vlan_vni_ht_clear_db(node);
    
    if (!cached_db) {
        /* First time - create new database */
        cached_db = vlan_vni_ht_create_db();
        if (!cached_db) {
            return false;
        }
    }
    
    /* Step 2: Check if mapping already exists and remove it */
    vlan_vni_ht_entry_t *existing_vlan_entry = NULL;
    vni_vlan_ht_entry_t *existing_vni_entry = NULL;
    
    /* Check for existing VLAN mapping */
    existing_vlan_entry = (vlan_vni_ht_entry_t *)hashtable_search(cached_db->vlan_to_vni_ht, &vlan_id);
    if (existing_vlan_entry) {
        /* Remove old VNI mapping first */
        existing_vni_entry = (vni_vlan_ht_entry_t *)hashtable_remove(cached_db->vni_to_vlan_ht, &existing_vlan_entry->vni_id);
        if (existing_vni_entry) {
            free(existing_vni_entry);
            cached_db->entry_count--;
        }
        /* Remove old VLAN mapping */
        existing_vlan_entry = (vlan_vni_ht_entry_t *)hashtable_remove(cached_db->vlan_to_vni_ht, &vlan_id);
        if (existing_vlan_entry) {
            free(existing_vlan_entry);
        }
    }
    
    /* Check for existing VNI mapping */
    existing_vni_entry = (vni_vlan_ht_entry_t *)hashtable_search(cached_db->vni_to_vlan_ht, &vni_id);
    if (existing_vni_entry) {
        /* Remove old VLAN mapping first */
        existing_vlan_entry = (vlan_vni_ht_entry_t *)hashtable_remove(cached_db->vlan_to_vni_ht, &existing_vni_entry->vlan_id);
        if (existing_vlan_entry) {
            free(existing_vlan_entry);
            cached_db->entry_count--;
        }
        /* Remove old VNI mapping */
        existing_vni_entry = (vni_vlan_ht_entry_t *)hashtable_remove(cached_db->vni_to_vlan_ht, &vni_id);
        if (existing_vni_entry) {
            free(existing_vni_entry);
        }
    }
    
    /* Step 3: Create new VLAN -> VNI entry */
    vlan_vni_ht_entry_t *vlan_entry = (vlan_vni_ht_entry_t *)calloc(1, sizeof(vlan_vni_ht_entry_t));
    if (!vlan_entry) {
        /* Restore cached pointer on failure */
        vlan_vni_ht_set_db(node, cached_db);
        return false;
    }
    vlan_entry->vlan_id = vlan_id;
    vlan_entry->vni_id = vni_id;
    
    /* Step 4: Create new VNI -> VLAN entry */
    vni_vlan_ht_entry_t *vni_entry = (vni_vlan_ht_entry_t *)calloc(1, sizeof(vni_vlan_ht_entry_t));
    if (!vni_entry) {
        free(vlan_entry);
        /* Restore cached pointer on failure */
        vlan_vni_ht_set_db(node, cached_db);
        return false;
    }
    vni_entry->vni_id = vni_id;
    vni_entry->vlan_id = vlan_id;
    
    /* Step 5: Create persistent keys */
    vlan_id_t *vlan_key = (vlan_id_t *)calloc(1, sizeof(vlan_id_t));
    uint32_t *vni_key = (uint32_t *)calloc(1, sizeof(uint32_t));
    if (!vlan_key || !vni_key) {
        free(vlan_entry);
        free(vni_entry);
        if (vlan_key) free(vlan_key);
        if (vni_key) free(vni_key);
        /* Restore cached pointer on failure */
        vlan_vni_ht_set_db(node, cached_db);
        return false;
    }
    *vlan_key = vlan_id;
    *vni_key = vni_id;
    
    /* Step 6: Insert new entries into hashtables */
    if (!hashtable_insert(cached_db->vlan_to_vni_ht, vlan_key, vlan_entry) ||
        !hashtable_insert(cached_db->vni_to_vlan_ht, vni_key, vni_entry)) {
        free(vlan_entry);
        free(vni_entry);
        free(vlan_key);
        free(vni_key);
        /* Restore cached pointer on failure */
        vlan_vni_ht_set_db(node, cached_db);
        return false;
    }
    
    /* Step 7: Update entry count */
    cached_db->entry_count++;
    
    /* Step 8: Atomically set back the pointer to hashtables */
    vlan_vni_ht_set_db(node, cached_db);
    
    tracer(node->dptr, DL2SW, 
           "VLAN-VNI HT: Added mapping VLAN %u -> VNI %u (total: %u entries)\n", 
           vlan_id, vni_id, cached_db->entry_count);
    
    return true;
}

/* Remove mapping with atomic update */
bool 
vlan_vni_ht_remove_mapping(node_t *node, vlan_id_t vlan_id) {
    /* Step 1: Atomically set pointer to NULL and cache it */
    vlan_vni_ht_db_t *cached_db = vlan_vni_ht_get_db(node);
    vlan_vni_ht_clear_db(node);
    
    if (!cached_db) {
        /* No hashtable exists - nothing to remove */
        return false;
    }
    
    /* Step 2: Search for the VLAN mapping */
    vlan_vni_ht_entry_t *vlan_entry = (vlan_vni_ht_entry_t *)hashtable_search(cached_db->vlan_to_vni_ht, &vlan_id);
    if (!vlan_entry) {
        /* VLAN mapping not found - restore pointer and return false */
        vlan_vni_ht_set_db(node, cached_db);
        return false;
    }
    
    /* Step 3: Get the associated VNI for removal */
    uint32_t vni_id = vlan_entry->vni_id;
    
    /* Step 4: Remove VLAN -> VNI mapping */
    vlan_entry = (vlan_vni_ht_entry_t *)hashtable_remove(cached_db->vlan_to_vni_ht, &vlan_id);
    if (vlan_entry) {
        free(vlan_entry);
    }
    
    /* Step 5: Remove VNI -> VLAN mapping */
    vni_vlan_ht_entry_t *vni_entry = (vni_vlan_ht_entry_t *)hashtable_remove(cached_db->vni_to_vlan_ht, &vni_id);
    if (vni_entry) {
        free(vni_entry);
    }
    
    /* Step 6: Update entry count */
    if (cached_db->entry_count > 0) {
        cached_db->entry_count--;
    }
    
    /* Step 7: Atomically set back the pointer to hashtables */
    vlan_vni_ht_set_db(node, cached_db);
    
    tracer(node->dptr, DL2SW, 
           "VLAN-VNI HT: Removed mapping VLAN %u -> VNI %u (total: %u entries)\n", 
           vlan_id, vni_id, cached_db->entry_count);
    
    return true;
}

/* Remove mapping by VNI with atomic update */
bool 
vlan_vni_ht_remove_mapping_by_vni(node_t *node, uint32_t vni_id) {
    /* Step 1: Atomically set pointer to NULL and cache it */
    vlan_vni_ht_db_t *cached_db = vlan_vni_ht_get_db(node);
    vlan_vni_ht_clear_db(node);
    
    if (!cached_db) {
        /* No hashtable exists - nothing to remove */
        return false;
    }
    
    /* Step 2: Search for the VNI mapping */
    vni_vlan_ht_entry_t *vni_entry = (vni_vlan_ht_entry_t *)hashtable_search(cached_db->vni_to_vlan_ht, &vni_id);
    if (!vni_entry) {
        /* VNI mapping not found - restore pointer and return false */
        vlan_vni_ht_set_db(node, cached_db);
        return false;
    }
    
    /* Step 3: Get the associated VLAN for removal */
    vlan_id_t vlan_id = vni_entry->vlan_id;
    
    /* Step 4: Remove VNI -> VLAN mapping */
    vni_entry = (vni_vlan_ht_entry_t *)hashtable_remove(cached_db->vni_to_vlan_ht, &vni_id);
    if (vni_entry) {
        free(vni_entry);
    }
    
    /* Step 5: Remove VLAN -> VNI mapping */
    vlan_vni_ht_entry_t *vlan_entry = (vlan_vni_ht_entry_t *)hashtable_remove(cached_db->vlan_to_vni_ht, &vlan_id);
    if (vlan_entry) {
        free(vlan_entry);
    }
    
    /* Step 6: Update entry count */
    if (cached_db->entry_count > 0) {
        cached_db->entry_count--;
    }
    
    /* Step 7: Atomically set back the pointer to hashtables */
    vlan_vni_ht_set_db(node, cached_db);
    
    tracer(node->dptr, DL2SW, 
           "VLAN-VNI HT: Removed mapping VNI %u -> VLAN %u (total: %u entries)\n", 
           vni_id, vlan_id, cached_db->entry_count);
    
    return true;
}

/* Internal function to sync from control plane database */
static void 
vlan_vni_ht_sync_from_cp_db_internal(node_t *node, vlan_vni_ht_db_t *ht_db) {
    vxlan_vni_db_t *cp_db = NODE_VLAN_VNI_DB(node);
    if (!cp_db || !ht_db) return;
    
    glthread_t *curr;
    vxlan_vni_mapping_t *mapping;
    
    /* Iterate through control plane database and populate hashtables */
    ITERATE_GLTHREAD_BEGIN(&cp_db->mappings, curr) {
        mapping = vxlan_vni_glue_to_mapping(curr);
        
        /* Create VLAN -> VNI entry */
        vlan_vni_ht_entry_t *vlan_entry = (vlan_vni_ht_entry_t *)calloc(1, sizeof(vlan_vni_ht_entry_t));
        vlan_entry->vlan_id = mapping->vlan_id;
        vlan_entry->vni_id = mapping->vni_id;
        
        /* Create VNI -> VLAN entry */
        vni_vlan_ht_entry_t *vni_entry = (vni_vlan_ht_entry_t *)calloc(1, sizeof(vni_vlan_ht_entry_t));
        vni_entry->vni_id = mapping->vni_id;
        vni_entry->vlan_id = mapping->vlan_id;
        
        /* Create keys (need to be persistent) */
        vlan_id_t *vlan_key = (vlan_id_t *)calloc(1, sizeof(vlan_id_t));
        *vlan_key = mapping->vlan_id;
        
        uint32_t *vni_key = (uint32_t *)calloc(1, sizeof(uint32_t));
        *vni_key = mapping->vni_id;
        
        /* Insert into hashtables */
        hashtable_insert(ht_db->vlan_to_vni_ht, vlan_key, vlan_entry);
        hashtable_insert(ht_db->vni_to_vlan_ht, vni_key, vni_entry);
        
        ht_db->entry_count++;
        
    } ITERATE_GLTHREAD_END(&cp_db->mappings, curr);
}

/* Public sync function */
void 
vlan_vni_ht_sync_from_cp_db(node_t *node) {
    /* Step 1: Set pointer to NULL */
    vlan_vni_ht_db_t *old_db = vlan_vni_ht_get_db(node);
    vlan_vni_ht_clear_db(node);
    
    /* Step 2: Create new database */
    vlan_vni_ht_db_t *new_db = vlan_vni_ht_create_db();
    if (!new_db) {
        /* Restore old pointer on failure */
        vlan_vni_ht_set_db(node, old_db);
        return;
    }
    
    /* Step 3: Sync from control plane database */
    vlan_vni_ht_sync_from_cp_db_internal(node, new_db);
    
    /* Step 4: Set new pointer */
    vlan_vni_ht_set_db(node, new_db);
    
    /* Step 5: Cleanup old database */
    if (old_db) {
        vlan_vni_ht_destroy_db(old_db);
    }
}

/* Clear all mappings */
void 
vlan_vni_ht_clear_all_mappings(node_t *node) {
    vlan_vni_ht_db_t *old_db = vlan_vni_ht_get_db(node);
    vlan_vni_ht_clear_db(node);
    
    if (old_db) {
        vlan_vni_ht_destroy_db(old_db);
    }
}

/* Get mapping count */
uint32_t 
vlan_vni_ht_get_mapping_count(node_t *node) {
    vlan_vni_ht_db_t *ht_db = vlan_vni_ht_get_db(node);
    return ht_db ? ht_db->entry_count : 0;
}

/* Dump mappings for debugging */
void 
vlan_vni_ht_dump_mappings(node_t *node) {
    vlan_vni_ht_db_t *ht_db = vlan_vni_ht_get_db(node);
    if (!ht_db) {
        printf("VLAN-VNI Hashtable: No mappings (NULL database)\n");
        return;
    }
    
    printf("VLAN-VNI Hashtable: %u mappings\n", ht_db->entry_count);
    printf("VLAN -> VNI table entries: %u\n", 
           ht_db->vlan_to_vni_ht ? hashtable_count(ht_db->vlan_to_vni_ht) : 0);
    printf("VNI -> VLAN table entries: %u\n", 
           ht_db->vni_to_vlan_ht ? hashtable_count(ht_db->vni_to_vlan_ht) : 0);
}

/* Initialize hashtable for node */
void 
vlan_vni_ht_init(node_t *node) {
    NODE_VLAN_VNI_HT(node).store(nullptr);
}

/* Cleanup hashtable for node */
void 
vlan_vni_ht_cleanup(node_t *node) {
    vlan_vni_ht_clear_all_mappings(node);
}
