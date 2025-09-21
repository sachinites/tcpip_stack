/*
 * =====================================================================================
 *
 *       Filename:  vlan_vni_ht.h
 *
 *    Description:  VLAN-VNI hashtable mapping for O(1) lookup performance
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

#ifndef __VLAN_VNI_HT_H__
#define __VLAN_VNI_HT_H__

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>
#include "../../../utils.h"
#include "../../../c-hashtable/hashtable.h"

/* Forward declarations */
typedef struct node_ node_t;
typedef uint16_t vlan_id_t;

/* VLAN-VNI mapping entry for hashtable */
typedef struct vlan_vni_ht_entry_ {
    vlan_id_t vlan_id;
    uint32_t vni_id;
} vlan_vni_ht_entry_t;

/* VNI-VLAN mapping entry for reverse lookup hashtable */
typedef struct vni_vlan_ht_entry_ {
    uint32_t vni_id;
    vlan_id_t vlan_id;
} vni_vlan_ht_entry_t;

/* Hashtable database structure containing both forward and reverse mappings */
typedef struct vlan_vni_ht_db_ {
    hashtable_t *vlan_to_vni_ht;    /* VLAN -> VNI mapping */
    hashtable_t *vni_to_vlan_ht;    /* VNI -> VLAN mapping */
    uint32_t entry_count;           /* Number of active mappings */
    pthread_mutex_t mutex;          /* Mutex for thread-safe access */
} vlan_vni_ht_db_t;

/* Hash functions for VLAN and VNI keys */
unsigned int vlan_hash_function(void *key);
int vlan_key_equal_function(void *key1, void *key2);
unsigned int vni_hash_function(void *key);
int vni_key_equal_function(void *key1, void *key2);

/* Hashtable database management functions */
vlan_vni_ht_db_t *vlan_vni_ht_create_db(void);
void vlan_vni_ht_destroy_db(vlan_vni_ht_db_t *ht_db);
vlan_vni_ht_db_t *vlan_vni_ht_clone_db(vlan_vni_ht_db_t *source_db);

/* Thread-safe hashtable pointer management */
void vlan_vni_ht_set_db(node_t *node, vlan_vni_ht_db_t *new_db);
vlan_vni_ht_db_t *vlan_vni_ht_get_db(node_t *node);
void vlan_vni_ht_clear_db(node_t *node);
bool vlan_vni_ht_compare_and_swap_db(node_t *node, vlan_vni_ht_db_t *expected, vlan_vni_ht_db_t *new_db);

/* O(1) lookup functions */
uint32_t vlan_vni_ht_vlan_to_vni_lookup(node_t *node, vlan_id_t vlan_id);
vlan_id_t vlan_vni_ht_vni_to_vlan_lookup(node_t *node, uint32_t vni_id);

/* Mapping management functions with atomic updates */
bool vlan_vni_ht_add_mapping(node_t *node, vlan_id_t vlan_id, uint32_t vni_id);
bool vlan_vni_ht_remove_mapping(node_t *node, vlan_id_t vlan_id);
bool vlan_vni_ht_remove_mapping_by_vni(node_t *node, uint32_t vni_id);

/* Database synchronization with control plane */
void vlan_vni_ht_sync_from_cp_db(node_t *node);
void vlan_vni_ht_clear_all_mappings(node_t *node);

/* Utility functions */
uint32_t vlan_vni_ht_get_mapping_count(node_t *node);
void vlan_vni_ht_dump_mappings(node_t *node);

/* Initialization and cleanup */
void vlan_vni_ht_init(node_t *node);
void vlan_vni_ht_cleanup(node_t *node);

/* Macros for accessing node hashtable database */
#define NODE_VLAN_VNI_HT(node_ptr) \
    ((node_ptr)->node_nw_prop.vlan_vni_ht)

#endif /* __VLAN_VNI_HT_H__ */
