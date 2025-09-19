#ifndef __VXLAN_DP_H__
#define __VXLAN_DP_H__

#include "../../layer2.h"
#include "../../../gluethread/glthread.h"

/* Forward declarations */
typedef struct node_ node_t;
typedef struct mac_table_ mac_table_t;

/* VNI MAC Table Data Structures */
typedef struct vni_mac_table_entry_ {
    uint32_t vni_id;
    mac_table_t *mac_table;
    glthread_t glue;
} vni_mac_table_entry_t;

GLTHREAD_TO_STRUCT(vni_mac_table_glue_to_entry, vni_mac_table_entry_t, glue);

typedef struct vni_mac_table_db_ {
    glthread_t vni_mac_tables;
} vni_mac_table_db_t;

/* VNI MAC Table Management APIs */
void init_vni_mac_table_db(vni_mac_table_db_t **vni_mac_table_db);
vni_mac_table_entry_t *vni_mac_table_lookup(vni_mac_table_db_t *vni_mac_table_db, uint32_t vni_id);
mac_table_t *get_vni_mac_table(node_t *node, uint32_t vni_id);
bool create_vni_mac_table(node_t *node, uint32_t vni_id);
bool delete_vni_mac_table(node_t *node, uint32_t vni_id);
void clear_vni_mac_table_db(vni_mac_table_db_t *vni_mac_table_db);
void dump_vni_mac_table(node_t *node, uint32_t vni_id);

#endif /* __VXLAN_DP_H__ */
