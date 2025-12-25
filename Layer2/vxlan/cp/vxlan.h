#ifndef __VXLAN_H__
#define __VXLAN_H__

#include "../../layer2.h"
#include "../../../router_init.h"
#include "../../../gluethread/glthread.h"

/* Forward declarations */
typedef struct node_ node_t;
typedef uint16_t vlan_id_t;

/* VLAN-VNI Mapping Data Structures */
typedef struct vxlan_vni_mapping_ {
    glthread_t glue;
    uint32_t vni_id;
    vlan_id_t vlan_id;
} __attribute__((aligned(8))) vxlan_vni_mapping_t;

GLTHREAD_TO_STRUCT(vxlan_vni_glue_to_mapping, vxlan_vni_mapping_t, glue);

typedef struct vxlan_vni_db_ {
    glthread_t mappings;
} __attribute__((aligned(8))) vxlan_vni_db_t;

/* VLAN-VNI Management APIs */
void init_vlan_vni_db(vxlan_vni_db_t **vlan_vni_db);
vxlan_vni_mapping_t *vlan_vni_lookup(vxlan_vni_db_t *vlan_vni_db, vlan_id_t vlan_id);
vxlan_vni_mapping_t *vlan_vni_lookup_by_vni(vxlan_vni_db_t *vlan_vni_db, uint32_t vni_id);
bool vlan_vni_add_mapping(node_t *node, vlan_id_t vlan_id, uint32_t vni_id);
bool vlan_vni_remove_mapping(node_t *node, vlan_id_t vlan_id);
void clear_vlan_vni_db(vxlan_vni_db_t *vlan_vni_db);
uint32_t vlan_to_vni_lookup(node_t *node, vlan_id_t vlan_id);
vlan_id_t vni_to_vlan_lookup(node_t *node, uint32_t vni_id);

#endif /* __VXLAN_H__ */
