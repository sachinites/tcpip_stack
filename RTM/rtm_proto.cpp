#include "rtm_proto.h"
#include "rtm.h"
#include "rtm_error.h"
#include <memory.h>
#include <stdlib.h>
#include <assert.h>

/* ========================================================================
 * NH PROTO (rtm_nh_proto_t) Management Functions
 * ======================================================================== */

/* Create and initialize a new NH protocol info structure */
rtm_error_t
rtm_nh_proto_info_create(rtm_t *rtm,
                         const RTM_PROTO_T proto,
                         const RTM_SUB_PROTO_T sub_proto,
                         const uint32_t inst_no,
                         const uint8_t vrf_id,
                         rtm_nh_proto_t **out) {
    
    if (!rtm || proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    // Check if NH proto info already exists
    rtm_nh_proto_t *existing = rtm_nh_proto_lookup(rtm, proto, sub_proto, inst_no, vrf_id);
    
    if (existing) {
        *out = existing;
        return RTM_ERROR_PROTO_INFO_ALREADY_EXISTS;
    }
    
    // Allocate new NH proto info structure
    rtm_nh_proto_t *nh_proto = (rtm_nh_proto_t *)calloc(1, sizeof(rtm_nh_proto_t));
    
    // Initialize keys
    nh_proto->proto = proto;
    nh_proto->sub_proto = sub_proto;
    nh_proto->instance_no = inst_no;
    nh_proto->vrf_id = vrf_id;
    
    // Initialize the glue node
    memset(&nh_proto->proto_glue, 0, sizeof(avltree_node_t));
    
    // Initialize reference count
    nh_proto->ref_count = 0;
    
    *out = nh_proto;
    return RTM_SUCCESS;
}

/* Compare two NH protocol info structures */
int8_t
rtm_nh_proto_compare(rtm_nh_proto_t *nh_proto1, rtm_nh_proto_t *nh_proto2) {
    
    if (!nh_proto1 || !nh_proto2) {
        return -1;
    }
    
    // Compare by VRF first
    if (nh_proto1->vrf_id < nh_proto2->vrf_id) return -1;
    if (nh_proto1->vrf_id > nh_proto2->vrf_id) return 1;
    
    // Then by protocol type
    if (nh_proto1->proto < nh_proto2->proto) return -1;
    if (nh_proto1->proto > nh_proto2->proto) return 1;
    
    // Then by sub-protocol
    if (nh_proto1->sub_proto < nh_proto2->sub_proto) return -1;
    if (nh_proto1->sub_proto > nh_proto2->sub_proto) return 1;
    
    // Finally by instance number
    if (nh_proto1->instance_no < nh_proto2->instance_no) return -1;
    if (nh_proto1->instance_no > nh_proto2->instance_no) return 1;
    
    return 0;
}

/* Add NH protocol info to RTM */
rtm_error_t
rtm_nh_proto_add (rtm_t *rtm, rtm_nh_proto_t *nh_proto) {
    
    if (!rtm || !nh_proto) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    if (nh_proto->proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    rtm_nh_proto_t *existing = rtm_nh_proto_lookup(rtm, 
                                                    nh_proto->proto, 
                                                    nh_proto->sub_proto,
                                                    nh_proto->instance_no,
                                                    nh_proto->vrf_id);
    
    if (existing) {
        return RTM_ERROR_PROTO_INFO_ALREADY_EXISTS;
    }
    
    if (avltree_insert(&nh_proto->proto_glue, 
                       &rtm->nh_proto_info_tree)) {
	return RTM_ERROR_CONTAINER_INSERTION_FAILED;
    }
    
    rtm_nh_proto_reference(nh_proto);
    
    return RTM_SUCCESS;
}

static void
rtm_nh_proto_del(rtm_t *rtm, rtm_nh_proto_t *nh_proto) {

    assert(nh_proto->ref_count == 1);
    avltree_remove(&nh_proto->proto_glue, &rtm->nh_proto_info_tree);
    nh_proto->ref_count--;
    free (nh_proto);
}

rtm_nh_proto_t *
rtm_nh_proto_lookup(const rtm_t *rtm, 
                    const RTM_PROTO_T proto,
                    const RTM_SUB_PROTO_T sub_proto,
                    const uint32_t inst_no,
                    const uint8_t vrf_id) {
    
    if (!rtm || proto >= RTM_PROTO_MAX) {
        return NULL;
    }
    
    if (avltree_is_empty((avltree_t*)&rtm->nh_proto_info_tree)) {
        return NULL;
    }
    
    rtm_nh_proto_t temp_nh_proto;
    memset(&temp_nh_proto, 0, sizeof(rtm_nh_proto_t));
    temp_nh_proto.proto = proto;
    temp_nh_proto.sub_proto = sub_proto;
    temp_nh_proto.instance_no = inst_no;
    temp_nh_proto.vrf_id = vrf_id;
    
    avltree_node_t *node = avltree_lookup(&temp_nh_proto.proto_glue, 
                                         (avltree_t*)&rtm->nh_proto_info_tree);
    
    if (!node) {
        return NULL;
    }
    
    return avltree_container_of(node, rtm_nh_proto_t, proto_glue);
}

/* Increment NH protocol info reference count */
void
rtm_nh_proto_reference(rtm_nh_proto_t *nh_proto) {
    
    nh_proto->ref_count++;
}

/* Decrement NH protocol info reference count and free if necessary */
void
rtm_nh_proto_dereference(rtm_t *rtm, rtm_nh_proto_t *nh_proto) {
    
    assert(nh_proto->ref_count > 0);
    nh_proto->ref_count--;
    if (nh_proto->ref_count > 1) return;
    rtm_nh_proto_del(rtm, nh_proto);
}



/* ========================================================================
 * PROTO INFO (rtm_proto_info_t) Management Functions
 * ======================================================================== */

/* Create and initialize a new protocol info structure */
rtm_proto_info_t *
rtm_proto_info_create(rtm_t *rtm, RTM_PROTO_T proto, uint32_t inst_no) {
    
    if (!rtm || proto >= RTM_PROTO_MAX) {
        return NULL;
    }
    
    // Check if protocol info already exists
    rtm_proto_info_t *existing = rtm_proto_lookup(rtm, proto, inst_no);
    
    if (existing) {
        return existing;
    }
    
    // Allocate new protocol info structure
    rtm_proto_info_t *proto_info = (rtm_proto_info_t *)calloc(1, sizeof(rtm_proto_info_t));

    // Initialize keys
    proto_info->proto = proto;
    proto_info->instance_no = inst_no;
    proto_info->vrf_id = rtm->vrf;
    
    // Initialize the glue node
    memset(&proto_info->proto_glue, 0, sizeof(avltree_node_t));
    
    return proto_info;
}

/* Compare two protocol info structures */
int8_t
rtm_proto_compare(rtm_proto_info_t* proto1, rtm_proto_info_t* proto2) {
    
    if (!proto1 || !proto2) {
        return -1;
    }
    
    // Compare by VRF first
    if (proto1->vrf_id < proto2->vrf_id) return -1;
    if (proto1->vrf_id > proto2->vrf_id) return 1;
    
    // Then by protocol type
    if (proto1->proto < proto2->proto) return -1;
    if (proto1->proto > proto2->proto) return 1;
    
    // Finally by instance number
    if (proto1->instance_no < proto2->instance_no) return -1;
    if (proto1->instance_no > proto2->instance_no) return 1;
    
    return 0;
}

/* Add protocol info to RTM */
rtm_error_t 
rtm_proto_info_add(const rtm_t* rtm, rtm_proto_info_t* proto_info) {
    
    if (!rtm || !proto_info) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    // Validate protocol type
    if (proto_info->proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    // Check if protocol info already exists
    rtm_proto_info_t *existing = rtm_proto_lookup(rtm, proto_info->proto, proto_info->instance_no);

    if (existing) {
        return RTM_ERROR_PROTO_INFO_ALREADY_EXISTS;
    }
    
    // Get the appropriate protocol info tree
    avltree_t *proto_tree = (avltree_t*)&rtm->proto_info_tree[proto_info->proto];
    
    // Insert into protocol info tree
    if (avltree_insert(&proto_info->proto_glue, proto_tree)) {
        return RTM_ERROR_CONTAINER_INSERTION_FAILED;
    }
    
    return RTM_SUCCESS;
}

/* Delete protocol info from RTM */
rtm_error_t 
rtm_proto_info_del(const rtm_t* rtm, RTM_PROTO_T proto, uint32_t inst_no) {
    
    if (!rtm) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    // Validate protocol type
    if (proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    // Find the protocol info
    rtm_proto_info_t *proto_info = rtm_proto_lookup(rtm, proto, inst_no);
    if (!proto_info) {
        return RTM_ERROR_CONTAINER_LOOKUP_FAILED;
    }
    
    // Get the appropriate protocol info tree
    avltree_t *proto_tree = (avltree_t*)&rtm->proto_info_tree[proto];
    
    // Remove from protocol info tree
    avltree_remove(&proto_info->proto_glue, proto_tree);
    
    // Free the protocol info
    free(proto_info);
    
    return RTM_SUCCESS;
}

/* Lookup protocol info in RTM */
rtm_proto_info_t *
rtm_proto_lookup(const rtm_t* rtm, RTM_PROTO_T proto, uint32_t inst_no) {
    
    if (!rtm || proto >= RTM_PROTO_MAX) {
        return NULL;
    }
    
    // Get the appropriate protocol info tree
    avltree_t *proto_tree = (avltree_t*)&rtm->proto_info_tree[proto];
    
    // Check if tree is empty
    if (avltree_is_empty(proto_tree)) {
        return NULL;
    }
    
    // Create a temporary protocol info for lookup
    rtm_proto_info_t temp_proto_info;
    memset(&temp_proto_info, 0, sizeof(rtm_proto_info_t));
    temp_proto_info.proto = proto;
    temp_proto_info.instance_no = inst_no;
    temp_proto_info.vrf_id = rtm->vrf;
    
    // Look up in the protocol info tree
    avltree_node_t *node = avltree_lookup(&temp_proto_info.proto_glue, proto_tree);
    
    if (!node) {
        return NULL;
    }
    
    return avltree_container_of(node, rtm_proto_info_t, proto_glue);
}
