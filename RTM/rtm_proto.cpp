#include <memory.h>
#include <stdlib.h>
#include <assert.h>
#include "../graph.h"
#include "rtm_proto.h"
#include "rtm.h"
#include "rtm_error.h"
#include "../lmm_enums.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "rtm_presentation.h"
#include "../Tracer/tracer.h"

/* ========================================================================
 * NH PROTO (rtm_nh_proto_t) Management Functions
 * ======================================================================== */

static int 
rtm_subscription_db_compare_fn(
        const avltree_node_t *node1, const avltree_node_t *node2) {
    
    rtm_rt_subscription_t *sub1 = avltree_container_of(node1, rtm_rt_subscription_t, avl_glue);
    rtm_rt_subscription_t *sub2 = avltree_container_of(node2, rtm_rt_subscription_t, avl_glue);
    
    if (sub1->target_proto < sub2->target_proto) return -1;
    if (sub1->target_proto > sub2->target_proto) return 1;
    
    if (sub1->target_sub_proto < sub2->target_sub_proto) return -1;
    if (sub1->target_sub_proto > sub2->target_sub_proto) return 1;

    if (sub1->target_instance_no < sub2->target_instance_no) return -1;
    if (sub1->target_instance_no > sub2->target_instance_no) return 1;

    return 0;
}

/* Create and initialize a new NH protocol info structure */
rtm_error_t
rtm_nh_proto_info_create(
                         const RTM_PROTO_T proto,
                         const RTM_SUB_PROTO_T sub_proto,
                         const uint32_t inst_no,
                         const uint8_t vrf_id,
                         rtm_nh_proto_t **out) {
    
    if (proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    // Allocate new NH proto info structure
    rtm_nh_proto_t *nh_proto = (rtm_nh_proto_t *)XCALLOC2(0, 1, rtm_nh_proto_t);
    
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
rtm_nh_proto_add (rtm_t *rtm, 
                            rtm_nh_proto_t *nh_proto, 
                            rtm_nh_proto_t **existing_nh_proto_out) {
    
    if (!rtm || !nh_proto) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    if (nh_proto->proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    rtm_nh_proto_t *existing = rtm_nh_proto_lookup(
                                                    rtm, nh_proto);
    
    *existing_nh_proto_out = NULL;

    if (existing) {
        *existing_nh_proto_out = existing;
        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : NH Proto Info already exists Proto=%s SubProto=%s Inst=%u ref_count=%u\n",
            rtm->name,
            rtm_proto_to_string(nh_proto->proto),
            rtm_sub_proto_to_string(nh_proto->sub_proto),
            nh_proto->instance_no,
            existing->ref_count);
        return  RTM_ERROR_NEXTHOP_PROTO_ALREADY_EXISTS;
    }
    
    if (avltree_insert(&nh_proto->proto_glue, 
                       &rtm->nh_proto_info_tree)) {
                        
	    return RTM_ERROR_CONTAINER_INSERTION_FAILED;
    }
    
    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : NH Proto Info added Proto=%s SubProto=%s Inst=%u VRF=%u\n",
        rtm->name,
        rtm_proto_to_string(nh_proto->proto),
        rtm_sub_proto_to_string(nh_proto->sub_proto),
        nh_proto->instance_no,
        nh_proto->vrf_id);
    
    //rtm_nh_proto_reference(nh_proto);
    return RTM_SUCCESS;
}

rtm_nh_proto_t *
rtm_nh_proto_lookup(const rtm_t *rtm, 
                    rtm_nh_proto_t *nh_proto_template) {
    
    if (avltree_is_empty((avltree_t*)&rtm->nh_proto_info_tree)) {
        return NULL;
    }
    
    avltree_node_t *node = avltree_lookup(&nh_proto_template->proto_glue, 
                                         (avltree_t*)&rtm->nh_proto_info_tree);
    
    if (!node) return NULL;
    
    return avltree_container_of(node, rtm_nh_proto_t, proto_glue);
}

/* Increment NH protocol info reference count */
void
rtm_nh_proto_reference(rtm_nh_proto_t *nh_proto) {
    
    nh_proto->ref_count++;
    
    /* Note: We don't have rtm context here, so we can't trace with RTM name */
}

static void 
rtm_nh_proto_release_all_resources(rtm_t *rtm, rtm_nh_proto_t *nh_proto) {

    /* Nothing to release */
}

static void 
rtm_nh_proto_check_and_delete (rtm_t *rtm, 
        rtm_nh_proto_t *nh_proto) {

    char proto_str[32];

    rtm_nh_proto_release_all_resources(rtm, nh_proto);
    
    avltree_strict_remove(&nh_proto->proto_glue, &rtm->nh_proto_info_tree);

    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : Deleting NH Proto Info Proto=%s SubProto=%s Inst=%u VRF=%u\n",
        rtm->name,
        rtm_proto_to_string(nh_proto->proto),
        rtm_sub_proto_to_string(nh_proto->sub_proto),
        nh_proto->instance_no,
        nh_proto->vrf_id);
    
    XFREE (nh_proto);
}

void
rtm_nh_proto_dereference (rtm_t *rtm, rtm_nh_proto_t *nh_proto) {

    nh_proto->ref_count--;

    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : NH Proto Info dereferenced Proto=%s SubProto=%s Inst=%u new ref_count=%u\n",
        rtm->name,
        rtm_proto_to_string(nh_proto->proto),
        rtm_sub_proto_to_string(nh_proto->sub_proto),
        nh_proto->instance_no,
        nh_proto->ref_count);

    if (nh_proto->ref_count == 0){
        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : NH Proto Info ref_count=0, initiating deletion Proto=%s SubProto=%s\n",
            rtm->name,
            rtm_proto_to_string(nh_proto->proto),
            rtm_sub_proto_to_string(nh_proto->sub_proto));
        rtm_nh_proto_check_and_delete (rtm, nh_proto);
    }
}

int8_t 
rtm_nh_proto_is_equal (
    rtm_nh_proto_t *nh_proto1,
    rtm_nh_proto_t *nh_proto2) {

    assert (nh_proto1 && nh_proto2);

    if (nh_proto1->proto < nh_proto2->proto) return -1;
    if (nh_proto1->proto > nh_proto2->proto) return 1;

    if (nh_proto1->sub_proto < nh_proto2->sub_proto) return -1;
    if (nh_proto1->sub_proto > nh_proto2->sub_proto) return 1;

    if (nh_proto1->instance_no < nh_proto2->instance_no) return -1;
    if (nh_proto1->instance_no > nh_proto2->instance_no) return 1;

    if (nh_proto1->vrf_id < nh_proto2->vrf_id) return -1;
    if (nh_proto1->vrf_id > nh_proto2->vrf_id) return 1;

    switch (nh_proto1->proto) {
        case RTM_PROTO_STATIC:
            return memcmp (&nh_proto1->u.statc, &nh_proto2->u.statc, sizeof (nh_proto1->u.statc));
        case RTM_PROTO_CONNECTED:
            return memcmp (&nh_proto1->u.connected, &nh_proto2->u.connected, sizeof (nh_proto1->u.connected));
        case RTM_PROTO_LOCAL:
            return memcmp (&nh_proto1->u.local, &nh_proto2->u.local, sizeof (nh_proto1->u.local));
        case RTM_PROTO_ISIS:
            return memcmp (&nh_proto1->u.isis, &nh_proto2->u.isis, sizeof (nh_proto1->u.isis));
        case RTM_PROTO_OSPF:
            return memcmp (&nh_proto1->u.ospf, &nh_proto2->u.ospf, sizeof (nh_proto1->u.ospf));
        case RTM_PROTO_BGP:
            return memcmp (&nh_proto1->u.bgp, &nh_proto2->u.bgp, sizeof (nh_proto1->u.bgp));
        case RTM_PROTO_LDP:
            return memcmp (&nh_proto1->u.ldp, &nh_proto2->u.ldp, sizeof (nh_proto1->u.ldp));
        case RTM_PROTO_SR:
            return memcmp (&nh_proto1->u.sr, &nh_proto2->u.sr, sizeof (nh_proto1->u.sr));
        case RTM_PROTO_SRTE:
            return memcmp (&nh_proto1->u.srte, &nh_proto2->u.srte, sizeof (nh_proto1->u.srte));
        default:
            return 0;
    }

    assert(0);
    return 0;
}


void 
rtm_nh_proto_initialize(rtm_nh_proto_t *nh_proto) {

    memset (nh_proto, 0, sizeof (*nh_proto));
    avltree_node_init(&nh_proto->proto_glue);
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
    rtm_proto_info_t *proto_info = (rtm_proto_info_t *)XCALLOC2(0, 1, rtm_proto_info_t);

    // Initialize keys
    proto_info->proto = proto;
    proto_info->instance_no = inst_no;
    proto_info->vrf_id = rtm->vrf;
    
    // Initialize the glue node
    avltree_node_init (&proto_info->proto_glue);
    avltree_init (&proto_info->sub_db, rtm_subscription_db_compare_fn);
    
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

void 
rtm_nh_proto_copy(rtm_nh_proto_t *src_nh_proto, rtm_nh_proto_t *dst_nh_proto) {

    avltree_node_t avl_node;
    uint32_t ref_count = dst_nh_proto->ref_count;
    memcpy(&avl_node, &dst_nh_proto->proto_glue, sizeof(avltree_node_t));
    memcpy(dst_nh_proto, src_nh_proto, sizeof(rtm_nh_proto_t));
    memcpy (&dst_nh_proto->proto_glue, &avl_node, sizeof(avltree_node_t));
    dst_nh_proto->ref_count = ref_count;
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
    avltree_node_init (&proto_info->proto_glue); 
    // Remove from protocol info tree
    avltree_strict_remove(&proto_info->proto_glue, proto_tree);
    
    // Free the protocol info
    XFREE(proto_info);
    
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
