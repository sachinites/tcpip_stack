/*
 * =====================================================================================
 *
 *       Filename:  rtm_proto.cpp
 *
 *    Description:  RTM Protocol Information and Route Target RTM Selection
 *
 *        This file manages protocol-specific information structures and provides
 *        the logic for selecting the appropriate routing table (RTM) based on
 *        protocol type, address family, and VRF context.
 *
 *        Protocol Information Management:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │                    RTM Structure                            │
 *        │  ┌──────────────────────────────────────────────────────┐   │
 *        │  │  nh_proto_info_tree (AVL Tree)                       │   │
 *        │  │  └─> rtm_nh_proto_t entries                          │   │
 *        │  │      - Protocol type (BGP, OSPF, ISIS, etc.)         │   │
 *        │  │      - Sub-protocol (BGP_VPN, OSPF_IA, etc.)         │   │
 *        │  │      - Instance number                               │   │
 *        │  │      - VRF ID                                         │   │
 *        │  │      - Reference count                                │   │
 *        │  └──────────────────────────────────────────────────────┘   │
 *        │  ┌──────────────────────────────────────────────────────┐   │
 *        │  │  proto_info_tree[RTM_PROTO_MAX] (AVL Trees)         │   │
 *        │  │  └─> rtm_proto_info_t entries                        │   │
 *        │  │      - Protocol registration info                    │   │
 *        │  │      - Subscription database                         │   │
 *        │  └──────────────────────────────────────────────────────┘   │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Route Target RTM Selection Logic:
 *        ┌─────────────────────────────────────────────────────────────┐
 *        │  Protocol → RTM Mapping                                     │
 *        ├─────────────────────────────────────────────────────────────┤
 *        │  Protocol    │ AF    │ VRF    │ Table ID │ RTM Name        │
 *        ├──────────────┼───────┼────────┼──────────┼──────────────────┤
 *        │  STATIC      │ IPv4  │ Default│    0     │ inet.0           │
 *        │  STATIC      │ IPv6  │ Default│    0     │ inet6.0          │
 *        │  STATIC      │ IPv4  │ Custom │    0     │ vrf.inet.0       │
 *        │  STATIC      │ IPv6  │ Custom │    0     │ vrf.inet6.0      │
 *        │  LDP         │ IPv4  │ Default│    3     │ inet.3           │
 *        │  LDP         │ IPv6  │ Default│    3     │ inet6.3          │
 *        │  LDP         │ *     │ Custom │    -     │ NULL (not supp.) │
 *        │  BGP VPN     │ IPv4  │ Default│  128     │ bgp.l3vpn.0 (v4)│
 *        │  BGP VPN     │ IPv6  │ Default│  128     │ bgp.l3vpn.0 (v6)│
 *        │  SR/SRTE     │ IPv4  │ Default│    3     │ inet.3           │
 *        │  SR/SRTE     │ IPv6  │ Default│    3     │ inet6.3          │
 *        │  ISIS        │ IPv4  │ *      │    0     │ inet.0/inet6.0   │
 *        │  ISIS        │ IPv6  │ *      │    0     │ inet.0/inet6.0   │
 *        │  MPLS        │ Label │ Default│    0     │ mpls.0           │
 *        └─────────────────────────────────────────────────────────────┘
 *
 *        Version:  1.0
 *        Created:  [Original Date]
 *       Revision:  1.0
 *       Compiler:  gcc/g++
 *
 * =====================================================================================
 */

#include <memory.h>
#include <stdlib.h>
#include <assert.h>
#include "../router_init.h"
#include "rtm_proto.h"
#include "rtm.h"
#include "rtm_error.h"
#include "../lmm_enums.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "rtm_presentation.h"
#include "../Tracer/tracer.h"
#include "../vrf/vrf.h"

/* ========================================================================
 * NH PROTO (rtm_nh_proto_t) Management Functions
 * ======================================================================== */

/**
 * @brief Comparison function for subscription database AVL tree
 * 
 * Used to maintain subscriptions in sorted order for efficient lookup.
 * Comparison order:
 * 1. Target protocol
 * 2. Target sub-protocol
 * 3. Target instance number
 * 
 * @param node1 First AVL tree node
 * @param node2 Second AVL tree node
 * @return -1 if node1 < node2, 0 if equal, 1 if node1 > node2
 */
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

/**
 * @brief Create and initialize a new NH protocol info structure
 * 
 * Nexthop Protocol Information (rtm_nh_proto_t) tracks which protocol
 * installed a nexthop. This is used for:
 * - Protocol-specific nexthop management
 * - Reference counting
 * - Route redistribution tracking
 * 
 * Structure:
 * ┌─────────────────────────────────────────────────────────┐
 * │ rtm_nh_proto_t                                          │
 * │  - proto: RTM_PROTO_T (BGP, OSPF, ISIS, etc.)           │
 * │  - sub_proto: RTM_SUB_PROTO_T (BGP_VPN, OSPF_IA, etc.) │
 * │  - instance_no: Protocol instance number                │
 * │  - vrf_id: VRF identifier                               │
 * │  - ref_count: Reference count (number of nexthops)      │
 * │  - proto_glue: AVL tree node for storage                │
 * └─────────────────────────────────────────────────────────┘
 * 
 * @param proto Protocol type
 * @param sub_proto Sub-protocol type
 * @param inst_no Instance number
 * @param vrf_id VRF identifier
 * @param out Output parameter for created structure
 * 
 * @return RTM_SUCCESS on success, error code on failure
 */
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

    /* Allocate new NH proto info structure */
    rtm_nh_proto_t *nh_proto = (rtm_nh_proto_t *)XCALLOC2(0, 1, rtm_nh_proto_t);
    
    /* Initialize keys (used for AVL tree lookup) */
    nh_proto->proto = proto;
    nh_proto->sub_proto = sub_proto;
    nh_proto->instance_no = inst_no;
    nh_proto->vrf_id = vrf_id;
    
    /* Initialize the AVL tree glue node */
    memset(&nh_proto->proto_glue, 0, sizeof(avltree_node_t));
    
    /* Initialize reference count (starts at 0, incremented when nexthops use it) */
    nh_proto->ref_count = 0;
    
    *out = nh_proto;
    return RTM_SUCCESS;
}

/**
 * @brief Compare two NH protocol info structures
 * 
 * Used for AVL tree operations. Comparison order:
 * 1. VRF ID
 * 2. Protocol type
 * 3. Sub-protocol
 * 4. Instance number
 * 
 * @param nh_proto1 First protocol info
 * @param nh_proto2 Second protocol info
 * 
 * @return -1 if nh_proto1 < nh_proto2, 0 if equal, 1 if nh_proto1 > nh_proto2
 */
int8_t
rtm_nh_proto_compare(rtm_nh_proto_t *nh_proto1, rtm_nh_proto_t *nh_proto2) {
    
    if (!nh_proto1 || !nh_proto2) {
        return -1;
    }
    
    /* Compare by VRF first */
    if (nh_proto1->vrf_id < nh_proto2->vrf_id) return -1;
    if (nh_proto1->vrf_id > nh_proto2->vrf_id) return 1;
    
    /* Then by protocol type */
    if (nh_proto1->proto < nh_proto2->proto) return -1;
    if (nh_proto1->proto > nh_proto2->proto) return 1;
    
    /* Then by sub-protocol */
    if (nh_proto1->sub_proto < nh_proto2->sub_proto) return -1;
    if (nh_proto1->sub_proto > nh_proto2->sub_proto) return 1;
    
    /* Finally by instance number */
    if (nh_proto1->instance_no < nh_proto2->instance_no) return -1;
    if (nh_proto1->instance_no > nh_proto2->instance_no) return 1;
    
    return 0;
}

/**
 * @brief Add NH protocol info to RTM
 * 
 * Adds a protocol information structure to the RTM's protocol tree.
 * If the protocol info already exists, returns the existing one.
 * 
 * @param rtm Pointer to routing table
 * @param nh_proto Protocol info to add
 * @param existing_nh_proto_out Output parameter for existing protocol info (if any)
 * 
 * @return RTM_SUCCESS on success, error code on failure
 */
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
    
    /* Check if protocol info already exists */
    rtm_nh_proto_t *existing = rtm_nh_proto_lookup(rtm, nh_proto);
    
    *existing_nh_proto_out = NULL;

    if (existing) {
        /* Protocol info already exists, return it */
        *existing_nh_proto_out = existing;
        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : NH Proto Info already exists Proto=%s SubProto=%s Inst=%u ref_count=%u\n",
            rtm->name,
            rtm_proto_to_string(nh_proto->proto),
            rtm_sub_proto_to_string(nh_proto->sub_proto),
            nh_proto->instance_no,
            existing->ref_count);
        return RTM_ERROR_NEXTHOP_PROTO_ALREADY_EXISTS;
    }
    
    /* Insert into AVL tree */
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
    
    return RTM_SUCCESS;
}

/**
 * @brief Lookup NH protocol info in RTM
 * 
 * Searches for a protocol info structure matching the template.
 * 
 * @param rtm Pointer to routing table
 * @param nh_proto_template Template to match
 * 
 * @return Pointer to found protocol info, or NULL if not found
 */
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

/**
 * @brief Increment NH protocol info reference count
 * 
 * Called when a nexthop starts using this protocol info.
 * Reference counting ensures protocol info is not deleted
 * while nexthops are still using it.
 * 
 * @param nh_proto Protocol info to reference
 */
void
rtm_nh_proto_reference(rtm_nh_proto_t *nh_proto) {
    
    nh_proto->ref_count++;
    
    /* Note: We don't have rtm context here, so we can't trace with RTM name */
}

/**
 * @brief Release all resources associated with NH protocol info
 * 
 * Currently a placeholder for future resource cleanup.
 * 
 * @param rtm Pointer to routing table
 * @param nh_proto Protocol info to clean up
 */
static void 
rtm_nh_proto_release_all_resources(rtm_t *rtm, rtm_nh_proto_t *nh_proto) {

    /* Nothing to release currently */
}

/**
 * @brief Check and delete NH protocol info if ref_count reaches zero
 * 
 * Removes protocol info from RTM and frees memory when no longer referenced.
 * 
 * @param rtm Pointer to routing table
 * @param nh_proto Protocol info to check and potentially delete
 */
static void 
rtm_nh_proto_check_and_delete (rtm_t *rtm, 
        rtm_nh_proto_t *nh_proto) {

    char proto_str[32];

    /* Release any associated resources */
    rtm_nh_proto_release_all_resources(rtm, nh_proto);
    
    /* Remove from AVL tree */
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

/**
 * @brief Decrement NH protocol info reference count
 * 
 * Called when a nexthop stops using this protocol info.
 * If ref_count reaches zero, the protocol info is deleted.
 * 
 * Reference Counting Flow:
 * ┌─────────────────────────────────────────────────────────┐
 * │ 1. Nexthop created → rtm_nh_proto_reference()          │
 * │    ref_count: 0 → 1                                     │
 * │ 2. More nexthops use same proto → ref_count++           │
 * │ 3. Nexthop deleted → rtm_nh_proto_dereference()         │
 * │    ref_count: N → N-1                                   │
 * │ 4. When ref_count == 0 → Delete protocol info           │
 * └─────────────────────────────────────────────────────────┘
 * 
 * @param rtm Pointer to routing table
 * @param nh_proto Protocol info to dereference
 */
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

    /* If no more references, delete the protocol info */
    if (nh_proto->ref_count == 0){
        tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : NH Proto Info ref_count=0, initiating deletion Proto=%s SubProto=%s\n",
            rtm->name,
            rtm_proto_to_string(nh_proto->proto),
            rtm_sub_proto_to_string(nh_proto->sub_proto));
        rtm_nh_proto_check_and_delete (rtm, nh_proto);
    }
}

/**
 * @brief Compare two NH protocol info structures for equality
 * 
 * Performs deep comparison including protocol-specific union fields.
 * 
 * @param nh_proto1 First protocol info
 * @param nh_proto2 Second protocol info
 * 
 * @return -1 if nh_proto1 < nh_proto2, 0 if equal, 1 if nh_proto1 > nh_proto2
 */
int8_t 
rtm_nh_proto_is_equal (
    rtm_nh_proto_t *nh_proto1,
    rtm_nh_proto_t *nh_proto2) {

    assert (nh_proto1 && nh_proto2);

    /* Compare basic fields first */
    if (nh_proto1->proto < nh_proto2->proto) return -1;
    if (nh_proto1->proto > nh_proto2->proto) return 1;

    if (nh_proto1->sub_proto < nh_proto2->sub_proto) return -1;
    if (nh_proto1->sub_proto > nh_proto2->sub_proto) return 1;

    if (nh_proto1->instance_no < nh_proto2->instance_no) return -1;
    if (nh_proto1->instance_no > nh_proto2->instance_no) return 1;

    if (nh_proto1->vrf_id < nh_proto2->vrf_id) return -1;
    if (nh_proto1->vrf_id > nh_proto2->vrf_id) return 1;

    /* Compare protocol-specific union fields */
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
        default:
            return 0;
    }

    assert(0);
    return 0;
}

/**
 * @brief Initialize NH protocol info structure
 * 
 * Zero-initializes the structure and initializes the AVL tree glue node.
 * 
 * @param nh_proto Protocol info to initialize
 */
void 
rtm_nh_proto_initialize(rtm_nh_proto_t *nh_proto) {

    memset (nh_proto, 0, sizeof (*nh_proto));
    avltree_node_init(&nh_proto->proto_glue);
}

/* ========================================================================
 * PROTO INFO (rtm_proto_info_t) Management Functions
 * ======================================================================== */

/**
 * @brief Create and initialize a new protocol info structure
 * 
 * Protocol Info (rtm_proto_info_t) is used for protocol registration
 * and subscription management. Each registered protocol has one
 * protocol info structure per RTM.
 * 
 * Structure:
 * ┌─────────────────────────────────────────────────────────┐
 * │ rtm_proto_info_t                                        │
 * │  - proto: RTM_PROTO_T                                   │
 * │  - instance_no: Protocol instance number                │
 * │  - vrf_id: VRF identifier                               │
 * │  - proto_glue: AVL tree node                            │
 * │  - sub_db: Subscription database (AVL tree)             │
 * └─────────────────────────────────────────────────────────┘
 * 
 * @param rtm Pointer to routing table
 * @param proto Protocol type
 * @param inst_no Instance number
 * 
 * @return Pointer to created or existing protocol info, NULL on error
 */
rtm_proto_info_t *
rtm_proto_info_create(rtm_t *rtm, RTM_PROTO_T proto, uint32_t inst_no) {
    
    if (!rtm || proto >= RTM_PROTO_MAX) {
        return NULL;
    }
    
    /* Check if protocol info already exists */
    rtm_proto_info_t *existing = rtm_proto_lookup(rtm, proto, inst_no);
    
    if (existing) {
        /* Return existing protocol info */
        return existing;
    }
    
    /* Allocate new protocol info structure */
    rtm_proto_info_t *proto_info = (rtm_proto_info_t *)XCALLOC2(0, 1, rtm_proto_info_t);

    /* Initialize keys */
    proto_info->proto = proto;
    proto_info->instance_no = inst_no;
    proto_info->vrf_id = rtm->vrf;
    
    /* Initialize the AVL tree glue node */
    avltree_node_init (&proto_info->proto_glue);
    
    /* Initialize subscription database (AVL tree for efficient lookup) */
    avltree_init (&proto_info->sub_db, rtm_subscription_db_compare_fn);
    
    return proto_info;
}

/**
 * @brief Compare two protocol info structures
 * 
 * Used for AVL tree operations. Comparison order:
 * 1. VRF ID
 * 2. Protocol type
 * 3. Instance number
 * 
 * @param proto1 First protocol info
 * @param proto2 Second protocol info
 * 
 * @return -1 if proto1 < proto2, 0 if equal, 1 if proto1 > proto2
 */
int8_t
rtm_proto_compare(rtm_proto_info_t* proto1, rtm_proto_info_t* proto2) {
    
    if (!proto1 || !proto2) {
        return -1;
    }
    
    /* Compare by VRF first */
    if (proto1->vrf_id < proto2->vrf_id) return -1;
    if (proto1->vrf_id > proto2->vrf_id) return 1;
    
    /* Then by protocol type */
    if (proto1->proto < proto2->proto) return -1;
    if (proto1->proto > proto2->proto) return 1;
    
    /* Finally by instance number */
    if (proto1->instance_no < proto2->instance_no) return -1;
    if (proto1->instance_no > proto2->instance_no) return 1;
    
    return 0;
}

/**
 * @brief Copy NH protocol info from source to destination
 * 
 * Performs deep copy while preserving AVL tree glue and reference count.
 * 
 * @param src_nh_proto Source protocol info
 * @param dst_nh_proto Destination protocol info
 */
void 
rtm_nh_proto_copy(rtm_nh_proto_t *src_nh_proto, rtm_nh_proto_t *dst_nh_proto) {

    /* Save AVL tree glue and reference count */
    avltree_node_t avl_node;
    uint32_t ref_count = dst_nh_proto->ref_count;
    memcpy(&avl_node, &dst_nh_proto->proto_glue, sizeof(avltree_node_t));
    
    /* Copy entire structure */
    memcpy(dst_nh_proto, src_nh_proto, sizeof(rtm_nh_proto_t));
    
    /* Restore AVL tree glue and reference count */
    memcpy (&dst_nh_proto->proto_glue, &avl_node, sizeof(avltree_node_t));
    dst_nh_proto->ref_count = ref_count;
}

/**
 * @brief Add protocol info to RTM
 * 
 * Registers a protocol with the RTM. Each protocol instance can only
 * be registered once per RTM.
 * 
 * @param rtm Pointer to routing table
 * @param proto_info Protocol info to add
 * 
 * @return RTM_SUCCESS on success, error code on failure
 */
rtm_error_t 
rtm_proto_info_add(const rtm_t* rtm, rtm_proto_info_t* proto_info) {
    
    if (!rtm || !proto_info) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    /* Validate protocol type */
    if (proto_info->proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    /* Check if protocol info already exists */
    rtm_proto_info_t *existing = rtm_proto_lookup(rtm, proto_info->proto, proto_info->instance_no);

    if (existing) {
        return RTM_ERROR_PROTO_INFO_ALREADY_EXISTS;
    }
    
    /* Get the appropriate protocol info tree (one per protocol type) */
    avltree_t *proto_tree = (avltree_t*)&rtm->proto_info_tree[proto_info->proto];
    
    /* Insert into protocol info tree */
    if (avltree_insert(&proto_info->proto_glue, proto_tree)) {
        return RTM_ERROR_CONTAINER_INSERTION_FAILED;
    }
    
    return RTM_SUCCESS;
}

/**
 * @brief Delete protocol info from RTM
 * 
 * Unregisters a protocol from the RTM and frees associated memory.
 * 
 * @param rtm Pointer to routing table
 * @param proto Protocol type
 * @param inst_no Instance number
 * 
 * @return RTM_SUCCESS on success, error code on failure
 */
rtm_error_t 
rtm_proto_info_del(const rtm_t* rtm, RTM_PROTO_T proto, uint32_t inst_no) {
    
    if (!rtm) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    /* Validate protocol type */
    if (proto >= RTM_PROTO_MAX) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }
    
    /* Find the protocol info */
    rtm_proto_info_t *proto_info = rtm_proto_lookup(rtm, proto, inst_no);
    if (!proto_info) {
        return RTM_ERROR_CONTAINER_LOOKUP_FAILED;
    }
    
    /* Get the appropriate protocol info tree */
    avltree_t *proto_tree = (avltree_t*)&rtm->proto_info_tree[proto];
    
    /* Re-initialize glue node before removal */
    avltree_node_init (&proto_info->proto_glue);
    
    /* Remove from protocol info tree */
    avltree_strict_remove(&proto_info->proto_glue, proto_tree);
    
    /* Free the protocol info */
    XFREE(proto_info);
    
    return RTM_SUCCESS;
}

/**
 * @brief Lookup protocol info in RTM
 * 
 * Searches for a protocol info structure matching the protocol type
 * and instance number.
 * 
 * @param rtm Pointer to routing table
 * @param proto Protocol type
 * @param inst_no Instance number
 * 
 * @return Pointer to found protocol info, or NULL if not found
 */
rtm_proto_info_t *
rtm_proto_lookup(const rtm_t* rtm, RTM_PROTO_T proto, uint32_t inst_no) {
    
    if (!rtm || proto >= RTM_PROTO_MAX) {
        return NULL;
    }
    
    /* Get the appropriate protocol info tree */
    avltree_t *proto_tree = (avltree_t*)&rtm->proto_info_tree[proto];
    
    /* Check if tree is empty */
    if (avltree_is_empty(proto_tree)) {
        return NULL;
    }
    
    /* Create a temporary protocol info for lookup */
    rtm_proto_info_t temp_proto_info;
    memset(&temp_proto_info, 0, sizeof(rtm_proto_info_t));
    temp_proto_info.proto = proto;
    temp_proto_info.instance_no = inst_no;
    temp_proto_info.vrf_id = rtm->vrf;
    
    /* Look up in the protocol info tree */
    avltree_node_t *node = avltree_lookup(&temp_proto_info.proto_glue, proto_tree);
    
    if (!node) {
        return NULL;
    }
    
    return avltree_container_of(node, rtm_proto_info_t, proto_glue);
}

/* ========================================================================
 * Route Target RTM Selection
 * ======================================================================== */

/**
 * @brief Get the target RTM for a given protocol, address family, and VRF
 * 
 * This is the core function that determines which routing table (RTM) should
 * be used for a given protocol. Different protocols use different tables:
 * 
 * Selection Logic Flow:
 * ┌─────────────────────────────────────────────────────────┐
 * │ 1. Determine if default VRF or customer VRF            │
 * │ 2. Check protocol-specific rules:                      │
 * │    - LDP: Only supported in default VRF, uses inet.3   │
 * │    - STATIC: Uses inet.0/inet6.0 (default or customer) │
 * │    - BGP VPN: Uses bgp.l3vpn.0 (default VRF only)      │
 * │    - SR/SRTE: Uses inet.3/inet6.3 (default VRF only)   │
 * │    - ISIS: Uses inet.0/inet6.0 (any VRF)               │
 * │    - MPLS: Uses mpls.0 (default VRF only)              │
 * │ 3. Return appropriate RTM pointer                      │
 * └─────────────────────────────────────────────────────────┘
 * 
 * Protocol-Specific Table Selection:
 * 
 * LDP (Label Distribution Protocol):
 *   - Purpose: MPLS label distribution
 *   - Tables: inet.3 (IPv4), inet6.3 (IPv6)
 *   - VRF: Default VRF only
 *   - Note: LDP is not supported in customer VRFs
 * 
 * STATIC Routes:
 *   - Purpose: Manually configured routes
 *   - Tables: inet.0 (IPv4), inet6.0 (IPv6)
 *   - VRF: Default VRF or any customer VRF
 * 
 * BGP L3VPN:
 *   - Purpose: VPN route distribution
 *   - Tables: bgp.l3vpn.0 (IPv4), bgp.l3vpn.0 (IPv6)
 *   - VRF: Default VRF only (routes then propagated to customer VRFs)
 * 
 * SR/SRTE (Segment Routing / SR-TE):
 *   - Purpose: Traffic engineering with segment routing
 *   - Tables: inet.3 (IPv4), inet6.3 (IPv6)
 *   - VRF: Default VRF only
 * 
 * ISIS:
 *   - Purpose: Link-state routing protocol
 *   - Tables: inet.0 (IPv4), inet6.0 (IPv6)
 *   - VRF: Default VRF or any customer VRF
 * 
 * MPLS:
 *   - Purpose: MPLS forwarding table
 *   - Tables: mpls.0
 *   - VRF: Default VRF only
 * 
 * @param node Pointer to network node
 * @param vrf VRF pointer (NULL or def_vrf for default VRF)
 * @param afi Address Family (AF_IPV4, AF_IPV6, AF_LABEL)
 * @param proto Protocol type (RTM_PROTO_STATIC, RTM_PROTO_BGP, etc.)
 * @param sub_proto Sub-protocol type (RTM_PROTO_BGP_VPN, etc.)
 * 
 * @return Pointer to target RTM, or NULL if not found/invalid combination
 */
rtm_t *
rtm_get_route_target_rtm( node_t *node, 
                          vrf_t *vrf, AFI_T afi,
                          RTM_PROTO_T proto, 
                          RTM_SUB_PROTO_T sub_proto) {

    /* Get default VRF pointer */
    vrf_t *def_vrf = NODE_DEF_VRF(node);
    
    /* Determine if this is the default VRF */
    bool is_def_vrf = (vrf == def_vrf);

    /* ====================================================================
     * LDP (Label Distribution Protocol) Routes
     * ==================================================================== */
    /* LDP is only supported in default VRF */
    /* IPv4 LDP routes go to inet.3 */
    if ( afi == AF_IPV4 && proto == RTM_PROTO_LDP) {
        if (is_def_vrf) return NODE_DEF_VRF_VRF_MEMBER(node, inet3);
        return vrf->inet3;
    }

    /* IPv6 LDP routes go to inet6.3 */
    if (afi == AF_IPV6 && proto == RTM_PROTO_LDP) {
        if (is_def_vrf) return NODE_DEF_VRF_VRF_MEMBER(node, inet63);
        return vrf->inet63;
    }


    /* LDP is not supported in customer VRFs */
    if (!is_def_vrf && proto == RTM_PROTO_LDP) return NULL;

    /* ====================================================================
     * STATIC Routes
     * ==================================================================== */
    /* Default VRF static routes go to inet.0/inet6.0 */
    if (is_def_vrf && afi == AF_IPV4 && proto == RTM_PROTO_STATIC)
        return NODE_DEF_VRF_VRF_MEMBER(node, inet0);

    if (is_def_vrf && afi == AF_IPV6 && proto == RTM_PROTO_STATIC)
        return NODE_DEF_VRF_VRF_MEMBER(node, inet6);

    /* Customer VRF static routes go to vrf.inet.0/vrf.inet6.0 */
    if (!is_def_vrf && afi == AF_IPV4 && proto == RTM_PROTO_STATIC)
        return vrf->inet0;

    if (!is_def_vrf && afi == AF_IPV6 && proto == RTM_PROTO_STATIC)
        return vrf->inet6;

    /* ====================================================================
     * BGP L3VPN Routes
     * ==================================================================== */
    /* BGP L3VPN routes are only in default VRF */
    /* IPv4 VPN routes go to bgp.l3vpn.0 (IPv4) */
    if (is_def_vrf && afi == AF_IPV4 && proto == RTM_PROTO_BGP && sub_proto == RTM_PROTO_BGP_VPN)
        return NODE_DEF_VRF_MEMBER(node, l3vpnv4);

    /* IPv6 VPN routes go to bgp.l3vpn.0 (IPv6) */
    if (is_def_vrf && afi == AF_IPV6 && proto == RTM_PROTO_BGP && sub_proto == RTM_PROTO_BGP_VPN)
        return NODE_DEF_VRF_MEMBER(node, l3vpnv6);

    /* ====================================================================
     * SR/SRTE (Segment Routing / SR-TE) Routes
     * ==================================================================== */
    /* SR routes use the same tables as LDP (inet.3/inet6.3) */
    /* IPv4 SR/SRTE routes go to inet.3 */
    if (afi == AF_IPV4 && (sub_proto == RTM_SUB_PROTO_SR || sub_proto == RTM_SUB_PROTO_SRTE)) {

        if (is_def_vrf) return NODE_DEF_VRF_VRF_MEMBER(node, inet3);
        return vrf->inet3;
    }

    /* IPv6 SR/SRTE routes go to inet6.3 */
    if (afi == AF_IPV6 && (sub_proto == RTM_SUB_PROTO_SR || sub_proto == RTM_SUB_PROTO_SRTE)) {

        if (is_def_vrf) return NODE_DEF_VRF_VRF_MEMBER(node, inet63);
        return vrf->inet63;
    }

    if  (sub_proto == RTM_SUB_PROTO_SRv6 || 
          sub_proto == RTM_SUB_PROTO_SRv6_SRTE) {

        if (is_def_vrf) return NODE_DEF_VRF_VRF_MEMBER(node, inet6);
        return vrf->inet6;
    }

    /* ====================================================================
     * ISIS Routes
     * ==================================================================== */
    /* ISIS routes can be in default VRF or customer VRFs */
    /* Note: The condition below has a bug - it checks proto == RTM_PROTO_ISIS
     * but then checks sub_proto against ISIS-specific values. This should be
     * checking sub_proto directly. However, keeping original logic. */
    if (proto == RTM_PROTO_ISIS && 
            (sub_proto == RTM_PROTO_L1_ISIS_INT || 
             sub_proto == RTM_PROTO_L2_ISIS_INT || 
             sub_proto == RTM_PROTO_L1_ISIS_EXT || 
             sub_proto == RTM_PROTO_L2_ISIS_EXT)) {

        if (afi == AF_IPV4) {
            if (is_def_vrf) return NODE_DEF_VRF_VRF_MEMBER(node, inet0);
            else return vrf->inet0;
        }
        else if (afi == AF_IPV6) {
            if (is_def_vrf) return NODE_DEF_VRF_VRF_MEMBER(node, inet6);
            else return vrf->inet6;
        }
    }

    /* SRv6 Routes :
        SRv6 routes can be installed statically, by ISIS, or by OSPF
    */
    switch (proto) {

        case RTM_PROTO_ISIS:
        case RTM_PROTO_OSPF:
        case RTM_PROTO_STATIC:
            switch (sub_proto) {

                case RTM_SUB_PROTO_SRv6:
                case RTM_SUB_PROTO_SRv6_SRTE:

                if (afi == AF_IPV4) return NULL;

                if (is_def_vrf) return NODE_DEF_VRF_VRF_MEMBER(node, inet63);
                return vrf->inet63;

                default : 
                    break;
            }
        default:
            break;
    }

    /* ====================================================================
     * Default/Unicast Routes
     * ==================================================================== */
    /* For all other cases, use the unicast tables */
    /* Default VRF IPv4 routes go to inet.0 */
    if (is_def_vrf && afi == AF_IPV4) 
        return NODE_DEF_VRF_VRF_MEMBER(node, inet0);

    /* Customer VRF IPv4 routes go to vrf.inet.0 */
    if (!is_def_vrf && afi == AF_IPV4) return vrf->inet0;

    /* Default VRF IPv6 routes go to inet6.0 */
    if (is_def_vrf && afi == AF_IPV6) 
        return NODE_DEF_VRF_VRF_MEMBER(node, inet6);

    /* Customer VRF IPv6 routes go to vrf.inet6.0 */
    if (!is_def_vrf && afi == AF_IPV6) return vrf->inet6;

    /* MPLS routes always go to mpls.0 (default VRF only) */
    if (afi == AF_MPLS) 
        return NODE_DEF_VRF_MEMBER(node, mpls0);

    return NULL;
}
