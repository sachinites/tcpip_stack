#include <stdint.h>
#include <cstring>
#include <assert.h>
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include "../gluethread/glthread.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "rtm.h"
#include "rtm_common.h"
#include "rtm_route.h"
#include "rtm_proto.h"
#include "rtm_nh.h"
#include "../lmm_enums.h"

/* Forward declaration of LPM tree functions */
extern void rtm_lpm_tree_init(rtm_t *rtm);
extern void rtm_lpm_tree_destroy(rtm_t *rtm);

/* AVL Tree comparison function */
extern int8_t
rtm_nh_proto_is_equal (rtm_nh_proto_t *nh_proto1, rtm_nh_proto_t *nh_proto2);
extern int8_t
rtm_proto_compare (rtm_proto_info_t* proto1, rtm_proto_info_t* proto2);
extern int
rtm_route_compare(const avltree_node_t *node1, const avltree_node_t *node2);
extern int
rtm_nh_compare_by_idx (const avltree_node_t *node1, const avltree_node_t *node2);

/* Wrapper for NH proto compare */
static int
rtm_nh_proto_avl_tree_comp_fn (const avltree_node_t *node1, const avltree_node_t *node2) {

    rtm_nh_proto_t *nh_proto1 = avltree_container_of(node1, rtm_nh_proto_t, proto_glue);
    rtm_nh_proto_t *nh_proto2 = avltree_container_of(node2, rtm_nh_proto_t, proto_glue);

    return rtm_nh_proto_is_equal(nh_proto1, nh_proto2);
}

/* Wrapper for proto info compare */
static int
rtm_proto_info_avl_tree_comp_fn (const avltree_node_t *node1, const avltree_node_t *node2) {

    rtm_proto_info_t *proto_info1 = avltree_container_of(node1, rtm_proto_info_t, proto_glue);
    rtm_proto_info_t *proto_info2 = avltree_container_of(node2, rtm_proto_info_t, proto_glue);

    return rtm_proto_compare(proto_info1, proto_info2);
}

/* Initialize a new RTM instance */
rtm_t *
rtm_initialize(uint8_t vrf, RTM_AFI_T afi, uint32_t rtm_id) {
    
    rtm_t *rtm = (rtm_t *)XCALLOC2 (0, 1, rtm_t);

    rtm->vrf = vrf;
    rtm->afi = afi;
    rtm->rtm_id = rtm_id;
    
    snprintf (rtm->name, sizeof(rtm->name), "%d.%s.%d", vrf, 
        afi == RTM_AF_IPV4 ? "inet" : afi == RTM_AF_IPV6 ? "inet6" :  afi == RTM_AF_LABEL ? "mpls" : "mac",
        rtm_id);

    rtm_lpm_tree_init(rtm);
    avltree_init(&rtm->route_tree, rtm_route_compare);
    avltree_init (&rtm->nh_proto_info_tree, rtm_nh_proto_avl_tree_comp_fn);
    avltree_init (&rtm->nhs_by_idx, rtm_nh_compare_by_idx);

    for (int i = 0; i < RTM_PROTO_MAX; i++) {
        init_glthread(&rtm->nhs_by_src[i]);
        avltree_init(&rtm->proto_info_tree[i], rtm_proto_info_avl_tree_comp_fn);
        init_Fglthread (&rtm->advt_nhs[i]);
    }
    
    init_Fglthread (&rtm->advt_queue);
    rtm->node = NULL;
    init_Fglthread(&rtm->unresolvable_paths);
    rtm->advt_job = NULL;
    
    return rtm;
}


/* Destroy an RTM instance */
void rtm_destroy (rtm_t *rtm) {
    
    /* Before we delete RTM, check all resources have been freed already*/
    assert (avltree_is_empty (&rtm->route_tree) );
    assert (avltree_is_empty (&rtm->nh_proto_info_tree) );
    assert (avltree_is_empty (&rtm->nhs_by_idx));


    // Clean up protocol info trees
    for (int i = 0; i < RTM_PROTO_MAX; i++) {
        assert (avltree_is_empty (&rtm->proto_info_tree[i]) );
        assert (IS_GLTHREAD_LIST_EMPTY (&rtm->nhs_by_src[i]) );
        assert (Fglthread_list_is_empty (&rtm->advt_nhs[i]) );
    }
    
    assert (Fglthread_list_is_empty(&rtm->unresolvable_paths) );
    assert (Fglthread_list_is_empty(&rtm->advt_queue) );
    assert (rtm->advt_job == NULL);

    /* Destroy LPM tree */
    rtm_lpm_tree_destroy(rtm);
    XFREE(rtm);
}

rtm_nh *
rtm_nh_lookup_by_idx(rtm_t *rtm, uint32_t idx) {

    rtm_nh nh_template;

    rtm_nh_initialize (&nh_template);
    nh_template.idx = idx;

    avltree_node_t *node = avltree_lookup(&nh_template.idx_glue, &rtm->nhs_by_idx);
    if (!node) return NULL;

    return avltree_container_of(node, rtm_nh, idx_glue);
}

rtm_error_t 
rtm_nh_add_to_idx_tree(rtm_t *rtm, rtm_nh *nh) {

    if (!rtm || !nh || !nh->idx) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    if (avltree_insert(&nh->idx_glue, &rtm->nhs_by_idx)) {
        return RTM_ERROR_CONTAINER_INSERTION_FAILED;
    }

    rtm_nh_reference (nh);
    return RTM_SUCCESS;
}

rtm_error_t 
rtm_nh_remove_from_idx_tree(rtm_t *rtm, rtm_nh *nh) {

    if (!rtm || !nh || !nh->idx) {
        return RTM_ERROR_INVALID_ARGUMENT;
    }

    avltree_remove(&nh->idx_glue, &rtm->nhs_by_idx);
    avltree_node_init (&nh->idx_glue); 
    rtm_nh_dereference (rtm, nh);

    return RTM_SUCCESS;
}
