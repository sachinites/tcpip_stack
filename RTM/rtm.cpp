#include <stdint.h>
#include <cstring>
#include <assert.h>
#include <memory.h>
#include <stdlib.h>
#include "rtm.h"
#include "rtm_common.h"
#include "rtm_route.h"
#include "../gluethread/glthread.h"
#include "rtm_proto.h"

/* Tree contains RTMs, a Global Tree */
avltree_t rtm_tree;

/* AVL Tree comparison function */
extern int8_t
rtm_nh_proto_compare (rtm_nh_proto_t *nh_proto1, rtm_nh_proto_t *nh_proto2);
extern int8_t
rtm_proto_compare (rtm_proto_info_t* proto1, rtm_proto_info_t* proto2);
extern int
rtm_route_compare(const avltree_node_t *node1, const avltree_node_t *node2);

/* Wrapper for NH proto compare */
static int
rtm_nh_proto_avl_tree_comp_fn (const avltree_node_t *node1, const avltree_node_t *node2) {

    rtm_nh_proto_t *nh_proto1 = avltree_container_of(node1, rtm_nh_proto_t, proto_glue);
    rtm_nh_proto_t *nh_proto2 = avltree_container_of(node2, rtm_nh_proto_t, proto_glue);

    return rtm_nh_proto_compare(nh_proto1, nh_proto2);
}

/* Wrapper for proto info compare */
static int
rtm_proto_info_avl_tree_comp_fn (const avltree_node_t *node1, const avltree_node_t *node2) {

    rtm_proto_info_t *proto_info1 = avltree_container_of(node1, rtm_proto_info_t, proto_glue);
    rtm_proto_info_t *proto_info2 = avltree_container_of(node2, rtm_proto_info_t, proto_glue);

    return rtm_proto_compare(proto_info1, proto_info2);
}

/* Initialize a new RTM instance */
void 
rtm_initialize(uint8_t vrf, RTM_AFI_T afi, uint32_t rtm_id) {
    
    rtm_t *existing_rtm = rtm_get(vrf, afi, rtm_id);
    
    if (existing_rtm) return;
    
    rtm_t *rtm = (rtm_t *)calloc (1, sizeof(rtm_t));
    if (!rtm) return;

    rtm->vrf = vrf;
    rtm->afi = afi;
    rtm->rtm_id = rtm_id;
    
    avltree_init(&rtm->route_tree, rtm_route_compare);
    avltree_init (&rtm->nh_proto_info_tree, rtm_nh_proto_avl_tree_comp_fn);

    for (int i = 0; i < RTM_PROTO_MAX; i++) {
        avltree_init(&rtm->proto_info_tree[i], rtm_proto_info_avl_tree_comp_fn);
    }
    
    init_glthread(&rtm->unresolvable_lnhs);
    memset(&rtm->rtm_glue, 0, sizeof(avltree_node_t));

    avltree_insert(&rtm->rtm_glue, &rtm_tree);
}


/* Destroy an RTM instance */
void rtm_destroy (uint8_t vrf, RTM_AFI_T afi, uint32_t rtm_id) {
    
    rtm_t *rtm_to_destroy = rtm_get(vrf, afi, rtm_id);
    
    if (!rtm_to_destroy) {
        return;
    }
    
    // Remove from global RTM tree
    avltree_remove(&rtm_to_destroy->rtm_glue, &rtm_tree);
    
    /* Before we delete RTM, check all resources have been freed already*/
    assert (avltree_is_empty (&rtm_to_destroy->route_tree) );
    assert (avltree_is_empty (&rtm_to_destroy->nh_proto_info_tree) );
    
    // Clean up protocol info trees
    for (int i = 0; i < RTM_PROTO_MAX; i++) {
        assert (avltree_is_empty (&rtm_to_destroy->proto_info_tree[i]) );
    }
    
    assert (IS_GLTHREAD_LIST_EMPTY (&rtm_to_destroy->unresolvable_lnhs) );

    free (rtm_to_destroy);
}

/* Get an RTM instance by VRF, AFI, and RTM ID */
rtm_t* 
rtm_get(uint8_t vrf, RTM_AFI_T afi, uint32_t rtm_id) {
    
    rtm_t temp_rtm;
    temp_rtm.vrf = vrf;
    temp_rtm.afi = afi;
    temp_rtm.rtm_id = rtm_id;
    
    avltree_node_t *node = avltree_lookup(&temp_rtm.rtm_glue, &rtm_tree);
    
    if (!node) {
        return nullptr;
    }
    
    return avltree_container_of(node, rtm_t, rtm_glue);
}
