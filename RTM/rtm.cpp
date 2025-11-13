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
rtm_t *
rtm_initialize(uint8_t vrf, RTM_AFI_T afi, uint32_t rtm_id) {
    
    rtm_t *rtm = (rtm_t *)calloc (1, sizeof(rtm_t));

    rtm->vrf = vrf;
    rtm->afi = afi;
    rtm->rtm_id = rtm_id;
    
    avltree_init(&rtm->route_tree, rtm_route_compare);
    avltree_init (&rtm->nh_proto_info_tree, rtm_nh_proto_avl_tree_comp_fn);

    for (int i = 0; i < RTM_PROTO_MAX; i++) {
        avltree_init(&rtm->proto_info_tree[i], rtm_proto_info_avl_tree_comp_fn);
    }
    
    init_glthread(&rtm->unresolvable_lnhs);
    return rtm;
}


/* Destroy an RTM instance */
void rtm_destroy (rtm_t *rtm) {
    
    /* Before we delete RTM, check all resources have been freed already*/
    assert (avltree_is_empty (&rtm->route_tree) );
    assert (avltree_is_empty (&rtm->nh_proto_info_tree) );
    
    // Clean up protocol info trees
    for (int i = 0; i < RTM_PROTO_MAX; i++) {
        assert (avltree_is_empty (&rtm->proto_info_tree[i]) );
    }
    
    assert (IS_GLTHREAD_LIST_EMPTY (&rtm->unresolvable_lnhs) );

    free (rtm);
}