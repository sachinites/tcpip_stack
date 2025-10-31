#include <stdlib.h>
#include <assert.h>
#include "rtm_api.h"
#include "rtm_storage.h"

extern avltree_t rtm_tree;

rtm_t *
rtm_init(uint8_t vrf, RTM_AFI_T afi)
{
    rtm_t tmplate = {0};
    tmplate.vrf = vrf;
    tmplate.afi = afi;
    
    /* Lookup RTM instance in global rtm_tree */
    avltree_node_t *avl_node = avltree_lookup(&tmplate.rtm_tree_node, &rtm_tree);
    assert (!avl_node);

    rtm_t *rtm = (rtm_t *)calloc(1, sizeof(rtm_t));
    
    /* RTM keys*/
    rtm->vrf = vrf;
    rtm->afi = afi;

    avltree_init(&rtm->rs.rs_route_tree, NULL);
    avltree_init(&rtm->rs.rs_nh_connected_tree, NULL);
    avltree_init(&rtm->rs.rs_nh_fwd_tree, NULL);
    avltree_init(&rtm->rs.rs_nh_tunnelled_tree, NULL);
    avltree_init(&rtm->rs.rs_bgp_info_tree, NULL);
    avltree_init(&rtm->rs.rs_ospf_info_tree, NULL);
    avltree_init(&rtm->rs.rs_isis_info_tree, NULL);
    avltree_init(&rtm->rs.rs_lfa_info_tree, NULL);
    avltree_insert(&rtm->rtm_tree_node, &rtm_tree);
    return rtm;
}