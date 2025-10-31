
#ifndef __RTM_STORAGE__
#define __RTM_STORAGE__

#include <stdint.h>
#include <time.h>
#include "../Tree/libtree.h"
#include "../gluethread/glthread.h"
#include "rtm_enums.h"
#include "rtm_common.h"
#include "rtm_proto.h"

typedef struct rtm_rt_cb_ rtm_rt_cb_t;

/* Local or Connected Nexthop */
typedef struct rtm_nh_connected_ {

    /* Action of this nexthop*/
    RTM_NH_ACTION_TYPE_T action_id;
    
    /* Outgoing interface */
    uint32_t if_index;

} rtm_nh_connected_t;

typedef struct rtm_nh_ipv4_ {

    /* Action of this nexthop*/
    RTM_NH_ACTION_TYPE_T action_id;
    
    /* Outgoing interface */
    uint32_t if_index;

    /* Concrete nexthop address */
    rtm_prefix_t nh_addr;

} rtm_nh_ipv4_t;

typedef struct rtm_nh_ipv6_ {

    /* Action of this nexthop*/
    RTM_NH_ACTION_TYPE_T action_id;
    
    /* Outgoing interface */
    uint32_t if_index;

    /* Concrete nexthop address */
    rtm_prefix_t nh_addr6;

} rtm_nh_ipv6_t;

typedef struct rtm_lnh_ipv4_ {

    /* Action of this nexthop*/
    RTM_NH_ACTION_TYPE_T action_id;

    /* Outgoing interface, will be known when this nexthop is resolved */
    uint32_t if_index;

    /* Concrete nexthop address */
    rtm_prefix_t lnh_addr;

    /* List of Actual Loose nexthops */
    glthread_t l4_path_list;

} rtm_lnh_ipv4_t;

typedef struct rtm_lnh_ipv6_ {

    /* Action of this nexthop*/
    RTM_NH_ACTION_TYPE_T action_id;

    /* Outgoing interface, will be known when this nexthop is resolved */
    uint32_t if_index;

    /* Concrete nexthop address */
    rtm_prefix_t lnh_addr6;

    /* List of Actual Loose nexthops */
    glthread_t l4_path_list;

} rtm_lnh_ipv6_t;


typedef struct rtm_nh_ipv4_tunnel_ {

    /* Action of this nexthop*/
    RTM_NH_ACTION_TYPE_T action_id;

    /* Outgoing interface, will be known when this nexthop is resolved */
    uint32_t if_index;
    
    uint32_t mpls_label;

    /* Concrete nexthop address */
    rtm_prefix_t lnh_addr;

} rtm_nh_ipv4_tunnel_t;

typedef struct rtm_nh_ipv6_tunnel_ {

    /* Action of this nexthop*/
    RTM_NH_ACTION_TYPE_T action_id;

    /* Outgoing interface, will be known when this nexthop is resolved */
    uint32_t if_index;
        
    uint32_t mpls_label;
    
    /* Concrete nexthop address */
    rtm_prefix_t lnh_addr6;

} rtm_nh_ipv6_tunnel_t;



typedef struct rtm_source_ {

  /* List of paths originated by this source */
  glthread_t src_path_list;

  /* Type of this source */
  RTM_SOURCE_TYPE_T src_type;

} rtm_source_t;



/* Nexthop Structure */
typedef struct rtm_path_cb_ {

    /* Protocol of this nexthop */
    rtm_rpm_proto_info_t *pth_prot_specific;

    /* Backpointer to the owning route*/
    rtm_rt_cb_t *pth_route;

    /* Next nexthop in the list*/
    glthread_t pth_next;

    /* If this nexthop is LNH, then glue it in LNH list*/
    glthread_t pth_lnh_list_entry;

    /* Aggregate all NHs based on Source, 
        glue it in src_path_list of QCRS_SOURCE_CB*/
    glthread_t pth_src_node;

    time_t pth_last_update_time;

    RTM_NH_ACTION_TYPE_T pth_action;

    uint32_t pth_cost;

    uint16_t pth_flags;

} rtm_path_cb_t;


/* Route Structure */
struct rtm_rt_cb_ {

    /* Keyed by prefix */
    avltree_node_t rt_tree_node;

    /* Pointer to the first NH in the list of NHs*/
    glthread_t rt_path_list;

    /* List of Queries satisfied by this route */
    glthread_t rt_solved_query_list;

    /* glue to hook up in Tree of Active Routes */
    avltree_node_t rt_pat_node;

    rtm_prefix_t rt_dest;

    uint16_t rt_flags;

    char padding[6];

};



typedef struct rtm_rt_storage_ {

    /* Tree of Routes */
    avltree_t rs_route_tree;

    avltree_t rs_nh_connected_tree;

    avltree_t rs_nh_fwd_tree;

    avltree_t rs_nh_tunnelled_tree;

    avltree_t rs_bgp_info_tree;   

    avltree_t rs_ospf_info_tree;   

    avltree_t rs_isis_info_tree;   

    avltree_t rs_lfa_info_tree;
       
} rtm_rt_storage_t;


typedef struct rtm_ {

    uint8_t vrf;
    RTM_AFI_T afi;

    avltree_node_t rtm_tree_node;

    rtm_rt_storage_t rs;

} rtm_t;


#endif 