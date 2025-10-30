
#ifndef __NH_STRUCT__
#define __NH_STRUCT__

#include <stdint.h>
#include "../Tree/libtree.h"
#include "../gluethread/glthread.h"
#include "rtm_enums.h"
#include "rtm_common.h"

typedef struct nh_connected_ {


} nh_conntected_t;

typedef struct nh_local_ {


} nh_local_t;


typedef struct nh_ipv4_ {


} nh_ipv4_t;


typedef struct nh_ipv6_ {


} nh_ipv6_t;


typedef struct nh_ipv4_tunnel_ {


} nh_ipv4_tunnel_t;

typedef struct nh_ipv6_tunnel_ {


} nh_ipv6_tunnel_t;


/* Nexthop Structure */
typedef struct rtm_path_cb_ {


} rtm_path_cb_t;


/* Route Structure */
typedef struct rtm_rt_cb_ {

    /* Keyed by prefix */
    avltree_node_t rt_tree_node;

    /* Pointer to the first NH in the list of NHs*/
    rtm_path_cb_t *rt_first_path;

    /* List of Queries satisfied by this route */
    glthread_t rt_solved_query_list;

    /* glue to hook up in Tree of Active Routes */
    avltree_node_t rt_pat_node;

    rtm_prefix_t rt_dest;

    uint8_t rt_flags;
    uint8_t rt_flags2;
    uint8_t rt_flags3;

    char padding1[5];

} rtm_rt_cb_t;


#endif 