
#ifndef __RTM__
#define __RTM__

#include <stdint.h>
#include "../Tree/libtree.h"
#include "../gluethread/glthread.h"
#include "rtm_enums.h"
#include "rtm_error.h"

typedef struct node_ node_t;
typedef struct rtm_nh_ rtm_nh;
typedef struct task_ task_t;
typedef struct mtrie_ mtrie_t;

#pragma pack(push, 8)

typedef struct rtm_ {

    /* Keys */
    uint8_t vrf;
    RTM_AFI_T afi;
    uint32_t rtm_id;

    /* RTM name : vrf.inet[6]|mpls.table_id */
    char name[32];

    /* LPM tree of routes in this RTM*/
    mtrie_t *lpm_rt_tree;

    /* Route tree keyed by prefix in this RTM */
    avltree_t route_tree;

    /* Protocol information which came attached with nexthop 
        in the RTM, all fields are keys */
    avltree_t nh_proto_info_tree;

    /* Nexthops indexed by their unique idx */
    avltree_t nhs_by_idx;

    /* Nexthops grouped by their source protocol */
    glthread_t nhs_by_src[RTM_PROTO_MAX];

    /* Protocol information registered in this RTM. Used to
        store protocol subscription and filters */
    avltree_t proto_info_tree[RTM_PROTO_MAX];

    /* List of NHs queued for advertisement to protocols */
    Fglthread_t advt_nhs[RTM_PROTO_MAX];

    /* Advertisement temporary task queue */
    Fglthread_t advt_queue;

    /* BAckpointer to owning node*/
    node_t *node; 
    
    /* List of Orphan Indirect NHs which have no route to resolve over */
    Fglthread_t unresolvable_paths;
    
    /* List of routes whose resolved INHs are to be propogated upstream in Resolution Graph*/
    Fglthread_t resolved_unpropogated_routes;

    /* Job to resolve INHs */
    task_t *nh_resolution_job;

    /* Job to propogate resolved route Active NH upstream in Resolution Graph */
    task_t *rt_resolution_job;

    /* Job to advertise the routes to protocols, preemptive */
    task_t *advt_job;
    
} rtm_t;

#pragma pack(pop)

rtm_t* rtm_initialize (uint8_t vrf, RTM_AFI_T afi, uint32_t rtm_id);
void rtm_destroy (uint8_t vrf, RTM_AFI_T afi, uint32_t rtm_id);

rtm_nh *rtm_nh_lookup_by_idx(rtm_t *rtm, uint32_t idx);
rtm_error_t rtm_nh_add_to_idx_tree(rtm_t *rtm, rtm_nh *nh);
rtm_error_t rtm_nh_remove_from_idx_tree(rtm_t *rtm, rtm_nh *nh);


#endif