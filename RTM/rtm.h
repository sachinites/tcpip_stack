
#ifndef __RTM__
#define __RTM__
#pragma pack(push, 8)

#include <stdint.h>
#include "../Tree/libtree.h"
#include "../gluethread/glthread.h"
#include "rtm_enums.h"
#include "rtm_error.h"

typedef struct node_ node_t;
typedef struct rtm_nh_ rtm_nh;
typedef struct task_ task_t;

typedef struct rtm_ {

    /* Keys */
    uint8_t vrf;
    RTM_AFI_T afi;
    uint32_t rtm_id;
    char name[32];
    avltree_t route_tree;
    avltree_t nh_proto_info_tree;
    avltree_t nhs_by_idx;
    glthread_t nhs_by_src[RTM_PROTO_MAX];
    avltree_t proto_info_tree[RTM_PROTO_MAX];
    Fglthread_t advt_nhs[RTM_PROTO_MAX];

    node_t *node; 
    /* List of lnh_list_t */
    glthread_t unresolvable_lnhs;

    task_t *advt_job;
    
} rtm_t;

rtm_t* rtm_initialize (uint8_t vrf, RTM_AFI_T afi, uint32_t rtm_id);
void rtm_destroy (uint8_t vrf, RTM_AFI_T afi, uint32_t rtm_id);

rtm_nh *rtm_nh_lookup_by_idx(rtm_t *rtm, uint32_t idx);
rtm_error_t rtm_nh_add_to_idx_tree(rtm_t *rtm, rtm_nh *nh);
rtm_error_t rtm_nh_remove_from_idx_tree(rtm_t *rtm, rtm_nh *nh);

#pragma pack(pop)

#endif