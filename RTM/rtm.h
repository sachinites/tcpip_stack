
#ifndef __RTM__
#define __RTM__
#pragma pack(push, 8)

#include <stdint.h>
#include "../Tree/libtree.h"
#include "../gluethread/glthread.h"
#include "rtm_enums.h"
typedef struct node_ node_t;

typedef struct rtm_ {

    /* Keys */
    uint8_t vrf;
    RTM_AFI_T afi;
    uint32_t rtm_id;

    avltree_t route_tree;
    avltree_t nh_proto_info_tree;
    avltree_t proto_info_tree[RTM_PROTO_MAX];

    node_t *node; 
    /* List of lnh_list_t */
    glthread_t unresolvable_lnhs;
    
} rtm_t;

rtm_t* rtm_initialize (uint8_t vrf, RTM_AFI_T afi, uint32_t rtm_id);
void rtm_destroy (uint8_t vrf, RTM_AFI_T afi, uint32_t rtm_id);

#pragma pack(pop)

#endif