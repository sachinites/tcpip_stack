#ifndef __RTM_PROTO__
#define __RTM_PROTO__

#include <stdint.h>
#include "../Tree/libtree.h"

typedef struct rtm_rpm_proto_info_ {

    uint32_t ref_count;
    avltree_node_t avl_node;

} rtm_rpm_proto_info_t;

typedef struct rtm_rpm_isis_info_ {

    rtm_rpm_proto_info_t info_node;

    uint32_t admin_tag;
    uint8_t next_hop_router_id[6];

} rtm_rpm_isis_info_t;

/* Represent the routing protocol */
typedef struct rtm_rpm_ {

    
} rtm_rpm_t;

#endif 