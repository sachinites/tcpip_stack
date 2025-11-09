#ifndef __RTM_RESOLUTION__
#define __RTM_RESOLUTION__

#pragma pack(push, 8)

#include <stdint.h>
#include <stdbool.h>
#include "../gluethread/glthread.h"
#include "../Tree/libtree.h"
#include "rtm_enums.h"
#include "rtm_common.h"
#include "rtm_error.h"
#include "rtm_fwd_decl.h"


typedef struct lnh_list_ {

    /* List of nexthops which needs resolution*/
    glthread_t list_head;

    /* Glue to hook up in main route*/
    glthread_t route_glue;

    /* Is this resolved */
    bool is_resolved;

    /* Is the dependent route exist which resolves this*/
    bool is_resolvable;

    /* Route to be resolved */
    rtm_prefix_t prefix;
    /* Target VRF to be resolved */
    uint8_t target_vrf;
    /* Target RTM id to be resolved into (optional)*/
    uint32_t target_rtm_id;

    /* Resolution Data after resolution */
    rtm_prefix_t resolved_nexthop;
    uint32_t resolved_if_ifindex;
    RTM_PROTO_T resolved_proto;
    RTM_NH_ACTION_TYPE_T resolved_action;
    lstack_t *resolved_label_stack;

} lnh_list_t;
GLTHREAD_TO_STRUCT(route_glue_to_lnh_list, lnh_list_t, route_glue);

#pragma pack(pop)
#endif
