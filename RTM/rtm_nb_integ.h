#ifndef __RTM_INTEG__
#define __RTM_INTEG__

#include <stdint.h>
#include "rtm_enums.h"
#include "rtm_common.h"
#include "rtm_proto.h"
#include "../Interface/InterfaceFwd.h"
#include "../Layer3/SegmentRouting/SRv6/common/srv6_const.h"

typedef struct node_ node_t;
typedef struct rtm_ rtm_t;

#pragma pack(push, 8)

typedef struct cp_nexthop_template_ {

    RTM_PROTO_T proto;
    RTM_SUB_PROTO_T sub_proto;

    rtm_nh_proto_t *rtm_nh_proto;

    uint32_t metric;

    RTM_NH_ACTION_TYPE_T action;

    rtm_prefix_t gateway;
    InterfaceP Oif;
    bool is_indirect;

    union {

        struct {

            lstack_t *label_stack;

        } l_stack;

        struct {
            
            Srv6_endpcode_t endfn;
            uint8_t n_segment_list;
            rtm_prefix_t *v6segment_lst;

        } srv6_stack;

    }u;

} cp_nexthop_template_t;

#pragma pack(pop)

void node_init_default_rtm(node_t *node);
rtm_t *rtm_get(node_t *node, uint8_t vrf, RTM_AFI_T afi, uint8_t rtm_id);
rtm_error_t  cp_rtm_install_route ( rtm_t *rtm, rtm_prefix_t *route, cp_nexthop_template_t *nh_template);

#endif 