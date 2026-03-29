#include <memory.h>

#include "../../RTM/rtm_proto.h"
#include "../../RTM/rtm_presentation.h"
#include "../../RTM/rtm_show.h"
#include "../../RTM/rtm_error.h"
#include "../../RTM/rtm_nh.h"
#include "../../RTM/rtm_priv_api.h"
#include "../../RTM/rtm_enums.h"
#include "../../RTM/rtm_nb_integ.h"

typedef struct isis_node_info_ isis_node_info_t;
extern int cprintf(const char *format, ...);

static void isis_rtm_test_cbk (
                rtm_t *rtm, uint32_t nh_idx, 
                rtm_nh *nh, 
                rtm_ppt_operation_t ops) {

    cprintf("isis_rtm_test_cbk\n");
}

void isis_rtm_test(node_t *node)
{
    rtm_t *rtm = rtm_get(node, RTM_DEFAULT_VRF, AF_IPV4, 0);

    cp_rtm_protocol_register(rtm, RTM_IP_PROTO_ISIS, 0, RTM_DEFAULT_VRF);

    rtm_rt_subscription_t sub;
    memset(&sub, 0, sizeof(rtm_rt_subscription_t));
    sub.target_proto = RTM_IP_PROTO_ISIS;
    sub.target_sub_proto = RTM_PROTO_L1_ISIS_INT;
    sub.target_instance_no = 0;
    sub.cbk = isis_rtm_test_cbk;

    cp_rtm_subscribe(rtm, 0, 0, RTM_IP_PROTO_ISIS, &sub);

    sub.target_proto = RTM_PROTO_OSPF;
    sub.target_sub_proto = RTM_SUB_PROTO_OSPF_EXT;
    cp_rtm_subscribe(rtm, 0, 0, RTM_IP_PROTO_ISIS, &sub);

    sub.target_proto = RTM_PROTO_BGP;
    sub.target_sub_proto = RTM_PROTO_BGP_INT;
    cp_rtm_subscribe(rtm, 0, 0, RTM_IP_PROTO_ISIS, &sub);

    sub.target_proto = RTM_PROTO_BGP;
    sub.target_sub_proto = RTM_PROTO_BGP_EXT;
    cp_rtm_subscribe(rtm, 0, 0, RTM_IP_PROTO_ISIS, &sub);

    sub.target_proto = RTM_PROTO_STATIC;
    sub.target_sub_proto = RTM_SUB_PROTO_NA;
    cp_rtm_subscribe(rtm, 0, 0, RTM_IP_PROTO_ISIS, &sub);

    //rtm_on_demand_route_request(rtm, RTM_DEFAULT_VRF, 0, RTM_IP_PROTO_ISIS);
}
