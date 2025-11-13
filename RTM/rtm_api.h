#ifndef __RTM_API__
#define __RTM_API__

#include "rtm_error.h"
#include "rtm_common.h"
#include "rtm_enums.h"
#include "rtm.h"
#include "rtm_proto.h"
#include "rtm_route.h"
#include "rtm_nh.h"

rtm_error_t 
rtm_install_static_route (
        rtm_t *rtm,
        rtm_prefix_t *prefix, 
        rtm_prefix_t *gateway,
        uint32_t oif_index, uint32_t cost);

rtm_error_t 
rtm_install_static_local_route (
        rtm_t *rtm,
        rtm_prefix_t *prefix, 
        uint32_t oif_index, uint32_t cost);

rtm_error_t 
rtm_install_protocol_route (
        rtm_t *rtm,
        rtm_prefix_t *prefix, 
        rtm_prefix_t *gateway,
        RTM_PROTO_T proto,
        RTM_SUB_PROTO_T sub_proto,
        uint32_t instance_no,
        uint32_t oif_index, 
        uint32_t cost);

rtm_error_t 
rtm_install_protocol_route_nh (rtm_t *rtm,
                                rtm_prefix_t *prefix, 
                                rtm_nh *nh, 
                                rtm_nh_proto_t *nh_proto);

rtm_error_t 
rtm_uninstall_protocol_route_nh (rtm_t *rtm,
                                  rtm_prefix_t *prefix, 
                                  rtm_nh *nh, 
                                  rtm_nh_proto_t *nh_proto);

rtm_error_t 
rtm_uninstall_protocol_all_route (
                                   rtm_t *rtm,
                                    RTM_PROTO_T proto,
                                    RTM_SUB_PROTO_T sub_proto);

rtm_error_t 
rtm_fib_install_protocol_route_nh (rtm_t *rtm,
                                           rtm_route *route);
                                         

rtm_error_t 
rtm_fib_uninstall_protocol_route_nh (rtm_t *rtm,
                                                         rtm_route *route);
                                                        

#endif 