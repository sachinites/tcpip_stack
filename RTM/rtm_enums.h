#ifndef __RTM_ENUMS__
#define __RTM_ENUMS__

typedef enum RTM_AFI_ {

    RTM_AF_IPV4,
    RTM_AF_IPV6
    
} RTM_AFI_T;

typedef enum protocols_
{
    RTM_PROTO_STATIC    = 0x00010000,
    RTM_PROTO_CONNECTED = 0x00020000,
    RTM_PROTO_LOCAL     = 0x00030000,
    RTM_PROTO_BGP       = 0x00040000,
    RTM_PROTO_ISIS      = 0x00050000,
    RTM_PROTO_SR        = 0x00060000,
    RTM_PROTO_LFA       = 0x00070000,
    RTM_PROTO_LDP       = 0x00080000,
    RTM_PROTO_SRTE      = 0x00090000

} RTM_PROTO_T;

typedef enum sub_protocols_ {

    RTM_PROTO_L1_ISIS_INT = 1, 
    RTM_PROTO_L2_ISIS_INT, 
    RTM_PROTO_L1_ISIS_EXT, 
    RTM_PROTO_L2_ISIS_EXT, 

    RTM_PROTO_BGP_INT = 1,
    RTM_PROTO_BGP_EXT,
    RTM_PROTO_BGP_VPN,
    RTM_PROTO_BGP_EVPN

} RTM_SUB_PROTO_T;

typedef enum rt_action_type_ {

    RTM_RT_REJECT,
    RTM_RT_DISCARD,
    RTM_RT_LOCAL,
    RTM_RT_FORWARD,
    RTM_RT_TUNNEL

} RT_ACTION_TYPE_T;

typedef enum nh_action_type_ {

    RTM_NH_REJECT,
    RTM_NH_DISCARD,
    RTM_NH_LOCAL,
    RTM_NH_FORWARD,
    RTM_NH_TUNNEL

} RT_ACTION_TYPE_T;

#endif 