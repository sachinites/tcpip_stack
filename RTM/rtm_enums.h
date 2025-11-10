#ifndef __RTM_ENUMS__
#define __RTM_ENUMS__

typedef enum RTM_AFI_ {

    RTM_AF_IPV4,
    RTM_AF_IPV6,
    RTM_AF_LABEL,
    RTM_AFI_MAC,
    RTM_AFI_MAX

} RTM_AFI_T;

typedef enum protocols_ {

    RTM_PROTO_STATIC, 
    RTM_PROTO_CONNECTED,
    RTM_PROTO_LOCAL,
    RTM_PROTO_BGP,  
    RTM_PROTO_ISIS, 
    RTM_PROTO_SR,
    RTM_PROTO_LFA,
    RTM_PROTO_LDP,
    RTM_PROTO_SRTE,
    RTM_PROTO_MAX

} RTM_PROTO_T;

typedef enum sub_protocols_ {

    RTM_SUB_PROTO_STATIC,
    RTM_PROTO_L1_ISIS_INT,
    RTM_PROTO_L2_ISIS_INT, 
    RTM_PROTO_L1_ISIS_EXT, 
    RTM_PROTO_L2_ISIS_EXT, 

    RTM_PROTO_BGP_INT,
    RTM_PROTO_BGP_EXT,
    RTM_PROTO_BGP_VPN,
    RTM_PROTO_BGP_EVPN,

    RTM_SUB_PROTO_MAX

} RTM_SUB_PROTO_T;

/* Order Matter : Most preferred action first */
typedef enum nh_action_type_ {

    RTM_NH_ACTION_LOCAL,
    RTM_NH_ACTION_CONNECTED,
    RTM_NH_ACTION_FORWARD,
    RTM_NH_ACTION_TUNNEL,
    RTM_NH_ACTION_DISCARD,
    RTM_NH_ACTION_REJECT,
    RTM_NH_ACTION_MAX

} RTM_NH_ACTION_TYPE_T;

typedef enum rtm_admin_dist_ {

    RTM_ADMIN_DIST_CONNECTED    = 0,
    RTM_ADMIN_DIST_STATIC       = 1,
    RTM_ADMIN_DIST_OSPF_INTER   = 110,
    RTM_ADMIN_DIST_OSPF_INTRA   = 110,
    RTM_ADMIN_DIST_OSPF_EXT     = 110,
    RTM_ADMIN_DIST_BGP_INT      = 200,
    RTM_ADMIN_DIST_BGP_EXT      = 20,
    RTM_ADMIN_DIST_ISIS         = 115,
    RTM_ADMIN_DIST_TNL_ENDP     = 2,
    RTM_ADMIN_DIST_UNKNOWN      = 255
    
} RTM_AD_T;

typedef enum mpls_op_ {

    LBL_STACK_OPS_UNKNOWN,
    LBL_SWAP,
    LBL_CONTINUE = LBL_SWAP,
    LBL_NEXT,
    LBL_PUSH = LBL_NEXT,
    LBL_POP

} mpls_op_t;

#define RTM_DEFAULT_VRF 0

#endif 