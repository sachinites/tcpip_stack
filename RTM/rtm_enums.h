#ifndef __RTM_ENUMS__
#define __RTM_ENUMS__

typedef enum protocols_ {

    RTM_PROTO_STATIC, 
    RTM_PROTO_CONNECTED,
    RTM_PROTO_LOCAL,
    RTM_PROTO_BGP,  
    RTM_IP_PROTO_ISIS, 
    RTM_PROTO_OSPF,
    RTM_PROTO_LDP,
    RTM_PROTO_MAX

} RTM_PROTO_T;

typedef enum sub_protocols_ {

    RTM_SUB_PROTO_NA,
    RTM_PROTO_L1_ISIS_INT,
    RTM_PROTO_L2_ISIS_INT, 
    RTM_PROTO_L1_ISIS_EXT, 
    RTM_PROTO_L2_ISIS_EXT, 

    RTM_PROTO_BGP_INT,
    RTM_PROTO_BGP_EXT,
    RTM_PROTO_BGP_VPN,
    RTM_PROTO_BGP_EVPN,

    RTM_SUB_PROTO_OSPF_EXT,
    RTM_SUB_PROTO_OSPF_INTER,
    RTM_SUB_PROTO_OSPF_INTRA,

    RTM_SUB_PROTO_SR,
    RTM_SUB_PROTO_SRTE,
    RTM_SUB_PROTO_SRv6,
    RTM_SUB_PROTO_SRv6_SRTE,

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
    RTM_ADMIN_DIST_LDP          = 7,
    RTM_ADMIN_DIST_SRTE         = 8,
    RTM_ADMIN_DIST_TNL_ENDP     = 2,
    RTM_ADMIN_DIST_UNKNOWN      = 255
    
} RTM_AD_T;

#define RTM_DEFAULT_VRF 0

/* Helper function to convert protocol to string */
static const char* rtm_proto_to_string(RTM_PROTO_T proto) {
    switch(proto) {
        case RTM_PROTO_STATIC: return "Static";
        case RTM_PROTO_CONNECTED: return "Connected";
        case RTM_PROTO_LOCAL: return "Local";
        case RTM_PROTO_OSPF: return "OSPF";
        case RTM_PROTO_BGP: return "BGP";
        case RTM_IP_PROTO_ISIS: return "ISIS";
        case RTM_PROTO_LDP: return "LDP";
        default: return "Unknown";
    }
}

/* Helper function to convert sub-protocol to string */
static const char* rtm_sub_proto_to_string(RTM_SUB_PROTO_T sub_proto) {
    switch(sub_proto) {
        case RTM_SUB_PROTO_NA: return "NA";
        case RTM_PROTO_L1_ISIS_INT: return "L1-ISIS-INT";
        case RTM_PROTO_L2_ISIS_INT: return "L2-ISIS-INT";
        case RTM_PROTO_L1_ISIS_EXT: return "L1-ISIS-EXT";
        case RTM_PROTO_L2_ISIS_EXT: return "L2-ISIS-EXT";
        case RTM_PROTO_BGP_INT: return "BGP-INT";
        case RTM_PROTO_BGP_EXT: return "BGP-EXT";
        case RTM_PROTO_BGP_VPN: return "BGP-VPN";
        case RTM_PROTO_BGP_EVPN: return "BGP-EVPN";
        case RTM_SUB_PROTO_OSPF_EXT: return "OSPF-EXT";
        case RTM_SUB_PROTO_OSPF_INTER: return "OSPF-INTER";
        case RTM_SUB_PROTO_OSPF_INTRA: return "OSPF-INTRA";
        case RTM_SUB_PROTO_SR: return "SR-MPLS";
        case RTM_SUB_PROTO_SRTE: return "SR-TE";
        case RTM_SUB_PROTO_SRv6: return "SRv6";
        case RTM_SUB_PROTO_SRv6_SRTE: return "SRv6-SRTE";
        default: return "Unknown";
    }
}

/* Helper function to convert NH action to string */
static const char* rtm_nh_action_to_string(RTM_NH_ACTION_TYPE_T action) {
    switch(action) {
        case RTM_NH_ACTION_REJECT: return "Reject";
        case RTM_NH_ACTION_DISCARD: return "Discard";
        case RTM_NH_ACTION_LOCAL: return "Local";
        case RTM_NH_ACTION_CONNECTED: return "Connected";
        case RTM_NH_ACTION_FORWARD: return "Forward";
        case RTM_NH_ACTION_TUNNEL: return "Tunnel";
        default: return "Unknown";
    }
}

#endif 
