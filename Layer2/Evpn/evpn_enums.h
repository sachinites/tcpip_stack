#ifndef __EVPN_ENUMS__
#define __EVPN_ENUMS__

typedef enum evpn_rt_type_ {

    EVPN_RT_TYPE_1= 1,
    EVPN_RT_TYPE_MAC_ONLY = 2,
    EVPN_RT_TYPE_MAC_IP = 2,
    EVPN_RT_TYPE_IMET = 3,
    EVPN_RT_TYPE_4 = 4,
    EVPN_RT_TYPE_L3_VNI = 5

} evpn_rt_type_t;

typedef enum evpn_proto_ {

    EVPN_PROTO_BGP = 1,
    EVPN_PROTO_STATIC = 2,
    EVPN_PROTO_DP = 3

} evpn_proto_t;

/* EVPN RT Flags */
#define EVPN_RT_F_LOCAL             1
#define EVPN_RT_F_SENT_TO_BGP       2
#define EVPN_RT_F_SENT_TO_DP        4
#define EVPN_RT_F_SENT_TO_MAC_VRF   8
#define EVPN_RT_F_SENT_TO_IP_VRF    16

#endif 
