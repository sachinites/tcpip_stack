#ifndef __EVPN_ENUMS__
#define __EVPN_ENUMS__

typedef enum evpn_rt_type_ {

    EVPN_RT_TYPE_1= 1,
    EVPN_RT_TYPE_MAC_ONLY = 2,
    EVPN_RT_TYPE_MAC_IP = 2,
    EVPN_RT_TYPE_IMET = 3,
    EVPN_RT_TYPE_4 = 4,
    EVPN_RT_TYPE_IP_PREFIX = 5

} evpn_rt_type_t;

#endif 
