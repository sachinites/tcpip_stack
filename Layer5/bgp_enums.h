#ifndef __BGP_ENUM__
#define __BGP_ENUM__

#define TR_BGP_CONFIGS          (1 << 0)
#define TR_BGP_EVENTS           (1 << 1)
#define TR_BGP_GRPC_TALK        (1 << 2)    
#define TR_BGP_RT_EVENTS        (1 << 3)
#define TR_BGP_RT_ERRORS        (1 << 4)


#define BGP_RTM_TAG  "BGP-RTM"
#define BGP_RTM_IM   "BGP-RT-IMPORT"
#define BGP_RTM_EM   "BGP-RT-EXPORT"


/* BGP Global Rib Names */
#define BGP_VPN_V4_RIB_NAME "bgp.vpnv4.0"
#define BGP_IPV4_UNICAST_RIB_NAME "bgp.ipv4.0"
#define BGP_EVPN_RIB_NAME "bgp.evpn.0"
#define BGP_L3EVPN_RIB_NAME "bgp.l3evpn.0"

#endif 