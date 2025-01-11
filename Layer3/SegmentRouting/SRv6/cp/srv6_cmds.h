#ifndef __SRV6_COMMAND_CODES__
#define __SRV6_COMMAND_CODES__


/* config node <node-name> protocol source-packet-routing srv6  */
#define IPV6_SRV6_ENABLE_CONFIG  1
/* config node <node-name> protocol source-packet-routing srv6 locator <loc-name> <ipv6-address> <[prefix-len]>*/
#define IPV6_SRV6_LOCATOR_CONFIG  2
/* config node <node-name> ipv6 route [no] <ipv6-address> <mask>  srv6 endpoint end [flavor [psp|usp|usd]]*/
#define IPV6_SRV6_STATIC_ROUTE_SID_CONFIG  3
/* config node <node-name> ipv6 route [no] <ipv6-address> <mask>  srv6 endpoint end-x <oif-name> [flavor [psp | usp | usd ]]*/
#define IPV6_SRV6_ADJ_SID_CONFIG  4
/* config node <node-name> ipv6 route <v6-address> <mask> srv6 endpoint end-b6-encaps segment-list <seg1> <seg2> <seg3> .... <segn> [flavor [psp | usp | usd ]] */
#define IPV6_SRV6_END_B6_ENCAPS_SID_CONFIG 5
/* config node <node-name> ipv6 route <v6-address> <mask> srv6 endpoint end-b6-x-encaps segment-list <seg1> <seg2> <seg3> .... <segn> nexthop <oif-name> [flavor [psp | usp | usd ]]*/
#define IPV6_SRV6_END_B6_ENCAPS_X_SID_CONFIG 6
/* config node <node-name> ipv6 route <v6-address> <mask>  binding-sid <v6-address>*/ 
#define IPV6_SRV6_BINDING_SID_CONFIG 7
/* run node <node-name> ping6 srv6 <seg1> <seg2> <seg3> <seg4> . . .  */
 #define CMDCODE_PING6_SRV6 8
/* config node H1 protocol source-packet-routing srv6 endpoint end 
    <ipv6-addr> [flavor [psp | usp | usd ]] */ 
 #define CMD_CODE_END_SID_CONFIG 9

#define IPV6_SRV6_LOCATOR_CONFIG_ALGORITHM 10



/* show node <node-name> protocol srv6 locator */
#define CMD_CODE_SHOW_SRV6_LOCAL_ROUTES 20


#endif 