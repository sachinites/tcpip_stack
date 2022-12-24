#ifndef __GRE_COMDCODES__
#define __GRE_COMDCODES__

/* config node <node-name> interface tunnel <tunnel-id> */
#define GRE_CONFIG_CREATE_TUNNEL_INTF   1

/* config node <node-name> interface tunnel <tunnel-id> tunnel-source < [ip-addr | interface <if-name>] > */
#define GRE_CONFIG_TUNNEL_SOURCE_IPADDR 2
#define GRE_CONFIG_TUNNEL_SOURCE_INTF 3

/* config node <node-name> interface tunnel <tunnel-id> tunnel-destination ip-addr */
#define GRE_CONFIG_TUNNEL_DESTINATION 4

/* config node <node-name> interface tunnel <tunnel-id> ip-address <intf-ip-address> <mask> */
#define GRE_CONFIG_TUNNEL_LOCAL_IP   5

#endif 