#ifndef __ISIS_CMDCODES__
#define __ISIS_CMDCODES__

/* config node <node-name> protocol isis */
#define ISIS_CONFIG_NODE_ENABLE 1
/* config node <node-name> protocol isis interface <intf-name>*/
#define CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ENABLE 2
/* config node <node-name> protocol isis interface all*/
#define CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ALL_ENABLE 3
/* show node <node-name> protocol isis */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL 4
/* show node <node-name> protocol isis interface <if-name> */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_INTF 5
/* show node <node-name> protocol isis lsdb */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_LSDB 6
/* show node <node-name> protocol isis event-counters */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_EVENT_COUNTERS 7
/* clear node <node-name> protocol isis lsdb */
#define CMDCODE_CLEAR_NODE_ISIS_LSDB 8
/* show node <node-name> protocol isis lsdb <rtr-id> */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_LSP 9
/* config node <node-name> protocol isis overload */
#define CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD 10
/* config node <node-name> protocol isis overload timeout <time in sec>*/
#define CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD_TIMEOUT 11

/* interface group related CLIs */
/* config node <node-name> protocol isis interface-group <grp-name>*/
#define CMDCODE_CONF_NODE_ISIS_PROTO_INTF_GRP   12
/* config node <node-name> protocol isis interface <if-name> interface-group <grp-name>*/
#define CMDCODE_CONF_NODE_ISIS_PROTO_INTF_GROUP_MEMBERSHIP   13
/* show node <node-name> protocol isis interface-groups*/
#define CMDCODE_SHOW_NODE_ISIS_PROTO_INTF_GROUPS 14

#endif /* __ISIS_CMDCODES__ */