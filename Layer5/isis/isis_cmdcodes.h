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

#endif /* __ISIS_CMDCODES__ */