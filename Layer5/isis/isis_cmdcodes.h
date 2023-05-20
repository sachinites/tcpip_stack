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
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_INTF 5
/* show node <node-name> protocol isis interface */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_INTF 6
/* show node <node-name> protocol isis lsdb */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_LSDB 7
/* show node <node-name> protocol isis event-counters */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_EVENT_COUNTERS 8
/* show node <node-name> protocol isis adjacency */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_ADJACENCY 9
/* clear node <node-name> protocol isis lsdb */
#define CMDCODE_CLEAR_NODE_ISIS_LSDB 10
/* show node <node-name> protocol isis lsdb <rtr-id> */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_LSP 11
/* config node <node-name> protocol isis overload */
#define CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD 12
/* config node <node-name> protocol isis overload timeout <time in sec>*/
#define CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD_TIMEOUT 13

/* interface group related CLIs */
/* config node <node-name> protocol isis interface-group <grp-name>*/
#define CMDCODE_CONF_NODE_ISIS_PROTO_INTF_GRP   14
/* config node <node-name> protocol isis interface <if-name> interface-group <grp-name>*/
#define CMDCODE_CONF_NODE_ISIS_PROTO_INTF_GROUP_MEMBERSHIP   15
/* show node <node-name> protocol isis interface-groups*/
#define CMDCODE_SHOW_NODE_ISIS_PROTO_INTF_GROUPS 16
/* config node <node-name> protocol isis dynamic-interface-group */ 
#define CMDCODE_CONF_NODE_ISIS_PROTO_DYN_IGRP 17
/* config node <node-name> protocol isis layer2-map*/
#define CMDCODE_CONF_NODE_ISIS_PROTO_LAYER2_MAP 18
/* show node <node-name> protocol isis ted*/
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_TED 19
/* show node <node-name> protocol isis ted <rtr-id> <pn-id>*/
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_TED_ENTRY 20
/* show node <node-name> protocol isis ted detail*/
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_TED_DETAIL 21
/* show node <node-name> protocol isis ted <rtr-id> <pn-id> detail*/
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_TED_ENTRY_DETAIL 22
/* clear node <node-name> protocol isis adjacency */
#define CMDCODE_CLEAR_NODE_ISIS_ADJACENCY 23
/*  show node <node-name> protocol isis spf-log */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_SPF_LOG 24

/* Policies */
/* config node <node-name> protocol isis import-policy <pfx-list-name> */
#define CMDCODE_CONF_NODE_ISIS_PROTO_IMPORT_POLICY 25
/* config node <node-name> protocol isis export-policy <pfx-list-name> */
#define CMDCODE_CONF_NODE_ISIS_PROTO_EXPORT_POLICY 26

/* Interface Types*/
/* config node <node-name> protocol isis interface <if-name> p2p */
#define CMDCODE_CONF_NODE_ISIS_PROTO_INTF_P2P   27
/* config node <node-name> protocol isis interface <if-name> lan */
#define CMDCODE_CONF_NODE_ISIS_PROTO_INTF_LAN   28

 /* config node <node-name> protocol isis interface <if-name> priority <val>*/
#define CMDCODE_CONF_NODE_ISIS_PROTO_INTF_PRIORITY 29

 /* config node <node-name> protocol isis interface <if-name> metric <val>*/
#define CMDCODE_CONF_NODE_ISIS_PROTO_INTF_METRIC 30

/* show node <node-name> protocol isis link-state-database*/
#define CMCODE_SHOW_ISIS_ADVT_DB  31

#endif /* __ISIS_CMDCODES__ */