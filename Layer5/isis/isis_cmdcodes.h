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

/* run node <node-name> protocol isis lsp <rtr-id> <pn-id> install*/
#define CMDCODE_RUN_ISIS_LSP_TED_INSTALL 32

/* run node <node-name> protocol isis lsp <rtr-id> <pn-id> uninstall*/
#define CMDCODE_RUN_ISIS_LSP_TED_UNINSTALL 33

/* Enable/Disable Tracing options for ISIS*/
/* config node <node-name> protocol isis [no] traceoptions console*/
#define CMDCODE_CONF_ISIS_LOG_CONSOLE    34
/* config node <node-name> protocol isis [no] traceoptions file-logging*/
#define CMDCODE_CONF_ISIS_LOG_FILE    35
/* config node <node-name> protocol isis [no] traceoptions spf */
#define CMDCODE_CONF_ISIS_LOG_SPF    36
/* config node <node-name> protocol isis [no] traceoptions lsdb */
#define CMDCODE_CONF_ISIS_LOG_LSDB    37
/* config node <node-name> protocol isis [no] traceoptions packet */
#define CMDCODE_CONF_ISIS_LOG_PACKET    38
/* config node <node-name> protocol isis [no] traceoptions packet hello*/
#define CMDCODE_CONF_ISIS_LOG_PACKET_HELLO    39
/* config node <node-name> protocol isis [no] traceoptions packet lsp*/
#define CMDCODE_CONF_ISIS_LOG_PACKET_LSP    40
/* config node <node-name> protocol isis [no] traceoptions adjacency*/
#define CMDCODE_CONF_ISIS_LOG_ADJ    41
/* config node <node-name> protocol isis [no] traceoptions route*/
#define CMDCODE_CONF_ISIS_LOG_ROUTE    42
/* config node <node-name> protocol isis [no] traceoptions policy*/
#define CMDCODE_CONF_ISIS_LOG_POLICY    43
/* config node <node-name> protocol isis [no] traceoptions events*/
#define CMDCODE_CONF_ISIS_LOG_EVENTS    44
/* config node <node-name> protocol isis [no] traceoptions errors*/
#define CMDCODE_CONF_ISIS_LOG_ERRORS    45
/* config node <node-name> protocol isis [no] traceoptions all*/
#define CMDCODE_CONF_ISIS_LOG_ALL    46

/* show node <node-name> protocol isis traceoptions*/
#define CMCODE_SHOW_ISIS_TRACEOPTIONS 47
/* clear node <node-name> protocol isis reset-log-file*/
#define CMDCODE_RESET_NODE_ISIS_LOG_FILE 48
/* show node <node-name> protocol isis spf-result */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_SPF_RESULT 49

 /* debug node <node-name> protocol isis toggle-lsdb-advt */
 #define CMDCODE_DEBUG_NODE_ISIS_TOGGLE_LSDB_ADVT 50
 
#endif /* __ISIS_CMDCODES__ */