#ifndef __ISIS_CMDCODES__
#define __ISIS_CMDCODES__

#define ISIS_CONFIG_NODE_ENABLE  1
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL 2
#define CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ALL_ENABLE 3
#define CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ENABLE 4
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_INTF    5
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_INTF    6

#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_LSDB 7

/* show node <node-name> protocol isis adjacency */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_ADJACENCY 8
/* clear node <node-name> protocol isis adjacency */
#define CMDCODE_CLEAR_NODE_ISIS_ADJACENCY 9
/* show node <node-name> protocol isis lsdb <A,B.C.D> */
#define CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_LSP_DETAIL 10
/* clear node <node-name> protocol isis lsdb */
#define CMDCODE_CLEAR_NODE_ISIS_LSDB 11
#endif 