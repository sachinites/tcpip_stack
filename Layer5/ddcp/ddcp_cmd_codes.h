/*
 * =====================================================================================
 *
 *       Filename:  nbrship_mgmt_cmd_codes.h
 *
 *    Description: This file defines the CLI cmd codes for ddcp protocol 
 *
 *        Version:  1.0
 *        Created:  07/12/2021 12:43:58 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#ifndef __DDCP_CMD_CODES__
#define __DDCP_CMD_CODES__


#define CMDCODE_RUN_DDCP_QUERY          1  /* run node <node-name> ddcp-query*/
#define CMDCODE_RUN_DDCP_QUERY_PERIODIC 2  /* run node <node-name> ddcp-query periodic <ddcp-q-interval in sec>*/

#define CMDCODE_SHOW_DDCP_DB            3  /* show node <node-name> ddcp-db*/

#define CMDCODE_CONF_NODE_DDCP_PROTO    4  /* conf node <node-name> protocol ddcp */

/* conf node <node-name> protocol ddcp interface <if-name> */
#define CMDCODE_CONF_NODE_DDCP_PROTO_INTF_ENABLE    5

/*  conf node <node-name> protocol ddcp interface all */
#define CMDCODE_CONF_NODE_DDCP_PROTO_INTF_ALL_ENABLE 6

#endif /* __DDCP_CMD_CODES__  */



