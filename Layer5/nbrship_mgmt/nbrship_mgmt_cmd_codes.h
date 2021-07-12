/*
 * =====================================================================================
 *
 *       Filename:  nbrship_mgmt_cmd_codes.h
 *
 *    Description: This file defines the CLI cmd codes for nbrship mgmt protocol 
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

#ifndef __NBR_MGMT_CMD_CODES__
#define __NBR_MGMT_CMD_CODES__

/* conf node <node-name> [no] protocol nmp*/
#define CMDCODE_CONF_NODE_NBRSHIP_ENABLE    1
/* config node <node-name> [no] protocol nmp interface <intf-name>*/
#define CMDCODE_CONF_NODE_INTF_NBRSHIP_ENABLE   2
/* config node <node-name> [no] protocol nmp interface all*/
#define CMDCODE_CONF_NODE_INTF_ALL_NBRSHIP_ENABLE   3


/* show node <node-name> protocol nmp nbrships*/
#define CMDCODE_SHOW_NODE_NBRSHIP   4
/* show node <node-name> nmp state*/
#define CMDCODE_SHOW_NODE_NMP_STATE 5
/* show node <node-name> protocol nmp stats*/
#define CMDCODE_SHOW_NODE_NMP_PROTOCOL_ALL_INTF_STATS   6

#endif /* __NBR_MGMT_CMD_CODES__  */



