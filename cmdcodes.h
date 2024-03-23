/*
 * =====================================================================================
 *
 *       Filename:  cmdcodes.h
 *
 *    Description:  This file Comtains all CMD Codes for commands
 *
 *        Version:  1.0
 *        Created:  Friday 20 September 2019 06:44:01  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *        
 *        This file is part of the NetworkGraph distribution (https://github.com/sachinites).
 *        Copyright (c) 2017 Abhishek Sagar.
 *        This program is free software: you can redistribute it and/or modify
 *        it under the terms of the GNU General Public License as published by  
 *        the Free Software Foundation, version 3.
 *
 *        This program is distributed in the hope that it will be useful, but 
 *        WITHOUT ANY WARRANTY; without even the implied warranty of 
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *        General Public License for more details.
 *
 *        You should have received a copy of the GNU General Public License 
 *        along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * =====================================================================================
 */

#ifndef __CMDCODES__
#define __CMDCODES__

#define CMDCODE_SHOW_NW_TOPOLOGY    1   /*show topology*/
#define CMDCODE_PING                2   /*run node <node-name> ping <ip-address> -c <count>*/
#define CMDCODE_SHOW_NODE_ARP_TABLE 3   /*show node <node-name> arp*/
#define CMDCODE_RUN_ARP             4   /*run node <node-name> resolve-arp <ip-address>*/
#define CMDCODE_INTF_CONFIG_L2_MODE 5   /*config node <node-name> interface <intf-name> l2mode <access|trunk>*/
#define CMDCODE_INTF_CONFIG_IP_ADDR 6   /*config node <node-name> interface <intf-name> ip-address <ip-address> <mask>*/
#define CMDCODE_INTF_CONFIG_VLAN    7   /*config node <node-name> interface <intf-name> vlan <vlan-id>*/
#define CMDCODE_SHOW_NODE_MAC_TABLE 8   /*show node <node-name> mac*/
#define CMDCODE_SHOW_NODE_RT_TABLE  9   /*show node <node-name> rt*/
#define CMDCODE_CONF_NODE_L3ROUTE   10  /*config node <node-name> route <ip-address> <mask> [<gw-ip> <oif>]*/
#define CMDCODE_ERO_PING            11  /*run <node-name> ping <ip-address> ero <ero-ip-address>*/
#define CMDCODE_UNUSED_1            12  /*Not used*/
#define CMDCODE_SHOW_INTF_STATS     13     /*show node <node-name> interface statistics*/
#define CMDCODE_DEBUG_SHOW_NODE_TIMER   14 /*debug show node <node-name> timer*/

#define CMDCODE_RUN_SPF             15  /*run node <node-name> spf*/
#define CMDCODE_SHOW_SPF_RESULTS    16  /*show node <node-name> spf-results*/
#define CMDCODE_RUN_SPF_ALL         17  /*run spf all*/

//Logging and Debugging
#define CMDCODE_DEBUG_LOGGING_PER_NODE   18  /*config node <node-name> traceoptions flag <all | no-all | recv | no-recv | send | no-send | stdout | no-stdout>*/
#define CMDCODE_DEBUG_LOGGING_PER_INTF   19  /*config node <node-name> interface <intf-name> traceoptions flag <all | no-all | recv | no-recv | send | no-send | stdout | no-stdout>*/
#define CMDCODE_DEBUG_SHOW_LOG_STATUS    20  /*show node <node-name> log-status*/
#define CMDCODE_DEBUG_GLOBAL_STDOUT      21  /*config global stdout*/
#define CMDCODE_DEBUG_GLOBAL_NO_STDOUT   22  /*config global no-stdout*/
/*Interface Up Down*/ 
#define CMDCODE_CONF_INTF_UP_DOWN        23 /*config node <node-name> interface <if-name> <up|down>*/

#define CMDCODE_INTF_CONFIG_METRIC       24 /*config node <node-name> interface <if-name> metric <metric-val>*/

#define CMDCODE_DEBUG_SHOW_NODE_TIMER_LOGGING	25 /* debug show node <node-name> timer logging */

/* Traffic generation */
#define CMDCODE_CONF_NODE_TRAFFIC_GEN	26 /* config node <node-name> interface <if-name> traffic-gen <dest-ip> */

#define CMDCODE_CLEAR_LOG_FILE  27 /* clear log-file */

#define CMDCODE_DEBUG_SHOW_MEMORY_USAGE 28 /* debug show mem-usage*/
#define CMDCODE_DEBUG_SHOW_MEMORY_USAGE_DETAIL 29 /*  debug show mem-usage detail <struct-name> */ 

/* Policy Command Codes */
#define CMDCODE_IMPORT_POLICY_CREATE_DELETE 30  /* config node <node-name> [no] import-policy <policy-name> */
#define CMDCODE_IMPORT_POLICY_PREFIX 31 /* config node <node-name> [no] import-policy <policy-name> prefix <prefix> <mask>*/

/* debug Commands */
#define CMDCODE_DEBUG_SHOW_NODE_MTRIE_RT 32 /* debug show node <node-name> mtrie rt */
#define CMDCODE_DEBUG_SHOW_NODE_MTRIE_ACL 33 /* debug show node <node-name> mtrie access-list <acl-name> */

#define CMDCODE_CONFIG_PREFIX_LST   34 /* config node <node-name> prefix-list <name> <seq-no> <network> <mask> [le <N>] [ge <N>] */

#define CMDCODE_SHOW_PREFIX_LST_ALL 35
#define CMDCODE_SHOW_PREFIX_LST_ONE 36

#define CMDCODE_CONF_RIB_IMPORT_POLICY 37  /* conf node <node-name> [no] rib <rib-name> import-policy <prefix-lst-name> */

#define CMDCODE_INTF_CONFIG_LOOPBACK 38

#define CMDCODE_CLEAR_RT_TABLE 39

/* conf node <node-name> [no] traceoptions access-list <access-list-name>*/
#define CMDCODE_DEBUG_ACCESS_LIST_FILTER_NAME 40

/* conf node <node-name> [no]  interface <if-name> traceoptions access-list <access-list-name>*/
#define CMDCODE_DEBUG_ACCESS_LIST_FILTER_NAME_INTF 41


/* config node <node-name> transport-service-profile <transport-service-name> */
#define CMDCODE_CONFIG_NODE_TRANSPORT_SVC   42

/* config node <node-name> transport-service-profile <transport-service-name> vlan add <vlan-d>*/
#define CMDCODE_CONFIG_NODE_TRANSPORT_SVC_VLAN_ADD  43

/* config node <node-name> transport-service-profile <transport-service-name> vlan del <vlan-d>*/
#define CMDCODE_CONFIG_NODE_TRANSPORT_SVC_VLAN_DEL  44

/* config node <node-name> transport-service-profile <transport-service-name> vlan del all*/
#define CMDCODE_CONFIG_NODE_TRANSPORT_SVC_VLAN_DEL_ALL  45

#endif /* __CMDCODES__ */
