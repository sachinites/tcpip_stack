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
#define CMDCODE_PING                2   /*run <node-name> ping <ip-address>*/
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

#endif /* __CMDCODES__ */
