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
#define CMDCODE_CONFIG_RTR_ID       3   /* config node <node-name> router-id <rtr-id>*/
#define CMDCODE_RUN_ARP             4   /*run node <node-name> resolve-arp <ip-address>*/
#define CMDCODE_INTF_CONFIG_SWITCHPORT 5   /*config node <node-name> interface <intf-name> l2mode <access|trunk>*/
#define CMDCODE_INTF_CONFIG_IP_ADDR 6   /*config node <node-name> interface <intf-name> ip-address <ip-address> <mask>*/
#define CMDCODE_INTF_CONFIG_IPV6_ADDR 77   /*config node <node-name> interface <intf-name> ipv6-address <ipv6-address/mask>*/
#define CMDCODE_INTF_CONFIG_VLAN    7   /*config node <node-name> interface <intf-name> switchport access vlan <vlan-id>*/
#define CMDCODE_SHOW_NODE_MAC_TABLE 8   /*show node <node-name> mac*/
#define CMDCODE_SHOW_NODE_RT_TABLE  9   /*show node <node-name> rt*/
#define CMDCODE_CONF_NODE_L3ROUTE   10  /*config node <node-name> route <ip-address> <mask> [<gw-ip> <oif>]*/
#define CMDCODE_ERO_PING            11  /*run <node-name> ping <ip-address> ero <ero-ip-address>*/
#define CMDCODE_UNUSED_1            12  /*Not used*/

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

/* conf node <node-name> [no] rib <rib-name> import-policy <prefix-lst-name> */
#define CMDCODE_CONF_RIB_IMPORT_POLICY 37

#define CMDCODE_INTF_CONFIG_LOOPBACK_CREATE 38

#define CMDCODE_CLEAR_RT_TABLE 39

/* conf node <node-name> [no] traceoptions access-list <access-list-name>*/
#define CMDCODE_DEBUG_ACCESS_LIST_FILTER_NAME 40

/* conf node <node-name> [no]  interface <if-name> traceoptions access-list <access-list-name>*/
#define CMDCODE_DEBUG_ACCESS_LIST_FILTER_NAME_INTF 41

/* config node <node-name> transport-service-profile <transport-service-name> */
#define CMDCODE_CONFIG_NODE_TRANSPORT_SVC   42

/* config node <node-name> transport-service-profile <transport-service-name> vlan add <vlan-d>*/
#define CMDCODE_CONFIG_NODE_TRANSPORT_SVC_VLAN_ADD  43

/* config node <node-name> interface ethernet <if-name>  transport-service-profile <transport-service-name> */
#define CMDCODE_CONFIG_INTF_TRANSPORT_SVC  46

/* show node <node-name> transport-service-profile <tsp-name>*/
#define CMDCODE_SHOW_TRANSPORT_SVC_PROFILE  47

/* config node <node-name> interface vlan <vlan-id> */
#define CMDCODE_CONFIG_INTF_VLAN_CREATE  48

/* config node <node-name> interface vlan <vlan-id> <up|down> */
#define CMDCODE_CONFIG_INTF_VLAN_UP_DOWN  50

/* show node <node-name> vlan members */
#define CMDCODE_SHOW_VLAN_MEMBERS   51

  /*config node <node-name> interface virtual-port <vp-name> */
#define CMDCODE_INTF_CONFIG_VP_CREATE 52

/*config node <node-name> interface virtual-port <if-name> overlay-tunnel <tunnel-name>*/
#define CMDCODE_INTF_CONFIG_BIND_OVERLAY_TUNNEL 53

/* show node <node-name> rt6*/
#define CMDCODE_SHOW_NODE_RT6_TABLE 54

 /* debug show node <node-name> mtrie rt6 */
#define CMDCODE_DEBUG_SHOW_NODE_MTRIE_RT6 55

 /* run node <node-name> ip-traffic <src-addr> <dst-addr> <protocol> count <count> */
#define CMDCODE_RUN_TRAFFIC 56

/* config node <node-name> interface vlan <vlan-id> vni <vni-id> */
#define CMDCODE_CONFIG_INTF_VLAN_VNI 57

/* show node <node-name> vlan-db */
#define CMDCODE_SHOW_VLAN_DB 58

/* show node <node-name> vlan vni <vni-id> */
#define CMDCODE_SHOW_NODE_MAC_VNI_TABLE 59

/* config node <node-name> interface nve <if-name> */
#define CMDCODE_INTF_CONFIG_NVE_CREATE 60

/* config node <node-name> interface nve <if-name> member l2vni <vni-id> */
#define CMDCODE_INTF_CONFIG_NVE_MEMBER_VNI 61

/* config node <node-name> mac install vlan <vlan-id> <mac-address> remote-vtep <ip-address> */
#define CMDCODE_CONFIG_MAC_INSTALL 62

/* config node <node-name> rtm-route prefix <prefix/mask> 
    <proto-id> <sub-proto-id> <instance-no> l3vpn srv6-sid <ipv6-addr> */
#define CMDCODE_CONFIG_RTM_ROUTE_L3VPN_SRV6 63

#define CMDCODE_SHOW_NODE_RTM_ROUTE 67

#define CMDCODE_SHOW_NODE_RTM_ROUTE_DETAIL 68

/* config node <node-name> rtm-route prefix <prefix/mask> <proto-id> <sub-proto-id> <instance-no> <action-id> <metric> gateway <gateway-ip> interface <if-name> label-stack <list of labels> */
#define CMDCODE_CONFIG_RTM_ROUTE_IP 69

/* show node <node-name> rtm protocol-subscriptions */
#define CMDCODE_SHOW_NODE_RTM_PROTOCOL_SUBSCRIPTIONS 70

/* show node <node-name> rtm <rib-name> unresolvable-routes */
#define CMDCODE_SHOW_NODE_RTM_UNRESOLVABLE_ROUTES 71

/* show node <node-name> rtm <rib-name> ppt-db */
#define CMDCODE_SHOW_NODE_RTM_PPT_DB 72

/* show node <node-name> rtm <rib-name> ppt-db <prefix-filter> */
#define CMDCODE_SHOW_NODE_RTM_PPT_DB_FILTER 73

#define CMDCODE_CONF_INTF_VRF 75

/* show node <node-name> vrf */
#define CMDCODE_SHOW_NODE_VRF 76

/* Flag to distinguish if the CLI typed should go to
  control plane scheduler or data plane scheduler*/
#define CLI_F_CONTROL_PLANE 1
#define CLI_F_DATA_PLANE 2

#endif /* __CMDCODES__ */
