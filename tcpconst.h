/*
 * =====================================================================================
 *
 *       Filename:  tcpconst.h
 *
 *    Description:  This file defines all standard Constants used by TCPIP stack
 *
 *        Version:  1.0
 *        Created:  Tuesday 24 September 2019 01:09:27  IST
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

#ifndef __TCPCONST__
#define __TCPCONST__

/*Specified in ethernet_hdr->type*/
#define ARP_BROAD_REQ   1
#define ARP_REPLY       2
#define ARP_MSG         806
#define BROADCAST_MAC   0xFFFFFFFFFFFF
#define ETH_IP          0x0800
#define ICMP_PRO        1
#define ICMP_ECHO_REQ   8
#define ICMP_ECHO_REP   0
#define MTCP            20
#define USERAPP1        21
#define VLAN_8021Q_PROTO    0x8100
#define IP_IN_IP        4
#define NMP_HELLO_MSG_CODE	13 /*Randomly chosen*/
#define INTF_MAX_METRIC     16777215 /*Choosen as per the standard = 2^24 -1*/
#define INTF_METRIC_DEFAULT 1

/*Add DDCP Protocol Numbers*/
#define DDCP_MSG_TYPE_FLOOD_QUERY    1  /*Randomly chosen, should not exceed 2^16 -1*/
#define DDCP_MSG_TYPE_UCAST_REPLY    2  /*Randomly chosen, must not exceed 255*/
#define PKT_BUFFER_RIGHT_ROOM        128
#define MAX_NXT_HOPS        4

#define IP_HDR_INCLUDED (1  << 0)
#define DATA_LINK_HDR_INCLUDED  (1 << 1)


/*Dynamic Registration of Protocol with TCP/IP stack*/
#define MAX_L2_PROTO_INCLUSION_SUPPORTED    16
#define MAX_L3_PROTO_INCLUSION_SUPPORTED    16

#endif /* __TCPCONST__ */

