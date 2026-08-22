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

#include <stdint.h>
#include <assert.h>

#include "libs/common/protoIds.h"

#define MAX_MTU 1500

#define NODE_NAME_SIZE   32
#define IF_NAME_SIZE     64
#define MAX_INTF_PER_NODE   64

 /* Should be less than or equal to UT_PARSER_BUFF_MAX_SIZE */
#define NODE_PRINT_BUFF_LEN (1024 * 1024)

#define INTF_MAX_METRIC     16777215 /*Choosen as per the standard = 2^24 -1*/
#define INTF_METRIC_DEFAULT 1
#define TCP_LOG_BUFFER_LEN  512

#define MAX_NXT_HOPS        4
#define VRF_NAME_LEN 32

static const char *BROADCAST_MAC = "\xff\xff\xff\xff\xff\xff";


#define APPLICATION_LAYER   5
#define TRANSPORT_LAYER 4
#define NETWORK_LAYER   3
#define LINK_LAYER  2
#define PHYSICAL_LAYER  1
#define UNKNOWN_LAYER   0

static inline uint8_t
tcpip_protocol_classification(uint16_t proto) {

    switch(proto) {

        case IP_PROTO_IP_IN_IP:
        case IP_PROTO_IPv6:
            return NETWORK_LAYER;
        case IP_PROTO_ICMP:
            return APPLICATION_LAYER;
        case IP_PROTO_ISIS:
        case IP_PROTO_ISIS_SRv6:
            return LINK_LAYER;
        case IP_PROTO_TCP:
        case IP_PROTO_UDP:
            return TRANSPORT_LAYER;
        case PROTO_STATIC:
            return NETWORK_LAYER;
        default:
            return UNKNOWN_LAYER;
    }
}

#define DEFAULT_VLAN_ID         0
#define MAC_ENTRY_EXP_TIME      1800 /*Seconds*/
#define DEFAULT_VRF             0
#define DEF_VRF_NAME            "0"
#define MAX_INTF_IFINDEX        8191
#define MAX_EVPN_INDEX          8
#define MAX_VRF_SUPPORTED       256 /* have to widen uint8_t to support more */
#define MAX_BD_SUPPORT          64
#define MAX_VLAN_MEMBERPORTS    16
#define MAX_BD_MEMBERPORTS      16
#define MAX_VLAN_SUPPORTED      4096


/* Special interface ifindices */
#define RMAC_INTF_INDEX               (MAX_INTF_IFINDEX)   /* Only one instance exist, you may lookup in array */
#define RMAC_INTF_NAME                 "rmacif"
#define BD_RMAC_INTF_INDEX             (MAX_INTF_IFINDEX - 1)/* Only one instance exist, you may lookup in array */
#define BDRMAC_INTF_NAME                "bdrmacif"

#define VLAN_FLOOD_INDEX               (MAX_INTF_IFINDEX - 2)/* Only one instance exist, you may lookup in array */
#define VLAN_FLOOD_INTF_NAME            "vfif"
#define BD_FLOOD_IFINDEX               (MAX_INTF_IFINDEX - 3)/* Only one instance exist, you may lookup in array */
#define BD_FLOOD_INTF_NAME              "bdvfif"

#define NVE_IFINDEX                    (MAX_INTF_IFINDEX - 4)/* Only one instance exist, you may lookup in array */
#define NVE_INTF_NAME                   "nve"

#define HOST_PATH_IFINDEX              (MAX_INTF_IFINDEX - 5)/* Only one instance exist, you may lookup in array */
#define HOST_PATH_INTF_NAME             "hpif"

#define MPLS_TO_BD_INTF_STEER_IFINDEX  (MAX_INTF_IFINDEX - 6) /* Many instances with same ifindex exist, do not lookup in dp_ctx->intf_table[]*/
#define MPLS_TO_BD_STEER_INTF_NAME      "mpls-xconn-bd"
#define MPLS_TO_VRF_INTF_STEER_IFINDEX (MAX_INTF_IFINDEX - 7) /* Many instances with same ifindex exist, do not lookup in dp_ctx->intf_table[]*/
#define MPLS_TO_VRF_STEER_INTF_NAME     "mpls-xconn-vrf"

#define SRv6_TO_VRF_INTF_STEER_IFINDEX (MAX_INTF_IFINDEX - 8) /* Many instances with same ifindex exist, do not lookup in dp_ctx->intf_table[]*/
#define SRv6_TO_VRF_STEER_INTF_NAME     "srv6-xconn-vrf"
#define SRv6_TO_BD_STEER_IFINDEX       (MAX_INTF_IFINDEX - 9)/* Only one instance exist, you may lookup in array */
#define SRv6_TO_BD_STEER_INTF_NAME      "srv6-xconn-bd"

/* VPNV4 LABEL SPACE */
#define VPNV4_START_LABEL 16
#define VPNV4_LABEL_RANGE MAX_VRF_SUPPORTED   /* Must be Same as MAX_VRF_SUPPORTED */

#define L2VPN_START_LABEL (VPNV4_START_LABEL + VPNV4_LABEL_RANGE)
#define L2VPN_LABEL_RANGE MAX_VRF_SUPPORTED   /* Must be Same as MAX_VRF_SUPPORTED */

#endif /* __TCPCONST__ */
