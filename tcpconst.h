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

/* Internal Hdr representation */
typedef enum{

    ETH_HDR,
    IP_HDR,
    ARP_HDR,
    ICMP_HDR,
    TCP_HDR,
    UDP_HDR,
    IP_IN_IP_HDR,
    GRE_HDR,
    MISC_APP_HDR
} hdr_type_t;

typedef uint16_t pkt_size_t;

/*Specified in ethernet_hdr->type*/
#define ARP_BROAD_REQ   1
#define ARP_REPLY       2
#define PROTO_ARP         806
#define BROADCAST_MAC   0xFFFFFFFFFFFF
#define ETH_IP          0x0800
#define ICMP_PROTO        1
#define TCP_PROTO 0x6
#define UDP_PROTO   0x11
#define GRE_PROTO 47
#define ICMP_ECHO_REQ   8
#define ICMP_ECHO_REP   0
#define EIGRP_PROTO   80
#define MTCP            20
#define USERAPP1        21
#define VLAN_8021Q_PROTO    0x8100
#define IP_IN_IP        4
#define NMP_HELLO_MSG_CODE	13 /*Randomly chosen*/
#define INTF_MAX_METRIC     16777215 /*Choosen as per the standard = 2^24 -1*/
#define INTF_METRIC_DEFAULT 1
#define TCP_LOG_BUFFER_LEN	512
 /* Should be less than or equal to UT_PARSER_BUFF_MAX_SIZE */
#define NODE_PRINT_BUFF_LEN (1024 * 1024)

/*Add DDCP Protocol Numbers*/
#define DDCP_MSG_TYPE_FLOOD_QUERY    1  /*Randomly chosen, should not exceed 2^16 -1*/
#define DDCP_MSG_TYPE_UCAST_REPLY    2  /*Randomly chosen, must not exceed 255*/
#define PKT_BUFFER_RIGHT_ROOM        128   
#define MAX_NXT_HOPS        4


/* Protocol IDs*/
#define PROTO_STATIC 101
#define PROTO_ISIS       0x83
#define PROTO_ANY       (0xFFFF - 1)

static inline unsigned char *
proto_name_str (uint16_t proto) {

    switch(proto) {
        case PROTO_ISIS:
            return (unsigned char *)"isis";
        case PROTO_STATIC:
            return (unsigned char *)"static";
        case PROTO_ARP:
            return (unsigned char *)"arp";
        case ETH_IP:
            return (unsigned char *)"ip";
        case ICMP_PROTO:
            return (unsigned char *)"icmp";
        case TCP_PROTO:
            return (unsigned char *)"tcp";
        case UDP_PROTO:
            return (unsigned char *)"udp";
        case PROTO_ANY:
            return (unsigned char *)"any";
        case EIGRP_PROTO:
            return (unsigned char *)"eigrp";
        default:
            return NULL;
    }
}

#define APPLICATION_LAYER   5
#define TRANSPORT_LAYER 4
#define NETWORK_LAYER   3
#define LINK_LAYER  2
#define PHYSICAL_LAYER  1
#define UNKNOWN_LAYER   0

static inline uint8_t
tcpip_protocol_classification(uint16_t proto) {

    switch(proto) {

        case ETH_IP:
            return NETWORK_LAYER;
        case ICMP_PROTO:
            return APPLICATION_LAYER;
        case PROTO_ISIS:
            return LINK_LAYER;
        case TCP_PROTO:
        case UDP_PROTO:
            return TRANSPORT_LAYER;
        case PROTO_STATIC:
            return NETWORK_LAYER;
        default:
            return UNKNOWN_LAYER;
    }
}

static inline uint16_t 
tcp_ip_convert_internal_proto_to_std_proto (hdr_type_t hdr_type) {

    switch (hdr_type)
    {
    case ETH_HDR:
        return 0;
    case IP_HDR:
        return ETH_IP;
    case ARP_HDR:
        return PROTO_ARP;
    case ICMP_HDR:
        return ICMP_PROTO;
    case TCP_HDR:
        return TCP_PROTO;
    case UDP_HDR:
        return UDP_PROTO;
    case IP_IN_IP_HDR:
        return IP_IN_IP;
    case GRE_HDR:
        return GRE_PROTO;
    default:;
    }
    return 0;
}

#define MAC_ADDR_SIZE   6
#define IPV4_ADDR_LEN_STR   16

#endif /* __TCPCONST__ */

