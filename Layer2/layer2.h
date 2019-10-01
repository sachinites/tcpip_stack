/*
 * =====================================================================================
 *
 *       Filename:  layer2.h
 *
 *    Description: This file defines the structures required for Layer 2 functionality 
 *
 *        Version:  1.0
 *        Created:  Saturday 21 September 2019 09:51:27  IST
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

#ifndef __LAYER2__
#define __LAYER2__

#include "../net.h"
#include "../gluethread/glthread.h"
#include "tcpconst.h"

#pragma pack (push,1)
typedef struct arp_hdr_{

    short hw_type;          /*1 for ethernet cable*/
    short proto_type;       /*0x0800 for IPV4*/
    char hw_addr_len;       /*6 for MAC*/
    char proto_addr_len;    /*4 for IPV4*/
    short op_code;          /*req or reply*/
    mac_add_t src_mac;      /*MAC of OIF interface*/
    unsigned int src_ip;    /*IP of OIF*/
    mac_add_t dst_mac;      /*?*/
    unsigned int dst_ip;        /*IP for which ARP is being resolved*/
} arp_hdr_t;

typedef struct ethernet_hdr_{

    mac_add_t dst_mac;
    mac_add_t src_mac;
    short type;
    char payload[248];  /*Max allowed 1500*/
    unsigned int FCS;
} ethernet_hdr_t;

#pragma pack(pop)

#define ETH_HDR_SIZE_EXCL_PAYLOAD   \
    (sizeof(ethernet_hdr_t) - sizeof(((ethernet_hdr_t *)0)->payload))

#define ALLOC_ETH_HDR_WITH_PAYLOAD(payload_size) \
    (calloc(1, (VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD) + payload_size))

#define ETH_FCS(eth_hdr_ptr, payload_size)  \
    (*(unsigned int *)(((char *)(eth_hdr_ptr->payload) + payload_size)))

static inline bool_t 
l2_frame_recv_qualify_on_interface(interface_t *interface, 
                                    ethernet_hdr_t *ethernet_hdr){

    /* Presence of IP address on interface makes it work in L3 mode,
     * while absence of IP-address automatically make it work in
     * L2 mode. For interfaces working in L2 mode (L2 switch interfaces),
     * We should accept all frames. L2 switch never discards the frames
     * based on MAC addresses*/

    /*If receiving interface is neither working in L3 mode
     * nor in L2 mode, then reject the packet*/
    if(!IS_INTF_L3_MODE(interface) &&
        IF_L2_MODE(interface) == L2_MODE_UNKNOWN){

        return FALSE;
    }

    /*If interface is working in L2 mode, then accept
     * the packet irrespective of its Dst Mac address*/
    if(!IS_INTF_L3_MODE(interface) && 
        (IF_L2_MODE(interface) == ACCESS ||
        IF_L2_MODE(interface) == TRUNK)){
     
        return TRUE;
    }

    /* If interface is working in L3 mode, then accept the frame only when
     * its dst mac matches with receiving interface MAC*/
    if(IS_INTF_L3_MODE(interface) &&
        memcmp(IF_MAC(interface), 
        ethernet_hdr->dst_mac.mac, 
        sizeof(mac_add_t)) == 0){

        return TRUE;
    }

    /*If interface is working in L3 mode, then accept the frame with
     * broadcast MAC*/
    if(IS_INTF_L3_MODE(interface) &&
        IS_MAC_BROADCAST_ADDR(ethernet_hdr->dst_mac.mac)){

        return TRUE;
    }

    return FALSE;
}

void
send_arp_broadcast_request(node_t *node, 
                           interface_t *oif, 
                           char *ip_addr);

/*ARP Table APIs*/
typedef struct arp_table_{

    glthread_t arp_entries;
} arp_table_t;

typedef struct arp_pending_entry_ arp_pending_entry_t;
typedef struct arp_entry_ arp_entry_t;
typedef void (*arp_processing_fn)(node_t *, 
                                  interface_t *oif,
                                  arp_entry_t *, 
                                  arp_pending_entry_t *);
struct arp_pending_entry_{

    glthread_t arp_pending_entry_glue;
    arp_processing_fn cb;
    unsigned int pkt_size;  /*Including ether net hdr*/
    char pkt[0];
};
GLTHREAD_TO_STRUCT(arp_pending_entry_glue_to_arp_pending_entry, \
    arp_pending_entry_t, arp_pending_entry_glue);


struct arp_entry_{

    ip_add_t ip_addr;   /*key*/
    mac_add_t mac_addr;
    char oif_name[IF_NAME_SIZE];
    glthread_t arp_glue;
    bool_t is_sane;
    /* List of packets which are pending for
     * this ARP resolution*/
    glthread_t arp_pending_list;
};
GLTHREAD_TO_STRUCT(arp_glue_to_arp_entry, arp_entry_t, arp_glue);
GLTHREAD_TO_STRUCT(arp_pending_list_to_arp_entry, arp_entry_t, arp_pending_list);

#define IS_ARP_ENTRIES_EQUAL(arp_entry_1, arp_entry_2)  \
    (strncmp(arp_entry_1->ip_addr.ip_addr, arp_entry_2->ip_addr.ip_addr, 16) == 0 && \
        strncmp(arp_entry_1->mac_addr.mac, arp_entry_2->mac_addr.mac, 6) == 0 && \
        strncmp(arp_entry_1->oif_name, arp_entry_2->oif_name, IF_NAME_SIZE) == 0 && \
        arp_entry_1->is_sane == arp_entry_2->is_sane &&     \
        arp_entry_1->is_sane == FALSE)

void
init_arp_table(arp_table_t **arp_table);

arp_entry_t *
arp_table_lookup(arp_table_t *arp_table, char *ip_addr);

void
clear_arp_table(arp_table_t *arp_table);

void
delete_arp_entry(arp_entry_t *arp_entry);

void
delete_arp_table_entry(arp_table_t *arp_table, char *ip_addr);

bool_t
arp_table_entry_add(arp_table_t *arp_table, arp_entry_t *arp_entry,
                        glthread_t **arp_pending_list);

void
dump_arp_table(arp_table_t *arp_table);

void
arp_table_update_from_arp_reply(arp_table_t *arp_table,
                                arp_hdr_t *arp_hdr, interface_t *iif);

/*APIs to be used to create topologies*/
void
node_set_intf_l2_mode(node_t *node, char *intf_name, intf_l2_mode_t intf_l2_mode);

void
node_set_intf_vlan_membsership(node_t *node, char *intf_name, unsigned int vlan_id);

void
add_arp_pending_entry(arp_entry_t *arp_entry, 
                        arp_processing_fn, 
                        char *pkt, 
                        unsigned int pkt_size); 

void
create_arp_sane_entry(arp_table_t *arp_table, char *ip_addr,
                      char *pkt, unsigned int pkt_size);

static bool_t 
arp_entry_sane(arp_entry_t *arp_entry){

    return arp_entry->is_sane;
}


/*VLAN support*/

#pragma pack (push,1)
/*Vlan 802.1q 4 byte hdr*/
typedef struct vlan_8021q_hdr_{

    short tpid; /* = 0x8100*/
    short tci_pcp : 3 ;  /* inital 4 bits not used in this course*/
    short tci_dei : 1;   /*Not used*/
    short tci_vid : 12 ; /*Tagged vlan id*/
} vlan_8021q_hdr_t;

typedef struct vlan_ethernet_hdr_{

    mac_add_t dst_mac;
    mac_add_t src_mac;
    vlan_8021q_hdr_t vlan_8021q_hdr;
    short type;
    char payload[248];  /*Max allowed 1500*/
    unsigned int FCS;
} vlan_ethernet_hdr_t;
#pragma pack(pop)

static inline unsigned int
GET_802_1Q_VLAN_ID(vlan_8021q_hdr_t *vlan_8021q_hdr){

    return (unsigned int)vlan_8021q_hdr->tci_vid;
}

#define VLAN_ETH_FCS(vlan_eth_hdr_ptr, payload_size)  \
    (*(unsigned int *)(((char *)(vlan_eth_hdr_ptr->payload) + payload_size)))

#define VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD  \
   (sizeof(vlan_ethernet_hdr_t) - sizeof(((vlan_ethernet_hdr_t *)0)->payload)) 

/* Return 0 if not vlan tagged, else return pointer to 801.1q vlan hdr
 * present in ethernet hdr*/
static inline vlan_8021q_hdr_t *
is_pkt_vlan_tagged(ethernet_hdr_t *ethernet_hdr){

    /*Check the 13th and 14th byte of the ethernet hdr,
     *      * if is value is 0x8100 then it is vlan tagged*/

    vlan_8021q_hdr_t *vlan_8021q_hdr =
        (vlan_8021q_hdr_t *)((char *)ethernet_hdr + (sizeof(mac_add_t) * 2));

    if(vlan_8021q_hdr->tpid == VLAN_8021Q_PROTO)
        return vlan_8021q_hdr;

    return NULL;
}

/*fn to get access to ethernet payload address*/
static inline char *
GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr_t *ethernet_hdr){

   if(is_pkt_vlan_tagged(ethernet_hdr)){
        return ((vlan_ethernet_hdr_t *)(ethernet_hdr))->payload;
   }
   else
       return ethernet_hdr->payload;
}
#endif /* __LAYER2__ */
