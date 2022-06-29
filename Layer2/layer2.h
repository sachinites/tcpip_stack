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

#include <stdlib.h>  /*for calloc*/
#include <stdint.h>
#include "../net.h"
#include "../gluethread/glthread.h"
#include "../tcpconst.h"
#include "../LinuxMemoryManager/uapi_mm.h"

typedef struct pkt_block_ pkt_block_t;

#pragma pack (push,1)
typedef struct ethernet_hdr_{

    mac_add_t dst_mac;
    mac_add_t src_mac;
    unsigned short type;
    char payload[248];  /*Max allowed 1500*/
    uint32_t FCS;
} ethernet_hdr_t;
#pragma pack(pop)

#define ETH_FCS_SIZE    (sizeof(((ethernet_hdr_t *)0)->FCS))

#define ETH_HDR_SIZE_EXCL_PAYLOAD   \
    (sizeof(ethernet_hdr_t) - sizeof(((ethernet_hdr_t *)0)->payload))

#define ETH_FCS(eth_hdr_ptr, payload_size)  \
    (*(uint32_t *)(((char *)(((ethernet_hdr_t *)eth_hdr_ptr)->payload) + payload_size)))

/*APIs to be used to create topologies*/
void
node_set_intf_l2_mode(node_t *node, char *intf_name, intf_l2_mode_t intf_l2_mode);

void
node_set_intf_vlan_membership(node_t *node, char *intf_name, uint32_t vlan_id);


/*VLAN support*/

#pragma pack (push,1)
/*Vlan 802.1q 4 byte hdr*/
typedef struct vlan_8021q_hdr_{

    unsigned short tpid; /* = 0x8100*/
    short tci_pcp : 3 ;  /* inital 4 bits not used in this course*/
    short tci_dei : 1;   /*Not used*/
    short tci_vid : 12 ; /*Tagged vlan id*/
} vlan_8021q_hdr_t;

typedef struct vlan_ethernet_hdr_{

    mac_add_t dst_mac;
    mac_add_t src_mac;
    vlan_8021q_hdr_t vlan_8021q_hdr;
    unsigned short type;
    char payload[248];  /*Max allowed 1500*/
    uint32_t FCS;
} vlan_ethernet_hdr_t;
#pragma pack(pop)

static inline uint32_t
GET_802_1Q_VLAN_ID(vlan_8021q_hdr_t *vlan_8021q_hdr){

    return (uint32_t)vlan_8021q_hdr->tci_vid;
}

#define VLAN_ETH_FCS(vlan_eth_hdr_ptr, payload_size)  \
    (*(uint32_t *)(((char *)(((vlan_ethernet_hdr_t *)vlan_eth_hdr_ptr)->payload) + payload_size)))

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

#define GET_COMMON_ETH_FCS(eth_hdr_ptr, payload_size)   \
        (is_pkt_vlan_tagged(eth_hdr_ptr) ? VLAN_ETH_FCS(eth_hdr_ptr, payload_size) : \
            ETH_FCS(eth_hdr_ptr, payload_size))

static inline void
SET_COMMON_ETH_FCS(ethernet_hdr_t *ethernet_hdr, 
                   uint32_t payload_size,
                   uint32_t new_fcs){

    if(is_pkt_vlan_tagged(ethernet_hdr)){
        VLAN_ETH_FCS(ethernet_hdr, payload_size) = new_fcs;
    }
    else{
        ETH_FCS(ethernet_hdr, payload_size) = new_fcs;
    }
}

bool 
l2_frame_recv_qualify_on_interface(
                                    node_t *node,
                                    interface_t *interface, 
                                    pkt_block_t *pkt_block,
                                    uint32_t *output_vlan_id);

void
promote_pkt_to_layer2(
                    node_t *node,
                    interface_t *iif, 
                    pkt_block_t *pkt_block);
                    
static inline uint32_t 
GET_ETH_HDR_SIZE_EXCL_PAYLOAD(ethernet_hdr_t *ethernet_hdr){

    if(is_pkt_vlan_tagged(ethernet_hdr)){
        return VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;        
    }
    else{
        return ETH_HDR_SIZE_EXCL_PAYLOAD; 
    }
}

void untag_pkt_with_vlan_id(pkt_block_t *pkt_block);
void tag_pkt_with_vlan_id (pkt_block_t *pkt_block, int vlan_id );

/* L2 Switching */


/*L2 Switch Owns Mac Table*/

typedef struct mac_table_entry_{

    mac_add_t mac;
    char oif_name[IF_NAME_SIZE];
    glthread_t mac_entry_glue;
} mac_table_entry_t;
GLTHREAD_TO_STRUCT(mac_entry_glue_to_mac_entry, mac_table_entry_t, mac_entry_glue);

typedef struct mac_table_{

    glthread_t mac_entries;
} mac_table_t;


#endif /* __LAYER2__ */
