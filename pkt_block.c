/*
 * =====================================================================================
 *
 *       Filename:  pkt_block.c
 *
 *    Description:  This file defines the structure and routines to work with Packet 
 *
 *        Version:  1.0
 *        Created:  05/15/2022 12:42:47 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <stdint.h>
#include <memory.h>
#include "LinuxMemoryManager/uapi_mm.h"
#include "graph.h"
#include "Layer2/layer2.h"
#include "Layer2/arp.h"
#include "Layer3/rt_table/nexthop.h"
#include "Layer3/layer3.h"
#include "Layer5/layer5.h"
#include "tcpconst.h"
#include "pkt_block.h"
#include "common/l3_hdrs.h"
void
pkt_block_mem_init () {

    MM_REG_STRUCT(0, pkt_block_t);
}

hdr_type_t
pkt_block_get_starting_hdr(pkt_block_t *pkt_block) {

    return pkt_block->hdr_type;
}

pkt_block_t *
pkt_block_get_new2(uint8_t *pkt, pkt_size_t pkt_size, const char *fn_name, uint16_t lineno) {

    pkt_block_t *pkt_block = (pkt_block_t *)XCALLOC(0, 1, pkt_block_t);
    pkt_block->pkt_id = 0;
    pkt_block->pkt = pkt;
    pkt_block->pkt_size = pkt_size;
    pkt_block->ref_count = 1;
    pkt_block->lineno = lineno;
    pkt_block->fn_name = fn_name;
    return pkt_block;
}

pkt_block_t *
pkt_block_get_new_pkt_buffer2(pkt_size_t pkt_size, const char *fn_name, uint16_t lineno) {

    pkt_block_t *pkt_block = (pkt_block_t *)XCALLOC(0, 1, pkt_block_t);
    pkt_block->pkt_id = 0;
    pkt_block->pkt = (uint8_t *)tcp_ip_get_new_pkt_buffer(pkt_size);
    pkt_block->pkt_size = pkt_size;
    pkt_block->ref_count = 1;
    pkt_block->lineno = lineno;
    pkt_block->fn_name = fn_name;
    return pkt_block;
}

uint8_t *
pkt_block_get_pkt(pkt_block_t *pkt_block, pkt_size_t *pkt_size) {

    if (pkt_size) *pkt_size = pkt_block->pkt_size;
    return (uint8_t *)pkt_block->pkt;
}

void
pkt_block_set_starting_hdr_type(pkt_block_t *pkt_block, hdr_type_t hdr_type) {

    pkt_block->hdr_type = hdr_type;
}

void
pkt_block_reference(pkt_block_t *pkt_block) {

    pkt_block->ref_count++;
}

void
pkt_block_free(pkt_block_t *pkt_block) {

    tcp_ip_free_pkt_buffer(pkt_block->pkt, pkt_block->pkt_size);
    assert (!pkt_block->recommended_oif);
    assert (!pkt_block->exclude_oif);
    XFREE(pkt_block);
}

uint8_t
pkt_block_dereference(pkt_block_t *pkt_block) {

    uint8_t ref_count = pkt_block->ref_count;

    if (pkt_block->ref_count == 0) {
        pkt_block_set_recommended_oif (pkt_block, NULL);
        pkt_block_set_exclude_oif (pkt_block, NULL);
        pkt_block_free(pkt_block);
        return 0;
    }

    pkt_block->ref_count--;

    if (pkt_block->ref_count == 0) {
        pkt_block_set_recommended_oif (pkt_block, NULL);
        pkt_block_set_exclude_oif (pkt_block, NULL);
        pkt_block_free(pkt_block);
        return 0;
    }

    return ref_count - 1;
}

ethernet_hdr_t *
pkt_block_get_ethernet_hdr(pkt_block_t *pkt_block) {

    if (pkt_block->hdr_type == ETH_HDR)
        return (ethernet_hdr_t *) (pkt_block->pkt);
    else if (pkt_block->hdr_type == GRE_HDR) {
        gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt_block->pkt;
        if (gre_hdr->protocol_type == PROTO_GRE_ENCAP_ETHERNET) {
            return (ethernet_hdr_t *)(gre_hdr + 1);
        }
    }
    return NULL;
}

ip_hdr_t *
pkt_block_get_ip_hdr (pkt_block_t *pkt_block) {

    ip_hdr_t *ip_hdr;
    ethernet_hdr_t *eth_hdr;

     if (pkt_block->hdr_type == ETH_HDR) {

         eth_hdr = pkt_block_get_ethernet_hdr(pkt_block);

         if (eth_hdr->type == ETH_IP || 
                eth_hdr->type == PROTO_IP_IN_IP ) {

             return (ip_hdr_t *)eth_hdr->payload;
         }
         return NULL;
     }

     else if (pkt_block->hdr_type == IP_HDR) {

         return (ip_hdr_t *) (pkt_block->pkt);
     }

     else if (pkt_block->hdr_type == GRE_HDR) {

         gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt_block->pkt;

         if (gre_hdr->protocol_type == ETH_IP) {
             return (ip_hdr_t *)(gre_hdr + 1);
         }
     }

     return NULL;
}

arp_hdr_t *
pkt_block_get_arp_hdr (pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    ethernet_hdr_t *eth_hdr;
    vlan_ethernet_hdr_t *vlan_eth_hdr;

    switch(pkt_block->hdr_type) {
        
        case ETH_HDR:

            eth_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

            if (is_pkt_vlan_tagged(eth_hdr)) {

                vlan_eth_hdr = (vlan_ethernet_hdr_t *)eth_hdr;

                if (vlan_eth_hdr->type == PROTO_ARP) {
                    return (arp_hdr_t *)vlan_eth_hdr->payload;
                }
                else
                {
                    return NULL;
                }
            }

            else
            {
                if (eth_hdr->type == PROTO_ARP)
                {
                    return (arp_hdr_t *)eth_hdr->payload;
                }
                else
                {
                    return NULL;
                }
            }
            break;

        case ARP_HDR:
           return (arp_hdr_t *)pkt_block->pkt;

        default:
            return NULL;
    }
}

void
pkt_block_free_internals (pkt_block_t *pkt_block) {

    tcp_ip_free_pkt_buffer(pkt_block->pkt, pkt_block->pkt_size);
    pkt_block->pkt = NULL;
    pkt_block->pkt_size = 0;
}

void
pkt_block_set_new_pkt(pkt_block_t *pkt_block, uint8_t *pkt, pkt_size_t pkt_size) {

    pkt_block->pkt = pkt;
    pkt_block->pkt_size = pkt_size;
}

pkt_block_t *
pkt_block_dup2(pkt_block_t *pkt_block, const char *fn_name, uint16_t lineno) {

    pkt_block_t *pkt_block2 = (pkt_block_t *)XCALLOC(0, 1, pkt_block_t );
    pkt_block2->pkt_id = 0;
    pkt_block2->pkt = (uint8_t *) tcp_ip_get_new_pkt_buffer(pkt_block->pkt_size);
    memcpy(pkt_block2->pkt , pkt_block->pkt, pkt_block->pkt_size);
    pkt_block2->pkt_size = pkt_block->pkt_size;
    pkt_block2->hdr_type = pkt_block->hdr_type;
    pkt_block2->ref_count = 1;
    pkt_block2->lineno = lineno;
    pkt_block2->fn_name = fn_name;    
    pkt_block2->no_modify = pkt_block->no_modify;
    return pkt_block2;
}

bool
pkt_block_expand_buffer_left (pkt_block_t *pkt_block, pkt_size_t expand_bytes) {

    uint8_t *pkt;
    pkt_size_t pkt_size;

    pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    if (!pkt) {
        pkt = (uint8_t *)tcp_ip_get_new_pkt_buffer(expand_bytes);
        pkt_block_set_new_pkt(pkt_block, pkt, expand_bytes);
        pkt_size = expand_bytes;
    }

    if ( (MAX_PACKET_BUFFER_SIZE - pkt_size) < expand_bytes ) {
        return false;
    }

    pkt = pkt - expand_bytes;
    pkt_size = pkt_size + expand_bytes;
    pkt_block_set_new_pkt(pkt_block, pkt, pkt_size);

    return true;
}

bool
pkt_block_verify_pkt (pkt_block_t *pkt_block, hdr_type_t hdr_type) {

    return (pkt_block_get_starting_hdr (pkt_block) == hdr_type);
}

void
tcp_ip_expand_buffer_ethernet_hdr(pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    pkt_size_t new_pkt_size;

    /* No use case of encapsulating ethernet hdr inside ethernet hdr */
    assert (pkt_block_get_starting_hdr (pkt_block) != ETH_HDR);
    uint8_t *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);
    char *temp = (char *)XCALLOC_BUFF(0, pkt_size);   
    memcpy(temp, pkt, pkt_size);    
    pkt_block_expand_buffer_left (pkt_block, ETH_HDR_SIZE_EXCL_PAYLOAD);
    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &new_pkt_size);
    memset((char *)eth_hdr, 0, ETH_HDR_SIZE_EXCL_PAYLOAD);
    memcpy(eth_hdr->payload, temp, pkt_size);
    SET_COMMON_ETH_FCS(eth_hdr, pkt_size, 0);
    XFREE(temp);
    pkt_block_set_starting_hdr_type(pkt_block , ETH_HDR);
}

void 
pkt_block_set_no_modify (pkt_block_t *pkt_block, bool modify) {

    pkt_block->no_modify = modify;
}

void
print_pkt_block(pkt_block_t *pkt_block) {

    cprintf ("pkt_block->pkt = %p\n", pkt_block->pkt);
    cprintf ("pkt_block->pkt_id = %lu\n", pkt_block->pkt_id);
    cprintf ("pkt_block->pkt_size = %d\n", pkt_block->pkt_size);
    cprintf ("pkt_block->hdr_type = %d\n", pkt_block->hdr_type);
    cprintf ("pkt_block->ref_count = %d\n", pkt_block->ref_count);
    cprintf ("pkt_block alloc :  %s(%d)\n", pkt_block->fn_name, pkt_block->lineno);
    cprintf ("pkt_block->no_modify = %d\n", pkt_block->no_modify);
}

void 
pkt_block_debug(pkt_block_t *pkt_block) {
    
}

void 
pkt_block_set_recommended_oif (pkt_block_t *pkt_block, Interface *oif) {

    if (!oif && !pkt_block->recommended_oif) {
        return;
    }

    if (!oif) {

        if (pkt_block->recommended_oif ) {
            pkt_block->recommended_oif->InterfaceUnLockDynamic();
        }
        pkt_block->recommended_oif = NULL;
        return;
    }

    if (pkt_block->recommended_oif &&
         pkt_block->recommended_oif != oif ) {

        pkt_block->recommended_oif->InterfaceUnLockDynamic();
    }

    pkt_block->recommended_oif = oif;
    oif->InterfaceLockDynamic();
}

void
pkt_block_set_exclude_oif (pkt_block_t *pkt_block, Interface *oif) {

    if (!oif && !pkt_block->exclude_oif) {
        return;
    }
    
    if (!oif) {

        if (pkt_block->exclude_oif) {
            pkt_block->exclude_oif->InterfaceUnLockDynamic();
        }
        pkt_block->exclude_oif = NULL;
        return;
    }

    if (pkt_block->exclude_oif &&
                pkt_block->exclude_oif != oif) {

        pkt_block->exclude_oif->InterfaceUnLockDynamic();
    }

    pkt_block->exclude_oif = oif;
    pkt_block->exclude_oif->InterfaceLockDynamic();
}

char *
pkt_ip (pkt_block_t *pkt_block, char *buffer) {

    ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt_block);
    memset (buffer, 0, sizeof (buffer));
    tcp_ip_covert_ip_n_to_p (ip_hdr->dst_ip, buffer);
    return buffer;
} 

char *
pkt_ip_str (pkt_block_t *pkt_block, char *buffer) {

    ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt_block);
    memset (buffer, 0, sizeof (buffer));
    strcpy(buffer, "IP:");
    tcp_ip_covert_ip_n_to_p (ip_hdr->dst_ip, buffer + 3);
    return buffer;
} 

char *
pkt_mac_str (pkt_block_t *pkt_block, char *buffer) {

    ethernet_hdr_t *eth_hdr = pkt_block_get_ethernet_hdr(pkt_block);
    memset (buffer, 0, sizeof (buffer));
    sprintf(buffer,  "ETH:%02x:%02x:%02x:%02x:%02x:%02x",
                    eth_hdr->dst_mac.mac[0], eth_hdr->dst_mac.mac[1], eth_hdr->dst_mac.mac[2],
                    eth_hdr->dst_mac.mac[3], eth_hdr->dst_mac.mac[4], eth_hdr->dst_mac.mac[5]);    
    return buffer;
}

/* This API used inbuilt memory of pkt_block, so use this API with caution */
char *
pkt_block_str (pkt_block_t *pkt_block) {

    hdr_type_t hdr_type = pkt_block_get_starting_hdr(pkt_block);

    switch (hdr_type) {

        case ETH_HDR:
        {
            ethernet_hdr_t *eth_hdr = pkt_block_get_ethernet_hdr(pkt_block);
            pkt_size_t old_pkt_size;
            uint8_t *old_pkt = pkt_block_get_pkt(pkt_block, &old_pkt_size);
            pkt_block_expand_buffer_left (pkt_block, 4 + 17 + 1);
            uint8_t *mac_addr_str = pkt_block_get_pkt(pkt_block, NULL);
            pkt_block_set_new_pkt(pkt_block, old_pkt, old_pkt_size);
            pkt_mac_str (pkt_block, (char *)mac_addr_str);
            return (char *)mac_addr_str;
        }
        break;

        case IP_HDR:
        case IP_IN_IP_HDR:
        {
            ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt_block);
            pkt_size_t old_pkt_size;
            uint8_t *old_pkt = pkt_block_get_pkt(pkt_block, &old_pkt_size);
            pkt_block_expand_buffer_left (pkt_block, 3 + 16 + 1);
            uint8_t *ip_addr_str = pkt_block_get_pkt(pkt_block, NULL);
            pkt_block_set_new_pkt(pkt_block, old_pkt, old_pkt_size);
            pkt_ip_str (pkt_block, (char *)ip_addr_str);
            return (char *)ip_addr_str;
        }
        break;

        case GRE_HDR:
        {
            pkt_size_t old_pkt_size;
            uint8_t *old_pkt = pkt_block_get_pkt(pkt_block, &old_pkt_size);
            gre_hdr_t *gre_hdr = (gre_hdr_t *)old_pkt;
            switch (gre_hdr->protocol_type) {
                case PROTO_GRE_ENCAP_ETHERNET:
                {
                    pkt_block_expand_buffer_left (pkt_block, 7 + 4 + 17 + 1);
                    uint8_t *buffer = pkt_block_get_pkt(pkt_block, NULL);
                    strncpy (buffer, "GRE-EN:", 7);
                    pkt_block_set_new_pkt(pkt_block, (uint8_t *)(gre_hdr + 1), old_pkt_size - sizeof(gre_hdr_t));
                    pkt_block_set_new_pkt(pkt_block, old_pkt, old_pkt_size);
                    pkt_mac_str (pkt_block, (char *)buffer + 7);
                    return (char *)buffer;
                }
                case ETH_IP:
                {
                    pkt_block_expand_buffer_left (pkt_block, 7 + 3 + 16 + 1);
                    uint8_t *buffer = pkt_block_get_pkt(pkt_block, NULL);
                    strncpy (buffer, "GRE-EN:", 7);
                    pkt_block_set_new_pkt(pkt_block, (uint8_t *)(gre_hdr + 1), old_pkt_size - sizeof(gre_hdr_t));                    
                    pkt_block_set_new_pkt(pkt_block, old_pkt, old_pkt_size);
                    pkt_ip_str (pkt_block, (char *)buffer + 7);
                    return (char *)buffer;
                }
                break;
                default:
                    break;
            }
        }
        break;

    }

    return NULL;
}
