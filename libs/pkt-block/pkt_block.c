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
#include <stdio.h>
#include <stdint.h>
#include <memory.h>
#include <arpa/inet.h>
#include <assert.h>
#include "pkt_block.h"
#include "../common/protoIds.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../common/l2_hdrs.h"
#include "../common/l3_hdrs.h"

gen_proto_id_t
pkt_block_get_starting_hdr(pkt_block_t *pkt_block) {

    return pkt_block->hdr_type;
}

pkt_block_t *
pkt_block_get_new2(uint8_t *pkt, pkt_size_t pkt_size, const char *fn_name, uint16_t lineno) {

    pkt_block_t *pkt_block = (pkt_block_t *)calloc(1, sizeof(pkt_block_t));
    pkt_block->pkt_id = 0;
    pkt_block->pkt = pkt;
    pkt_block->pkt_size = pkt_size;
    pkt_block->ref_count = 1;
    pkt_block->lineno = lineno;
    pkt_block->fn_name = fn_name;
    pkt_block->alloc_ptr = (uintptr_t)pkt;
    return pkt_block;
}

pkt_block_t *
pkt_block_get_new_pkt_buffer2(pkt_size_t pkt_size, const char *fn_name, uint16_t lineno) {

    pkt_block_t *pkt_block = (pkt_block_t *)calloc( 1, sizeof(pkt_block_t));
    pkt_block->pkt_id = 0;
    pkt_block->alloc_ptr = (uintptr_t )XCALLOC_BUFF(0, pkt_size);
    pkt_block->pkt = (uint8_t *)
        (pkt_block->alloc_ptr + 
         MAX_PACKET_BUFFER_SIZE - (pkt_size + PKT_BUFFER_RIGHT_ROOM));
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
pkt_block_reference(pkt_block_t *pkt_block) {

    pkt_block->ref_count++;
}

static void
pkt_block_free(pkt_block_t *pkt_block) {

    XFREE((void *)pkt_block->alloc_ptr);
    assert (!pkt_block->encap_data);
    assert (!pkt_block->ingress_intf);
    free(pkt_block);
}

uint8_t
pkt_block_dereference(pkt_block_t *pkt_block) {

    uint8_t ref_count = pkt_block->ref_count;

    if (pkt_block->ref_count == 0) {
        if (pkt_block->encap_data) free(pkt_block->encap_data);
        pkt_block->encap_data = NULL;
        if (pkt_block->ingress_intf) pkt_block->ingress_intf = 0;
        pkt_block_free(pkt_block);
        return 0;
    }

    pkt_block->ref_count--;

    if (pkt_block->ref_count == 0) {
        if (pkt_block->encap_data) free(pkt_block->encap_data);
        pkt_block->encap_data = NULL;        
        if (pkt_block->ingress_intf) pkt_block->ingress_intf = 0;
        pkt_block_free(pkt_block);
        return 0;
    }

    return ref_count - 1;
}

ethernet_hdr_t *
pkt_block_get_ethernet_hdr(pkt_block_t *pkt_block) {

    if (pkt_block->hdr_type == ETHERNET_HEADER)
        return (ethernet_hdr_t *) (pkt_block->pkt);
    else if (pkt_block->hdr_type == IP_PROTO_GRE) {
        gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt_block->pkt;
        if (ntohs(gre_hdr->protocol_type) == ETH_TYPE_GRE) {
            return (ethernet_hdr_t *)(gre_hdr + 1);
        }
    }
    return NULL;
}

ip_hdr_t *
pkt_block_get_ip_hdr (pkt_block_t *pkt_block) {

    ip_hdr_t *ip_hdr;
    ethernet_hdr_t *eth_hdr;

     if (pkt_block->hdr_type == ETHERNET_HEADER) {

         eth_hdr = pkt_block_get_ethernet_hdr(pkt_block);

         if (ntohs(eth_hdr->type) == ETH_TYPE_IPv4) {

             return (ip_hdr_t *)eth_hdr->payload;
         }
         return NULL;
     }

     else if (pkt_block->hdr_type == IP_PROTO_IP_IN_IP) {

         return (ip_hdr_t *) (pkt_block->pkt);
     }

     else if (pkt_block->hdr_type == IP_PROTO_GRE) {

         gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt_block->pkt;

         if (ntohs(gre_hdr->protocol_type) == IP_PROTO_IP_IN_IP) {
             return (ip_hdr_t *)(gre_hdr + 1);
         }
     }

     return NULL;
}

ipv6_hdr_t *
pkt_block_get_ip6_hdr (pkt_block_t *pkt_block) {

    ipv6_hdr_t *ipv6_hdr;
    ethernet_hdr_t *eth_hdr;

     if (pkt_block->hdr_type == ETHERNET_HEADER) {

         eth_hdr = pkt_block_get_ethernet_hdr(pkt_block);

         if (ntohs(eth_hdr->type) == ETH_TYPE_IPv6) {

             return (ipv6_hdr_t *)eth_hdr->payload;
         }
         return NULL;
     }

     else if (pkt_block->hdr_type == IP_PROTO_IPv6) {

         return (ipv6_hdr_t *) (pkt_block->pkt);
     }

     else if (pkt_block->hdr_type == IP_PROTO_GRE) {

         gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt_block->pkt;

         if (ntohs(gre_hdr->protocol_type) == IP_PROTO_IPv6) {
             return (ipv6_hdr_t *)(gre_hdr + 1);
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
        
        case ETHERNET_HEADER:

            eth_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

            if (is_pkt_vlan_tagged(eth_hdr)) {

                vlan_eth_hdr = (vlan_ethernet_hdr_t *)eth_hdr;

                if (ntohs(vlan_eth_hdr->type) == ETH_TYPE_ARP) {
                    return (arp_hdr_t *)vlan_eth_hdr->payload;
                }
                else
                {
                    return NULL;
                }
            }

            else
            {
                if (ntohs(eth_hdr->type) == ETH_TYPE_ARP)
                {
                    return (arp_hdr_t *)eth_hdr->payload;
                }
                else
                {
                    return NULL;
                }
            }
            break;

        case ETH_TYPE_ARP:
           return (arp_hdr_t *)pkt_block->pkt;

        default:
            return NULL;
    }
}

void
pkt_block_free_internals (pkt_block_t *pkt_block) {

    //tcp_ip_free_pkt_buffer(pkt_block->pkt, pkt_block->pkt_size);
    XFREE(pkt_block->alloc_ptr);
    pkt_block->pkt = NULL;
    pkt_block->pkt_size = 0;
}

void
pkt_block_set_new_pkt(pkt_block_t *pkt_block, uint8_t *pkt, pkt_size_t pkt_size) {

    pkt_block->pkt = pkt;
    pkt_block->pkt_size = pkt_size;
    if (!pkt_block->alloc_ptr) pkt_block->alloc_ptr = (uintptr_t)pkt;
}

pkt_block_t *
pkt_block_dup2(pkt_block_t *pkt_block, const char *fn_name, uint16_t lineno) {

    pkt_block_t *pkt_block2 = pkt_block_get_new_pkt_buffer(pkt_block->pkt_size);
    pkt_block2->pkt_id = 0;
    memcpy(pkt_block2->pkt , pkt_block->pkt, pkt_block->pkt_size);
    pkt_block2->hdr_type = pkt_block->hdr_type;
    pkt_block2->no_modify = pkt_block->no_modify;
    pkt_block2->ingress_intf = pkt_block->ingress_intf;
    if (pkt_block->encap_data) {
        pkt_block2->encap_data = (encap_meta_data_t *)calloc( 1, sizeof(encap_meta_data_t));
        memcpy (pkt_block2->encap_data, pkt_block->encap_data, 
            sizeof (*pkt_block->encap_data));
    }
    return pkt_block2;
}

bool
pkt_block_expand_buffer_left (pkt_block_t *pkt_block, pkt_size_t expand_bytes) {

    uint8_t *pkt;
    pkt_size_t pkt_size;

    pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    if ( (MAX_PACKET_BUFFER_SIZE - pkt_size) < expand_bytes ) {
        return false;
    }

    pkt = pkt - expand_bytes;
    pkt_size = pkt_size + expand_bytes;
    pkt_block_set_new_pkt(pkt_block, pkt, pkt_size);

    return true;
}

bool
pkt_block_verify_pkt (pkt_block_t *pkt_block, gen_proto_id_t hdr_type) {

    return (pkt_block_get_starting_hdr (pkt_block) == hdr_type);
}

void 
pkt_block_update_new_hdr_type (pkt_block_t *pkt_block, uint16_t proto) {

    pkt_block->hdr_type = proto;
}

void
tcp_ip_expand_buffer_ethernet_hdr(pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    pkt_size_t new_pkt_size;
    uint8_t *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);
    pkt -= (ETH_HDR_SIZE_EXCL_PAYLOAD - ETH_FCS_SIZE);
    pkt_size += ETH_HDR_SIZE_EXCL_PAYLOAD;
    pkt_block_set_new_pkt(pkt_block, pkt, pkt_size);
    pkt_block_update_new_hdr_type(pkt_block, ETHERNET_HEADER);
    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &new_pkt_size);
    memset (eth_hdr->dst_mac.mac, 0, sizeof (mac_addr_t));
    memset (eth_hdr->src_mac.mac, 0, sizeof (mac_addr_t));
    eth_hdr->type = 0;
    SET_COMMON_ETH_FCS(eth_hdr, pkt_size, 0);
}

void 
pkt_block_set_no_modify (pkt_block_t *pkt_block, bool modify) {

    pkt_block->no_modify = modify;
}

void
print_pkt_block(pkt_block_t *pkt_block) {

    #if 0
    cprintf ("pkt_block->pkt = %p\n", pkt_block->pkt);
    cprintf ("pkt_block->pkt_id = %lu\n", pkt_block->pkt_id);
    cprintf ("pkt_block->pkt_size = %d\n", pkt_block->pkt_size);
    cprintf ("pkt_block->hdr_type = %d\n", pkt_block->hdr_type);
    cprintf ("pkt_block->ref_count = %d\n", pkt_block->ref_count);
    cprintf ("pkt_block alloc :  %s(%d)\n", pkt_block->fn_name, pkt_block->lineno);
    cprintf ("pkt_block->no_modify = %d\n", pkt_block->no_modify);
    #endif
}

void 
pkt_block_debug(pkt_block_t *pkt_block) {
    
}

char *
pkt_ip (pkt_block_t *pkt_block, char *buffer) {

    ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt_block);
    memset (buffer, 0, sizeof (buffer));
    uint32_t ip_addr = ip_hdr->dst_ip;
    inet_ntop(AF_INET, &ip_addr, buffer, sizeof(buffer));
    return buffer;
} 

char *
pkt_ip_str (pkt_block_t *pkt_block, char *buffer) {

    ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt_block);
    strcpy(buffer, "IP:");
    uint32_t ip_addr = ip_hdr->dst_ip;
    inet_ntop(AF_INET, &ip_addr, buffer + 3, INET_ADDRSTRLEN);
    return buffer;
} 

char *
pkt_mac_str (pkt_block_t *pkt_block, char *buffer) {

    ethernet_hdr_t *eth_hdr = pkt_block_get_ethernet_hdr(pkt_block);
    sprintf(buffer,  "ETH:%02x:%02x:%02x:%02x:%02x:%02x",
                    eth_hdr->dst_mac.mac[0], eth_hdr->dst_mac.mac[1], eth_hdr->dst_mac.mac[2],
                    eth_hdr->dst_mac.mac[3], eth_hdr->dst_mac.mac[4], eth_hdr->dst_mac.mac[5]);    
    return buffer;
}

/* This API used inbuilt memory of pkt_block, so use this API with caution */
char *
pkt_block_str (pkt_block_t *pkt_block) {

    gen_proto_id_t hdr_type = pkt_block_get_starting_hdr(pkt_block);

    switch (hdr_type) {

        case ETHERNET_HEADER:
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

        case IP_PROTO_IPv6:
        {
            int rc;
            pkt_size_t old_pkt_size;
            uint8_t *old_pkt = pkt_block_get_pkt(pkt_block, &old_pkt_size);
            ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)old_pkt;
            pkt_block_expand_buffer_left (pkt_block, 48);
            uint8_t *ipv6_addr_str = pkt_block_get_pkt(pkt_block, NULL);
            pkt_block_set_new_pkt(pkt_block, old_pkt, old_pkt_size);
            rc = sprintf (ipv6_addr_str, "Dest:");
            inet_ntop(AF_INET6, ipv6_hdr->dst_addr, ipv6_addr_str + rc, INET6_ADDRSTRLEN);
            return (char *)ipv6_addr_str;
        }
        break;

        case IP_PROTO_IP_IN_IP:
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

        case IP_PROTO_GRE:
        {
            pkt_size_t old_pkt_size;
            uint8_t *old_pkt = pkt_block_get_pkt(pkt_block, &old_pkt_size);
            gre_hdr_t *gre_hdr = (gre_hdr_t *)old_pkt;

            switch (ntohs(gre_hdr->protocol_type)) {
                
                case ETH_TYPE_GRE:
                {
                    pkt_block_expand_buffer_left (pkt_block, 7 + 4 + 17 + 1);
                    uint8_t *buffer = pkt_block_get_pkt(pkt_block, NULL);
                    strncpy (buffer, "GRE-EN:", 7);
                    pkt_block_set_new_pkt(pkt_block, (uint8_t *)(gre_hdr + 1), old_pkt_size - sizeof(gre_hdr_t));
                    pkt_block_set_new_pkt(pkt_block, old_pkt, old_pkt_size);
                    pkt_mac_str (pkt_block, (char *)buffer + 7);
                    return (char *)buffer;
                }

                case IP_PROTO_IP_IN_IP:
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

void 
pkt_block_slide (pkt_block_t *pkt_block, 
                 int8_t lorr1, 
                 int8_t lorr2, 
                 uint16_t space) {

    uint8_t *pkt;
    pkt_size_t pkt_size;

    assert (pkt_block->alloc_ptr);

    assert (lorr1 == -1 || lorr1 == 1);
    assert (lorr2 == -1 || lorr2 == 1);

    pkt = (uint8_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    switch (lorr1) {

        case -1:

            switch (lorr2) {

                case -1:
                    pkt -= space;
                    pkt_size += space;
                    break;
                case 1:
                    pkt += space;
                    pkt_size -= space;
                    break;
            }
            break;

        case 1:

            switch (lorr2) {

                case -1:
                    pkt_size -= space;
                    break;
                case 1:
                    pkt_size += space;
                    break;
            }

        break;
    }

    if (lorr1 == -1) pkt_block->pkt = pkt;
    pkt_block->pkt_size = pkt_size;
}
