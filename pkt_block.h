/*
 * =====================================================================================
 *
 *       Filename:  pkt_block.h
 *
 *    Description: This file defines the structure and routines to work with Packet 
 *
 *        Version:  1.0
 *        Created:  05/15/2022 12:39:09 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#ifndef __PKT_BLOCK__
#define __PKT_BLOCK__

#include <stdint.h>
#include <stdbool.h>

typedef struct ip_hdr_ ip_hdr_t;
typedef struct arp_hdr_ arp_hdr_t;
typedef struct pkt_block_ pkt_block_t;
typedef struct ethernet_hdr_ ethernet_hdr_t;

void
pkt_block_mem_init ();

hdr_type_t
pkt_block_get_starting_hdr(pkt_block_t *pkt_block);

void
pkt_block_reference(pkt_block_t *pkt_block);

void
pkt_block_free(pkt_block_t *pkt_block);

uint8_t *
pkt_block_get_pkt(pkt_block_t *pkt_block, pkt_size_t *pkt_size) ;

uint8_t
pkt_block_dereference(pkt_block_t *pkt_block);

pkt_block_t *
pkt_block_get_new(uint8_t *pkt, pkt_size_t pkt_size);

void
pkt_block_set_starting_hdr_type(pkt_block_t *pkt_block, hdr_type_t hdr_type) ;

ethernet_hdr_t *
pkt_block_get_ethernet_hdr(pkt_block_t *pkt_block);

arp_hdr_t *
pkt_block_get_arp_hdr(pkt_block_t *pkt_block);

ip_hdr_t *
pkt_block_get_ip_hdr(pkt_block_t *pkt_block);

void
pkt_block_free_internals (pkt_block_t *pkt_block);

void
pkt_block_set_new_pkt(pkt_block_t *pkt_block, uint8_t *pkt, pkt_size_t pkt_size);

pkt_block_t *
pkt_block_dup(pkt_block_t *pkt_block);

bool
pkt_block_expand_buffer_left (pkt_block_t *pkt_block, pkt_size_t expand_bytes);

bool
pkt_block_verify_pkt (pkt_block_t *pkt_block, hdr_type_t hdr_type);

void
tcp_ip_expand_buffer_ethernet_hdr(pkt_block_t *pkt_block) ;

void
print_pkt_block(pkt_block_t *pkt_block);

#endif
