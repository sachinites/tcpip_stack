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
#include "tcpconst.h"

typedef struct pkt_block_ {

    unsigned char *pkt;
    size_t pkt_size;
    hdr_type_t hdr_type; /* Starting hdr type */
    uint8_t ref_count;
} pkt_block_t;

void
pkt_block_reference(pkt_block_t *pkt_block);

void
pkt_block_free(pkt_block_t *pkt_block);

void
pkt_block_dereference(pkt_block_t *pkt_block);

pkt_block_t *pkt_block_get_new(unsigned char *pkt, size_t pkt_size);

void
pkt_block_set_starting_hdr_type(pkt_block_t *pkt_block, hdr_type_t hdr_type) ;

#endif
