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
#include <memory.h>
#include "net.h"
#include "pkt_block.h"

pkt_block_t *
pkt_block_get_new(unsigned char *pkt, size_t pkt_size) {

    pkt_block_t *pkt_block = (pkt_block_t *)calloc(1, sizeof(pkt_block_t));
    pkt_block->pkt = pkt;
    pkt_block->pkt_size = pkt_size;
    pkt_block->ref_count = 1;
    return pkt_block;
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
    free(pkt_block);
}

void
pkt_block_dereference(pkt_block_t *pkt_block) {

    if (pkt_block->ref_count == 0) {
        pkt_block_free(pkt_block);
        return;
    }

    pkt_block->ref_count--;

    if (pkt_block->ref_count == 0) {
        pkt_block_free(pkt_block);
    }
}