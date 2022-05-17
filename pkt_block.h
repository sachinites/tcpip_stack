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
#include "stdbool.h"
#include "tcpconst.h"

typedef struct pkt_block_ {

    unsigned char *pkt;
    uint16_t pkt_size;
    hdr_type_t hdr_type; /* Starting hdr type */
    uint8_t ref_count;
} pkt_block_t;

static inline void
pkt_block_reference(pkt_block_t *pkt_block) {

    pkt_block->ref_count++;
}

static inline void
pkt_block_free(pkt_block_t *pkt_block) {

    free(pkt_block->pkt);
    free(pkt_block);
}

static inline void
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

pkt_block_t *
pkt_block_get_new();

#endif
