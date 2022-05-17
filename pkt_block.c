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
#include "pkt_block.h"

pkt_block_t *
pkt_block_get_new() {

    pkt_block_t *pkt_block = (pkt_block_t *)calloc(1, sizeof(pkt_block_t));
    return pkt_block;
}