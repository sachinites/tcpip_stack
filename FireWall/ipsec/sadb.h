/*
 * =====================================================================================
 *
 *       Filename:  sadb.h
 *
 *    Description: This file declares the routines to work with SAD 
 *
 *        Version:  1.0
 *        Created:  11/12/2021 11:53:16 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#ifndef __IPSEC__SAD__
#define __IPSEC__SAD__

#include <stdint.h>
#include "ipsec_const.h"
#include "../../Tree/libtree.h"

/* SAD entry */
typedef struct ipsec_sad_entry_ {

    uint32_t src_addr;
    uint32_t dst_addr;
    SEC_PROTO sec_proto;
    CRYPTO_ALGO crypto_algo;
    uint32_t spi;
    uint16_t lifetime; /* in sec */
    avltree_node_t avl_node;
} ipsec_sad_entry_t;

typedef struct ipsec_sad_ {

    avltree_t root;
} ipsec_sad_t;

#endif
