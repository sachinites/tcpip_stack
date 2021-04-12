/*
 * =====================================================================================
 *
 *       Filename:  lsp_mgmt.h
 *
 *    Description: This file declares the structures and routines for Link state pkt mgmt 
 *
 *        Version:  1.0
 *        Created:  03/28/2021 11:30:20 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#ifndef __LSP_MGMT__
#define __LSP_MGMT__

#include <stdint.h>

#pragma pack (push,1)

typedef struct igp_tlv_ {

    uint8_t tlv_type;
    uint8_t tlv_len;
    char value[0];
} igp_tlv_t;

typedef struct igp_pkt_hdr_ {

    char rtr_id[16];
    uint32_t seq_no;
    uint32_t flags;
} igp_pkt_hdr_t;

typedef struct igp_pkt_ {

    igp_pkt_hdr_t igp_hdr;
    igp_tlv_t tlvs[0];
} igp_pkt_t;

#pragma pack(pop)

typedef struct node_ node_t;
typedef struct interface_ interface_t;

igp_pkt_t *
igp_generate_lsp_pkt(node_t *node, uint32_t *pkt_size);

void
igp_flood_lsp_pkt(node_t *node,
                  igp_pkt_t *lsp_pkt,
                  uint32_t pkt_size);

void
igp_start_periodic_self_lsp_pkt_flooding(node_t *node);

void
igp_stop_periodic_self_lsp_pkt_flooding(node_t *node);

void
igp_recv_lsp_pkt(node_t *node,
                 interface_t *interface,
                 igp_pkt_t *lsp_pkt,
                 uint32_t pkt_size);

#endif /* __LSP_MGMT__  */
