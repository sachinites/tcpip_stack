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
#include "Layer3/gre-tunneling/gre.h"
#include "Interface/InterfaceFwd.h"
#include "Layer3/ipv6/ipv6_hdrs.h"

typedef struct ip_hdr_ ip_hdr_t;
typedef struct arp_hdr_ arp_hdr_t;
typedef struct ethernet_hdr_ ethernet_hdr_t;

typedef struct encap_meta_data_ {

        union {

                struct {

                    uint32_t vni;
                    uint32_t remote_vtep_ip;
                    
                } vxlan;

                struct {


                } gre;

        } u;
} encap_meta_data_t;

struct pkt_block_ {

    uint8_t *pkt;
    pkt_size_t pkt_size;
    hdr_type_t hdr_type;
    dp_intf_t *recommended_oif;
    dp_intf_t *exclude_oif;
    dp_intf_t *ingress_intf;
    encap_meta_data_t *encap_data;
    char *fn_name;
    uint64_t pkt_id;
    uint16_t lineno;
    uint8_t ref_count;
    bool no_modify;
} ;

hdr_type_t
pkt_block_get_starting_hdr(pkt_block_t *pkt_block);

void
pkt_block_reference(pkt_block_t *pkt_block);

uint8_t *
pkt_block_get_pkt(pkt_block_t *pkt_block, pkt_size_t *pkt_size) ;

uint8_t
pkt_block_dereference(pkt_block_t *pkt_block);

pkt_block_t *
pkt_block_get_new2(uint8_t *pkt, pkt_size_t pkt_size, const char *fn_name, uint16_t lineno);

pkt_block_t *
pkt_block_get_new_pkt_buffer2(pkt_size_t pkt_size, const char *fn_name, uint16_t lineno);

void
pkt_block_set_starting_hdr_type(pkt_block_t *pkt_block, hdr_type_t hdr_type) ;

ethernet_hdr_t *
pkt_block_get_ethernet_hdr(pkt_block_t *pkt_block);

arp_hdr_t *
pkt_block_get_arp_hdr(pkt_block_t *pkt_block);

ip_hdr_t *
pkt_block_get_ip_hdr(pkt_block_t *pkt_block);

ipv6_hdr_t *
pkt_block_get_ip6_hdr (pkt_block_t *pkt_block) ;

void
pkt_block_free_internals (pkt_block_t *pkt_block);

void
pkt_block_set_new_pkt(pkt_block_t *pkt_block, uint8_t *pkt, pkt_size_t pkt_size);

void 
pkt_block_update_new_hdr_type (pkt_block_t *pkt_block, uint16_t proto);

pkt_block_t *
pkt_block_dup2(pkt_block_t *pkt_block, const char *fn_name, uint16_t lineno);

bool
pkt_block_expand_buffer_left (pkt_block_t *pkt_block, pkt_size_t expand_bytes);

bool
pkt_block_verify_pkt (pkt_block_t *pkt_block, hdr_type_t hdr_type);

void
tcp_ip_expand_buffer_ethernet_hdr(pkt_block_t *pkt_block) ;

void
print_pkt_block(pkt_block_t *pkt_block);

void 
pkt_block_set_no_modify (pkt_block_t *pkt_block, bool modify) ;

void 
pkt_block_debug(pkt_block_t *pkt_block);

void 
pkt_block_set_recommended_oif (pkt_block_t *pkt_block, dp_intf_t *oif) ;

void
pkt_block_set_exclude_oif (pkt_block_t *pkt_block, dp_intf_t *oif) ;

char *
pkt_ip (pkt_block_t *pkt_block, char *buffer);

char *
pkt_ip_str (pkt_block_t *pkt_block, char *buffer);

char *
pkt_mac_str (pkt_block_t *pkt_block, char *buffer) ;

#define pkt_block_get_new(pkt_ptr, pkt_size)  \
    pkt_block_get_new2 (pkt_ptr, pkt_size, __FUNCTION__, __LINE__)

#define pkt_block_get_new_pkt_buffer(pkt_size)  \
    pkt_block_get_new_pkt_buffer2(pkt_size, __FUNCTION__, __LINE__)

#define pkt_block_dup(pkt_block_ptr)    \
    pkt_block_dup2(pkt_block_ptr, __FUNCTION__, __LINE__)

char *
pkt_block_str (pkt_block_t *pkt_block);

#endif
