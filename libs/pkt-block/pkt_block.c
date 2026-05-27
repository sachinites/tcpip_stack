/*
 * pkt_block.c — thin wrappers over pkt_mbuf_* for legacy pkt_block_t callers.
 */
#include <stdlib.h>
#include <assert.h>
#include "pkt_block.h"

static pkt_block_t *
pkt_block_wrap_mbuf(struct rte_mbuf *mbuf, const char *fn_name, uint16_t lineno)
{
    pkt_block_t *pb = (pkt_block_t *)calloc(1, sizeof(pkt_block_t));
    pb->mbuf    = mbuf;
    pb->fn_name = (char *)fn_name;
    pb->lineno  = lineno;
    return pb;
}

gen_proto_id_t pkt_block_get_starting_hdr(pkt_block_t *pb)
{ return pkt_mbuf_get_starting_hdr(pb->mbuf); }

void pkt_block_reference(pkt_block_t *pb)
{ pkt_mbuf_ref_inc(pb->mbuf); }

uint8_t *pkt_block_get_pkt(pkt_block_t *pb, pkt_size_t *pkt_size)
{ return pkt_mbuf_get_pkt(pb->mbuf, pkt_size); }

uint8_t pkt_block_dereference(pkt_block_t *pb)
{
    uint8_t rc = pkt_mbuf_dereference(pb->mbuf);
    if (rc == 0) {
        pb->mbuf = NULL;
        free(pb);
    }
    return rc;
}

void pkt_block_update_new_hdr_type(pkt_block_t *pb, gen_proto_id_t hdr_type)
{ pkt_mbuf_update_new_hdr_type(pb->mbuf, hdr_type); }

ethernet_hdr_t *pkt_block_get_ethernet_hdr(pkt_block_t *pb)
{ return pkt_mbuf_get_ethernet_hdr(pb->mbuf); }

arp_hdr_t *pkt_block_get_arp_hdr(pkt_block_t *pb)
{ return pkt_mbuf_get_arp_hdr(pb->mbuf); }

ip_hdr_t *pkt_block_get_ip_hdr(pkt_block_t *pb)
{ return pkt_mbuf_get_ip_hdr(pb->mbuf); }

ipv6_hdr_t *pkt_block_get_ip6_hdr(pkt_block_t *pb)
{ return pkt_mbuf_get_ip6_hdr(pb->mbuf); }

pkt_block_t *pkt_block_clone(pkt_block_t *pb, const char *fn, uint16_t lineno)
{
    return pkt_block_wrap_mbuf(pkt_mbuf_clone(pb->mbuf->pool, pb->mbuf), fn, lineno);
}

bool pkt_block_expand_buffer_left(pkt_block_t *pb, pkt_size_t n)
{ return pkt_mbuf_expand_buffer_left(pb->mbuf, n); }

bool pkt_block_verify_pkt(pkt_block_t *pb, gen_proto_id_t hdr_type)
{ return pkt_mbuf_verify_pkt(pb->mbuf, hdr_type); }

void tcp_ip_expand_buffer_ethernet_hdr(pkt_block_t *pb)
{ pkt_mbuf_tcp_ip_expand_buffer_ethernet_hdr(pb->mbuf); }

void print_pkt_block(pkt_block_t *pb) { (void)pb; }

void pkt_block_set_no_modify(pkt_block_t *pb, bool modify)
{ pkt_mbuf_set_no_modify(pb->mbuf, modify); }

void pkt_block_debug(pkt_block_t *pb)
{ pkt_mbuf_debug(pb->mbuf); }

char *pkt_ip(pkt_block_t *pb, char *buffer)
{ return pkt_mbuf_ip(pb->mbuf, buffer); }

char *pkt_ip_str(pkt_block_t *pb, char *buffer)
{ return pkt_mbuf_ip_str(pb->mbuf, buffer); }

char *pkt_mac_str(pkt_block_t *pb, char *buffer)
{ return pkt_mbuf_mac_str(pb->mbuf, buffer); }

pkt_block_t *pkt_block_wrap_raw_buffer(struct rte_mempool *pool,
    uint8_t *pkt, pkt_size_t pkt_size, const char *fn, uint16_t lineno)
{
    return pkt_block_wrap_mbuf(
        pkt_mbuf_wrap_raw_buffer(pool, pkt, pkt_size, fn, lineno), fn, lineno);
}

pkt_block_t *pkt_block_get_new_pkt_buffer(struct rte_mempool *pool,
    pkt_size_t pkt_size, const char *fn, uint16_t lineno)
{
    return pkt_block_wrap_mbuf(pkt_mbuf_get_new(pool, pkt_size, fn, lineno), fn, lineno);
}

char *pkt_block_str(pkt_block_t *pb)
{ return pkt_mbuf_str(pb->mbuf); }

void pkt_block_slide(pkt_block_t *pb, int8_t l1, int8_t l2, uint16_t space)
{ pkt_mbuf_slide(pb->mbuf, l1, l2, space); }

pkt_block_t *pkt_block_new_with_mbuf(struct rte_mbuf *mbuf)
{
    return pkt_block_wrap_mbuf(mbuf, __FUNCTION__, (uint16_t)__LINE__);
}

pkt_mbuf_pvt_data_t *pkt_block_get_pvt_data(pkt_block_t *pb)
{ return pkt_mbuf_get_pvt_data(pb->mbuf); }

pkt_size_t pkt_block_get_data_size(pkt_block_t *pb)
{ return pkt_mbuf_get_data_size(pb->mbuf); }

bool pkt_block_get_no_modify_value(pkt_block_t *pb)
{ return pkt_mbuf_get_no_modify_value(pb->mbuf); }

void pkt_block_set_no_modify_value(pkt_block_t *pb, bool value)
{ pkt_mbuf_set_no_modify_value(pb->mbuf, value); }

dp_intf_t *pkt_block_get_ingress_intf(pkt_block_t *pb)
{ return pkt_mbuf_get_ingress_intf(pb->mbuf); }

void pkt_block_set_ingress_intf(pkt_block_t *pb, dp_intf_t *intf)
{ pkt_mbuf_set_ingress_intf(pb->mbuf, intf); }
