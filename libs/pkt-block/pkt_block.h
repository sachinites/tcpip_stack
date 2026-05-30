/*
 * pkt_block.h — compatibility shim over pkt_mbuf.h (non-datapath callers).
 * Datapath code should include pkt_mbuf.h and use struct rte_mbuf * directly.
 */
#ifndef __PKT_BLOCK__
#define __PKT_BLOCK__

#include "pkt_mbuf.h"

typedef struct pkt_block_ pkt_block_t;

#pragma pack(push, 8)

struct pkt_block_ {
    char *fn_name;
    struct rte_mbuf *mbuf;
    uint16_t lineno;
};

#pragma pack(pop)

gen_proto_id_t pkt_block_get_starting_hdr(pkt_block_t *pkt_block);
void pkt_block_reference(pkt_block_t *pkt_block);
uint8_t *pkt_block_get_pkt(pkt_block_t *pkt_block, pkt_size_t *pkt_size);
uint8_t pkt_block_dereference(pkt_block_t *pkt_block);
void pkt_block_update_new_hdr_type(pkt_block_t *pkt_block, gen_proto_id_t hdr_type);
ethernet_hdr_t *pkt_block_get_ethernet_hdr(pkt_block_t *pkt_block);
arp_hdr_t *pkt_block_get_arp_hdr(pkt_block_t *pkt_block);
ip_hdr_t *pkt_block_get_ip_hdr(pkt_block_t *pkt_block);
ipv6_hdr_t *pkt_block_get_ip6_hdr(pkt_block_t *pkt_block);
pkt_block_t *pkt_block_clone(pkt_block_t *pkt_block, const char *fn_name, uint16_t lineno);
bool pkt_block_expand_buffer_left(pkt_block_t *pkt_block, pkt_size_t expand_bytes);
bool pkt_block_verify_pkt(pkt_block_t *pkt_block, gen_proto_id_t hdr_type);
void tcp_ip_expand_buffer_ethernet_hdr(pkt_block_t *pkt_block);
void print_pkt_block(pkt_block_t *pkt_block);
void pkt_block_set_no_modify(pkt_block_t *pkt_block, bool modify);
void pkt_block_debug(pkt_block_t *pkt_block);
char *pkt_ip(pkt_block_t *pkt_block, char *buffer);
char *pkt_ip_str(pkt_block_t *pkt_block, char *buffer);
char *pkt_mac_str(pkt_block_t *pkt_block, char *buffer);
pkt_block_t *pkt_block_wrap_raw_buffer(struct rte_mempool *mbuf_pool,
    uint8_t *pkt, pkt_size_t pkt_size, const char *fn_name, uint16_t lineno);
pkt_block_t *pkt_block_get_new_pkt_buffer(struct rte_mempool *mbuf_pool,
    pkt_size_t pkt_size, const char *fn_name, uint16_t lineno);
#define PKT_BLOCK_WRAP(mpool_ptr, pkt_ptr, pkt_size) \
    pkt_block_wrap_raw_buffer(mpool_ptr, pkt_ptr, pkt_size, __FUNCTION__, __LINE__)
#define PKT_BLOCK_GET_NEW(mpool_ptr, pkt_size) \
    pkt_block_get_new_pkt_buffer(mpool_ptr, pkt_size, __FUNCTION__, __LINE__)
#define PKT_BLOCK_DUP(pkt_block_ptr) pkt_block_clone(pkt_block_ptr, __FUNCTION__, __LINE__)
char *pkt_block_str(pkt_block_t *pkt_block);
void pkt_block_slide(pkt_block_t *pkt_block, int8_t lorr1, int8_t lorr2, uint16_t space);
pkt_block_t *pkt_block_new_with_mbuf(struct rte_mbuf *mbuf);
pkt_mbuf_pvt_data_t *pkt_block_get_pvt_data(pkt_block_t *pkt_block);
pkt_size_t pkt_block_get_data_size(pkt_block_t *pkt_block);
bool pkt_block_get_no_modify_value(pkt_block_t *pkt_block);
void pkt_block_set_no_modify_value(pkt_block_t *pkt_block, bool value);
dp_intf_t *pkt_block_get_ingress_intf(pkt_block_t *pkt_block);
void pkt_block_set_ingress_intf(pkt_block_t *pkt_block, dp_intf_t *intf);

#endif
