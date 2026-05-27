#ifndef __PKT_MBUF__
#define __PKT_MBUF__

#include <stdint.h>
#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "../common/protoIds.h"
#include "../common/cmn_struct.h"
#include "../../Layer3/gre-tunneling/gre.h"
#include "../common/ipv6_hdrs.h"

typedef struct ip_hdr_ ip_hdr_t;
typedef struct arp_hdr_ arp_hdr_t;
typedef struct ethernet_hdr_ ethernet_hdr_t;
typedef struct dp_intf_ dp_intf_t;

typedef struct rte_mbuf pkt_mbuf_t;

#define MAX_PACKET_BUFFER_SIZE   2048
#define PKT_BUFFER_RIGHT_ROOM    128

typedef struct pkt_mbuf_encap_meta_data_
{
    union
    {
        struct
        {
            uint32_t vni;
            uint32_t remote_vtep_ip;
        } vxlan;

        struct
        {
        } gre;

    } u;
} pkt_mbuf_encap_meta_data_t;

typedef struct pkt_mbuf_pvt_data_ {

    uintptr_t                   ingress_intf;
    pkt_mbuf_encap_meta_data_t  *encap_data;
    gen_proto_id_t              hdr_type;
    bool                        no_modify;

} pkt_mbuf_pvt_data_t;

/* ------------------------------------------------------------------------- */
/* Mempool / mbuf primitives                                                   */
/* ------------------------------------------------------------------------- */

struct rte_mempool *
pkt_mbuf_init(const char *pool_name,
              uint32_t num_mbufs,
              uint32_t mbuf_cache_size,
              uint16_t priv_size,
              uint16_t data_room_size,
              int socket_id);

struct rte_mbuf *
pkt_mbuf_alloc(struct rte_mempool *mbuf_pool);

void
pkt_mbuf_free(struct rte_mbuf *mbuf);

struct rte_mbuf *
pkt_mbuf_clone(struct rte_mempool *mbuf_pool, struct rte_mbuf *mbuf);

uint8_t *
pkt_mbuf_expland_left(struct rte_mbuf *mbuf, uint32_t n);

uint8_t *
pkt_mbuf_expland_right(struct rte_mbuf *mbuf, uint32_t n);

uint8_t *
pkt_mbuf_shrink_right(struct rte_mbuf *mbuf, uint32_t n);

uint8_t *
pkt_mbuf_shrink_left(struct rte_mbuf *mbuf, uint32_t n);

void
pkt_mbuf_ref_inc(struct rte_mbuf *mbuf);

void
pkt_mbuf_ref_dec(struct rte_mbuf *mbuf);

/* Returns remaining refcount after dropping one reference (0 if freed). */
uint8_t
pkt_mbuf_dereference(struct rte_mbuf *mbuf);

gen_proto_id_t
pkt_mbuf_get_starting_hdr(struct rte_mbuf *mbuf);

uint8_t *
pkt_mbuf_get_raw_pkt(struct rte_mbuf *mbuf, uint16_t *pkt_size_out);

uint8_t *
pkt_mbuf_get_pkt(struct rte_mbuf *mbuf, pkt_size_t *pkt_size);

void
pkt_mbuf_update_new_hdr_type(struct rte_mbuf *mbuf, gen_proto_id_t hdr_type);

bool
pkt_mbuf_verify_pkt(struct rte_mbuf *mbuf, gen_proto_id_t hdr_type);

void
pkt_mbuf_debug(struct rte_mbuf *mbuf);

char *
pkt_mbuf_ip(struct rte_mbuf *mbuf, char *buffer);

char *
pkt_mbuf_ip_str(struct rte_mbuf *mbuf, char *buffer);

char *
pkt_mbuf_mac_str(struct rte_mbuf *mbuf, char *buffer);

/* ------------------------------------------------------------------------- */
/* Packet lifecycle                                                            */
/* ------------------------------------------------------------------------- */

struct rte_mbuf *
pkt_mbuf_wrap_raw_buffer(struct rte_mempool *mbuf_pool,
                         uint8_t *pkt, pkt_size_t pkt_size,
                         const char *fn_name, uint16_t lineno);

struct rte_mbuf *
pkt_mbuf_get_new(struct rte_mempool *mbuf_pool,
                 pkt_size_t pkt_size,
                 const char *fn_name, uint16_t lineno);

#define PKT_MBUF_WRAP(mpool_ptr, pkt_ptr, pkt_size)  \
    pkt_mbuf_wrap_raw_buffer(mpool_ptr, pkt_ptr, pkt_size, __FUNCTION__, __LINE__)

#define PKT_MBUF_GET_NEW(mpool_ptr, pkt_size)  \
    pkt_mbuf_get_new(mpool_ptr, pkt_size, __FUNCTION__, __LINE__)

#define PKT_MBUF_DUP(mbuf_ptr)    \
    pkt_mbuf_clone((mbuf_ptr)->pool, mbuf_ptr)

/* ------------------------------------------------------------------------- */
/* Header walkers & buffer helpers                                             */
/* ------------------------------------------------------------------------- */

ethernet_hdr_t *
pkt_mbuf_get_ethernet_hdr(struct rte_mbuf *mbuf);

arp_hdr_t *
pkt_mbuf_get_arp_hdr(struct rte_mbuf *mbuf);

ip_hdr_t *
pkt_mbuf_get_ip_hdr(struct rte_mbuf *mbuf);

ipv6_hdr_t *
pkt_mbuf_get_ip6_hdr(struct rte_mbuf *mbuf);

bool
pkt_mbuf_expand_buffer_left(struct rte_mbuf *mbuf, pkt_size_t expand_bytes);

void
pkt_mbuf_tcp_ip_expand_buffer_ethernet_hdr(struct rte_mbuf *mbuf);

char *
pkt_mbuf_str(struct rte_mbuf *mbuf);

void
pkt_mbuf_slide(struct rte_mbuf *mbuf,
               int8_t lorr1,
               int8_t lorr2,
               uint16_t space);

pkt_mbuf_pvt_data_t *
pkt_mbuf_get_pvt_data(struct rte_mbuf *mbuf);

pkt_size_t
pkt_mbuf_get_data_size(struct rte_mbuf *mbuf);

bool
pkt_mbuf_get_no_modify_value(struct rte_mbuf *mbuf);

void
pkt_mbuf_set_no_modify_value(struct rte_mbuf *mbuf, bool value);

void
pkt_mbuf_set_no_modify(struct rte_mbuf *mbuf, bool modify);

dp_intf_t *
pkt_mbuf_get_ingress_intf(struct rte_mbuf *mbuf);

void
pkt_mbuf_set_ingress_intf(struct rte_mbuf *mbuf, dp_intf_t *intf);

#endif /* __PKT_MBUF__ */
