#ifndef __PKT_MBUF__
#define __PKT_MBUF__

#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>

#include "../common/protoIds.h"


/* NOTE: these structs live in the mbuf's private data area (pure in-memory,
 * CPU-local state — never serialized to wire/disk). Do NOT use
 * #pragma pack here: packed layouts create misaligned loads of the pointer-
 * sized fields below, which are slower on x86 and a SIGBUS on some ARM /
 * RISC-V configurations. Fields are ordered below for minimum padding under
 * natural alignment. */

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

    uintptr_t                   ingress_intf;  /* 8 */
    pkt_mbuf_encap_meta_data_t  *encap_data;   /* 8 */
    gen_proto_id_t              hdr_type;      /* 2 */
    bool                        no_modify;     /* 1 */
    /* 5 bytes trailing pad -> 24 bytes total, all naturally aligned */

} pkt_mbuf_pvt_data_t;

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

/* API to expand the packet buffer by N bytes in the room */
uint8_t *
pkt_mbuf_expland_left(struct rte_mbuf *mbuf, uint32_t n);

/* API to expand the packet buffer by N bytes in the room */
uint8_t *
pkt_mbuf_expland_right(struct rte_mbuf *mbuf, uint32_t n);

/* API to shrink the packet buffer by N bytes towards right  */
uint8_t *
pkt_mbuf_shrink_right(struct rte_mbuf *mbuf, uint32_t n);

/* API to shrink the packet buffer by N bytes towards left  */
uint8_t *
pkt_mbuf_shrink_left(struct rte_mbuf *mbuf, uint32_t n);

/* API to increase the ref count of the packet buffer */
void
pkt_mbuf_ref_inc(struct rte_mbuf *mbuf);

/* API to decrease the ref count of the packet buffer */
void
pkt_mbuf_ref_dec(struct rte_mbuf *mbuf);

gen_proto_id_t
pkt_mbuf_get_starting_hdr(struct rte_mbuf *mbuf);

uint8_t *
pkt_mbuf_get_raw_pkt(struct rte_mbuf *mbuf, uint16_t *pkt_size_out) ;

void
pkt_mbuf_update_new_hdr_type(struct rte_mbuf *mbuf, gen_proto_id_t hdr_type) ;

bool
pkt_mbuf_verify_pkt (struct rte_mbuf *mbuf, gen_proto_id_t hdr_type);

void 
pkt_mbuf_debug(struct rte_mbuf *mbuf);

char *
pkt_mbuf_ip (struct rte_mbuf *mbuf, char *buffer);

char *
pkt_mbuf_ip_str (struct rte_mbuf *mbuf, char *buffer);

char *
pkt_mbuf_mac_str (struct rte_mbuf *mbuf, char *buffer) ;

#endif
