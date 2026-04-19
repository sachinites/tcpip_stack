/*
 * pkt_mbuf.c
 *
 * Thin, opinionated wrappers around DPDK rte_mbuf operations. These are the
 * mbuf-native counterparts of the pkt_block_* APIs from the tcpip_stack
 * project; instead of owning a malloc'd buffer, every packet is an rte_mbuf
 * drawn from a mempool, and per-packet metadata (protocol id, encap info,
 * allocation site) lives in the mbuf's private area (see pkt_mbuf_pvt_data_t
 * in pkt_mbuf.h, exposed via rte_mbuf_to_priv()).
 */

#include "pkt_mbuf.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_byteorder.h>

/* ------------------------------------------------------------------------- */
/* Mempool / mbuf lifecycle                                                  */
/* ------------------------------------------------------------------------- */

struct rte_mempool *
pkt_mbuf_init(const char *pool_name,
              uint32_t num_mbufs,
              uint32_t mbuf_cache_size,
              uint16_t priv_size,
              uint16_t data_room_size,
              int socket_id)
{
    struct rte_mempool *mbuf_pool =
        rte_pktmbuf_pool_create(pool_name,
                                num_mbufs,
                                mbuf_cache_size,
                                priv_size,
                                data_room_size,
                                socket_id);

    if (mbuf_pool == NULL) {
        return NULL;
    }

    return mbuf_pool;
}

struct rte_mbuf *
pkt_mbuf_alloc(struct rte_mempool *mbuf_pool)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(mbuf_pool);
    if (m == NULL) {
        return NULL;
    }

    /* Zero the private area so hdr_type / encap_data / fn_name start clean. */
    if (rte_pktmbuf_priv_size(mbuf_pool) >= sizeof(pkt_mbuf_pvt_data_t)) {
        memset(rte_mbuf_to_priv(m), 0, sizeof(pkt_mbuf_pvt_data_t));
    }

    return m;
}

void
pkt_mbuf_free(struct rte_mbuf *mbuf)
{
    /* No pool argument needed: rte_pktmbuf_free() reads mbuf->pool and
     * returns each segment of the chain to its own owning pool. */
    if (mbuf == NULL) {
        return;
    }

    rte_pktmbuf_free(mbuf);
}

struct rte_mbuf *
pkt_mbuf_clone(struct rte_mempool *mbuf_pool, struct rte_mbuf *mbuf)
{
    if (mbuf == NULL || mbuf_pool == NULL) {
        return NULL;
    }

    /* rte_pktmbuf_copy performs a deep copy (headers + payload, all segments).
     * Use this rather than rte_pktmbuf_clone so the caller gets an
     * independent, writable packet — matching pkt_block_dup semantics. */
    struct rte_mbuf *dup = rte_pktmbuf_copy(mbuf, mbuf_pool, 0, UINT32_MAX);
    if (dup == NULL) {
        return NULL;
    }

    /* Carry over the private metadata. */
    if (rte_pktmbuf_priv_size(mbuf_pool) >= sizeof(pkt_mbuf_pvt_data_t) &&
        mbuf->pool != NULL &&
        rte_pktmbuf_priv_size(mbuf->pool) >= sizeof(pkt_mbuf_pvt_data_t)) {
        memcpy(rte_mbuf_to_priv(dup),
               rte_mbuf_to_priv(mbuf),
               sizeof(pkt_mbuf_pvt_data_t));
    }

    return dup;
}

/* ------------------------------------------------------------------------- */
/* Buffer grow / shrink                                                       */
/* ------------------------------------------------------------------------- */

/* Grow the packet by n bytes at the HEAD (uses headroom). Returns a pointer
 * to the newly prepended region, or NULL if there is not enough headroom.
 * Operates on the head segment only — same contract as rte_pktmbuf_prepend. */
uint8_t *
pkt_mbuf_expland_left(struct rte_mbuf *mbuf, uint32_t n)
{
    if (mbuf == NULL || n == 0) {
        return NULL;
    }

    if (n > UINT16_MAX || (uint16_t)n > rte_pktmbuf_headroom(mbuf)) {
        return NULL;
    }

    return (uint8_t *)rte_pktmbuf_prepend(mbuf, (uint16_t)n);
}

/* Grow the packet by n bytes at the TAIL (uses tailroom of the last segment).
 * Returns a pointer to the newly appended region, or NULL on failure. */
uint8_t *
pkt_mbuf_expland_right(struct rte_mbuf *mbuf, uint32_t n)
{
    if (mbuf == NULL || n == 0) {
        return NULL;
    }

    if (n > UINT16_MAX) {
        return NULL;
    }

    return (uint8_t *)rte_pktmbuf_append(mbuf, (uint16_t)n);
}

/* Shrink the packet by n bytes at the TAIL. Returns a pointer to the new end
 * of data (or NULL on failure). Wraps rte_pktmbuf_trim. */
uint8_t *
pkt_mbuf_shrink_right(struct rte_mbuf *mbuf, uint32_t n)
{
    if (mbuf == NULL || n == 0) {
        return NULL;
    }

    if (n > UINT16_MAX || rte_pktmbuf_trim(mbuf, (uint16_t)n) < 0) {
        return NULL;
    }

    /* Return pointer just past the new last byte of packet data. */
    struct rte_mbuf *last = rte_pktmbuf_lastseg(mbuf);
    return rte_pktmbuf_mtod_offset(last, uint8_t *, last->data_len);
}

/* Shrink the packet by n bytes at the HEAD. Returns a pointer to the new
 * start of packet data, or NULL on failure. Wraps rte_pktmbuf_adj. */
uint8_t *
pkt_mbuf_shrink_left(struct rte_mbuf *mbuf, uint32_t n)
{
    if (mbuf == NULL || n == 0) {
        return NULL;
    }

    if (n > UINT16_MAX) {
        return NULL;
    }

    return (uint8_t *)rte_pktmbuf_adj(mbuf, (uint16_t)n);
}

/* ------------------------------------------------------------------------- */
/* Reference counting                                                         */
/* ------------------------------------------------------------------------- */

void
pkt_mbuf_ref_inc(struct rte_mbuf *mbuf)
{
    if (mbuf == NULL) {
        return;
    }
    rte_mbuf_refcnt_update(mbuf, 1);
}

/* Decrement the refcount; when it reaches 0, the mbuf (and its chain) is
 * returned to its owning pool. The mbuf_pool argument is kept for API
 * symmetry with pkt_block_dereference but is not required by DPDK. */
void
pkt_mbuf_ref_dec(struct rte_mbuf *mbuf)
{
    if (mbuf == NULL) {
        return;
    }

    /* rte_pktmbuf_free walks the segment chain, decrements each segment's
     * refcount, and frees segments that hit 0. */
    rte_pktmbuf_free(mbuf);
}

/* ------------------------------------------------------------------------- */
/* Private-area metadata accessors                                            */
/* ------------------------------------------------------------------------- */

static inline pkt_mbuf_pvt_data_t *
pkt_mbuf_priv(struct rte_mbuf *mbuf)
{
    if (mbuf == NULL || mbuf->pool == NULL) {
        return NULL;
    }
    if (rte_pktmbuf_priv_size(mbuf->pool) < sizeof(pkt_mbuf_pvt_data_t)) {
        return NULL;
    }
    return (pkt_mbuf_pvt_data_t *)rte_mbuf_to_priv(mbuf);
}

gen_proto_id_t
pkt_mbuf_get_starting_hdr(struct rte_mbuf *mbuf)
{
    /* hdr_type is stored in the mbuf's private data area. The owning pool
     * must have been created with priv_size >= sizeof(pkt_mbuf_pvt_data_t)
     * (see pkt_mbuf_init()), otherwise there is nowhere to store it. */
    assert(mbuf != NULL);
    assert(mbuf->pool != NULL);
    assert(rte_pktmbuf_priv_size(mbuf->pool) >= sizeof(pkt_mbuf_pvt_data_t));

    pkt_mbuf_pvt_data_t *priv =
        (pkt_mbuf_pvt_data_t *)rte_mbuf_to_priv(mbuf);

    return priv->hdr_type;
}

void
pkt_mbuf_update_new_hdr_type(struct rte_mbuf *mbuf, gen_proto_id_t hdr_type)
{
    pkt_mbuf_pvt_data_t *priv = pkt_mbuf_priv(mbuf);
    if (priv) {
        priv->hdr_type = hdr_type;
    }
}

bool
pkt_mbuf_verify_pkt(struct rte_mbuf *mbuf, gen_proto_id_t hdr_type)
{
    return pkt_mbuf_get_starting_hdr(mbuf) == hdr_type;
}

uint8_t *
pkt_mbuf_get_raw_pkt(struct rte_mbuf *mbuf, uint16_t *pkt_size_out)
{
    if (mbuf == NULL) {
        if (pkt_size_out) *pkt_size_out = 0;
        return NULL;
    }

    if (pkt_size_out) {
        /* Cap to uint16_t — single-segment length. For the whole-chain size,
         * callers should read mbuf->pkt_len directly. */
        *pkt_size_out = mbuf->data_len;
    }
    return rte_pktmbuf_mtod(mbuf, uint8_t *);
}

/* ------------------------------------------------------------------------- */
/* Header walkers (mirror pkt_block_get_*_hdr, using DPDK header structs)     */
/* ------------------------------------------------------------------------- */

static struct rte_ether_hdr *
pkt_mbuf_get_ethernet_hdr(struct rte_mbuf *mbuf)
{
    if (pkt_mbuf_get_starting_hdr(mbuf) != ETHERNET_HEADER) {
        return NULL;
    }
    return rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
}

static struct rte_ipv4_hdr *
pkt_mbuf_get_ipv4_hdr(struct rte_mbuf *mbuf)
{
    gen_proto_id_t hdr_type = pkt_mbuf_get_starting_hdr(mbuf);

    if (hdr_type == ETHERNET_HEADER) {
        struct rte_ether_hdr *eth =
            rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
        if (rte_be_to_cpu_16(eth->ether_type) == ETH_TYPE_IPv4) {
            return (struct rte_ipv4_hdr *)(eth + 1);
        }
        return NULL;
    }

    if (hdr_type == IP_PROTO_IP_IN_IP) {
        return rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
    }

    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Debug / pretty-print                                                       */
/* ------------------------------------------------------------------------- */

void
pkt_mbuf_debug(struct rte_mbuf *mbuf)
{
    if (mbuf == NULL) {
        printf("pkt_mbuf_debug: (null)\n");
        return;
    }

    pkt_mbuf_pvt_data_t *priv = pkt_mbuf_priv(mbuf);

    printf("rte_mbuf %p: pkt_len=%u data_len=%u nb_segs=%u data_off=%u "
           "refcnt=%u\n",
           (void *)mbuf,
           mbuf->pkt_len, mbuf->data_len, mbuf->nb_segs, mbuf->data_off,
           rte_mbuf_refcnt_read(mbuf));

    if (priv) {
        printf("  hdr_type=%u (%s)  no_modify=%d  ingress_intf=0x%lx\n",
               priv->hdr_type,
               proto_id_str(priv->hdr_type),
               (int)priv->no_modify,
               (unsigned long)priv->ingress_intf);
    } else {
        printf("  (no private metadata — pool priv_size too small)\n");
    }

    rte_pktmbuf_dump(stdout, mbuf, 64);
}

char *
pkt_mbuf_ip(struct rte_mbuf *mbuf, char *buffer)
{
    struct rte_ipv4_hdr *ip = pkt_mbuf_get_ipv4_hdr(mbuf);
    if (ip == NULL || buffer == NULL) {
        return NULL;
    }

    /* dst_addr is stored in network byte order; inet_ntop expects that. */
    uint32_t ip_addr = ip->dst_addr;
    inet_ntop(AF_INET, &ip_addr, buffer, INET_ADDRSTRLEN);
    return buffer;
}

char *
pkt_mbuf_ip_str(struct rte_mbuf *mbuf, char *buffer)
{
    struct rte_ipv4_hdr *ip = pkt_mbuf_get_ipv4_hdr(mbuf);
    if (ip == NULL || buffer == NULL) {
        return NULL;
    }

    memcpy(buffer, "IP:", 3);
    uint32_t ip_addr = ip->dst_addr;
    inet_ntop(AF_INET, &ip_addr, buffer + 3, INET_ADDRSTRLEN);
    return buffer;
}

char *
pkt_mbuf_mac_str(struct rte_mbuf *mbuf, char *buffer)
{
    struct rte_ether_hdr *eth = pkt_mbuf_get_ethernet_hdr(mbuf);
    if (eth == NULL || buffer == NULL) {
        return NULL;
    }

    const uint8_t *m = eth->dst_addr.addr_bytes;
    sprintf(buffer, "ETH:%02x:%02x:%02x:%02x:%02x:%02x",
            m[0], m[1], m[2], m[3], m[4], m[5]);
    return buffer;
}
