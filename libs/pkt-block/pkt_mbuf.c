/*
 * pkt_mbuf.c — DPDK rte_mbuf packet buffer API (canonical datapath packet type).
 */

#include "pkt_mbuf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "../common/protoIds.h"
#include "../common/l2_hdrs.h"
#include "../common/l3_hdrs.h"

static inline pkt_mbuf_pvt_data_t *
pkt_mbuf_priv(struct rte_mbuf *mbuf)
{
    if (mbuf == NULL || mbuf->pool == NULL) return NULL;
    if (rte_pktmbuf_priv_size(mbuf->pool) < sizeof(pkt_mbuf_pvt_data_t)) return NULL;
    return (pkt_mbuf_pvt_data_t *)rte_mbuf_to_priv(mbuf);
}

#define PKTMBUF_PKT(m) \
    ((m) ? rte_pktmbuf_mtod((m), uint8_t *) : NULL)
#define PKTMBUF_HDR_TYPE(m) pkt_mbuf_get_starting_hdr(m)

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
    return rte_pktmbuf_pool_create(pool_name,
                                   num_mbufs,
                                   mbuf_cache_size,
                                   priv_size,
                                   data_room_size,
                                   socket_id);
}

struct rte_mbuf *
pkt_mbuf_alloc(struct rte_mempool *mbuf_pool)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(mbuf_pool);
    if (m == NULL) return NULL;

    if (rte_pktmbuf_priv_size(mbuf_pool) >= sizeof(pkt_mbuf_pvt_data_t)) {
        memset(rte_mbuf_to_priv(m), 0, sizeof(pkt_mbuf_pvt_data_t));
    }
    return m;
}

void
pkt_mbuf_free(struct rte_mbuf *mbuf)
{
    if (mbuf == NULL) return;
    rte_pktmbuf_free(mbuf);
}

struct rte_mbuf *
pkt_mbuf_clone(struct rte_mempool *mbuf_pool, struct rte_mbuf *mbuf)
{
    if (mbuf == NULL || mbuf_pool == NULL) return NULL;

    struct rte_mbuf *dup = rte_pktmbuf_copy(mbuf, mbuf_pool, 0, UINT32_MAX);
    if (dup == NULL) return NULL;

    if (rte_pktmbuf_priv_size(mbuf_pool) >= sizeof(pkt_mbuf_pvt_data_t) &&
        mbuf->pool != NULL &&
        rte_pktmbuf_priv_size(mbuf->pool) >= sizeof(pkt_mbuf_pvt_data_t)) {
        memcpy(rte_mbuf_to_priv(dup),
               rte_mbuf_to_priv(mbuf),
               sizeof(pkt_mbuf_pvt_data_t));
    }
    return dup;
}

uint8_t *
pkt_mbuf_expland_left(struct rte_mbuf *mbuf, uint32_t n)
{
    if (mbuf == NULL || n == 0) return NULL;
    if (n > UINT16_MAX || (uint16_t)n > rte_pktmbuf_headroom(mbuf)) return NULL;
    return (uint8_t *)rte_pktmbuf_prepend(mbuf, (uint16_t)n);
}

uint8_t *
pkt_mbuf_expland_right(struct rte_mbuf *mbuf, uint32_t n)
{
    if (mbuf == NULL || n == 0) return NULL;
    if (n > UINT16_MAX) return NULL;
    return (uint8_t *)rte_pktmbuf_append(mbuf, (uint16_t)n);
}

uint8_t *
pkt_mbuf_shrink_right(struct rte_mbuf *mbuf, uint32_t n)
{
    if (mbuf == NULL || n == 0) return NULL;
    if (n > UINT16_MAX || rte_pktmbuf_trim(mbuf, (uint16_t)n) < 0) return NULL;
    struct rte_mbuf *last = rte_pktmbuf_lastseg(mbuf);
    return rte_pktmbuf_mtod_offset(last, uint8_t *, last->data_len);
}

uint8_t *
pkt_mbuf_shrink_left(struct rte_mbuf *mbuf, uint32_t n)
{
    if (mbuf == NULL || n == 0) return NULL;
    if (n > UINT16_MAX) return NULL;
    return (uint8_t *)rte_pktmbuf_adj(mbuf, (uint16_t)n);
}

void
pkt_mbuf_ref_inc(struct rte_mbuf *mbuf)
{
    if (mbuf == NULL) return;
    rte_mbuf_refcnt_update(mbuf, 1);
}

void
pkt_mbuf_ref_dec(struct rte_mbuf *mbuf)
{
    if (mbuf == NULL) return;
    rte_pktmbuf_free(mbuf);
}

uint8_t
pkt_mbuf_dereference(struct rte_mbuf *mbuf)
{
    assert(mbuf != NULL);

    uint16_t old = rte_mbuf_refcnt_read(mbuf);
    assert(old != 0);

    if (old == 1) {
        pkt_mbuf_pvt_data_t *priv = pkt_mbuf_priv(mbuf);
        if (priv) {
            if (priv->encap_data) {
                free(priv->encap_data);
                priv->encap_data = NULL;
            }
            priv->ingress_intf = 0;
        }
        pkt_mbuf_ref_dec(mbuf);
        return 0;
    }

    pkt_mbuf_ref_dec(mbuf);
    return (uint8_t)(old - 1);
}

/* ------------------------------------------------------------------------- */
/* Metadata & raw packet access                                                */
/* ------------------------------------------------------------------------- */

gen_proto_id_t
pkt_mbuf_get_starting_hdr(struct rte_mbuf *mbuf)
{
    assert(mbuf != NULL);
    assert(mbuf->pool != NULL);
    assert(rte_pktmbuf_priv_size(mbuf->pool) >= sizeof(pkt_mbuf_pvt_data_t));
    return ((pkt_mbuf_pvt_data_t *)rte_mbuf_to_priv(mbuf))->hdr_type;
}

void
pkt_mbuf_update_new_hdr_type(struct rte_mbuf *mbuf, gen_proto_id_t hdr_type)
{
    pkt_mbuf_pvt_data_t *priv = pkt_mbuf_priv(mbuf);
    if (priv) priv->hdr_type = hdr_type;
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
    if (pkt_size_out) *pkt_size_out = mbuf->data_len;
    return rte_pktmbuf_mtod(mbuf, uint8_t *);
}

uint8_t *
pkt_mbuf_get_pkt(struct rte_mbuf *mbuf, pkt_size_t *pkt_size)
{
    uint16_t sz = 0;
    uint8_t *p = pkt_mbuf_get_raw_pkt(mbuf, &sz);
    if (pkt_size) *pkt_size = (pkt_size_t)sz;
    return p;
}

struct rte_mbuf *
pkt_mbuf_get_new(struct rte_mempool *mbuf_pool,
                 pkt_size_t pkt_size,
                 const char *fn_name, uint16_t lineno)
{
    (void)fn_name;
    (void)lineno;

    struct rte_mbuf *mbuf = pkt_mbuf_alloc(mbuf_pool);
    assert(mbuf != NULL);
    if (pkt_size > 0) {
        uint8_t *p = pkt_mbuf_expland_left(mbuf, (uint32_t)pkt_size);
        assert(p != NULL);
        (void)p;
    }
    return mbuf;
}

struct rte_mbuf *
pkt_mbuf_wrap_raw_buffer(struct rte_mempool *mbuf_pool,
                         uint8_t *pkt, pkt_size_t pkt_size,
                         const char *fn_name, uint16_t lineno)
{
    struct rte_mbuf *mbuf =
        pkt_mbuf_get_new(mbuf_pool, pkt_size, fn_name, lineno);
    memcpy(pkt_mbuf_get_pkt(mbuf, NULL), pkt, pkt_size);
    return mbuf;
}

/* ------------------------------------------------------------------------- */
/* Header walkers                                                              */
/* ------------------------------------------------------------------------- */

ethernet_hdr_t *
pkt_mbuf_get_ethernet_hdr(struct rte_mbuf *mbuf)
{
    uint8_t        *pkt      = PKTMBUF_PKT(mbuf);
    gen_proto_id_t  hdr_type = PKTMBUF_HDR_TYPE(mbuf);

    if (hdr_type == ETHERNET_HEADER) {
        return (ethernet_hdr_t *)pkt;
    }
    else if (hdr_type == IP_PROTO_GRE) {
        gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt;
        if (ntohs(gre_hdr->protocol_type) == ETH_TYPE_GRE) {
            return (ethernet_hdr_t *)(gre_hdr + 1);
        }
    }
    return NULL;
}

ip_hdr_t *
pkt_mbuf_get_ip_hdr(struct rte_mbuf *mbuf)
{
    ethernet_hdr_t *eth_hdr;
    uint8_t        *pkt      = PKTMBUF_PKT(mbuf);
    gen_proto_id_t  hdr_type = PKTMBUF_HDR_TYPE(mbuf);

    if (hdr_type == ETHERNET_HEADER) {
        eth_hdr = pkt_mbuf_get_ethernet_hdr(mbuf);
        if (eth_hdr && ntohs(eth_hdr->type) == ETH_TYPE_IPv4) {
            return (ip_hdr_t *)eth_hdr->payload;
        }
        return NULL;
    }
    else if (hdr_type == IP_PROTO_IP_IN_IP) {
        return (ip_hdr_t *)pkt;
    }
    else if (hdr_type == IP_PROTO_GRE) {
        gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt;
        if (ntohs(gre_hdr->protocol_type) == IP_PROTO_IP_IN_IP) {
            return (ip_hdr_t *)(gre_hdr + 1);
        }
    }
    return NULL;
}

ipv6_hdr_t *
pkt_mbuf_get_ip6_hdr(struct rte_mbuf *mbuf)
{
    ethernet_hdr_t *eth_hdr;
    uint8_t        *pkt      = PKTMBUF_PKT(mbuf);
    gen_proto_id_t  hdr_type = PKTMBUF_HDR_TYPE(mbuf);

    if (hdr_type == ETHERNET_HEADER) {
        eth_hdr = pkt_mbuf_get_ethernet_hdr(mbuf);
        if (eth_hdr && ntohs(eth_hdr->type) == ETH_TYPE_IPv6) {
            return (ipv6_hdr_t *)eth_hdr->payload;
        }
        return NULL;
    }
    else if (hdr_type == IP_PROTO_IPv6) {
        return (ipv6_hdr_t *)pkt;
    }
    else if (hdr_type == IP_PROTO_GRE) {
        gre_hdr_t *gre_hdr = (gre_hdr_t *)pkt;
        if (ntohs(gre_hdr->protocol_type) == IP_PROTO_IPv6) {
            return (ipv6_hdr_t *)(gre_hdr + 1);
        }
    }
    return NULL;
}

arp_hdr_t *
pkt_mbuf_get_arp_hdr(struct rte_mbuf *mbuf)
{
    pkt_size_t pkt_size;
    ethernet_hdr_t *eth_hdr;
    vlan_ethernet_hdr_t *vlan_eth_hdr;
    gen_proto_id_t hdr_type = PKTMBUF_HDR_TYPE(mbuf);

    switch (hdr_type) {
        case ETHERNET_HEADER:
            eth_hdr = (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
            if (is_pkt_vlan_tagged(eth_hdr)) {
                vlan_eth_hdr = (vlan_ethernet_hdr_t *)eth_hdr;
                if (ntohs(vlan_eth_hdr->type) == ETH_TYPE_ARP) {
                    return (arp_hdr_t *)vlan_eth_hdr->payload;
                }
                return NULL;
            }
            if (ntohs(eth_hdr->type) == ETH_TYPE_ARP) {
                return (arp_hdr_t *)eth_hdr->payload;
            }
            return NULL;

        case ETH_TYPE_ARP:
            return (arp_hdr_t *)PKTMBUF_PKT(mbuf);

        default:
            return NULL;
    }
}

bool
pkt_mbuf_expand_buffer_left(struct rte_mbuf *mbuf, pkt_size_t expand_bytes)
{
    return pkt_mbuf_expland_left(mbuf, (uint32_t)expand_bytes) != NULL;
}

void
pkt_mbuf_slide(struct rte_mbuf *mbuf,
               int8_t lorr1,
               int8_t lorr2,
               uint16_t space)
{
    assert(lorr1 == -1 || lorr1 == 1);
    assert(lorr2 == -1 || lorr2 == 1);
    assert(mbuf != NULL);

    switch (lorr1) {
        case -1:
            if (lorr2 == -1)
                assert(pkt_mbuf_expland_left(mbuf, space) != NULL);
            else
                assert(pkt_mbuf_shrink_left(mbuf, space) != NULL);
            break;
        case 1:
            if (lorr2 == -1)
                assert(pkt_mbuf_shrink_right(mbuf, space) != NULL);
            else
                assert(pkt_mbuf_expland_right(mbuf, space) != NULL);
            break;
    }
}

void
pkt_mbuf_tcp_ip_expand_buffer_ethernet_hdr(struct rte_mbuf *mbuf)
{
    pkt_mbuf_slide(mbuf, -1, -1, sizeof(ethernet_hdr_t));
    pkt_mbuf_slide(mbuf,  1,  1, (uint16_t)ETH_FCS_SIZE);
    pkt_mbuf_update_new_hdr_type(mbuf, ETHERNET_HEADER);

    pkt_size_t pkt_size;
    ethernet_hdr_t *eth_hdr =
        (ethernet_hdr_t *)pkt_mbuf_get_pkt(mbuf, &pkt_size);
    memset(eth_hdr->dst_mac.mac, 0, sizeof(mac_addr_t));
    memset(eth_hdr->src_mac.mac, 0, sizeof(mac_addr_t));
    eth_hdr->type = 0;
    pkt_size_t payload_size =
        pkt_size - (pkt_size_t)sizeof(ethernet_hdr_t) - ETH_FCS_SIZE;
    SET_COMMON_ETH_FCS(eth_hdr, payload_size, 0);
}

/* ------------------------------------------------------------------------- */
/* Private metadata accessors                                                  */
/* ------------------------------------------------------------------------- */

pkt_mbuf_pvt_data_t *
pkt_mbuf_get_pvt_data(struct rte_mbuf *mbuf)
{
    return pkt_mbuf_priv(mbuf);
}

pkt_size_t
pkt_mbuf_get_data_size(struct rte_mbuf *mbuf)
{
    pkt_size_t size = 0;
    (void)pkt_mbuf_get_pkt(mbuf, &size);
    return size;
}

bool
pkt_mbuf_get_no_modify_value(struct rte_mbuf *mbuf)
{
    pkt_mbuf_pvt_data_t *priv = pkt_mbuf_get_pvt_data(mbuf);
    return priv ? priv->no_modify : false;
}

void
pkt_mbuf_set_no_modify_value(struct rte_mbuf *mbuf, bool value)
{
    pkt_mbuf_pvt_data_t *priv = pkt_mbuf_get_pvt_data(mbuf);
    if (priv) priv->no_modify = value;
}

void
pkt_mbuf_set_no_modify(struct rte_mbuf *mbuf, bool modify)
{
    pkt_mbuf_set_no_modify_value(mbuf, modify);
}

dp_intf_t *
pkt_mbuf_get_ingress_intf(struct rte_mbuf *mbuf)
{
    pkt_mbuf_pvt_data_t *priv = pkt_mbuf_get_pvt_data(mbuf);
    if (priv == NULL) return NULL;
    return (dp_intf_t *)priv->ingress_intf;
}

void
pkt_mbuf_set_ingress_intf(struct rte_mbuf *mbuf, dp_intf_t *intf)
{
    pkt_mbuf_pvt_data_t *priv = pkt_mbuf_get_pvt_data(mbuf);
    if (priv) priv->ingress_intf = (uintptr_t)intf;
}

/* ------------------------------------------------------------------------- */
/* Debug / pretty-print                                                        */
/* ------------------------------------------------------------------------- */

void
pkt_mbuf_debug(struct rte_mbuf *mbuf)
{
    if (mbuf == NULL) {
        printf("pkt_mbuf_debug: (null)\n");
        return;
    }

    pkt_mbuf_pvt_data_t *priv = pkt_mbuf_priv(mbuf);

    printf("rte_mbuf %p: pkt_len=%u data_len=%u nb_segs=%u data_off=%u refcnt=%u\n",
           (void *)mbuf,
           mbuf->pkt_len, mbuf->data_len, mbuf->nb_segs, mbuf->data_off,
           rte_mbuf_refcnt_read(mbuf));

    if (priv) {
        printf("  hdr_type=%u (%s)  no_modify=%d  ingress_intf=0x%lx\n",
               priv->hdr_type,
               proto_id_str(priv->hdr_type),
               (int)priv->no_modify,
               (unsigned long)priv->ingress_intf);
    }
    rte_pktmbuf_dump(stdout, mbuf, 64);
}

char *
pkt_mbuf_ip(struct rte_mbuf *mbuf, char *buffer)
{
    ip_hdr_t *ip_hdr = pkt_mbuf_get_ip_hdr(mbuf);
    memset(buffer, 0, INET_ADDRSTRLEN);
    uint32_t ip_addr = ip_hdr->dst_ip;
    inet_ntop(AF_INET, &ip_addr, buffer, INET_ADDRSTRLEN);
    return buffer;
}

char *
pkt_mbuf_ip_str(struct rte_mbuf *mbuf, char *buffer)
{
    ip_hdr_t *ip_hdr = pkt_mbuf_get_ip_hdr(mbuf);
    strcpy(buffer, "IP:");
    uint32_t ip_addr = ip_hdr->dst_ip;
    inet_ntop(AF_INET, &ip_addr, buffer + 3, INET_ADDRSTRLEN);
    return buffer;
}

char *
pkt_mbuf_mac_str(struct rte_mbuf *mbuf, char *buffer)
{
    ethernet_hdr_t *eth_hdr = pkt_mbuf_get_ethernet_hdr(mbuf);
    sprintf(buffer, "ETH:%02x:%02x:%02x:%02x:%02x:%02x",
            eth_hdr->dst_mac.mac[0], eth_hdr->dst_mac.mac[1], eth_hdr->dst_mac.mac[2],
            eth_hdr->dst_mac.mac[3], eth_hdr->dst_mac.mac[4], eth_hdr->dst_mac.mac[5]);
    return buffer;
}

char *
pkt_mbuf_str(struct rte_mbuf *mbuf)
{
    gen_proto_id_t hdr_type = pkt_mbuf_get_starting_hdr(mbuf);

    switch (hdr_type) {

        case ETHERNET_HEADER:
        {
            const uint16_t N = 4 + 17 + 1;
            pkt_mbuf_expand_buffer_left(mbuf, N);
            uint8_t *mac_addr_str = pkt_mbuf_get_pkt(mbuf, NULL);
            pkt_mbuf_slide(mbuf, -1, 1, N);
            pkt_mbuf_mac_str(mbuf, (char *)mac_addr_str);
            return (char *)mac_addr_str;
        }

        case IP_PROTO_IPv6:
        {
            int rc;
            const uint16_t N = 48;
            pkt_size_t old_pkt_size;
            uint8_t *old_pkt = pkt_mbuf_get_pkt(mbuf, &old_pkt_size);
            ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)old_pkt;
            pkt_mbuf_expand_buffer_left(mbuf, N);
            uint8_t *ipv6_addr_str = pkt_mbuf_get_pkt(mbuf, NULL);
            pkt_mbuf_slide(mbuf, -1, 1, N);
            rc = sprintf((char *)ipv6_addr_str, "Dest:");
            inet_ntop(AF_INET6, ipv6_hdr->dst_addr,
                      (char *)ipv6_addr_str + rc, INET6_ADDRSTRLEN);
            return (char *)ipv6_addr_str;
        }

        case IP_PROTO_IP_IN_IP:
        {
            const uint16_t N = 3 + 16 + 1;
            pkt_mbuf_expand_buffer_left(mbuf, N);
            uint8_t *ip_addr_str = pkt_mbuf_get_pkt(mbuf, NULL);
            pkt_mbuf_slide(mbuf, -1, 1, N);
            pkt_mbuf_ip_str(mbuf, (char *)ip_addr_str);
            return (char *)ip_addr_str;
        }

        case IP_PROTO_GRE:
        {
            pkt_size_t old_pkt_size;
            uint8_t *old_pkt = pkt_mbuf_get_pkt(mbuf, &old_pkt_size);
            gre_hdr_t *gre_hdr = (gre_hdr_t *)old_pkt;

            switch (ntohs(gre_hdr->protocol_type)) {

                case ETH_TYPE_GRE:
                {
                    const uint16_t N = 7 + 4 + 17 + 1;
                    pkt_mbuf_expand_buffer_left(mbuf, N);
                    uint8_t *buf = pkt_mbuf_get_pkt(mbuf, NULL);
                    memcpy((char *)buf, "GRE-EN:", 8);
                    pkt_mbuf_slide(mbuf, -1, 1, N);
                    pkt_mbuf_mac_str(mbuf, (char *)buf + 7);
                    return (char *)buf;
                }

                case IP_PROTO_IP_IN_IP:
                {
                    const uint16_t N = 7 + 3 + 16 + 1;
                    pkt_mbuf_expand_buffer_left(mbuf, N);
                    uint8_t *buf = pkt_mbuf_get_pkt(mbuf, NULL);
                    memcpy((char *)buf, "GRE-EN:", 8);
                    pkt_mbuf_slide(mbuf, -1, 1, N);
                    pkt_mbuf_ip_str(mbuf, (char *)buf + 7);
                    return (char *)buf;
                }

                default:
                    break;
            }
        }
        break;
    }

    return NULL;
}
