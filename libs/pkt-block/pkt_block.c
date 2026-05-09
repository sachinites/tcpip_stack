/*
 * =====================================================================================
 *
 *       Filename:  pkt_block.c
 *
 *    Description:  This file defines the structure and routines to work with Packet
 *                  buffers. When USE_DPDK is defined, pkt_block_t is a thin wrapper
 *                  around a struct rte_mbuf and every public API delegates to the
 *                  pkt_mbuf_* helpers from libs/pkt-mbuf/pkt_mbuf.h. When USE_DPDK is
 *                  NOT defined, behaviour is identical to the historical raw-buffer
 *                  implementation.
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
#include <stdio.h>
#include <stdint.h>
#include <memory.h>
#include <arpa/inet.h>
#include <assert.h>
#include "pkt_block.h"
#include "../common/protoIds.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../common/l2_hdrs.h"
#include "../common/l3_hdrs.h"

#ifdef USE_DPDK
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ether.h>


/* Convenience accessor for the pkt_mbuf_pvt_data_t sitting in the mbuf priv
 * area. Returns NULL if the mbuf or pool has too small a priv area. */
static inline pkt_mbuf_pvt_data_t *
pkt_block_mbuf_priv(struct rte_mbuf *m)
{
    if (m == NULL || m->pool == NULL) return NULL;
    if (rte_pktmbuf_priv_size(m->pool) < sizeof(pkt_mbuf_pvt_data_t)) return NULL;
    return (pkt_mbuf_pvt_data_t *)rte_mbuf_to_priv(m);
}

#endif /* USE_DPDK */

/* ------------------------------------------------------------------------- */
/* Starting-header accessor                                                   */
/* ------------------------------------------------------------------------- */

gen_proto_id_t
pkt_block_get_starting_hdr(pkt_block_t *pkt_block) {

#ifdef USE_DPDK
    return pkt_mbuf_get_starting_hdr(pkt_block->mbuf);
#else
    return pkt_block->pvt_data.hdr_type;
#endif
}

/* ------------------------------------------------------------------------- */
/* Constructors                                                               */
/* ------------------------------------------------------------------------- */

pkt_block_t *
pkt_block_wrap_raw_buffer(struct rte_mempool *mbuf_pool, 
                          uint8_t *pkt, pkt_size_t pkt_size, 
                          const char *fn_name, uint16_t lineno) {

    pkt_block_t *pkt_block = pkt_block_get_new_pkt_buffer(mbuf_pool,
                                pkt_size, fn_name, lineno);
        
    uint8_t *raw_pkt = pkt_block_get_pkt(pkt_block, NULL);
    memcpy (raw_pkt, pkt, pkt_size);
    return pkt_block;
}

pkt_block_t *
pkt_block_get_new_pkt_buffer(struct rte_mempool *mbuf_pool,  
                             pkt_size_t pkt_size, 
                             const char *fn_name, uint16_t lineno) {

    pkt_block_t *pkt_block = (pkt_block_t *)calloc(1, sizeof(pkt_block_t));

#ifdef USE_DPDK

    struct rte_mbuf *m = pkt_mbuf_alloc(mbuf_pool);
    assert(m != NULL);
    if (pkt_size > 0) {
        uint8_t *p = pkt_mbuf_expland_left(m, (uint32_t)pkt_size);
        assert(p != NULL);
        (void)p;
    }
    pkt_block->mbuf    = m;
    pkt_block->fn_name = (char *)fn_name;
    pkt_block->lineno  = lineno;
#else
    pkt_block->alloc_ptr = (uintptr_t)XCALLOC_BUFF(0, MAX_PACKET_BUFFER_SIZE);
    pkt_block->pkt       = (uint8_t *)
        (pkt_block->alloc_ptr +
         MAX_PACKET_BUFFER_SIZE - (pkt_size + PKT_BUFFER_RIGHT_ROOM));
    pkt_block->pkt_size  = pkt_size;
    pkt_block->ref_count = 1;
    pkt_block->lineno    = lineno;
    pkt_block->fn_name   = fn_name;
#endif
    return pkt_block;
}

/* ------------------------------------------------------------------------- */
/* Raw-buffer accessor                                                        */
/* ------------------------------------------------------------------------- */

uint8_t *
pkt_block_get_pkt(pkt_block_t *pkt_block, pkt_size_t *pkt_size) {

#ifdef USE_DPDK
    if (pkt_block->mbuf == NULL) {
        if (pkt_size) *pkt_size = 0;
        return NULL;
    }
    uint16_t sz = 0;
    uint8_t *p = pkt_mbuf_get_raw_pkt(pkt_block->mbuf, &sz);
    if (pkt_size) *pkt_size = (pkt_size_t)sz;
    return p;
#else
    if (pkt_size) *pkt_size = pkt_block->pkt_size;
    return (uint8_t *)pkt_block->pkt;
#endif
}

/* ------------------------------------------------------------------------- */
/* Reference counting                                                         */
/* ------------------------------------------------------------------------- */

void
pkt_block_reference(pkt_block_t *pkt_block) {

#ifdef USE_DPDK
    pkt_mbuf_ref_inc(pkt_block->mbuf);
#else
    pkt_block->ref_count++;
#endif
}

static void
pkt_block_free(pkt_block_t *pkt_block) {

#ifdef USE_DPDK
    /* Caller (pkt_block_dereference) must have already freed encap_data and
     * cleared ingress_intf in the mbuf priv area. Enforce that here so any
     * missed cleanup site is caught at the free boundary. */
    pkt_mbuf_pvt_data_t *priv = pkt_block_mbuf_priv(pkt_block->mbuf);
    if (priv) {
        assert(!priv->encap_data);
        assert(!priv->ingress_intf);
    }
    pkt_mbuf_free(pkt_block->mbuf);
    pkt_block->mbuf = NULL;
    free(pkt_block);
#else
    assert(!pkt_block->pvt_data.encap_data);
    assert(!pkt_block->pvt_data.ingress_intf);

    XFREE((void *)pkt_block->alloc_ptr);
    free(pkt_block);
#endif
}

uint8_t
pkt_block_dereference(pkt_block_t *pkt_block) {

#ifdef USE_DPDK
    struct rte_mbuf *m = pkt_block->mbuf;
    assert(m != NULL);

    uint16_t old = rte_mbuf_refcnt_read(m);
    assert(old != 0);

    if (old == 1) {
        /* Last reference: release any heap owned by the priv area BEFORE
         * the mbuf is returned to its pool, otherwise encap_data leaks
         * (the pool only zeroes priv on the next alloc, it does not free
         * what priv points at). */
        pkt_mbuf_pvt_data_t *priv = pkt_block_mbuf_priv(m);
        if (priv) {
            if (priv->encap_data) {
                free(priv->encap_data);
                priv->encap_data = NULL;
            }
            priv->ingress_intf = 0;
        }
        pkt_mbuf_ref_dec(m);
        pkt_block->mbuf = NULL;
        free(pkt_block);
        return 0;
    }

    /* Not the last reference — just drop ours. */
    pkt_mbuf_ref_dec(m);
    return (uint8_t)(old - 1);
#else
    uint8_t ref_count = pkt_block->ref_count;

    /* Dereferencing an already-zeroed block is a double-free bug in the
     * caller; catch it here rather than silently freeing again. */
    assert(pkt_block->ref_count != 0);

    pkt_block->ref_count--;

    if (pkt_block->ref_count == 0) {
        if (pkt_block->pvt_data.encap_data) {
            free(pkt_block->pvt_data.encap_data);
            pkt_block->pvt_data.encap_data = NULL;
        }
        pkt_block->pvt_data.ingress_intf = 0;
        if (pkt_block->pvt_data.ingress_intf) pkt_block->pvt_data.ingress_intf = 0;
        pkt_block_free(pkt_block);
        return 0;
    }

    return ref_count - 1;
#endif
}

/* ------------------------------------------------------------------------- */
/* Header walkers                                                             */
/* ------------------------------------------------------------------------- */

/* Small helper so the walker bodies below can stay source-identical between
 * the two build modes — only the pkt/hdr_type sources differ. */
#ifdef USE_DPDK
#define PKTBLOCK_PKT(pb)        \
    ((pb)->mbuf ? rte_pktmbuf_mtod((pb)->mbuf, uint8_t *) : NULL)
#define PKTBLOCK_HDR_TYPE(pb)   pkt_mbuf_get_starting_hdr((pb)->mbuf)
#else
#define PKTBLOCK_PKT(pb)        ((pb)->pkt)
#define PKTBLOCK_HDR_TYPE(pb)   ((pb)->pvt_data.hdr_type)
#endif

ethernet_hdr_t *
pkt_block_get_ethernet_hdr(pkt_block_t *pkt_block) {

    uint8_t        *pkt      = PKTBLOCK_PKT(pkt_block);
    gen_proto_id_t  hdr_type = PKTBLOCK_HDR_TYPE(pkt_block);

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
pkt_block_get_ip_hdr(pkt_block_t *pkt_block) {

    ethernet_hdr_t *eth_hdr;
    uint8_t        *pkt      = PKTBLOCK_PKT(pkt_block);
    gen_proto_id_t  hdr_type = PKTBLOCK_HDR_TYPE(pkt_block);

    if (hdr_type == ETHERNET_HEADER) {

        eth_hdr = pkt_block_get_ethernet_hdr(pkt_block);

        if (ntohs(eth_hdr->type) == ETH_TYPE_IPv4) {
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
pkt_block_get_ip6_hdr(pkt_block_t *pkt_block) {

    ethernet_hdr_t *eth_hdr;
    uint8_t        *pkt      = PKTBLOCK_PKT(pkt_block);
    gen_proto_id_t  hdr_type = PKTBLOCK_HDR_TYPE(pkt_block);

    if (hdr_type == ETHERNET_HEADER) {

        eth_hdr = pkt_block_get_ethernet_hdr(pkt_block);

        if (ntohs(eth_hdr->type) == ETH_TYPE_IPv6) {
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
pkt_block_get_arp_hdr(pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    ethernet_hdr_t *eth_hdr;
    vlan_ethernet_hdr_t *vlan_eth_hdr;

    gen_proto_id_t hdr_type = PKTBLOCK_HDR_TYPE(pkt_block);

    switch(hdr_type) {

        case ETHERNET_HEADER:

            eth_hdr = (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

            if (is_pkt_vlan_tagged(eth_hdr)) {

                vlan_eth_hdr = (vlan_ethernet_hdr_t *)eth_hdr;

                if (ntohs(vlan_eth_hdr->type) == ETH_TYPE_ARP) {
                    return (arp_hdr_t *)vlan_eth_hdr->payload;
                }
                return NULL;
            }
            else {
                if (ntohs(eth_hdr->type) == ETH_TYPE_ARP) {
                    return (arp_hdr_t *)eth_hdr->payload;
                }
                return NULL;
            }
            break;

        case ETH_TYPE_ARP:
            return (arp_hdr_t *)PKTBLOCK_PKT(pkt_block);

        default:
            return NULL;
    }
}

/* ------------------------------------------------------------------------- */
/* Buffer lifecycle helpers                                                   */
/* ------------------------------------------------------------------------- */

pkt_block_t *
pkt_block_clone(pkt_block_t *pkt_block, const char *fn_name, uint16_t lineno) {

#ifdef USE_DPDK
    struct rte_mbuf *dup_mbuf =
        pkt_mbuf_clone(pkt_block->mbuf->pool, pkt_block->mbuf);
    assert(dup_mbuf != NULL);

    pkt_block_t *pkt_block2 = (pkt_block_t *)calloc(1, sizeof(pkt_block_t));
    pkt_block2->mbuf    = dup_mbuf;
    pkt_block2->fn_name = (char *)fn_name;
    pkt_block2->lineno  = lineno;
    /* pkt_mbuf_clone already copied the priv area (hdr_type, encap_data,
     * ingress_intf, no_modify) from the source mbuf. */
    return pkt_block2;
#else
    pkt_block_t *pkt_block2 = pkt_block_get_new_pkt_buffer(
                                0, pkt_block->pkt_size, fn_name, lineno);
    memcpy(pkt_block2->pkt, pkt_block->pkt, pkt_block->pkt_size);
    pkt_block2->pvt_data.hdr_type = pkt_block->pvt_data.hdr_type;
    pkt_block2->pvt_data.no_modify = pkt_block->pvt_data.no_modify;
    pkt_block2->pvt_data.ingress_intf = pkt_block->pvt_data.ingress_intf;
    if (pkt_block->pvt_data.encap_data) {
        pkt_block2->pvt_data.encap_data = (pkt_mbuf_encap_meta_data_t *)calloc(1, sizeof(pkt_mbuf_encap_meta_data_t));
        memcpy(pkt_block2->pvt_data.encap_data, pkt_block->pvt_data.encap_data,
               sizeof(*pkt_block->pvt_data.encap_data));
    }
    (void)fn_name;
    (void)lineno;
    return pkt_block2;
#endif
}

bool
pkt_block_expand_buffer_left(pkt_block_t *pkt_block, pkt_size_t expand_bytes) {

#ifdef USE_DPDK
    return pkt_mbuf_expland_left(pkt_block->mbuf, (uint32_t)expand_bytes) != NULL;
#else
    pkt_size_t pkt_size;
    (void)pkt_block_get_pkt(pkt_block, &pkt_size);

    if ((MAX_PACKET_BUFFER_SIZE - pkt_size) < expand_bytes) {
        return false;
    }

    pkt_block_slide(pkt_block, -1, -1, (uint16_t)expand_bytes);
    return true;
#endif
}

bool
pkt_block_verify_pkt(pkt_block_t *pkt_block, gen_proto_id_t hdr_type) {

    return pkt_block_get_starting_hdr(pkt_block) == hdr_type;
}

void
pkt_block_update_new_hdr_type(pkt_block_t *pkt_block, uint16_t proto) {

#ifdef USE_DPDK
    pkt_mbuf_update_new_hdr_type(pkt_block->mbuf, (gen_proto_id_t)proto);
#else
    pkt_block->pvt_data.hdr_type = proto;
#endif
}

void
tcp_ip_expand_buffer_ethernet_hdr(pkt_block_t *pkt_block) {

    pkt_block_slide(pkt_block, -1, -1, sizeof (ethernet_hdr_t));
    pkt_block_slide(pkt_block,  1,  1, (uint16_t)ETH_FCS_SIZE);

    pkt_block_update_new_hdr_type(pkt_block, ETHERNET_HEADER);

    pkt_size_t pkt_size;
    ethernet_hdr_t *eth_hdr =
        (ethernet_hdr_t *)pkt_block_get_pkt(pkt_block, &pkt_size);
    memset(eth_hdr->dst_mac.mac, 0, sizeof(mac_addr_t));
    memset(eth_hdr->src_mac.mac, 0, sizeof(mac_addr_t));
    eth_hdr->type = 0;
    pkt_size_t payload_size = pkt_size - (pkt_size_t)sizeof(ethernet_hdr_t) - ETH_FCS_SIZE;
    SET_COMMON_ETH_FCS(eth_hdr, payload_size, 0);
}

void
pkt_block_set_no_modify(pkt_block_t *pkt_block, bool modify) {

#ifdef USE_DPDK
    pkt_mbuf_pvt_data_t *priv = pkt_block_mbuf_priv(pkt_block->mbuf);
    if (priv) priv->no_modify = modify;
#else
    pkt_block->pvt_data.no_modify = modify;
#endif
}

void
print_pkt_block(pkt_block_t *pkt_block) {

    (void)pkt_block;
    #if 0
    stdlib_printf("pkt_block->pkt = %p\n", pkt_block->pkt);
    stdlib_printf("pkt_block->pkt_size = %d\n", pkt_block->pkt_size);
    stdlib_printf("pkt_block->hdr_type = %d\n", pkt_block->pvt_data.hdr_type);
    stdlib_printf("pkt_block->ref_count = %d\n", pkt_block->ref_count);
    stdlib_printf("pkt_block alloc :  %s(%d)\n", pkt_block->fn_name, pkt_block->lineno);
    stdlib_printf("pkt_block->no_modify = %d\n", pkt_block->pvt_data.no_modify);
    #endif
}

void
pkt_block_debug(pkt_block_t *pkt_block) {

    pkt_size_t pkt_size;
    uint8_t *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);
    gen_proto_id_t hdr = pkt_block_get_starting_hdr(pkt_block);
}

/* ------------------------------------------------------------------------- */
/* Pretty-printers                                                            */
/*                                                                            */
/* These operate on the tcpip_stack's internal ip_hdr_t / ethernet_hdr_t      */
/* types, which we still get by casting over the mbuf/data memory.            */
/* ------------------------------------------------------------------------- */

char *
pkt_ip(pkt_block_t *pkt_block, char *buffer) {

    ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt_block);
    /* Preserved as INET_ADDRSTRLEN. */
    memset(buffer, 0, INET_ADDRSTRLEN);
    uint32_t ip_addr = ip_hdr->dst_ip;
    inet_ntop(AF_INET, &ip_addr, buffer, INET_ADDRSTRLEN);
    return buffer;
}

char *
pkt_ip_str(pkt_block_t *pkt_block, char *buffer) {

    ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt_block);
    strcpy(buffer, "IP:");
    uint32_t ip_addr = ip_hdr->dst_ip;
    inet_ntop(AF_INET, &ip_addr, buffer + 3, INET_ADDRSTRLEN);
    return buffer;
}

char *
pkt_mac_str(pkt_block_t *pkt_block, char *buffer) {

    ethernet_hdr_t *eth_hdr = pkt_block_get_ethernet_hdr(pkt_block);
    sprintf(buffer, "ETH:%02x:%02x:%02x:%02x:%02x:%02x",
            eth_hdr->dst_mac.mac[0], eth_hdr->dst_mac.mac[1], eth_hdr->dst_mac.mac[2],
            eth_hdr->dst_mac.mac[3], eth_hdr->dst_mac.mac[4], eth_hdr->dst_mac.mac[5]);
    return buffer;
}


/* This API uses in-built memory of pkt_block (slides the pkt pointer left to
 * carve out scratch space, writes a string there, then shrinks the head back
 * to restore the original pkt/size). Works identically under both modes
 * because pkt_block_expand_buffer_left / pkt_block_slide are ifdef-aware. */
char *
pkt_block_str(pkt_block_t *pkt_block) {

    gen_proto_id_t hdr_type = pkt_block_get_starting_hdr(pkt_block);

    switch (hdr_type) {

        case ETHERNET_HEADER:
        {
            const uint16_t N = 4 + 17 + 1;
            pkt_block_expand_buffer_left(pkt_block, N);
            uint8_t *mac_addr_str = pkt_block_get_pkt(pkt_block, NULL);
            pkt_block_slide(pkt_block, -1, 1, N);    /* restore head */
            pkt_mac_str(pkt_block, (char *)mac_addr_str);
            return (char *)mac_addr_str;
        }
        break;

        case IP_PROTO_IPv6:
        {
            int rc;
            const uint16_t N = 48;
            pkt_size_t old_pkt_size;
            uint8_t *old_pkt = pkt_block_get_pkt(pkt_block, &old_pkt_size);
            ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)old_pkt;
            pkt_block_expand_buffer_left(pkt_block, N);
            uint8_t *ipv6_addr_str = pkt_block_get_pkt(pkt_block, NULL);
            pkt_block_slide(pkt_block, -1, 1, N);    /* restore head */
            rc = sprintf((char *)ipv6_addr_str, "Dest:");
            inet_ntop(AF_INET6, ipv6_hdr->dst_addr, (char *)ipv6_addr_str + rc, INET6_ADDRSTRLEN);
            return (char *)ipv6_addr_str;
        }
        break;

        case IP_PROTO_IP_IN_IP:
        {
            const uint16_t N = 3 + 16 + 1;
            pkt_block_expand_buffer_left(pkt_block, N);
            uint8_t *ip_addr_str = pkt_block_get_pkt(pkt_block, NULL);
            pkt_block_slide(pkt_block, -1, 1, N);    /* restore head */
            pkt_ip_str(pkt_block, (char *)ip_addr_str);
            return (char *)ip_addr_str;
        }
        break;

        case IP_PROTO_GRE:
        {
            pkt_size_t old_pkt_size;
            uint8_t *old_pkt = pkt_block_get_pkt(pkt_block, &old_pkt_size);
            gre_hdr_t *gre_hdr = (gre_hdr_t *)old_pkt;

            switch (ntohs(gre_hdr->protocol_type)) {

                case ETH_TYPE_GRE:
                {
                    const uint16_t N = 7 + 4 + 17 + 1;
                    pkt_block_expand_buffer_left(pkt_block, N);
                    uint8_t *buffer = pkt_block_get_pkt(pkt_block, NULL);
                    strncpy((char *)buffer, "GRE-EN:", 7);
                    pkt_block_slide(pkt_block, -1, 1, N);    /* restore head */
                    pkt_mac_str(pkt_block, (char *)buffer + 7);
                    return (char *)buffer;
                }

                case IP_PROTO_IP_IN_IP:
                {
                    const uint16_t N = 7 + 3 + 16 + 1;
                    pkt_block_expand_buffer_left(pkt_block, N);
                    uint8_t *buffer = pkt_block_get_pkt(pkt_block, NULL);
                    strncpy((char *)buffer, "GRE-EN:", 7);
                    pkt_block_slide(pkt_block, -1, 1, N);    /* restore head */
                    pkt_ip_str(pkt_block, (char *)buffer + 7);
                    return (char *)buffer;
                }
                break;

                default:
                    break;
            }
        }
        break;
    }

    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Low-level slide                                                            */
/* ------------------------------------------------------------------------- */

void
pkt_block_slide(pkt_block_t *pkt_block,
                int8_t lorr1,
                int8_t lorr2,
                uint16_t space) {

    assert(lorr1 == -1 || lorr1 == 1);
    assert(lorr2 == -1 || lorr2 == 1);

#ifdef USE_DPDK
    /* Map the four (lorr1, lorr2) combinations onto the four pkt_mbuf_*
     * grow/shrink primitives:
     *   (-1,-1) = grow at head     (data moves left, size grows)
     *   (-1,+1) = shrink at head   (data moves right, size shrinks)
     *   (+1,-1) = shrink at tail   (size shrinks)
     *   (+1,+1) = grow at tail     (size grows) */
    assert(pkt_block->mbuf != NULL);
    switch (lorr1) {
        case -1:
            if (lorr2 == -1)
                assert(pkt_mbuf_expland_left(pkt_block->mbuf, space) != NULL);
            else
                assert(pkt_mbuf_shrink_left(pkt_block->mbuf, space) != NULL);
            break;
        case 1:
            if (lorr2 == -1)
                assert(pkt_mbuf_shrink_right(pkt_block->mbuf, space) != NULL);
            else
                assert(pkt_mbuf_expland_right(pkt_block->mbuf, space) != NULL);
            break;
    }
#else
    uint8_t *pkt;
    pkt_size_t pkt_size;

    assert(pkt_block->alloc_ptr);

    pkt = (uint8_t *)pkt_block_get_pkt(pkt_block, &pkt_size);

    switch (lorr1) {

        case -1:
            switch (lorr2) {
                case -1:
                    pkt      -= space;
                    pkt_size += space;
                    break;
                case 1:
                    pkt      += space;
                    pkt_size -= space;
                    break;
            }
            break;

        case 1:
            switch (lorr2) {
                case -1:
                    pkt_size -= space;
                    break;
                case 1:
                    pkt_size += space;
                    break;
            }
            break;
    }

    if (lorr1 == -1) pkt_block->pkt = pkt;
    pkt_block->pkt_size = pkt_size;
#endif
}

/* ------------------------------------------------------------------------- */
/* DPDK-only: construct a pkt_block wrapping an existing mbuf (RX path).      */
/* ------------------------------------------------------------------------- */

pkt_block_t *
pkt_block_new_with_mbuf(struct rte_mbuf *mbuf) {

#ifdef USE_DPDK
    pkt_block_t *pkt_block = (pkt_block_t *)calloc(1, sizeof(pkt_block_t));
    pkt_block->mbuf    = mbuf;
    pkt_block->fn_name = (char *)__FUNCTION__;
    pkt_block->lineno  = (uint16_t)__LINE__;
    return pkt_block;
#else
    (void)mbuf;
    assert(0 && "pkt_block_new_with_mbuf() requires USE_DPDK");
    return NULL;
#endif
}


pkt_mbuf_pvt_data_t *
pkt_block_get_pvt_data(pkt_block_t *pkt_block) {

    #ifdef USE_DPDK

        pkt_mbuf_pvt_data_t *pvt_data = 
            (pkt_mbuf_pvt_data_t *)rte_mbuf_to_priv(pkt_block->mbuf);
        return pvt_data;

    #else 

        return &pkt_block->pvt_data;

    #endif

}

/* ------------------------------------------------------------------------- */
/* Small accessors: size / no_modify / ingress_intf                           */
/*                                                                            */
/* All of these route through pkt_block_get_pvt_data() so the same source     */
/* code works for both USE_DPDK (priv area on the mbuf) and non-DPDK          */
/* (embedded pkt_block::pvt_data) builds.                                     */
/* ------------------------------------------------------------------------- */

pkt_size_t
pkt_block_get_data_size(pkt_block_t *pkt_block) {

    assert(pkt_block != NULL);

#ifdef USE_DPDK
    /* pkt_block_get_pkt() returns the head-segment size; for the full chain
     * size callers should read mbuf->pkt_len directly. */
    pkt_size_t size = 0;
    (void)pkt_block_get_pkt(pkt_block, &size);
    return size;
#else
    return pkt_block->pkt_size;
#endif
}

bool
pkt_block_get_no_modify_value(pkt_block_t *pkt_block) {

    assert(pkt_block != NULL);

    pkt_mbuf_pvt_data_t *priv = pkt_block_get_pvt_data(pkt_block);
    return priv ? priv->no_modify : false;
}

void
pkt_block_set_no_modify_value(pkt_block_t *pkt_block, bool value) {

    assert(pkt_block != NULL);

    pkt_mbuf_pvt_data_t *priv = pkt_block_get_pvt_data(pkt_block);
    if (priv) priv->no_modify = value;
}

dp_intf_t *
pkt_block_get_ingress_intf(pkt_block_t *pkt_block) {

    assert(pkt_block != NULL);

    pkt_mbuf_pvt_data_t *priv = pkt_block_get_pvt_data(pkt_block);
    if (priv == NULL) return NULL;
    return (dp_intf_t *)priv->ingress_intf;
}

void
pkt_block_set_ingress_intf(pkt_block_t *pkt_block, dp_intf_t *intf) {

    assert(pkt_block != NULL);

    pkt_mbuf_pvt_data_t *priv = pkt_block_get_pvt_data(pkt_block);
    if (priv) priv->ingress_intf = (uintptr_t)intf;
}
