#include <stdio.h>
#include <string.h>

#include "bgp_rib_vpnv4.h"
#include "bgp_nlri_key.h"
#include "bgp_nlri_wire.h"

static void
format_ipv4(uint32_t addr, char *buf, size_t buflen)
{
    snprintf(buf, buflen, "%u.%u.%u.%u",
             (addr >> 24) & 0xff,
             (addr >> 16) & 0xff,
             (addr >> 8) & 0xff,
             addr & 0xff);
}

static uint8_t
ipv4_prefix_byte_count(uint8_t prefix_len)
{
    return (uint8_t)((prefix_len + 7) / 8);
}

static void
encode_rd_type1(const rd_t *rd, uint8_t out[8])
{
    out[0] = 0x00;
    out[1] = 0x01;
    out[2] = (uint8_t)((rd->rtr_id >> 24) & 0xff);
    out[3] = (uint8_t)((rd->rtr_id >> 16) & 0xff);
    out[4] = (uint8_t)((rd->rtr_id >> 8) & 0xff);
    out[5] = (uint8_t)(rd->rtr_id & 0xff);
    out[6] = (uint8_t)((rd->vrf_id >> 8) & 0xff);
    out[7] = (uint8_t)(rd->vrf_id & 0xff);
}

static bgp_rib_err_t
decode_rd_type1(const uint8_t in[8], rd_t *rd_out)
{
    uint16_t rd_type = (uint16_t)((in[0] << 8) | in[1]);

    if (rd_type != 0x0001) {
        return BGP_RIB_ERR_DECODE;
    }

    rd_out->type = 1;
    rd_out->rtr_id = ((uint32_t)in[2] << 24) |
                     ((uint32_t)in[3] << 16) |
                     ((uint32_t)in[4] << 8) |
                     (uint32_t)in[5];
    rd_out->vrf_id = (uint16_t)((in[6] << 8) | in[7]);
    return BGP_RIB_OK;
}

bgp_rib_err_t
bgp_vpnv4_nlri_encode(const bgp_vpnv4_nlri_t *nlri,
                      bgp_nlri_key_t *key_out)
{
    uint8_t prefix_bytes;
    uint16_t offset;

    if (!nlri || !key_out || nlri->prefix_len > 32) {
        return BGP_RIB_ERR_NULL;
    }

    prefix_bytes = ipv4_prefix_byte_count(nlri->prefix_len);
    offset = 0;

    encode_rd_type1(&nlri->rd, &key_out->wire[offset]);
    offset += 8;

    key_out->wire[offset++] = nlri->prefix_len;

    {
        uint32_t v = nlri->prefix;
        uint8_t i;

        for (i = 0; i < prefix_bytes; i++) {
            key_out->wire[offset++] =
                (uint8_t)((v >> (24 - (i * 8))) & 0xff);
        }
    }

    if (nlri->label_present) {
        uint32_t label = nlri->label & 0xfffff;

        key_out->wire[offset++] = (uint8_t)((label >> 16) & 0xff);
        key_out->wire[offset++] = (uint8_t)((label >> 8) & 0xff);
        key_out->wire[offset++] = (uint8_t)((label & 0xff) | 0x01);
    }

    key_out->wire_len = offset;
    return BGP_RIB_OK;
}

bgp_rib_err_t
bgp_vpnv4_nlri_decode(const bgp_nlri_key_t *key,
                      bgp_vpnv4_nlri_t *nlri_out)
{
    uint8_t prefix_bytes;
    uint16_t offset = 0;
    uint8_t i;

    if (!key || !nlri_out || key->wire_len < 9) {
        return BGP_RIB_ERR_NULL;
    }

    memset(nlri_out, 0, sizeof(*nlri_out));

    if (decode_rd_type1(&key->wire[offset], &nlri_out->rd) != BGP_RIB_OK) {
        return BGP_RIB_ERR_DECODE;
    }
    offset += 8;

    nlri_out->prefix_len = key->wire[offset++];
    if (nlri_out->prefix_len > 32) {
        return BGP_RIB_ERR_DECODE;
    }

    prefix_bytes = ipv4_prefix_byte_count(nlri_out->prefix_len);
    if (key->wire_len < offset + prefix_bytes) {
        return BGP_RIB_ERR_DECODE;
    }

    for (i = 0; i < prefix_bytes; i++) {
        nlri_out->prefix =
            (nlri_out->prefix << 8) | key->wire[offset + i];
    }
    nlri_out->prefix <<= (32 - nlri_out->prefix_len);
    offset += prefix_bytes;

    if (key->wire_len >= offset + 3) {
        nlri_out->label =
            ((uint32_t)key->wire[offset] << 12) |
            ((uint32_t)key->wire[offset + 1] << 4) |
            ((uint32_t)key->wire[offset + 2] >> 4);
        nlri_out->label_present = true;
    }

    return BGP_RIB_OK;
}

int
bgp_vpnv4_nlri_format_compact(const bgp_nlri_key_t *key,
                              const bgp_rib_attrs_t *attrs,
                              char *buf,
                              size_t buflen)
{
    bgp_vpnv4_nlri_t nlri;
    char rd_str[32];
    char prefix_str[32];

    if (!key || !buf || buflen == 0) {
        return -1;
    }

    if (bgp_vpnv4_nlri_decode(key, &nlri) != BGP_RIB_OK) {
        return -1;
    }

    bgp_rd_wire_to_str(&key->wire[0], rd_str, sizeof(rd_str));
    format_ipv4(nlri.prefix, prefix_str, sizeof(prefix_str));
    {
        size_t used = strlen(prefix_str);
        snprintf(prefix_str + used, sizeof(prefix_str) - used,
                 "/%u", nlri.prefix_len);
    }

    if (nlri.label_present) {
        snprintf(buf, buflen,
                 "rd=%s prefix=%s label=%u nlri_len=%u",
                 rd_str, prefix_str, nlri.label,
                 bgp_nlri_key_bit_length(key));
    } else {
        snprintf(buf, buflen,
                 "rd=%s prefix=%s nlri_len=%u",
                 rd_str, prefix_str, bgp_nlri_key_bit_length(key));
    }

    if (attrs && attrs->nexthop[0] != '\0') {
        size_t used = strlen(buf);
        snprintf(buf + used, buflen - used, " nh=%s", attrs->nexthop);
        used = strlen(buf);
        if (attrs->med_present && used < buflen) {
            snprintf(buf + used, buflen - used, " med=%u", attrs->med);
        }
    }

    return 0;
}

int
bgp_vpnv4_ipv4_unicast_format_compact(const bgp_nlri_key_t *key,
                                       const bgp_rib_attrs_t *attrs,
                                       char *buf,
                                       size_t buflen)
{
    uint8_t prefix_len;
    uint8_t prefix_bytes;
    uint32_t prefix = 0;
    char prefix_str[32];
    uint8_t i;

    if (!key || key->wire_len < 1 || !buf || buflen == 0) {
        return -1;
    }

    prefix_len = key->wire[0];
    prefix_bytes = ipv4_prefix_byte_count(prefix_len);
    if (key->wire_len < 1 + prefix_bytes) {
        return -1;
    }

    for (i = 0; i < prefix_bytes; i++) {
        prefix = (prefix << 8) | key->wire[1 + i];
    }
    prefix <<= (32 - prefix_len);

    format_ipv4(prefix, prefix_str, sizeof(prefix_str));
    {
        size_t used = strlen(prefix_str);
        snprintf(prefix_str + used, sizeof(prefix_str) - used,
                 "/%u", prefix_len);
    }
    snprintf(buf, buflen, "prefix=%s nlri_len=%u",
             prefix_str, bgp_nlri_key_bit_length(key));

    if (attrs && attrs->nexthop[0] != '\0') {
        size_t used = strlen(buf);
        snprintf(buf + used, buflen - used, " nh=%s", attrs->nexthop);
    }

    return 0;
}

bgp_rib_err_t
bgp_vpnv4_rib_route_add(bgp_rib_t *rib,
                        const bgp_vpnv4_nlri_t *nlri,
                        const bgp_rib_attrs_t *attrs)
{
    bgp_nlri_key_t key;

    if (!rib || !nlri || !attrs) {
        return BGP_RIB_ERR_NULL;
    }

    memset(&key, 0, sizeof(key));
    if (bgp_vpnv4_nlri_encode(nlri, &key) != BGP_RIB_OK) {
        return BGP_RIB_ERR_ENCODE;
    }

    return bgp_rib_route_add(rib, &key, attrs);
}

bgp_rib_err_t
bgp_vpnv4_rib_route_delete(bgp_rib_t *rib,
                           const bgp_vpnv4_nlri_t *nlri)
{
    bgp_nlri_key_t key;

    if (!rib || !nlri) {
        return BGP_RIB_ERR_NULL;
    }

    memset(&key, 0, sizeof(key));
    if (bgp_vpnv4_nlri_encode(nlri, &key) != BGP_RIB_OK) {
        return BGP_RIB_ERR_ENCODE;
    }

    return bgp_rib_route_delete(rib, &key);
}

const bgp_rib_attrs_t *
bgp_vpnv4_rib_route_lookup(const bgp_rib_t *rib,
                           const bgp_vpnv4_nlri_t *nlri)
{
    bgp_nlri_key_t key;

    if (!rib || !nlri) {
        return NULL;
    }

    memset(&key, 0, sizeof(key));
    if (bgp_vpnv4_nlri_encode(nlri, &key) != BGP_RIB_OK) {
        return NULL;
    }

    return bgp_rib_route_lookup(rib, &key);
}
