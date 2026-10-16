#include <stdio.h>
#include <string.h>

#include "../../libs/Tracer/tracer.h"

#include "bgp_rib_evpn.h"
#include "bgp_nlri_key.h"
#include "bgp_nlri_wire.h"

#include "../bgp_route.h"
#include "../bgp_rtr.h"
#include "../bgp_enums.h"
#include "../../Layer2/Evpn/evpn.h"
#include "../../Layer2/Evpn/evpn_enums.h"
#include "../../router_init.h"
#include "../../tcpconst.h"
#include "../../utils.h"
#include "../../vrf/mac_vrf.h"
#include "../../vrf/vrf.h"
#include "../../libs/common/cmn_prefix.h"
#include "../../RTM/rtm.h"
#include "../../RTM/rtm_enums.h"
#include "../../RTM/rtm_error.h"
#include "../../RTM/rtm_nb_integ.h"
#include "../../RTM/rtm_proto.h"

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
decode_rd_wire(const uint8_t in[8], rd_t *rd_out)
{
    uint16_t rd_type = (uint16_t)((in[0] << 8) | in[1]);

    memset(rd_out, 0, sizeof(*rd_out));
    rd_out->type = rd_type;

    switch (rd_type) {
    case 0x0000:
        rd_out->rtr_id = (uint32_t)((in[2] << 8) | in[3]);
        rd_out->vrf_id = (uint16_t)((in[6] << 8) | in[7]);
        return BGP_RIB_OK;
    case 0x0001:
        rd_out->rtr_id = ((uint32_t)in[2] << 24) |
                         ((uint32_t)in[3] << 16) |
                         ((uint32_t)in[4] << 8) |
                         (uint32_t)in[5];
        rd_out->vrf_id = (uint16_t)((in[6] << 8) | in[7]);
        return BGP_RIB_OK;
    case 0x0002:
        rd_out->rtr_id = ((uint32_t)in[2] << 24) |
                         ((uint32_t)in[3] << 16) |
                         ((uint32_t)in[4] << 8) |
                         (uint32_t)in[5];
        rd_out->vrf_id = (uint16_t)((in[6] << 8) | in[7]);
        return BGP_RIB_OK;
    default:
        return BGP_RIB_ERR_DECODE;
    }
}

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
evpn_ipv4_prefix_octets(uint8_t prefix_len)
{
    if (prefix_len > 32) {
        return 4;
    }
    return (uint8_t)((prefix_len + 7) / 8);
}

static void
evpn_decode_ipv4_pfx_bytes(const uint8_t *wire,
                           uint8_t prefix_len,
                           uint32_t *addr_out)
{
    uint8_t n = evpn_ipv4_prefix_octets(prefix_len);
    uint32_t addr = 0;
    uint8_t i;

    for (i = 0; i < n && i < 4; i++) {
        addr |= (uint32_t)wire[i] << (24 - 8 * i);
    }
    *addr_out = addr;
}

static void
format_ipv4_prefix_cidr(uint32_t addr,
                        uint8_t prefix_len,
                        char *buf,
                        size_t buflen)
{
    snprintf(buf, buflen, "%u.%u.%u.%u/%u",
             (addr >> 24) & 0xff,
             (addr >> 16) & 0xff,
             (addr >> 8) & 0xff,
             addr & 0xff,
             prefix_len);
}

static void
evpn_encode_ipv4_pfx_bytes(uint32_t addr,
                           uint8_t prefix_len,
                           uint8_t *wire_out)
{
    uint8_t n = evpn_ipv4_prefix_octets(prefix_len);
    uint8_t i;

    for (i = 0; i < n; i++) {
        wire_out[i] = (uint8_t)((addr >> (24 - 8 * i)) & 0xff);
    }
}

static void
evpn_decode_mpls_label3(const uint8_t wire[3], uint32_t *label_out)
{
    uint32_t entry =
        ((uint32_t)wire[0] << 12) |
        ((uint32_t)wire[1] << 4) |
        ((uint32_t)wire[2] >> 4);

    *label_out = entry & 0xfffff;
}

static void
format_esi(const uint8_t esi[10], char *buf, size_t buflen)
{
    snprintf(buf, buflen,
             "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             esi[0], esi[1], esi[2], esi[3], esi[4],
             esi[5], esi[6], esi[7], esi[8], esi[9]);
}

static bool
evpn_esi_is_zero(const uint8_t esi[10])
{
    uint8_t i;

    for (i = 0; i < 10; i++) {
        if (esi[i] != 0) {
            return false;
        }
    }
    return true;
}

/* Bracket display: all-zero ESI is shown as "0". */
static void
format_evpn_esi_bracket(const uint8_t esi[10], char *buf, size_t buflen)
{
    if (evpn_esi_is_zero(esi)) {
        snprintf(buf, buflen, "0");
        return;
    }

    snprintf(buf, buflen,
             "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             esi[0], esi[1], esi[2], esi[3], esi[4],
             esi[5], esi[6], esi[7], esi[8], esi[9]);
}

bgp_rib_err_t
bgp_evpn_nlri_encode(const bgp_evpn_nlri_t *nlri,
                     bgp_nlri_key_t *key_out)
{
    uint16_t offset = 0;

    if (!nlri || !key_out) {
        return BGP_RIB_ERR_NULL;
    }

    key_out->wire[offset++] = nlri->route_type;

    encode_rd_type1(&nlri->rd, &key_out->wire[offset]);
    offset += 8;

    switch (nlri->route_type) {
    case EVPN_RT_TYPE_IP_PREFIX:
        memset(&key_out->wire[offset], 0, 10);
        offset += 10;

        key_out->wire[offset++] = (uint8_t)((nlri->eth_tag_id >> 24) & 0xff);
        key_out->wire[offset++] = (uint8_t)((nlri->eth_tag_id >> 16) & 0xff);
        key_out->wire[offset++] = (uint8_t)((nlri->eth_tag_id >> 8) & 0xff);
        key_out->wire[offset++] = (uint8_t)(nlri->eth_tag_id & 0xff);

        {
            uint8_t pfx_len = nlri->ip_len ? nlri->ip_len : 32;
            uint8_t pfx_bytes = evpn_ipv4_prefix_octets(pfx_len);

            key_out->wire[offset++] = pfx_len;
            evpn_encode_ipv4_pfx_bytes(nlri->ip_addr, pfx_len,
                                       &key_out->wire[offset]);
            offset += pfx_bytes;
        }

        evpn_encode_ipv4_pfx_bytes(nlri->gw_addr, 32,
                                   &key_out->wire[offset]);
        offset += 4;

        if (nlri->label_present) {
            uint32_t entry = ((nlri->label & 0xfffff) << 4) | 0x1;

            key_out->wire[offset++] = (uint8_t)((entry >> 16) & 0xff);
            key_out->wire[offset++] = (uint8_t)((entry >> 8) & 0xff);
            key_out->wire[offset++] = (uint8_t)(entry & 0xff);
        }
        break;

    case EVPN_RT_TYPE_IMET:
        key_out->wire[offset++] = (uint8_t)((nlri->eth_tag_id >> 24) & 0xff);
        key_out->wire[offset++] = (uint8_t)((nlri->eth_tag_id >> 16) & 0xff);
        key_out->wire[offset++] = (uint8_t)((nlri->eth_tag_id >> 8) & 0xff);
        key_out->wire[offset++] = (uint8_t)(nlri->eth_tag_id & 0xff);

        key_out->wire[offset++] = nlri->ip_len ? nlri->ip_len : 32;
        if ((nlri->ip_len == 0 || nlri->ip_len == 32) && nlri->ip_addr) {
            key_out->wire[offset++] = (uint8_t)((nlri->ip_addr >> 24) & 0xff);
            key_out->wire[offset++] = (uint8_t)((nlri->ip_addr >> 16) & 0xff);
            key_out->wire[offset++] = (uint8_t)((nlri->ip_addr >> 8) & 0xff);
            key_out->wire[offset++] = (uint8_t)(nlri->ip_addr & 0xff);
        }
        break;

    case EVPN_RT_TYPE_MAC_ONLY:
    default:
        memcpy(&key_out->wire[offset], nlri->esi, 10);
        offset += 10;

        key_out->wire[offset++] = (uint8_t)((nlri->eth_tag_id >> 24) & 0xff);
        key_out->wire[offset++] = (uint8_t)((nlri->eth_tag_id >> 16) & 0xff);
        key_out->wire[offset++] = (uint8_t)((nlri->eth_tag_id >> 8) & 0xff);
        key_out->wire[offset++] = (uint8_t)(nlri->eth_tag_id & 0xff);

        key_out->wire[offset++] = nlri->mac_len;
        memcpy(&key_out->wire[offset], nlri->mac.mac, MAC_ADDR_SIZE);
        offset += MAC_ADDR_SIZE;

        key_out->wire[offset++] = nlri->ip_len;
        if (nlri->ip_len == 32) {
            key_out->wire[offset++] = (uint8_t)((nlri->ip_addr >> 24) & 0xff);
            key_out->wire[offset++] = (uint8_t)((nlri->ip_addr >> 16) & 0xff);
            key_out->wire[offset++] = (uint8_t)((nlri->ip_addr >> 8) & 0xff);
            key_out->wire[offset++] = (uint8_t)(nlri->ip_addr & 0xff);
        }

        if (nlri->label_present) {
            uint32_t entry = ((nlri->label & 0xfffff) << 4) | 0x1;

            key_out->wire[offset++] = (uint8_t)((entry >> 16) & 0xff);
            key_out->wire[offset++] = (uint8_t)((entry >> 8) & 0xff);
            key_out->wire[offset++] = (uint8_t)(entry & 0xff);
        }
        break;
    }

    key_out->wire_len = offset;
    return BGP_RIB_OK;
}

bgp_rib_err_t
bgp_evpn_nlri_decode(const bgp_nlri_key_t *key,
                     bgp_evpn_nlri_t *nlri_out)
{
    uint16_t offset = 0;

    if (!key || !nlri_out || key->wire_len < 9) {
        return BGP_RIB_ERR_NULL;
    }

    memset(nlri_out, 0, sizeof(*nlri_out));

    nlri_out->route_type = key->wire[offset++];

    if (decode_rd_wire(&key->wire[offset], &nlri_out->rd) != BGP_RIB_OK) {
        return BGP_RIB_ERR_DECODE;
    }
    offset += 8;

    if (nlri_out->route_type == EVPN_RT_TYPE_IP_PREFIX) {
        if (key->wire_len < offset + 10) {
            return BGP_RIB_ERR_DECODE;
        }

        memcpy(nlri_out->esi, &key->wire[offset], 10);
        offset += 10;

        nlri_out->eth_tag_id =
            ((uint32_t)key->wire[offset] << 24) |
            ((uint32_t)key->wire[offset + 1] << 16) |
            ((uint32_t)key->wire[offset + 2] << 8) |
            (uint32_t)key->wire[offset + 3];
        offset += 4;

        if (key->wire_len <= offset) {
            return BGP_RIB_OK;
        }

        nlri_out->ip_len = key->wire[offset++];
        {
            uint8_t pfx_bytes =
                evpn_ipv4_prefix_octets(nlri_out->ip_len);

            if (key->wire_len < offset + pfx_bytes) {
                return BGP_RIB_ERR_DECODE;
            }
            evpn_decode_ipv4_pfx_bytes(&key->wire[offset],
                                       nlri_out->ip_len,
                                       &nlri_out->ip_addr);
            offset += pfx_bytes;
        }

        if (nlri_out->ip_len <= 32) {
            if (key->wire_len < offset + 4) {
                return BGP_RIB_OK;
            }
            evpn_decode_ipv4_pfx_bytes(&key->wire[offset], 32,
                                       &nlri_out->gw_addr);
            offset += 4;
        }

        if (key->wire_len >= offset + 3) {
            evpn_decode_mpls_label3(&key->wire[offset], &nlri_out->label);
            nlri_out->label_present = true;
        }
        return BGP_RIB_OK;
    }

    if (nlri_out->route_type == EVPN_RT_TYPE_IMET) {
        if (key->wire_len < offset + 5) {
            return BGP_RIB_ERR_DECODE;
        }

        nlri_out->eth_tag_id =
            ((uint32_t)key->wire[offset] << 24) |
            ((uint32_t)key->wire[offset + 1] << 16) |
            ((uint32_t)key->wire[offset + 2] << 8) |
            (uint32_t)key->wire[offset + 3];
        offset += 4;

        nlri_out->ip_len = key->wire[offset++];
        if (nlri_out->ip_len == 32) {
            if (key->wire_len < offset + 4) {
                return BGP_RIB_ERR_DECODE;
            }
            nlri_out->ip_addr =
                ((uint32_t)key->wire[offset] << 24) |
                ((uint32_t)key->wire[offset + 1] << 16) |
                ((uint32_t)key->wire[offset + 2] << 8) |
                (uint32_t)key->wire[offset + 3];
            offset += 4;
        }
        return BGP_RIB_OK;
    }

    if (key->wire_len < offset + 10) {
        return BGP_RIB_ERR_DECODE;
    }

    memcpy(nlri_out->esi, &key->wire[offset], 10);
    offset += 10;

    nlri_out->eth_tag_id =
        ((uint32_t)key->wire[offset] << 24) |
        ((uint32_t)key->wire[offset + 1] << 16) |
        ((uint32_t)key->wire[offset + 2] << 8) |
        (uint32_t)key->wire[offset + 3];
    offset += 4;

    nlri_out->mac_len = key->wire[offset++];
    if (nlri_out->mac_len != 48 || key->wire_len < offset + MAC_ADDR_SIZE) {
        return BGP_RIB_ERR_DECODE;
    }

    memcpy(nlri_out->mac.mac, &key->wire[offset], MAC_ADDR_SIZE);
    offset += MAC_ADDR_SIZE;

    if (key->wire_len <= offset) {
        return BGP_RIB_OK;
    }

    nlri_out->ip_len = key->wire[offset++];
    if (nlri_out->ip_len == 32) {
        if (key->wire_len < offset + 4) {
            return BGP_RIB_ERR_DECODE;
        }
        nlri_out->ip_addr =
            ((uint32_t)key->wire[offset] << 24) |
            ((uint32_t)key->wire[offset + 1] << 16) |
            ((uint32_t)key->wire[offset + 2] << 8) |
            (uint32_t)key->wire[offset + 3];
        offset += 4;
    }

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
bgp_evpn_nlri_format_bracket(const bgp_nlri_key_t *key,
                             char *buf,
                             size_t buflen)
{
    bgp_evpn_nlri_t nlri;
    char rd_str[32];
    char mac_hex[13];
    char ip_str[32];

    if (!key || !buf || buflen == 0) {
        return -1;
    }

    if (bgp_evpn_nlri_decode(key, &nlri) != BGP_RIB_OK) {
        return -1;
    }

    bgp_rd_wire_to_str(&key->wire[1], rd_str, sizeof(rd_str));

    if (nlri.route_type == EVPN_RT_TYPE_IP_PREFIX) {
        char gw_str[32];
        char esi_br[24];
        uint16_t bit_len = bgp_nlri_key_bit_length(key);

        format_evpn_esi_bracket(nlri.esi, esi_br, sizeof(esi_br));

        if (nlri.ip_len > 0) {
            format_ipv4(nlri.ip_addr, ip_str, sizeof(ip_str));
        } else {
            ip_str[0] = '\0';
        }
        format_ipv4(nlri.gw_addr, gw_str, sizeof(gw_str));

        if (nlri.label_present) {
            snprintf(buf, buflen,
                     "[%u][%s][%s][%u][%u][%s][%s][%u]/%u",
                     nlri.route_type, rd_str, esi_br, nlri.eth_tag_id,
                     nlri.ip_len,
                     nlri.ip_len > 0 ? ip_str : "*",
                     gw_str, nlri.label, bit_len);
        } else {
            snprintf(buf, buflen,
                     "[%u][%s][%s][%u][%u][%s][%s]/%u",
                     nlri.route_type, rd_str, esi_br, nlri.eth_tag_id,
                     nlri.ip_len,
                     nlri.ip_len > 0 ? ip_str : "*",
                     gw_str, bit_len);
        }
        return 0;
    }

    /*
     * Length in bits of the EVPN NLRI key fields, excluding the
     * trailing MPLS label (shown separately as the last bracket).
     */
    {
        uint16_t bit_len = bgp_nlri_key_bit_length(key);

        if (nlri.label_present && bit_len >= 24) {
            bit_len = (uint16_t)(bit_len - 24);
        }

        if (nlri.route_type == EVPN_RT_TYPE_IMET) {
            /* Type 3: [3][RD][EthTag][IPLen][Originating-IP]/bits
             * (no ESI / MAC fields, per RFC 7432 IMET format). */
            if (nlri.ip_len == 32) {
                format_ipv4(nlri.ip_addr, ip_str, sizeof(ip_str));
                snprintf(buf, buflen,
                         "[%u][%s][%u][%u][%s]/%u",
                         nlri.route_type, rd_str, nlri.eth_tag_id,
                         nlri.ip_len, ip_str, bit_len);
            } else {
                snprintf(buf, buflen,
                         "[%u][%s][%u][%u][*]/%u",
                         nlri.route_type, rd_str, nlri.eth_tag_id,
                         nlri.ip_len, bit_len);
            }
            return 0;
        }

        if (nlri.route_type == EVPN_RT_TYPE_MAC_ONLY) {
            /* Type 2: [2][RD][ESI][EthTag][MACLen][MAC][IPLen][IP|*][Label]/bits */
            char esi_br[24];
            char mac_colon[20];

            format_evpn_esi_bracket(nlri.esi, esi_br, sizeof(esi_br));
            snprintf(mac_colon, sizeof(mac_colon),
                     "%02X:%02X:%02X:%02X:%02X:%02X",
                     nlri.mac.mac[0], nlri.mac.mac[1], nlri.mac.mac[2],
                     nlri.mac.mac[3], nlri.mac.mac[4], nlri.mac.mac[5]);

            if (nlri.ip_len == 32) {
                format_ipv4(nlri.ip_addr, ip_str, sizeof(ip_str));
            }

            if (nlri.label_present) {
                snprintf(buf, buflen,
                         "[%u][%s][%s][%u][%u][%s][%u][%s][%u]/%u",
                         nlri.route_type, rd_str, esi_br, nlri.eth_tag_id,
                         nlri.mac_len, mac_colon, nlri.ip_len,
                         nlri.ip_len == 32 ? ip_str : "*", nlri.label,
                         bit_len);
            } else {
                snprintf(buf, buflen,
                         "[%u][%s][%s][%u][%u][%s][%u][%s]/%u",
                         nlri.route_type, rd_str, esi_br, nlri.eth_tag_id,
                         nlri.mac_len, mac_colon, nlri.ip_len,
                         nlri.ip_len == 32 ? ip_str : "*",
                         bit_len);
            }
            return 0;
        }
    }

    if (nlri.ip_len == 32) {
        format_ipv4(nlri.ip_addr, ip_str, sizeof(ip_str));
    }

    snprintf(mac_hex, sizeof(mac_hex),
             "%02x%02x%02x%02x%02x%02x",
             nlri.mac.mac[0], nlri.mac.mac[1], nlri.mac.mac[2],
             nlri.mac.mac[3], nlri.mac.mac[4], nlri.mac.mac[5]);

    {
        uint16_t bit_len = bgp_nlri_key_bit_length(key);

        if (nlri.label_present && bit_len >= 24) {
            bit_len = (uint16_t)(bit_len - 24);
        }

        if (nlri.ip_len == 32) {
            snprintf(buf, buflen,
                     "[%u][%s][%u][%u][%s][%u][%s]/%u",
                     nlri.route_type, rd_str, nlri.eth_tag_id,
                     nlri.mac_len, mac_hex, nlri.ip_len, ip_str,
                     bit_len);
        } else {
            snprintf(buf, buflen,
                     "[%u][%s][%u][%u][%s][%u][*]/%u",
                     nlri.route_type, rd_str, nlri.eth_tag_id,
                     nlri.mac_len, mac_hex, nlri.ip_len,
                     bit_len);
        }
    }

    return 0;
}

int
bgp_evpn_nlri_format_compact(const bgp_nlri_key_t *key,
                             const bgp_rib_attrs_t *attrs,
                             char *buf,
                             size_t buflen)
{
    bgp_evpn_nlri_t nlri;
    char rd_str[32];
    char esi_str[40];
    char ip_str[32];

    if (!key || !buf || buflen == 0) {
        return -1;
    }

    if (bgp_evpn_nlri_decode(key, &nlri) != BGP_RIB_OK) {
        return -1;
    }

    bgp_rd_wire_to_str(&key->wire[1], rd_str, sizeof(rd_str));
    format_esi(nlri.esi, esi_str, sizeof(esi_str));

    if (nlri.route_type == EVPN_RT_TYPE_IP_PREFIX) {
        char gw_str[32];

        if (nlri.ip_len > 0) {
            format_ipv4(nlri.ip_addr, ip_str, sizeof(ip_str));
        } else {
            ip_str[0] = '\0';
        }
        format_ipv4(nlri.gw_addr, gw_str, sizeof(gw_str));

        if (nlri.label_present) {
            snprintf(buf, buflen,
                     "route_type=%u nlri_len=%u rd=%s esi=%s eth_tag=%u "
                     "ip_len=%u ip=%s gw=%s label=%u",
                     nlri.route_type,
                     bgp_nlri_key_bit_length(key),
                     rd_str, esi_str, nlri.eth_tag_id,
                     nlri.ip_len, ip_str, gw_str, nlri.label);
        } else {
            snprintf(buf, buflen,
                     "route_type=%u nlri_len=%u rd=%s esi=%s eth_tag=%u "
                     "ip_len=%u ip=%s gw=%s",
                     nlri.route_type,
                     bgp_nlri_key_bit_length(key),
                     rd_str, esi_str, nlri.eth_tag_id,
                     nlri.ip_len, ip_str, gw_str);
        }
        if (attrs && attrs->nexthop[0] != '\0') {
            size_t used = strlen(buf);
            snprintf(buf + used, buflen - used, " nh=%s", attrs->nexthop);
        }
        return 0;
    }

    if (nlri.ip_len == 32) {
        format_ipv4(nlri.ip_addr, ip_str, sizeof(ip_str));
    } else {
        ip_str[0] = '\0';
    }

    if (nlri.label_present) {
        snprintf(buf, buflen,
                 "route_type=%u nlri_len=%u rd=%s esi=%s eth_tag=%u "
                 "mac_len=%u mac=%02x:%02x:%02x:%02x:%02x:%02x "
                 "ip_len=%u ip=%s label=%u",
                 nlri.route_type,
                 bgp_nlri_key_bit_length(key),
                 rd_str, esi_str, nlri.eth_tag_id,
                 nlri.mac_len,
                 nlri.mac.mac[0], nlri.mac.mac[1], nlri.mac.mac[2],
                 nlri.mac.mac[3], nlri.mac.mac[4], nlri.mac.mac[5],
                 nlri.ip_len, ip_str, nlri.label);
    } else {
        snprintf(buf, buflen,
                 "route_type=%u nlri_len=%u rd=%s esi=%s eth_tag=%u "
                 "mac_len=%u mac=%02x:%02x:%02x:%02x:%02x:%02x "
                 "ip_len=%u ip=%s",
                 nlri.route_type,
                 bgp_nlri_key_bit_length(key),
                 rd_str, esi_str, nlri.eth_tag_id,
                 nlri.mac_len,
                 nlri.mac.mac[0], nlri.mac.mac[1], nlri.mac.mac[2],
                 nlri.mac.mac[3], nlri.mac.mac[4], nlri.mac.mac[5],
                 nlri.ip_len, ip_str);
    }

    if (attrs && attrs->nexthop[0] != '\0') {
        size_t used = strlen(buf);
        snprintf(buf + used, buflen - used, " nh=%s", attrs->nexthop);
    }

    return 0;
}

bgp_rib_err_t
bgp_evpn_nlri_to_evpn_rt(const bgp_evpn_nlri_t *nlri,
                         uint32_t vtep_ip,
                         evpn_exp_rt_t *evpn_rt_out)
{
    if (!nlri || !evpn_rt_out) {
        return BGP_RIB_ERR_NULL;
    }

    memset(evpn_rt_out, 0, sizeof(*evpn_rt_out));

    switch (nlri->route_type) {
    case EVPN_RT_TYPE_MAC_ONLY:
        evpn_rt_out->type = EVPN_RT_TYPE_MAC_ONLY;
        evpn_rt_out->flags = EVPN_RT_F_REMOTE;
        evpn_rt_out->vtep_ip = vtep_ip;
        memcpy(evpn_rt_out->u.mac_only.mac.mac,
               nlri->mac.mac, MAC_ADDR_SIZE);
        evpn_rt_out->u.mac_only.ip_addr = nlri->ip_addr;
        evpn_rt_out->u.mac_only.label =
            nlri->label_present ? nlri->label : 0;
        return BGP_RIB_OK;

    case EVPN_RT_TYPE_IMET:
        evpn_rt_out->type = EVPN_RT_TYPE_IMET;
        evpn_rt_out->flags = EVPN_RT_F_REMOTE;
        evpn_rt_out->vtep_ip = vtep_ip;
        evpn_rt_out->u.imet.pe_addr = nlri->ip_addr;
        evpn_rt_out->u.imet.evpn_label =
            nlri->label_present ? nlri->label : 0;
        return BGP_RIB_OK;

    default:
        return BGP_RIB_ERR_UNSUPPORTED_NLRI;
    }
}

bgp_rib_err_t
bgp_evpn_rib_route_add(bgp_rib_t *rib,
                       const bgp_evpn_nlri_t *nlri,
                       const bgp_rib_attrs_t *attrs)
{
    bgp_nlri_key_t key;

    if (!rib || !nlri || !attrs) {
        return BGP_RIB_ERR_NULL;
    }

    memset(&key, 0, sizeof(key));
    if (bgp_evpn_nlri_encode(nlri, &key) != BGP_RIB_OK) {
        return BGP_RIB_ERR_ENCODE;
    }

    return bgp_rib_route_add(rib, &key, attrs);
}

bgp_rib_err_t
bgp_evpn_rib_route_delete(bgp_rib_t *rib,
                          const bgp_evpn_nlri_t *nlri)
{
    bgp_nlri_key_t key;

    if (!rib || !nlri) {
        return BGP_RIB_ERR_NULL;
    }

    memset(&key, 0, sizeof(key));
    if (bgp_evpn_nlri_encode(nlri, &key) != BGP_RIB_OK) {
        return BGP_RIB_ERR_ENCODE;
    }

    return bgp_rib_route_delete(rib, &key);
}

const bgp_rib_attrs_t *
bgp_evpn_rib_route_lookup(const bgp_rib_t *rib,
                          const bgp_evpn_nlri_t *nlri)
{
    bgp_nlri_key_t key;

    if (!rib || !nlri) {
        return NULL;
    }

    memset(&key, 0, sizeof(key));
    if (bgp_evpn_nlri_encode(nlri, &key) != BGP_RIB_OK) {
        return NULL;
    }

    return bgp_rib_route_lookup(rib, &key);
}

static bool
bgp_evpn_route_parse_nexthop(const char *nexthop, uint32_t *vtep_ip_out)
{
    char nh_addr[64];
    char *slash;

    if (!nexthop || !vtep_ip_out || nexthop[0] == '\0') {
        return false;
    }

    strncpy(nh_addr, nexthop, sizeof(nh_addr) - 1);
    nh_addr[sizeof(nh_addr) - 1] = '\0';

    slash = strchr(nh_addr, '/');
    if (slash) {
        *slash = '\0';
    }

    *vtep_ip_out = ip_pton((c_string)nh_addr);
    return (*vtep_ip_out != 0);
}

static bool
bgp_evpn_import_rt_matches(evpn_inst_t *evpn_inst, const rt_t *route_rt)
{
    if (!evpn_inst || !route_rt) {
        return false;
    }

    if (!evpn_inst->import_rt.rtr_id && !evpn_inst->import_rt.vrf_id) {
        return false;
    }

    return evpn_inst->import_rt.rtr_id == route_rt->rtr_id &&
           evpn_inst->import_rt.vrf_id == route_rt->vrf_id;
}

static void
bgp_evpn_format_mac(const mac_addr_t *mac, char *buf, size_t buflen)
{
    snprintf(buf, buflen,
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->mac[0], mac->mac[1], mac->mac[2],
             mac->mac[3], mac->mac[4], mac->mac[5]);
}

static bool
bgp_evpn_vrf_import_rt_matches(vrf_t *vrf, const rt_t *route_rt)
{
    if (!vrf || !route_rt) {
        return false;
    }

    if (!vrf->import_rt.rtr_id && !vrf->import_rt.vrf_id) {
        return false;
    }

    return vrf->import_rt.rtr_id == route_rt->rtr_id &&
           vrf->import_rt.vrf_id == route_rt->vrf_id;
}

static bool
bgp_evpn_type5_nlri_to_cmn_prefix(const bgp_evpn_nlri_t *nlri,
                                    cmn_prefix_t *prefix_out)
{
    if (!nlri || !prefix_out ||
        nlri->route_type != EVPN_RT_TYPE_IP_PREFIX) {
        return false;
    }

    if (nlri->ip_len == 0 || nlri->ip_len > 32) {
        return false;
    }

    cmn_prefix_initialize_v4(prefix_out, nlri->ip_addr, nlri->ip_len);
    return true;
}

static bool
bgp_evpn_type5_build_nh_template(bgp_rib_attrs_t *attrs,
                                 const bgp_evpn_nlri_t *nlri,
                                 cp_nexthop_template_t *cp_nh_template)
{
    char nh_cidr[72];
    cmn_prefix_t gateway;
    rt_t import_rt;
    rtm_error_t rc;

    memset(cp_nh_template, 0, sizeof(*cp_nh_template));

    if (!attrs || !nlri || attrs->nexthop[0] == '\0') {
        return false;
    }

    if (strchr(attrs->nexthop, '/')) {
        strncpy(nh_cidr, attrs->nexthop, sizeof(nh_cidr) - 1);
        nh_cidr[sizeof(nh_cidr) - 1] = '\0';
    } else {
        snprintf(nh_cidr, sizeof(nh_cidr), "%s/32", attrs->nexthop);
    }

    if (!cmn_parse_prefix_string(nh_cidr, &gateway) ||
        gateway.afi != AF_IPV4) {
        return false;
    }

    if (!bgp_route_parse_rt_string(attrs->import_rt, &import_rt)) {
        return false;
    }

    cp_nh_template->is_indirect = true;
    cp_nh_template->is_resolved = false;
    cp_nh_template->proto = RTM_PROTO_BGP;
    cp_nh_template->sub_proto = RTM_SUB_PROTO_BGP_EVPN;
    cp_nh_template->action = RTM_NH_ACTION_FORWARD;
    cp_nh_template->metric = attrs->med_present ? attrs->med : 0;
    cp_nh_template->import_rt = import_rt;
    if (nlri->label_present && nlri->label) {
        cp_nh_template->vpn_label = (mpls_label_val_t)nlri->label;
    }
    memcpy(&cp_nh_template->gateway, &gateway, sizeof(gateway));

    rc = rtm_nh_proto_info_create(RTM_PROTO_BGP,
                                  RTM_SUB_PROTO_BGP_EVPN,
                                  0,
                                  RTM_DEFAULT_VRF,
                                  &cp_nh_template->rtm_nh_proto);
    if (rc != RTM_SUCCESS) {
        memset(cp_nh_template, 0, sizeof(*cp_nh_template));
        return false;
    }

    return true;
}

static void
bgp_global_rib_export_evpn_type5_route_cb(void *ctx,
                                          uint8_t afi,
                                          uint8_t safi,
                                          bgp_nlri_key_t *key,
                                          bgp_rib_attrs_t *attrs,
                                          bool is_add,
                                          uint16_t target_vrf_id)
{
    int i;
    vrf_t *vrf;
    rtm_t *cust_rtm;
    rtm_error_t rc;
    char nh_str[48];
    char route_str[48];
    cmn_prefix_t cmn_prefix;
    cp_nexthop_template_t cp_nh_template;
    bgp_evpn_nlri_t nlri;
    bgp_inst_t *bgp_inst = (bgp_inst_t *)ctx;
    node_t *node = bgp_inst ? bgp_inst->node : NULL;

    (void)afi;
    (void)safi;

    if (!node || !key || !attrs) {
        return;
    }

    if (is_add) {
        uint32_t nh_int = ip_pton((c_string)attrs->nexthop);
        if (nh_int == 0 || nh_int == NODE_RTR_ID_INT(node)) {
            tracer(bgp_inst->tr, DEVPN_DET,
                   "%s : [%s] : Type-5 route skipped on add — nexthop %s is self/invalid\n",
                   BGP_RTM_IM, BGP_L3EVPN_RIB_NAME,
                   attrs->nexthop[0] ? attrs->nexthop : "-");
            return;
        }
    }

    if (bgp_evpn_nlri_decode(key, &nlri) != BGP_RIB_OK ||
        nlri.route_type != EVPN_RT_TYPE_IP_PREFIX) {
        return;
    }

    if (!bgp_evpn_type5_nlri_to_cmn_prefix(&nlri, &cmn_prefix)) {
        tracer(bgp_inst->tr, DRTM | DERR,
               "%s : [%s] : Failed to derive prefix from Type-5 NLRI, "
               "%sInstallation Failed\n",
               BGP_RTM_IM, BGP_L3EVPN_RIB_NAME,
               is_add ? "" : "Un");
        return;
    }

    rtm_format_prefix(&cmn_prefix, route_str, sizeof(route_str));

    if (!bgp_evpn_type5_build_nh_template(attrs, &nlri, &cp_nh_template)) {
        tracer(bgp_inst->tr, DRTM | DERR,
               "%s : [%s] : Route %s, failed to build nh_template, "
               "%sInstallation Failed\n",
               BGP_RTM_IM, BGP_L3EVPN_RIB_NAME, route_str,
               is_add ? "" : "Un");
        tracer(node->cptr, DRTM | DERR,
               "%s : [%s] : Route %s, failed to build nh_template, "
               "%sInstallation Failed\n",
               BGP_RTM_IM, BGP_L3EVPN_RIB_NAME, route_str,
               is_add ? "" : "Un");
        return;
    }

    rtm_format_nexthop(&cp_nh_template.gateway, nh_str, sizeof(nh_str));

    tracer(bgp_inst->tr, DRTM_DET,
           "%s : [%s] : Route %s, nh_template built, op=%s\n",
           BGP_RTM_IM, BGP_L3EVPN_RIB_NAME, route_str,
           is_add ? "Add" : "Del");

    if (target_vrf_id == 0) {
        for (i = 1; i < MAX_VRF_PER_NODE; i++) {
            if (!node->vrf[i]) {
                continue;
            }

            vrf = node->vrf[i];
            cust_rtm = vrf->inet0;
            if (!cust_rtm) {
                continue;
            }

            if (!bgp_evpn_vrf_import_rt_matches(vrf,
                                                &cp_nh_template.import_rt)) {
                continue;
            }

            if (is_add) {
                rc = cp_rtm_install_route(cust_rtm, &cmn_prefix,
                                          &cp_nh_template);
            } else {
                rc = cp_rtm_uninstall_route(cust_rtm, &cmn_prefix,
                                            &cp_nh_template);
            }

            tracer(node->cptr, DRTM_DET,
                   "RTM[%s] : EVPN Type-5 route %s, %s %sInstalled in VRF %s, "
                   "Result : %s\n",
                   cust_rtm->name, route_str, nh_str,
                   is_add ? "" : "Un", vrf->vrf_name,
                   rtm_error_to_string(rc));
        }

        rtm_nh_template_free_internals(&cp_nh_template);
        return;
    }

    vrf = vrf_get_by_id(node, (uint8_t)target_vrf_id);
    if (!vrf || !vrf->inet0) {
        rtm_nh_template_free_internals(&cp_nh_template);
        return;
    }

    if (!bgp_evpn_vrf_import_rt_matches(vrf, &cp_nh_template.import_rt)) {
        rtm_nh_template_free_internals(&cp_nh_template);
        return;
    }

    cust_rtm = vrf->inet0;
    if (is_add) {
        rc = cp_rtm_install_route(cust_rtm, &cmn_prefix, &cp_nh_template);
    } else {
        rc = cp_rtm_uninstall_route(cust_rtm, &cmn_prefix, &cp_nh_template);
    }

    tracer(node->cptr, DRTM_DET,
           "RTM[%s] : EVPN Type-5 route %s, %s %sInstalled in VRF %s, "
           "Result : %s\n",
           cust_rtm->name, route_str, nh_str,
           is_add ? "" : "Un", vrf->vrf_name,
           rtm_error_to_string(rc));

    rtm_nh_template_free_internals(&cp_nh_template);
}

static void
bgp_evpn_install_to_mac_vrf(mac_vrf_t *mac_vrf,
                            const bgp_evpn_nlri_t *nlri,
                            uint32_t vtep_ip,
                            uint32_t label,
                            uint32_t seq_no,
                            bool seq_present,
                            bool is_add)
{
    if (!mac_vrf || !nlri) {
        return;
    }

    switch (nlri->route_type) {
    case EVPN_RT_TYPE_MAC_ONLY:
        if (is_add) {
            mac_vrf_evpn_route_type2_remote_import(mac_vrf,
                                                 (mac_addr_t *)&nlri->mac,
                                                 nlri->ip_addr,
                                                 vtep_ip,
                                                 label,
                                                 seq_no);
        } else {
            mac_vrf_evpn_route_type2_remote_delete(mac_vrf,
                                                   (mac_addr_t *)&nlri->mac,
                                                   nlri->ip_addr,
                                                   seq_no,
                                                   seq_present);
        }
        break;

    case EVPN_RT_TYPE_IMET:
        if (is_add) {
            mac_vrf_evpn_route_type3_remote_import(mac_vrf,
                                                   nlri->ip_addr,
                                                   vtep_ip,
                                                   label);
        } else {
            mac_vrf_evpn_route_type3_remote_delete(mac_vrf, nlri->ip_addr);
        }
        break;

    default:
        break;
    }
}

void
bgp_global_rib_export_evpn_route_cb(void *ctx,
                                    uint8_t afi,
                                    uint8_t safi,
                                    bgp_nlri_key_t *key,
                                    bgp_rib_attrs_t *attrs,
                                    bool is_add,
                                    uint16_t target_evi)
{
    int i;
    char mac_str[32];
    char pe_str[16];
    char nh_str[16];
    rt_t import_rt;
    uint32_t vtep_ip = 0;
    uint32_t label = 0;
    uint32_t seq_no = 0;
    bool seq_present = false;
    bgp_evpn_nlri_t nlri;
    evpn_inst_t *evpn_inst;
    bgp_inst_t *bgp_inst = (bgp_inst_t *)ctx;
    node_t *node = bgp_inst->node;

    if (!node || !key || !attrs) {
        return;
    }

    if (is_add) {
        uint32_t nh_int = ip_pton((c_string)attrs->nexthop);
        if (nh_int == 0 || nh_int == NODE_RTR_ID_INT(node)) {
            tracer(bgp_inst->tr, DEVPN_DET,
                   "%s : [%s] : Route skipped on add — nexthop %s is self/invalid\n",
                   BGP_RTM_IM, BGP_EVPN_RIB_NAME,
                   attrs->nexthop[0] ? attrs->nexthop : "-");
            return;
        }
    }

    if (bgp_evpn_nlri_decode(key, &nlri) != BGP_RIB_OK) {
        return;
    }

    if (nlri.route_type == EVPN_RT_TYPE_IP_PREFIX) {
        bgp_global_rib_export_evpn_type5_route_cb(ctx, afi, safi, key, attrs,
                                                  is_add, target_evi);
        return;
    }

    if (nlri.route_type != EVPN_RT_TYPE_MAC_ONLY &&
        nlri.route_type != EVPN_RT_TYPE_IMET) {
        return;
    }

    if (!bgp_route_parse_rt_string(attrs->import_rt, &import_rt)) {
        tracer(bgp_inst->tr, DRTM | DERR,
               "%s : [%s] : Failed to parse import RT for EVPN route, "
               "%sInstallation Failed\n",
               BGP_RTM_IM, BGP_EVPN_RIB_NAME,
               is_add ? "" : "Un");
        return;
    }

    if (is_add &&
        !bgp_evpn_route_parse_nexthop(attrs->nexthop, &vtep_ip)) {
        tracer(bgp_inst->tr, DRTM | DERR,
               "%s : [%s] : Failed to parse VTEP nexthop, "
               "%sInstallation Failed\n",
               BGP_RTM_IM, BGP_EVPN_RIB_NAME,
               is_add ? "" : "Un");
        return;
    }

    if (nlri.label_present && nlri.label) {
        label = nlri.label;
    } else if (attrs->pmsi_label_present) {
        label = attrs->pmsi_label;
    } else if (attrs->evpn_label1_present) {
        label = attrs->evpn_label1;
    }

    if (attrs->mac_mobility_seq_present) {
        seq_no = attrs->mac_mobility_seq;
        seq_present = true;
    }

    if (nlri.route_type == EVPN_RT_TYPE_MAC_ONLY) {
        bgp_evpn_format_mac(&nlri.mac, mac_str, sizeof(mac_str));
    } else {
        format_ipv4(nlri.ip_addr, pe_str, sizeof(pe_str));
    }

    if (is_add) {
        ip_ntop(vtep_ip, (c_string)nh_str);
    } else {
        nh_str[0] = '\0';
    }

    if (nlri.route_type == EVPN_RT_TYPE_MAC_ONLY) {
        tracer(bgp_inst->tr, DRTM_DET,
               "%s : [%s] : Route %s, nh %s label %u, op=%s\n",
               BGP_RTM_IM, BGP_EVPN_RIB_NAME, mac_str,
               is_add ? nh_str : "-", label,
               is_add ? "Add" : "Del");

        tracer(node->cptr, DRTM_DET,
               "%s : [%s] : Route %s, nh %s label %u, op=%s\n",
               BGP_RTM_IM, BGP_EVPN_RIB_NAME, mac_str,
               is_add ? nh_str : "-", label,
               is_add ? "Add" : "Del");
    } else {
        tracer(bgp_inst->tr, DRTM_DET,
               "%s : [%s] : IMET PE %s, nh %s BUM label %u, op=%s\n",
               BGP_RTM_IM, BGP_EVPN_RIB_NAME, pe_str,
               is_add ? nh_str : "-", label,
               is_add ? "Add" : "Del");

        tracer(node->cptr, DRTM_DET,
               "%s : [%s] : IMET PE %s, nh %s BUM label %u, op=%s\n",
               BGP_RTM_IM, BGP_EVPN_RIB_NAME, pe_str,
               is_add ? nh_str : "-", label,
               is_add ? "Add" : "Del");
    }

    if (target_evi == 0) {
        for (i = 0; i < MAX_EVPN_INDEX; i++) {
            evpn_inst = node->evpn[i];
            if (!evpn_inst || !evpn_inst->mac_vrf) {
                continue;
            }

            if (!bgp_evpn_import_rt_matches(evpn_inst, &import_rt)) {
                continue;
            }

            bgp_evpn_install_to_mac_vrf(evpn_inst->mac_vrf,
                                        &nlri, vtep_ip, label, seq_no,
                                        seq_present, is_add);

            tracer(node->cptr, DRTM_DET,
                   "EVPN[%u] : Type-%u %s %sInstalled into MAC VRF %u\n",
                   evpn_inst->evi,
                   nlri.route_type,
                   nlri.route_type == EVPN_RT_TYPE_IMET ? pe_str : mac_str,
                   is_add ? "" : "Un",
                   evpn_inst->mac_vrf->mac_vrf_id);
        }
        return;
    }

    if (target_evi >= MAX_EVPN_INDEX) {
        return;
    }

    evpn_inst = node->evpn[target_evi];
    if (!evpn_inst || !evpn_inst->mac_vrf) {
        return;
    }

    if (!bgp_evpn_import_rt_matches(evpn_inst, &import_rt)) {
        return;
    }

    bgp_evpn_install_to_mac_vrf(evpn_inst->mac_vrf,
                                &nlri, vtep_ip, label, seq_no,
                                seq_present, is_add);

    tracer(node->cptr, DRTM_DET,
           "EVPN[%u] : Type-%u %s %sInstalled into MAC VRF %u\n",
           evpn_inst->evi,
           nlri.route_type,
           nlri.route_type == EVPN_RT_TYPE_IMET ? pe_str : mac_str,
           is_add ? "" : "Un",
           evpn_inst->mac_vrf->mac_vrf_id);
}
