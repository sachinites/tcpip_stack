#include <stdio.h>
#include <string.h>

#include "../../tcpconst.h"

#include "bgp_nlri_wire.h"
#include "bgp_nlri_key.h"
#include "bgp_rib_evpn.h"
#include "bgp_rib_vpnv4.h"

static void
append_attrs_suffix(const bgp_rib_attrs_t *attrs,
                    char *buf,
                    size_t buflen)
{
    size_t used = strlen(buf);

    if (!attrs || used >= buflen) {
        return;
    }

    if (attrs->nexthop[0] != '\0') {
        snprintf(buf + used, buflen - used, " nh=%s", attrs->nexthop);
        used = strlen(buf);
    }
    if (attrs->med_present && used < buflen) {
        snprintf(buf + used, buflen - used, " med=%u", attrs->med);
        used = strlen(buf);
    }
    if (attrs->local_pref_present && used < buflen) {
        snprintf(buf + used, buflen - used, " local_pref=%u", attrs->local_pref);
        used = strlen(buf);
    }
    if (attrs->rt_present && used < buflen) {
        snprintf(buf + used, buflen - used, " rt=%s", attrs->import_rt);
        used = strlen(buf);
    }
    if (attrs->best && used < buflen) {
        snprintf(buf + used, buflen - used, " best=1");
        used = strlen(buf);
    }
    if (attrs->is_from_external && used < buflen) {
        snprintf(buf + used, buflen - used, " external=1");
    }
}

int
bgp_rd_wire_to_str(const uint8_t rd_wire[8],
                   char *buf,
                   size_t buflen)
{
    uint16_t rd_type;

    if (!rd_wire || !buf || buflen == 0) {
        return -1;
    }

    rd_type = (uint16_t)((rd_wire[0] << 8) | rd_wire[1]);

    switch (rd_type) {
    case 0x0000: {
        uint16_t admin = (uint16_t)((rd_wire[2] << 8) | rd_wire[3]);
        uint32_t assigned = ((uint32_t)rd_wire[4] << 24) |
                            ((uint32_t)rd_wire[5] << 16) |
                            ((uint32_t)rd_wire[6] << 8) |
                            (uint32_t)rd_wire[7];
        snprintf(buf, buflen, "%u:%u", admin, assigned);
        break;
    }
    case 0x0001: {
        snprintf(buf, buflen,
                 "%u.%u.%u.%u:%u",
                 rd_wire[2], rd_wire[3], rd_wire[4], rd_wire[5],
                 (uint16_t)((rd_wire[6] << 8) | rd_wire[7]));
        break;
    }
    case 0x0002: {
        uint32_t admin = ((uint32_t)rd_wire[2] << 24) |
                         ((uint32_t)rd_wire[3] << 16) |
                         ((uint32_t)rd_wire[4] << 8) |
                         (uint32_t)rd_wire[5];
        uint16_t assigned = (uint16_t)((rd_wire[6] << 8) | rd_wire[7]);
        snprintf(buf, buflen, "%u:%u", admin, assigned);
        break;
    }
    default:
        snprintf(buf, buflen,
                 "type=%u bytes=%02x%02x%02x%02x%02x%02x%02x%02x",
                 rd_type,
                 rd_wire[0], rd_wire[1], rd_wire[2], rd_wire[3],
                 rd_wire[4], rd_wire[5], rd_wire[6], rd_wire[7]);
        break;
    }

    return 0;
}

int
bgp_nlri_wire_format_compact(uint8_t afi,
                             uint8_t safi,
                             const bgp_nlri_key_t *key,
                             const bgp_rib_attrs_t *attrs,
                             char *buf,
                             size_t buflen)
{
    if (!key || !buf || buflen == 0) {
        return -1;
    }

    buf[0] = '\0';

    if (safi == SAFI_MPLS_EVPN) {
        return bgp_evpn_nlri_format_compact(key, attrs, buf, buflen);
    }

    if (safi == SAFI_MPLS_VPN) {
        return bgp_vpnv4_nlri_format_compact(key, attrs, buf, buflen);
    }

    if (safi == SAFI_UNICAST && afi == AFI_IPV4) {
        return bgp_vpnv4_ipv4_unicast_format_compact(key, attrs, buf, buflen);
    }

    snprintf(buf, buflen,
             "nlri_len=%u wire=%02x",
             bgp_nlri_key_bit_length(key),
             key->wire_len > 0 ? key->wire[0] : 0);
    append_attrs_suffix(attrs, buf, buflen);
    return 0;
}

void
bgp_nlri_wire_print_route(uint8_t afi,
                          uint8_t safi,
                          const bgp_nlri_key_t *key,
                          const bgp_rib_attrs_t *attrs,
                          FILE *fp)
{
    char line[512];

    if (!fp || !key) {
        return;
    }

    if (bgp_nlri_wire_format_compact(afi, safi, key, attrs,
                                     line, sizeof(line)) != 0) {
        fprintf(fp, "nlri=<format-error>\n");
        return;
    }

    fprintf(fp, "%s\n", line);
}
