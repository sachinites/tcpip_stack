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

static void
format_esi(const uint8_t esi[10], char *buf, size_t buflen)
{
    snprintf(buf, buflen,
             "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
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
        /* RFC 8277: 20-bit label in high-order bits of 3 octets; BoS in LSB. */
        uint32_t entry = ((nlri->label & 0xfffff) << 4) | 0x1;

        key_out->wire[offset++] = (uint8_t)((entry >> 16) & 0xff);
        key_out->wire[offset++] = (uint8_t)((entry >> 8) & 0xff);
        key_out->wire[offset++] = (uint8_t)(entry & 0xff);
    }

    key_out->wire_len = offset;
    return BGP_RIB_OK;
}

bgp_rib_err_t
bgp_evpn_nlri_decode(const bgp_nlri_key_t *key,
                     bgp_evpn_nlri_t *nlri_out)
{
    uint16_t offset = 0;

    if (!key || !nlri_out || key->wire_len < 30) {
        return BGP_RIB_ERR_NULL;
    }

    memset(nlri_out, 0, sizeof(*nlri_out));

    nlri_out->route_type = key->wire[offset++];

    if (decode_rd_wire(&key->wire[offset], &nlri_out->rd) != BGP_RIB_OK) {
        return BGP_RIB_ERR_DECODE;
    }
    offset += 8;

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
    snprintf(mac_hex, sizeof(mac_hex),
             "%02x%02x%02x%02x%02x%02x",
             nlri.mac.mac[0], nlri.mac.mac[1], nlri.mac.mac[2],
             nlri.mac.mac[3], nlri.mac.mac[4], nlri.mac.mac[5]);

    if (nlri.ip_len == 32) {
        format_ipv4(nlri.ip_addr, ip_str, sizeof(ip_str));
    }

    /*
     * Length in bits of the EVPN NLRI key fields, excluding the
     * trailing MPLS label (shown separately as Label1).
     */
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

static void
bgp_evpn_install_to_mac_vrf(mac_vrf_t *mac_vrf,
                            const bgp_evpn_nlri_t *nlri,
                            uint32_t vtep_ip,
                            uint32_t label,
                            bool is_add)
{
    if (!mac_vrf || !nlri) {
        return;
    }

    if (nlri->route_type != EVPN_RT_TYPE_MAC_ONLY) {
        return;
    }

    if (is_add) {
        mac_vrf_evpn_route_type2_remote_import(mac_vrf,
                                             (mac_addr_t *)&nlri->mac,
                                             vtep_ip,
                                             label);
    } else {
        mac_vrf_evpn_route_type2_remote_delete(mac_vrf,
                                               (mac_addr_t *)&nlri->mac);
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
    char nh_str[16];
    rt_t import_rt;
    uint32_t vtep_ip = 0;
    uint32_t label = 0;
    bgp_evpn_nlri_t nlri;
    evpn_inst_t *evpn_inst;
    bgp_inst_t *bgp_inst = (bgp_inst_t *)ctx;
    node_t *node = bgp_inst->node;

    if (!node || !key || !attrs) {
        return;
    }

    {
        uint32_t nh_int = ip_pton((c_string)attrs->nexthop);
        if (nh_int == 0 || nh_int == NODE_RTR_ID_INT(node)) {
            return;
        }
    }

    if (bgp_evpn_nlri_decode(key, &nlri) != BGP_RIB_OK) {
        return;
    }

    if (nlri.route_type != EVPN_RT_TYPE_MAC_ONLY) {
        return;
    }

    if (is_add && !attrs->best) {
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
    } else if (attrs->evpn_label1_present) {
        label = attrs->evpn_label1;
    }

    bgp_evpn_format_mac(&nlri.mac, mac_str, sizeof(mac_str));
    if (is_add) {
        ip_ntop(vtep_ip, (c_string)nh_str);
    } else {
        nh_str[0] = '\0';
    }

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
                                        &nlri, vtep_ip, label, is_add);

            tracer(node->cptr, DRTM_DET,
                   "EVPN[%u] : Type-2 MAC %s %sInstalled into MAC VRF %u\n",
                   evpn_inst->evi, mac_str,
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
                                &nlri, vtep_ip, label, is_add);

    tracer(node->cptr, DRTM_DET,
           "EVPN[%u] : Type-2 MAC %s %sInstalled into MAC VRF %u\n",
           evpn_inst->evi, mac_str,
           is_add ? "" : "Un",
           evpn_inst->mac_vrf->mac_vrf_id);
}
